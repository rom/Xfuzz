package mutate

import (
	"bytes"
	"testing"

	"github.com/rom/Xfuzz/pkg/ir"
	"github.com/rom/Xfuzz/pkg/rng"
)

func testCtx(seed uint64) *Ctx {
	c := NewCtx(seed, 0, ir.NewArena())
	c.Dict = testDict()
	return c
}

func testDict() *Dictionary {
	d := NewDictionary()
	d.Add("ihdr", []byte("IHDR"), 0)
	d.Add("idat", []byte("IDAT"), 0)
	d.Add("magic", []byte{0x89, 0x50, 0x4e, 0x47}, 0)
	return d
}

func payload(a *ir.Arena, b []byte) *ir.Node {
	n := ir.Blob("data", nil)
	n.Raw = a.CopyBytes(b)
	return n
}

// TestOperatorsChangeSomething checks the contract every operator must honour:
// returning true means the node actually changed. Per-operator accounting is
// built on that promise, and an operator that lies about it makes the yield
// report worthless.
func TestOperatorsChangeSomething(t *testing.T) {
	for _, m := range All() {
		t.Run(m.Name(), func(t *testing.T) {
			c := testCtx(1)
			applied, honest := 0, 0

			for attempt := 0; attempt < 400; attempt++ {
				c.Arena.Reset()
				root := freshTree(c.Arena)
				c.Root = root
				c.Donor = donorTree(c.Arena)
				target := findTarget(c, root, m)
				if target == nil {
					continue
				}

				before := ir.Encode(root)
				if !m.Mutate(c, target) {
					continue
				}
				applied++
				if !bytes.Equal(ir.Encode(root), before) {
					honest++
				}
			}

			if applied == 0 {
				t.Fatalf("%s never applied in 400 attempts; it is dead weight in the schedule", m.Name())
			}
			// A few operators can legitimately produce an identical encoding —
			// a swap of two equal elements, for instance — but it must be rare.
			if float64(honest)/float64(applied) < 0.85 {
				t.Errorf("%s reported %d changes but only %d altered the encoding (%.0f%%)",
					m.Name(), applied, honest, 100*float64(honest)/float64(applied))
			}
		})
	}
}

// freshTree builds a tree exercising every node kind.
func freshTree(a *ir.Arena) *ir.Node {
	return ir.Struct("root",
		payload(a, []byte("the quick brown fox jumps over the lazy dog")),
		ir.U32BE("count", 7),
		ir.Choice("variant", 0, ir.U8("a", 1), ir.U16BE("b", 2), ir.Blob("c", []byte("cc"))),
		ir.Opt("maybe", true, ir.U8("m", 3)),
		ir.Repeat("items",
			ir.U8("", 1), ir.U8("", 2), ir.U8("", 3), ir.U8("", 4)),
		ir.Text("label", "hello world"),
	)
}

// findTarget returns the first node the operator can act on in this context.
func findTarget(c *Ctx, root *ir.Node, m Mutator) *ir.Node {
	var target *ir.Node
	ir.Walk(root, func(n *ir.Node) bool {
		if target == nil && m.CanApply(c, n) {
			target = n
		}
		return true
	})
	return target
}

func donorTree(a *ir.Arena) *ir.Node {
	return ir.Struct("root",
		payload(a, bytes.Repeat([]byte("DONOR"), 20)),
		ir.U32BE("count", 999),
		ir.Repeat("items", ir.U8("", 9), ir.U8("", 8)),
		ir.Text("label", "donated text"),
	)
}

// TestOperatorsAreDeterministic is the reproducibility contract from ASR-0008
// at the operator level: the same stream position produces the same mutation.
func TestOperatorsAreDeterministic(t *testing.T) {
	for _, m := range All() {
		t.Run(m.Name(), func(t *testing.T) {
			var results [2][]byte
			for run := 0; run < 2; run++ {
				c := testCtx(0xC0FFEE)
				root := freshTree(c.Arena)
				c.Root = root
				c.Donor = donorTree(c.Arena)
				target := findTarget(c, root, m)
				if target == nil {
					t.Skip("no applicable node")
				}
				m.Mutate(c, target)
				results[run] = ir.Encode(root)
			}
			if !bytes.Equal(results[0], results[1]) {
				t.Errorf("%s produced different results from the same seed", m.Name())
			}
		})
	}
}

func TestByteOperatorsRespectMaxBytes(t *testing.T) {
	for _, m := range []Mutator{InsertBytes{}, CopyBytes{}, DictInsert{}, SpliceBytes{}} {
		t.Run(m.Name(), func(t *testing.T) {
			c := testCtx(2)
			c.MaxBytes = 64
			c.Dict = testDict()
			for i := 0; i < 500; i++ {
				n := payload(c.Arena, bytes.Repeat([]byte{0x41}, 60))
				c.Root = ir.Struct("root", n)
				c.Donor = donorTree(c.Arena)
				m.Mutate(c, n)
				if len(n.Raw) > c.MaxBytes {
					t.Fatalf("%s grew a payload to %d bytes, past the %d limit",
						m.Name(), len(n.Raw), c.MaxBytes)
				}
			}
		})
	}
}

func TestRepeatOperatorsRespectMaxChildren(t *testing.T) {
	c := testCtx(3)
	c.MaxChildren = 10
	n := ir.Repeat("items", ir.U8("", 1), ir.U8("", 2))
	c.Root = n
	for i := 0; i < 500; i++ {
		RepeatInsert{}.Mutate(c, n)
		RepeatDuplicate{}.Mutate(c, n)
		if len(n.Children) > c.MaxChildren {
			t.Fatalf("a sequence grew to %d elements, past the %d limit", len(n.Children), c.MaxChildren)
		}
	}
}

func TestDeleteBytesShrinks(t *testing.T) {
	c := testCtx(4)
	n := payload(c.Arena, bytes.Repeat([]byte{1}, 100))
	before := len(n.Raw)
	if !(DeleteBytes{}).Mutate(c, n) {
		t.Fatal("delete did not apply")
	}
	if len(n.Raw) >= before {
		t.Errorf("delete left %d bytes, was %d", len(n.Raw), before)
	}
}

func TestChoiceSwitchAlwaysChangesSelection(t *testing.T) {
	c := testCtx(5)
	n := ir.Choice("v", 1, ir.U8("a", 1), ir.U8("b", 2), ir.U8("c", 3))
	for i := 0; i < 200; i++ {
		before := n.Sel
		if !(ChoiceSwitch{}).Mutate(c, n) {
			t.Fatal("switch did not apply")
		}
		if n.Sel == before {
			t.Fatal("switch selected the same alternative; it must always move")
		}
		if n.Sel < 0 || int(n.Sel) >= len(n.Children) {
			t.Fatalf("switch selected %d of %d", n.Sel, len(n.Children))
		}
	}
}

func TestIntOperatorsIgnoreDerivedNodes(t *testing.T) {
	// Derived values are recomputed by the fixup pass, so mutating them is at
	// best wasted work and at worst a change the fixup silently reverts, which
	// would corrupt per-operator accounting.
	c := testCtx(0)
	d := ir.LenOf("len", 4, ir.BigEndian, ir.Sibling("data"))
	for _, m := range []Mutator{IntArith{}, IntInteresting{}, IntRandom{}, IntBitFlip{}} {
		if m.CanApply(c, d) {
			t.Errorf("%s claims it can mutate a derived node", m.Name())
		}
	}
}

func TestSpliceNeedsADonor(t *testing.T) {
	c := testCtx(6)
	c.Donor = nil
	n := payload(c.Arena, []byte("target"))
	c.Root = ir.Struct("root", n)

	// Declining at CanApply is what matters: an operator that accepts a node and
	// then does nothing spends the scheduler's budget for no result.
	if (SpliceBytes{}).CanApply(c, n) {
		t.Error("splice-bytes claims it can apply without a donor")
	}
	if (SpliceSubtree{}).CanApply(c, n) {
		t.Error("splice-subtree claims it can apply without a donor")
	}
	if (SpliceBytes{}).Mutate(c, n) || (SpliceSubtree{}).Mutate(c, n) {
		t.Error("a splice operator applied without a donor")
	}
}

func TestSpliceSubtreeDeclinesTheRoot(t *testing.T) {
	// Replacing the root with a copy of the donor is a substitution, not a
	// crossover: the result is simply the other corpus entry.
	c := testCtx(6)
	root := freshTree(c.Arena)
	c.Root = root
	c.Donor = donorTree(c.Arena)
	if (SpliceSubtree{}).CanApply(c, root) {
		t.Error("splice-subtree should decline the root")
	}
	if !(SpliceSubtree{}).CanApply(c, root.Children[0]) {
		t.Error("splice-subtree should accept a non-root node with a donor")
	}
}

func TestSpliceSubtreeKeepsTheName(t *testing.T) {
	// Sibling derivations resolve by name, so a graft that renamed its target
	// would break every length and checksum that refers to it.
	c := testCtx(7)
	target := ir.Text("label", "original")
	c.Root = ir.Struct("root", target)
	c.Donor = donorTree(c.Arena)
	if !(SpliceSubtree{}).Mutate(c, target) {
		t.Skip("no compatible donor node")
	}
	if target.Name != "label" {
		t.Errorf("splice renamed the node to %q", target.Name)
	}
	if string(target.Raw) != "donated text" {
		t.Errorf("splice produced %q, want the donor's content", target.Raw)
	}
}

func TestDictionaryOperatorsAreInertWithoutTokens(t *testing.T) {
	c := testCtx(8)
	n := payload(c.Arena, []byte("some bytes here"))
	for _, dict := range []*Dictionary{nil, NewDictionary()} {
		c.Dict = dict
		if (DictOverwrite{}).CanApply(c, n) || (DictInsert{}).CanApply(c, n) {
			t.Error("a dictionary operator claims it can apply with no tokens")
		}
		if (DictOverwrite{}).Mutate(c, n) || (DictInsert{}).Mutate(c, n) {
			t.Error("a dictionary operator applied with no tokens")
		}
	}
}

func TestDictInsertPlacesTheWholeToken(t *testing.T) {
	c := testCtx(9)
	found := false
	for i := 0; i < 200 && !found; i++ {
		n := payload(c.Arena, []byte("xxxxxxxxxxxx"))
		if (DictInsert{}).Mutate(c, n) {
			for j := 0; j < c.Dict.Len(); j++ {
				_, tok := c.Dict.At(j)
				if bytes.Contains(n.Raw, tok) {
					found = true
				}
			}
		}
	}
	if !found {
		t.Error("dict-insert never placed a complete token")
	}
}

func TestWriteIntMatchesReadInt(t *testing.T) {
	for _, w := range []uint8{1, 2, 4, 8} {
		for _, e := range []ir.Endian{ir.BigEndian, ir.LittleEndian} {
			buf := make([]byte, w)
			const v = int64(0x0102030405060708)
			writeInt(buf, v, w, e)

			// A narrow window keeps only the low bytes, matching what the
			// encoder writes.
			want := v
			if w < 8 {
				want = v & (int64(1)<<(8*uint(w)) - 1)
			}
			if got := ir.ReadInt(buf, w, e, false); got != want {
				t.Errorf("width %d %s: read back %#x, want %#x", w, e, got, want)
			}
		}
	}
}

func TestNodeKindNames(t *testing.T) {
	for _, k := range []Kind{KindByte, KindStructural, KindSplice, KindDictionary} {
		if k.String() == "unknown" {
			t.Errorf("kind %d has no name", k)
		}
	}
	if Kind(99).String() != "unknown" {
		t.Error("an unrecognised kind should render as unknown")
	}
	// An operator that does not declare a class is treated as byte-level.
	if KindOf(undeclared{}) != KindByte {
		t.Error("an undeclared operator should default to KindByte")
	}
	if KindOf(IntArith{}) != KindStructural {
		t.Error("IntArith should declare itself structural")
	}
}

type undeclared struct{}

func (undeclared) Name() string                 { return "undeclared" }
func (undeclared) CanApply(*Ctx, *ir.Node) bool { return false }
func (undeclared) Mutate(*Ctx, *ir.Node) bool   { return false }

func TestNewCtxDerivesDistinctStreams(t *testing.T) {
	c := NewCtx(1234, 2, ir.NewArena())
	if c.Rand == nil || c.Select == nil || c.Nodes == nil {
		t.Fatal("NewCtx must derive all three streams")
	}
	a, b, d := c.Rand.Uint64(), c.Select.Uint64(), c.Nodes.Uint64()
	if a == b || b == d || a == d {
		t.Error("the three streams must be independent")
	}
	// And the same inputs must reproduce them.
	c2 := NewCtx(1234, 2, ir.NewArena())
	if c2.Rand.Uint64() != a || c2.Select.Uint64() != b || c2.Nodes.Uint64() != d {
		t.Error("NewCtx must be deterministic in campaign seed and worker id")
	}
}

var _ = rng.StreamMutatorParam
