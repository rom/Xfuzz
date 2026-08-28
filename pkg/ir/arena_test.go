package ir

import (
	"testing"
)

func sampleTree() *Node {
	return Repeat("chunks",
		chunk("IHDR", "\x00\x00\x01\x00\x00\x00\x01\x00\x08\x06\x00\x00\x00"),
		chunk("IDAT", "the quick brown fox jumps over the lazy dog"),
		chunk("tEXt", "Comment\x00generated"),
		chunk("IEND", ""),
	)
}

func TestArenaCloneIsIndependent(t *testing.T) {
	orig := sampleTree()
	a := NewArena()
	c := a.Clone(orig)

	if !Equal(orig, c) {
		t.Fatal("a clone must equal its original")
	}

	// Mutating the clone in place — including writing into a payload, which is
	// the fastest mutation there is — must not touch the corpus entry.
	before := string(Encode(orig))
	c.Children[1].Child("data").Raw[0] ^= 0xff
	c.Children[0].Child("length").Val = 999
	c.Children = c.Children[:2]

	if got := string(Encode(orig)); got != before {
		t.Error("mutating a clone changed the original: payloads must be copied, not shared")
	}
}

func TestArenaResetReusesWithoutAliasing(t *testing.T) {
	orig := sampleTree()
	a := NewArena()

	first := a.Clone(orig)
	firstEnc := string(Encode(first))

	a.Reset()
	second := a.Clone(orig)
	second.Children[0].Child("data").Raw[0] ^= 0xff

	// `first` is invalid after Reset by contract; what must hold is that the
	// original is untouched and the new clone is correct.
	if got := string(Encode(orig)); got == "" {
		t.Fatal("original became empty")
	}
	if Equal(orig, second) {
		t.Error("the mutation did not take effect on the second clone")
	}
	_ = firstEnc

	a.Reset()
	third := a.Clone(orig)
	if !Equal(orig, third) {
		t.Error("a clone taken after Reset must equal the original: a previous " +
			"generation's writes are leaking into reused slab slots")
	}
}

func TestArenaHandlesOversizedPayloads(t *testing.T) {
	big := make([]byte, byteSlabSize*2+7)
	for i := range big {
		big[i] = byte(i)
	}
	orig := Struct("s", Blob("big", big), U8("t", 1))

	a := NewArena()
	for i := 0; i < 3; i++ {
		a.Reset()
		c := a.Clone(orig)
		if !Equal(orig, c) {
			t.Fatalf("round %d: oversized payload did not survive cloning", i)
		}
		c.Child("big").Raw[0] = 0xff
		if orig.Child("big").Raw[0] != 0 {
			t.Fatalf("round %d: oversized payload was shared rather than copied", i)
		}
	}
}

func TestArenaHandlesManyChildren(t *testing.T) {
	kids := make([]*Node, kidSlabSize+11)
	for i := range kids {
		kids[i] = U8("", int64(i))
	}
	orig := Repeat("many", kids...)

	a := NewArena()
	c := a.Clone(orig)
	if !Equal(orig, c) {
		t.Error("a child list larger than one slab did not survive cloning")
	}
}

// TestCopyOnWriteCopiesOnlyThePath is the property that makes a one-byte change
// to a large tree cheap: only the nodes between the root and the mutation are
// duplicated.
func TestCopyOnWriteCopiesOnlyThePath(t *testing.T) {
	a := NewArena()
	orig := a.Clone(sampleTree())
	beforeEnc := string(Encode(orig))

	shared := a.Share(orig)
	root := shared
	a.ResetStats()

	target, err := a.MutablePath(&root, At(1), Named("data"))
	if err != nil {
		t.Fatal(err)
	}
	target.Raw = a.CopyBytes([]byte("REPLACED"))

	if root == orig {
		t.Error("mutating through a shared root must produce a new root")
	}
	if got := string(Encode(orig)); got != beforeEnc {
		t.Error("copy-on-write mutation changed the shared original")
	}
	if string(root.Children[1].Child("data").Raw) != "REPLACED" {
		t.Error("the mutation did not take effect on the copy")
	}

	// Untouched siblings must still be the very same nodes, not copies.
	if root.Children[0] != orig.Children[0] {
		t.Error("an untouched sibling was copied; only the path should be")
	}
	if n := a.Stats().CopyOnWrite; n != 3 {
		t.Errorf("copied %d nodes, want 3 (root, chunk, data)", n)
	}
}

func TestMutableChildRejectsSharedParent(t *testing.T) {
	a := NewArena()
	root := a.Share(a.Clone(sampleTree()))
	if _, err := a.MutableChild(root, 0); err == nil {
		t.Error("mutating a child of a shared parent must be refused: the write " +
			"would land in the shared tree")
	}
	if _, err := a.MutableChild(a.Mutable(root), 99); err == nil {
		t.Error("an out-of-range index must be refused")
	}
}

func TestMutablePathErrors(t *testing.T) {
	a := NewArena()
	root := a.Clone(sampleTree())
	if _, err := a.MutablePath(&root, Named("nope")); err == nil {
		t.Error("a path through a missing name must fail")
	}
	var nilRoot *Node
	if _, err := a.MutablePath(&nilRoot); err == nil {
		t.Error("a nil root must fail")
	}
}

// TestSteadyStateFuzzLoopDoesNotAllocate is the load-bearing test of M1.
//
// ASR-0007 requires the fuzz loop to be allocation-free in steady state, and the
// structured IR is where that is easiest to lose: a tree of pointers is exactly
// the shape Go's allocator likes to be handed. If this test cannot pass, the
// premise of ADR-0005 is wrong and the design needs revisiting rather than
// tuning.
//
// The loop measured here is the real one: reset, clone a corpus entry, mutate
// it, recompute derived values, encode.
func TestSteadyStateFuzzLoopDoesNotAllocate(t *testing.T) {
	orig := sampleTree()
	a := NewArena()
	f := NewFixer()
	var sink int

	step := func() {
		a.Reset()
		c := a.Clone(orig)
		data := c.Children[1].Child("data")
		data.Raw[0] ^= 0xff
		data.Raw = data.Raw[:len(data.Raw)-1]
		buf, err := f.Fix(c, Suppress{})
		if err != nil {
			panic(err)
		}
		sink += len(buf)
	}

	// Warm up until the slabs, the Fixer's buffer, and its maps have reached
	// their steady sizes.
	for i := 0; i < 50; i++ {
		step()
	}

	if n := testing.AllocsPerRun(200, step); n != 0 {
		t.Errorf("the steady-state loop allocated %v time(s) per iteration; ASR-0007 requires zero", n)
	}
	if sink == 0 {
		t.Fatal("the loop did no work")
	}
}

func TestArenaStats(t *testing.T) {
	a := NewArena()
	a.Clone(sampleTree())
	s := a.Stats()
	if s.Nodes == 0 || s.Clones != 1 {
		t.Errorf("stats after one clone = %+v, want non-zero nodes and one clone", s)
	}
	a.Reset()
	if a.Stats().Resets != 1 {
		t.Error("Reset must be counted")
	}
	a.ResetStats()
	if a.Stats() != (Stats{}) {
		t.Error("ResetStats must zero the counters")
	}
}

func BenchmarkCloneFixEncode(b *testing.B) {
	orig := sampleTree()
	a := NewArena()
	f := NewFixer()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		a.Reset()
		c := a.Clone(orig)
		c.Children[1].Child("data").Raw[0] ^= 0xff
		if _, err := f.Fix(c, Suppress{}); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCopyOnWriteMutation(b *testing.B) {
	// The base tree lives outside the arena, as a corpus entry does; the arena
	// holds only the per-iteration copies and is reset each time, which is the
	// pattern the fuzz loop actually uses.
	base := sampleTree()
	a := NewArena()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		a.Reset()
		a.Share(base)
		root := base
		n, err := a.MutablePath(&root, At(1), Named("data"))
		if err != nil {
			b.Fatal(err)
		}
		n.Raw[0] ^= 0xff
	}
}
