package mutate

import (
	"bytes"
	"strings"
	"testing"

	"github.com/rom/Xfuzz/pkg/ir"
)

func schedTree(a *ir.Arena) *ir.Node {
	return ir.Struct("root",
		payload(a, []byte("alpha bravo charlie delta echo foxtrot golf hotel")),
		ir.U32BE("n", 3),
		ir.Repeat("items", ir.U8("", 1), ir.U8("", 2), ir.U8("", 3)),
		ir.Choice("v", 0, ir.U8("a", 1), ir.U16BE("b", 2)),
	)
}

func TestSchedulerAppliesAndRecords(t *testing.T) {
	c := testCtx(1)
	s := Default()
	tree := schedTree(c.Arena)
	c.Root = tree
	c.Donor = donorTree(c.Arena)

	before := ir.Encode(tree)
	ops := s.Mutate(c, tree)
	if len(ops) == 0 {
		t.Fatal("the scheduler applied nothing")
	}
	if bytes.Equal(ir.Encode(tree), before) {
		t.Error("operators were recorded but the tree is unchanged")
	}
	for _, op := range ops {
		if op.Mutator == "" {
			t.Error("an operator was recorded with no name")
		}
		if _, ok := s.StatsFor(op.Mutator); !ok {
			t.Errorf("recorded operator %q is not registered", op.Mutator)
		}
	}
}

// TestProvenanceReplaysExactly is the ASR-0008 property at the mutation layer:
// a recorded chain of operators, paths, and stream positions is enough to
// reconstruct an input from its parent, on a fresh tree, with nothing else
// carried over.
//
// Paths are recorded against the tree as it stood when the operator ran, not
// against the final tree — a later delete can shorten a sequence an earlier
// path pointed into. That is correct for replay, which re-applies the operators
// in order, and it is why this test replays rather than resolving the recorded
// paths against the finished result.
func TestProvenanceReplaysExactly(t *testing.T) {
	for round := 0; round < 100; round++ {
		// Original run.
		c := testCtx(uint64(round))
		s := Default()
		base := schedTree(c.Arena)
		tree := c.Arena.Clone(base)
		donor := donorTree(c.Arena)
		c.Root, c.Donor = tree, donor
		ops := CloneOps(s.Mutate(c, tree))
		if len(ops) == 0 {
			continue
		}
		want := ir.Encode(tree)

		// Replay: a fresh tree, the same operators, seeking the parameter
		// stream to each recorded position.
		rc := testCtx(uint64(round))
		replayed := rc.Arena.Clone(base)
		rc.Root, rc.Donor = replayed, donorTree(rc.Arena)
		for i, op := range ops {
			m, ok := s.Operator(op.Mutator)
			if !ok {
				t.Fatalf("round %d: operator %q is not registered", round, op.Mutator)
			}
			n := replayed
			for j, step := range op.Path {
				if step < 0 || step >= len(n.Children) {
					t.Fatalf("round %d op %d (%s): path step %d (%d) does not resolve in the replayed tree",
						round, i, op.Mutator, j, step)
				}
				n = n.Children[step]
			}
			rc.Rand.Seek(op.RandPos)
			if !m.Mutate(rc, n) {
				t.Fatalf("round %d op %d (%s): replaying the operator did not apply",
					round, i, op.Mutator)
			}
		}

		if got := ir.Encode(replayed); !bytes.Equal(got, want) {
			t.Fatalf("round %d: replay produced a different input\n got %x\nwant %x\nops %v",
				round, got, want, ops)
		}
	}
}

// TestProvenancePathsAreDistinct guards the aliasing bug this code had: the
// selected node's path shared a buffer with the walk's own path, so every
// recorded path ended up being the last one visited.
func TestProvenancePathsAreDistinct(t *testing.T) {
	c := testCtx(3)
	s := Default()
	s.MinStack, s.MaxStack = 6, 6

	seen := map[string]bool{}
	for round := 0; round < 50; round++ {
		c.Arena.Reset()
		tree := schedTree(c.Arena)
		c.Root = tree
		c.Donor = donorTree(c.Arena)
		for _, op := range s.Mutate(c, tree) {
			var b strings.Builder
			for _, p := range op.Path {
				b.WriteByte(byte('0' + p))
			}
			seen[b.String()] = true
		}
	}
	if len(seen) < 3 {
		t.Errorf("only %d distinct paths were recorded across 50 rounds; "+
			"the recorded path is probably aliasing the walk buffer", len(seen))
	}
}

func TestSchedulerIsDeterministic(t *testing.T) {
	run := func() ([]byte, []string) {
		c := testCtx(0xBEEF)
		s := Default()
		tree := schedTree(c.Arena)
		c.Root = tree
		c.Donor = donorTree(c.Arena)
		var names []string
		for i := 0; i < 20; i++ {
			for _, op := range s.Mutate(c, tree) {
				names = append(names, op.Mutator)
			}
		}
		return ir.Encode(tree), names
	}
	encA, opsA := run()
	encB, opsB := run()
	if !bytes.Equal(encA, encB) {
		t.Error("the same seed produced different output")
	}
	if strings.Join(opsA, ",") != strings.Join(opsB, ",") {
		t.Error("the same seed produced a different operator sequence")
	}
}

// TestWeightsDecideTheMix is the property that operator-first selection buys.
// With node-first selection the operator with the broadest applicability
// dominated regardless of its weight.
func TestWeightsDecideTheMix(t *testing.T) {
	c := testCtx(4)
	s := NewScheduler()
	s.Add(BitFlip{}, 90)
	s.Add(RandomByte{}, 10)
	s.MinStack, s.MaxStack = 1, 1

	counts := map[string]int{}
	for i := 0; i < 5000; i++ {
		c.Arena.Reset()
		tree := schedTree(c.Arena)
		c.Root = tree
		for _, op := range s.Mutate(c, tree) {
			counts[op.Mutator]++
		}
	}
	ratio := float64(counts["bitflip"]) / float64(counts["randbyte"])
	if ratio < 7 || ratio > 12 {
		t.Errorf("weights 90:10 produced a ratio of %.1f (bitflip %d, randbyte %d), want about 9",
			ratio, counts["bitflip"], counts["randbyte"])
	}
}

func TestZeroWeightDisablesWithoutRenumbering(t *testing.T) {
	c := testCtx(5)
	s := NewScheduler(BitFlip{}, RandomByte{})
	if !s.SetWeight("bitflip", 0) {
		t.Fatal("SetWeight did not find bitflip")
	}
	if s.SetWeight("nonexistent", 1) {
		t.Error("SetWeight reported success for an unknown operator")
	}
	for i := 0; i < 200; i++ {
		c.Arena.Reset()
		tree := schedTree(c.Arena)
		c.Root = tree
		for _, op := range s.Mutate(c, tree) {
			if op.Mutator == "bitflip" {
				t.Fatal("a zero-weight operator was selected")
			}
		}
	}
	// Its slot is still there, so operator indices are unchanged.
	if len(s.Operators()) != 2 {
		t.Errorf("disabling removed the operator; indices must stay stable")
	}
}

func TestAddIsIdempotentOnName(t *testing.T) {
	s := NewScheduler(BitFlip{})
	s.Add(BitFlip{}, 7)
	if len(s.Operators()) != 1 {
		t.Errorf("re-adding by name registered a duplicate: %d operators", len(s.Operators()))
	}
}

func TestRecordOutcomeAttributesYield(t *testing.T) {
	s := Default()
	ops := []Op{{Mutator: "bitflip"}, {Mutator: "insert"}}

	s.RecordOutcome(ops, false, false)
	if st, _ := s.StatsFor("bitflip"); st.Interesting != 0 {
		t.Error("an uninteresting execution must not be credited")
	}
	s.RecordOutcome(ops, true, false)
	s.RecordOutcome(ops, true, true)

	st, _ := s.StatsFor("bitflip")
	if st.Interesting != 2 || st.Findings != 1 {
		t.Errorf("stats = %+v, want 2 interesting and 1 finding", st)
	}
	s.RecordOutcome([]Op{{Mutator: "not-registered"}}, true, true)

	// Yield needs attempts to be meaningful.
	if st.Yield() != 0 {
		t.Errorf("yield with no attempts = %v, want 0", st.Yield())
	}
}

func TestReportIsOrderedByYield(t *testing.T) {
	c := testCtx(6)
	s := Default()
	tree := schedTree(c.Arena)
	c.Root = tree
	c.Donor = donorTree(c.Arena)
	for i := 0; i < 50; i++ {
		ops := s.Mutate(c, tree)
		s.RecordOutcome(ops, i%3 == 0, false)
	}
	rep := s.Report()
	if len(rep) != len(s.Operators()) {
		t.Fatalf("report has %d rows, want %d", len(rep), len(s.Operators()))
	}
	for i := 1; i < len(rep); i++ {
		if rep[i-1].Yield() < rep[i].Yield() {
			t.Errorf("report is not ordered by yield at row %d", i)
		}
	}
	s.ResetStats()
	for _, r := range s.Report() {
		if r.Attempts != 0 || r.Interesting != 0 {
			t.Errorf("ResetStats left %s at %+v", r.Name, r.Stats)
		}
	}
}

func TestCloneOpsSurvivesTheNextRound(t *testing.T) {
	c := testCtx(7)
	s := Default()
	tree := schedTree(c.Arena)
	c.Root = tree
	c.Donor = donorTree(c.Arena)

	kept := CloneOps(s.Mutate(c, tree))
	if len(kept) == 0 {
		t.Skip("no operators applied")
	}
	before := append([]int(nil), kept[0].Path...)
	name := kept[0].Mutator

	for i := 0; i < 20; i++ {
		s.Mutate(c, tree)
	}
	if kept[0].Mutator != name {
		t.Error("a cloned record was overwritten by later rounds")
	}
	for i := range before {
		if kept[0].Path[i] != before[i] {
			t.Fatal("a cloned path was overwritten by later rounds")
		}
	}
	if CloneOps(nil) != nil {
		t.Error("CloneOps(nil) should be nil")
	}
}

func TestOpString(t *testing.T) {
	got := Op{Mutator: "bitflip", Path: []int{1, 0, 2}, RandPos: 42}.String()
	if !strings.Contains(got, "bitflip") || !strings.Contains(got, "1/0/2") ||
		!strings.Contains(got, "42") {
		t.Errorf("Op.String = %q, want it to carry the operator, path, and stream position", got)
	}
}

func TestSizeWeightingCanBeDisabled(t *testing.T) {
	c := testCtx(8)
	for _, weighting := range []bool{true, false} {
		s := NewScheduler(BitFlip{})
		s.SizeWeighting = weighting
		s.MinStack, s.MaxStack = 1, 1
		tree := ir.Struct("root",
			payload(c.Arena, bytes.Repeat([]byte{1}, 4096)),
			payload(c.Arena, []byte{2, 3}),
		)
		c.Root = tree
		big := 0
		for i := 0; i < 2000; i++ {
			for _, op := range s.Mutate(c, tree) {
				if len(op.Path) > 0 && op.Path[0] == 0 {
					big++
				}
			}
		}
		if weighting && big < 1400 {
			t.Errorf("with size weighting the 4 KB payload got %d of 2000 selections; "+
				"it should dominate the 2-byte one", big)
		}
		if !weighting && (big < 800 || big > 1200) {
			t.Errorf("without size weighting selection should be near-uniform, got %d of 2000", big)
		}
	}
}

func TestSchedulerHandlesTreesWithNoApplicableNodes(t *testing.T) {
	c := testCtx(9)
	s := NewScheduler(RepeatInsert{})
	tree := ir.Struct("root", ir.U8("a", 1)) // no sequences at all
	c.Root = tree
	if ops := s.Mutate(c, tree); len(ops) != 0 {
		t.Errorf("expected no operators to apply, got %v", ops)
	}
}

func TestSchedulerWithEveryOperatorDisabled(t *testing.T) {
	c := testCtx(10)
	s := NewScheduler(BitFlip{})
	s.SetWeight("bitflip", 0)
	tree := schedTree(c.Arena)
	c.Root = tree
	if ops := s.Mutate(c, tree); len(ops) != 0 {
		t.Errorf("expected nothing to apply, got %v", ops)
	}
}

// TestSchedulerDoesNotAllocate keeps mutation on the allocation-free path that
// ASR-0007 requires; provenance is recorded into reused buffers and only copied
// out for inputs that become corpus entries.
func TestSchedulerDoesNotAllocate(t *testing.T) {
	c := testCtx(11)
	s := Default()
	donor := donorTree(c.Arena)
	seed := schedTree(c.Arena)

	step := func() {
		c.Arena.Reset()
		tree := c.Arena.Clone(seed)
		c.Root = tree
		c.Donor = donor
		s.Mutate(c, tree)
	}
	for i := 0; i < 200; i++ {
		step()
	}
	if n := testing.AllocsPerRun(200, step); n != 0 {
		t.Errorf("a mutation round allocated %v times; the hot path must not allocate", n)
	}
}

func BenchmarkSchedulerMutate(b *testing.B) {
	c := testCtx(12)
	s := Default()
	donor := donorTree(c.Arena)
	seed := schedTree(c.Arena)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Arena.Reset()
		tree := c.Arena.Clone(seed)
		c.Root = tree
		c.Donor = donor
		s.Mutate(c, tree)
	}
}
