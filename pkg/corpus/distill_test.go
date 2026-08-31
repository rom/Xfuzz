package corpus

import (
	"fmt"
	"testing"
)

// seed makes a testcase of a given size whose identity is its bytes.
func seed(t *testing.T, body string) *Testcase {
	t.Helper()
	return NewTestcase(nil, []byte(body))
}

// cover attaches a coverage set to entries by their bytes.
func cover(m map[string][]uint32) func(*Testcase) []uint32 {
	return func(tc *Testcase) []uint32 { return m[string(tc.Bytes)] }
}

func TestDistillKeepsWhatCoversEverything(t *testing.T) {
	a := seed(t, "a")   // covers 1,2
	b := seed(t, "bb")  // covers 2,3
	c := seed(t, "ccc") // covers 1,2,3 — subsumes both
	entries := []*Testcase{a, b, c}
	rep := Distill(entries, cover(map[string][]uint32{
		"a": {1, 2}, "bb": {2, 3}, "ccc": {1, 2, 3},
	}))

	if len(rep.Keep) != 1 || rep.Keep[0] != c {
		t.Fatalf("kept %d entries; the one covering everything should be enough", len(rep.Keep))
	}
	if rep.Features != 3 || rep.Covered != 3 {
		t.Errorf("features %d, covered %d; want 3 and 3", rep.Features, rep.Covered)
	}
	if len(rep.Drop) != 2 {
		t.Errorf("dropped %d entries, want 2", len(rep.Drop))
	}
}

func TestDistillKeepsEveryFeature(t *testing.T) {
	// The property that makes distillation safe: nothing the corpus reached is
	// lost. A greedy cover that dropped a feature would silently undo a day of
	// a campaign's work.
	m := map[string][]uint32{}
	var entries []*Testcase
	for i := 0; i < 40; i++ {
		body := fmt.Sprintf("entry-%02d", i)
		e := seed(t, body)
		// Overlapping runs, so no single entry covers everything and the cover
		// needs several.
		m[body] = []uint32{uint32(i), uint32(i + 1), uint32(i + 2)}
		entries = append(entries, e)
	}
	rep := Distill(entries, cover(m))

	got := map[uint32]bool{}
	for _, tc := range rep.Keep {
		for _, f := range m[string(tc.Bytes)] {
			got[f] = true
		}
	}
	for _, tc := range entries {
		for _, f := range m[string(tc.Bytes)] {
			if !got[f] {
				t.Fatalf("feature %d was covered before and is not covered after", f)
			}
		}
	}
	if len(rep.Keep) >= len(entries) {
		t.Errorf("kept %d of %d entries; the corpus was not distilled at all",
			len(rep.Keep), len(entries))
	}
}

func TestDistillPrefersTheSmallerEntry(t *testing.T) {
	// Among entries that reach the same thing, the small one mutates faster and
	// minimises better, and it is the one a person reading the corpus wants.
	small := seed(t, "s")
	large := seed(t, "llllllllllllllllllll")
	rep := Distill([]*Testcase{large, small}, cover(map[string][]uint32{
		"s": {1, 2, 3}, "llllllllllllllllllll": {1, 2, 3},
	}))
	if len(rep.Keep) != 1 || rep.Keep[0] != small {
		t.Fatalf("kept %v; want the smaller entry", rep.Keep)
	}
}

func TestDistillIsDeterministic(t *testing.T) {
	// A distillation that produced a different corpus on each run would break
	// replay: the same campaign, resumed, would be fuzzing something else than
	// its checkpoint describes (ASR-0008).
	m := map[string][]uint32{}
	var entries []*Testcase
	for i := 0; i < 30; i++ {
		body := fmt.Sprintf("e%02d", i)
		entries = append(entries, seed(t, body))
		m[body] = []uint32{uint32(i % 7), uint32(i % 5), uint32(i % 3)}
	}
	first := Distill(entries, cover(m))
	for run := 0; run < 20; run++ {
		again := Distill(entries, cover(m))
		if len(again.Keep) != len(first.Keep) {
			t.Fatalf("run %d kept %d entries, the first kept %d",
				run, len(again.Keep), len(first.Keep))
		}
		for i := range first.Keep {
			if again.Keep[i] != first.Keep[i] {
				t.Fatalf("run %d kept a different set at position %d", run, i)
			}
		}
	}
}

func TestDistillDropsAnEntryThatReachesNothing(t *testing.T) {
	// An entry with no coverage is one the campaign learned nothing from. It is
	// the only case where dropping loses something — the input itself — and
	// keeping it would mean a distilled corpus still full of noise.
	useful := seed(t, "useful")
	noise := seed(t, "noise")
	rep := Distill([]*Testcase{useful, noise}, cover(map[string][]uint32{
		"useful": {1, 2},
	}))
	if len(rep.Keep) != 1 || rep.Keep[0] != useful {
		t.Fatalf("kept %v", rep.Keep)
	}
}

func TestDistillOnAnEmptyCorpusDoesNothing(t *testing.T) {
	rep := Distill(nil, cover(nil))
	if len(rep.Keep) != 0 || len(rep.Drop) != 0 || rep.Features != 0 {
		t.Fatalf("an empty corpus distilled to %+v", rep)
	}
}

func TestCorpusDistillRemovesTheEntriesAndKeepsTheIndex(t *testing.T) {
	c := New()
	a, b, all := seed(t, "a"), seed(t, "bb"), seed(t, "ccc")
	for _, tc := range []*Testcase{a, b, all} {
		if !c.Add(tc) {
			t.Fatalf("adding %q", tc.Bytes)
		}
	}
	rep := c.Distill(cover(map[string][]uint32{
		"a": {1}, "bb": {2}, "ccc": {1, 2},
	}))
	if c.Len() != 1 {
		t.Fatalf("the corpus has %d entries after distilling, want 1", c.Len())
	}
	if len(rep.Drop) != 2 {
		t.Errorf("the report says %d dropped", len(rep.Drop))
	}
	// The index has to agree with the entries, or Contains lies and a rediscovery
	// of a dropped input is refused as a duplicate of something no longer there.
	if c.Contains(a.ID) || c.Contains(b.ID) {
		t.Error("a dropped entry is still in the index")
	}
	if !c.Contains(all.ID) {
		t.Error("the kept entry is not in the index")
	}
	// And the entry can be found by the index it claims.
	if got := c.At(0); got != all {
		t.Errorf("At(0) = %q, want the kept entry", got.Bytes)
	}
	if rep.AfterBytes >= rep.BeforeBytes {
		t.Errorf("the corpus did not get smaller: %d bytes to %d",
			rep.BeforeBytes, rep.AfterBytes)
	}
}

func TestCorpusDistillLetsADroppedInputBeReadmitted(t *testing.T) {
	// The corpus must not remember what it dropped: an input that comes back
	// covering something new is a new discovery, not a duplicate.
	c := New()
	a, all := seed(t, "a"), seed(t, "ccc")
	c.Add(a)
	c.Add(all)
	c.Distill(cover(map[string][]uint32{"a": {1}, "ccc": {1, 2}}))
	if c.Contains(a.ID) {
		t.Fatal("the dropped entry is still known")
	}
	if !c.Add(seed(t, "a")) {
		t.Fatal("a dropped input was refused as a duplicate")
	}
}
