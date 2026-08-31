package corpus

import (
	"testing"
	"time"

	"github.com/rom/Xfuzz/pkg/feedback"
	"github.com/rom/Xfuzz/pkg/ir"
	"github.com/rom/Xfuzz/pkg/rng"
)

func entry(t *testing.T, payload string) *Testcase {
	t.Helper()
	n := ir.Blob("data", []byte(payload))
	return NewTestcase(n, ir.Encode(n))
}

func TestDigest(t *testing.T) {
	a, b := DigestOf([]byte("hello")), DigestOf([]byte("hello"))
	if a != b {
		t.Error("the same bytes must produce the same digest")
	}
	if a == DigestOf([]byte("world")) {
		t.Error("different bytes must produce different digests")
	}
	if len(a.String()) != 64 || len(a.Short()) != 8 {
		t.Errorf("digest renders as %q / %q", a.String(), a.Short())
	}
	if (Digest{}).IsZero() != true || a.IsZero() {
		t.Error("IsZero is wrong")
	}
}

// TestDeduplicationByContent is not an optimisation: without it a mutation that
// happens to reproduce an existing entry is admitted again, and the corpus fills
// with copies that each consume scheduling attention.
func TestDeduplicationByContent(t *testing.T) {
	c := New()
	if !c.Add(entry(t, "same")) {
		t.Fatal("the first entry was rejected")
	}
	if c.Add(entry(t, "same")) {
		t.Error("an identical input was admitted twice")
	}
	if !c.Add(entry(t, "different")) {
		t.Error("a different input was rejected")
	}
	if c.Len() != 2 {
		t.Errorf("corpus holds %d entries, want 2", c.Len())
	}
}

func TestLookupAndRemove(t *testing.T) {
	c := New()
	a, b, d := entry(t, "a"), entry(t, "b"), entry(t, "c")
	c.Add(a)
	c.Add(b)
	c.Add(d)

	if got, ok := c.Lookup(b.ID); !ok || got != b {
		t.Error("Lookup did not find an entry")
	}
	if !c.Contains(a.ID) {
		t.Error("Contains missed an entry")
	}

	// Removal swaps with the last entry, so the index of the moved entry has to
	// be repaired or every later lookup returns the wrong testcase.
	c.Remove(0)
	if c.Len() != 2 || c.Contains(a.ID) {
		t.Error("Remove did not remove the entry")
	}
	for i := 0; i < c.Len(); i++ {
		got, ok := c.Lookup(c.At(i).ID)
		if !ok || got != c.At(i) {
			t.Errorf("after removal, entry %d no longer resolves through its digest", i)
		}
	}
	c.Remove(c.Len() - 1)
	c.Remove(0)
	if c.Len() != 0 {
		t.Errorf("corpus still holds %d entries", c.Len())
	}
}

func TestAverages(t *testing.T) {
	c := New()
	if c.Averages() != (Averages{}) {
		t.Error("an empty corpus should have zero averages")
	}
	for i, size := range []int{10, 20, 30} {
		e := entry(t, string(make([]byte, size)))
		e.Meta.Size = size
		e.Meta.ExecTime = time.Duration(i+1) * time.Millisecond
		e.Meta.Coverage = (i + 1) * 5
		e.Meta.Depth = i
		c.Add(e)
	}
	avg := c.Averages()
	if avg.Size != 20 || avg.Coverage != 10 || avg.Depth != 1 {
		t.Errorf("averages = %+v", avg)
	}
}

func TestStatsAndSorting(t *testing.T) {
	c := New()
	for i, cov := range []int{5, 30, 12} {
		e := entry(t, string(rune('a'+i))+"payload")
		e.Meta.Coverage = cov
		e.Meta.Depth = i
		e.Meta.Favoured = i == 1
		c.Add(e)
	}
	s := c.Stats()
	if s.Entries != 3 || s.MaxDepth != 2 || s.Favoured != 1 {
		t.Errorf("stats = %+v", s)
	}
	order := c.SortedByCoverage()
	if c.At(order[0]).Meta.Coverage != 30 {
		t.Error("SortedByCoverage is not ordered by descending coverage")
	}
}

// --- schedules --------------------------------------------------------------

func fillCorpus(t *testing.T, n int) *Corpus {
	t.Helper()
	c := New()
	for i := 0; i < n; i++ {
		e := entry(t, string(rune('a'+i))+"-payload")
		e.Meta.Size = 10 + i
		e.Meta.Coverage = 10
		e.Meta.ExecTime = time.Millisecond
		c.Add(e)
	}
	return c
}

func TestSchedulersRefuseAnEmptyCorpus(t *testing.T) {
	r := rng.New(1)
	for _, s := range []Scheduler{NewRandScheduler(), NewRoundRobinScheduler(), NewFastScheduler()} {
		if _, err := s.Next(New(), r); err == nil {
			t.Errorf("%s scheduled from an empty corpus", s.Name())
		}
	}
}

func TestRoundRobinVisitsEveryEntry(t *testing.T) {
	c := fillCorpus(t, 4)
	s := NewRoundRobinScheduler()
	seen := map[int]int{}
	for i := 0; i < 12; i++ {
		idx, err := s.Next(c, rng.New(1))
		if err != nil {
			t.Fatal(err)
		}
		seen[idx]++
		s.Update(c, idx, feedback.Score{}, 0)
	}
	for i := 0; i < 4; i++ {
		if seen[i] != 3 {
			t.Errorf("entry %d selected %d times, want 3", i, seen[i])
		}
	}
}

func TestRandSchedulerCoversTheCorpus(t *testing.T) {
	c := fillCorpus(t, 5)
	s := NewRandScheduler()
	r := rng.New(3)
	seen := map[int]bool{}
	for i := 0; i < 200; i++ {
		idx, _ := s.Next(c, r)
		seen[idx] = true
		s.Update(c, idx, feedback.Score{}, 0)
	}
	if len(seen) != 5 {
		t.Errorf("uniform selection reached %d of 5 entries", len(seen))
	}
	if got := s.Energy(c, 0); got != s.Fixed {
		t.Errorf("energy = %d, want the fixed %d", got, s.Fixed)
	}
}

// TestFastSchedulerSpreadsAttention is the property a power schedule exists for:
// without it a campaign spends its whole budget on whichever seed happens to be
// first.
func TestFastSchedulerSpreadsAttention(t *testing.T) {
	c := fillCorpus(t, 6)
	s := NewFastScheduler()
	r := rng.New(5)
	seen := map[int]int{}
	for i := 0; i < 600; i++ {
		idx, err := s.Next(c, r)
		if err != nil {
			t.Fatal(err)
		}
		seen[idx]++
		s.Update(c, idx, feedback.Score{}, 0)
	}
	if len(seen) != 6 {
		t.Errorf("the schedule reached %d of 6 entries; attention is not spreading", len(seen))
	}
	for i, n := range seen {
		if n == 0 || n > 400 {
			t.Errorf("entry %d received %d of 600 selections", i, n)
		}
	}
}

// TestFastSchedulerIsDeterministic is ASR-0008 at the schedule level. The
// default schedule must not weigh anything that varies between runs — measured
// execution time above all, which is why PreferFast is off by default.
func TestFastSchedulerIsDeterministic(t *testing.T) {
	run := func(execTimes []time.Duration) []int {
		c := New()
		for i, d := range execTimes {
			e := entry(t, string(rune('a'+i))+"-payload")
			e.Meta.Size, e.Meta.Coverage, e.Meta.ExecTime = 10+i, 10, d
			c.Add(e)
		}
		s := NewFastScheduler()
		r := rng.New(9)
		var picks []int
		for i := 0; i < 50; i++ {
			idx, _ := s.Next(c, r)
			picks = append(picks, idx)
			s.Update(c, idx, feedback.Score{}, 0)
		}
		return picks
	}

	// The same corpus with wildly different measured times must schedule
	// identically.
	fast := run([]time.Duration{time.Millisecond, time.Millisecond, time.Millisecond})
	slow := run([]time.Duration{time.Second, 5 * time.Millisecond, 300 * time.Millisecond})
	for i := range fast {
		if fast[i] != slow[i] {
			t.Fatalf("the schedule diverged at pick %d (%d against %d); measured time is "+
				"leaking into a fuzzing decision, which breaks reproducibility",
				i, fast[i], slow[i])
		}
	}

	// Opting in restores the heuristic, and with it the divergence.
	withTiming := func(execTimes []time.Duration) []int {
		c := New()
		for i, d := range execTimes {
			e := entry(t, string(rune('a'+i))+"-payload")
			e.Meta.Size, e.Meta.Coverage, e.Meta.ExecTime = 10+i, 10, d
			c.Add(e)
		}
		s := NewFastScheduler()
		s.PreferFast = true
		r := rng.New(9)
		var picks []int
		for i := 0; i < 50; i++ {
			idx, _ := s.Next(c, r)
			picks = append(picks, idx)
			s.Update(c, idx, feedback.Score{}, 0)
		}
		return picks
	}
	a := withTiming([]time.Duration{time.Millisecond, time.Millisecond, time.Millisecond})
	b := withTiming([]time.Duration{time.Second, 5 * time.Millisecond, 300 * time.Millisecond})
	same := true
	for i := range a {
		if a[i] != b[i] {
			same = false
		}
	}
	if same {
		t.Error("PreferFast should make the schedule sensitive to measured time")
	}
}

func TestFastSchedulerEnergy(t *testing.T) {
	c := fillCorpus(t, 3)
	s := NewFastScheduler()

	first := s.Energy(c, 0)
	if first < MinEnergy || first > s.Max {
		t.Errorf("energy %d is outside [%d, %d]", first, MinEnergy, s.Max)
	}
	// Energy falls as an entry is revisited, so attention moves on rather than
	// grinding a seed that has stopped paying.
	for i := 0; i < 5; i++ {
		s.Update(c, 0, feedback.Score{}, 0)
	}
	if after := s.Energy(c, 0); after >= first {
		t.Errorf("energy after five visits is %d, was %d; it should decay", after, first)
	}

	// A favoured entry is worth more.
	c.At(1).Meta.Favoured = true
	if s.Energy(c, 1) <= s.Energy(c, 2) {
		t.Error("a favoured entry should receive more energy")
	}
}

func TestFastSchedulerExploits(t *testing.T) {
	c := fillCorpus(t, 4)
	s := NewFastScheduler()
	s.ExploitRatio = 1 // always take the best
	r := rng.New(11)
	first, _ := s.Next(c, r)
	second, _ := s.Next(c, r)
	if first != second {
		t.Error("pure exploitation should keep returning the same best entry")
	}
}

func TestUpdateRecordsChildren(t *testing.T) {
	c := fillCorpus(t, 2)
	s := NewFastScheduler()
	s.Update(c, 0, feedback.Score{NewSignal: 5}, 3)
	m := c.At(0).Meta
	if m.Fuzzed != 1 || m.Children != 3 || m.Score.NewSignal != 5 {
		t.Errorf("metadata after an update = %+v", m)
	}
	// A weaker score must not overwrite a stronger one.
	s.Update(c, 0, feedback.Score{NewSignal: 1}, 0)
	if c.At(0).Meta.Score.NewSignal != 5 {
		t.Error("a weaker score overwrote a stronger one")
	}
}

// TestMarkFavoured checks the minimal set: for every covered edge, the cheapest
// entry reaching it.
func TestMarkFavoured(t *testing.T) {
	c := New()
	small := entry(t, "small")
	small.Meta.Size = 10
	big := entry(t, "big-and-redundant")
	big.Meta.Size = 1000
	unique := entry(t, "unique")
	unique.Meta.Size = 500
	c.Add(small)
	c.Add(big)
	c.Add(unique)

	cov := map[*Testcase][]uint32{
		small:  {1, 2},
		big:    {1, 2}, // same edges, larger: should lose
		unique: {3},    // only entry reaching edge 3
	}
	MarkFavoured(c, func(tc *Testcase) []uint32 { return cov[tc] })

	if !small.Meta.Favoured {
		t.Error("the cheapest entry covering edges 1 and 2 should be favoured")
	}
	if big.Meta.Favoured {
		t.Error("a larger entry covering nothing extra should not be favoured")
	}
	if !unique.Meta.Favoured {
		t.Error("the only entry reaching an edge must be favoured")
	}
}

func TestTestcaseString(t *testing.T) {
	e := entry(t, "payload")
	e.Meta.Coverage, e.Meta.Depth, e.Meta.Fuzzed = 7, 2, 3
	s := e.String()
	for _, want := range []string{e.ID.Short(), "cov 7", "depth 2", "fuzzed 3"} {
		if !contains(s, want) {
			t.Errorf("Testcase.String() = %q, want it to contain %q", s, want)
		}
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func TestSchedulerNames(t *testing.T) {
	for _, s := range []Scheduler{NewRandScheduler(), NewRoundRobinScheduler(), NewFastScheduler()} {
		if s.Name() == "" {
			t.Error("a scheduler has no name")
		}
	}
}
