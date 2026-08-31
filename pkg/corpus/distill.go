package corpus

// Distillation: the smallest subset of a corpus that reaches everything the
// whole corpus reaches.
//
// It is a different question from the favoured set beside it, and the
// difference matters. MarkFavoured asks, for each feature, which entry is the
// cheapest way to reach it, and the answer *biases the schedule* — every entry
// stays, and the corpus keeps growing. Distillation asks how few entries would
// do, and the answer *removes* the rest.
//
// Why remove anything. A long campaign admits an entry whenever it sees
// something new, and most of what it admits is a slightly different route to
// somewhere it already went. After a day the corpus is thousands of entries,
// the scheduler divides its attention among all of them, and the marginal entry
// is a copy of its parent. Distilling is what turns that back into a corpus a
// person could read — and it is the operation that makes a corpus worth handing
// to somebody else (ASR-0013), because what they want is the seeds, not the
// campaign's sediment.
//
// This is `afl-cmin`'s job, and the algorithm is the same greedy set cover: it
// is not optimal — minimum set cover is NP-hard — and it is within a logarithmic
// factor, which for this purpose is indistinguishable from optimal and takes
// milliseconds instead of for ever.

// DistillReport is what a distillation did.
type DistillReport struct {
	// Keep and Drop partition the input, in the order it was given.
	Keep []*Testcase
	Drop []*Testcase

	// Features is how many distinct things the corpus reached, and Covered how
	// many the kept subset reaches. They are equal unless an entry reached
	// nothing at all, which is the one case where dropping is not lossless in
	// the coverage sense — and it is lossless in every sense that matters,
	// because an entry that reaches nothing is one the campaign learned nothing
	// from.
	Features int
	Covered  int

	// BeforeBytes and AfterBytes are the corpus's encoded size, which is what a
	// person notices about the result.
	BeforeBytes int64
	AfterBytes  int64
}

// Distill returns the smallest subset covering everything the corpus covers.
//
// coverageOf returns the features one entry reached. It is supplied rather than
// stored, for the reason MarkFavoured takes one: a bitmap per entry across a
// corpus of thousands is more memory than the corpus itself, and the caller
// usually has to re-execute to get an honest answer anyway.
//
// The result is deterministic: entries are considered in the order given and
// ties are broken by size and then by position, never by map iteration order.
// A distillation that produced a different corpus on each run would break
// replay (ASR-0008) — the same campaign, resumed, would be fuzzing a different
// corpus from the one its checkpoint described.
func Distill(entries []*Testcase, coverageOf func(*Testcase) []uint32) DistillReport {
	rep := DistillReport{}
	if len(entries) == 0 {
		return rep
	}

	// One pass to measure, so coverageOf is called once per entry however many
	// rounds the selection takes. It is the expensive half — usually an
	// execution — and calling it inside the loop would make distillation cost
	// O(n²) executions.
	covers := make([][]uint32, len(entries))
	all := map[uint32]bool{}
	for i, tc := range entries {
		covers[i] = coverageOf(tc)
		rep.BeforeBytes += int64(len(tc.Bytes))
		for _, f := range covers[i] {
			all[f] = true
		}
	}
	rep.Features = len(all)

	uncovered := make(map[uint32]bool, len(all))
	for f := range all {
		uncovered[f] = true
	}

	chosen := make([]bool, len(entries))
	for len(uncovered) > 0 {
		best, bestGain, bestSize := -1, 0, 0
		for i, tc := range entries {
			if chosen[i] {
				continue
			}
			gain := 0
			for _, f := range covers[i] {
				if uncovered[f] {
					gain++
				}
			}
			if gain == 0 {
				continue
			}
			size := len(tc.Bytes)
			// More new features first; among equals the smaller entry, which is
			// the one that mutates faster and minimises better. The final tie —
			// same gain, same size — goes to the earlier entry, which is what
			// makes the result depend on the corpus rather than on the map.
			if gain > bestGain || (gain == bestGain && size < bestSize) {
				best, bestGain, bestSize = i, gain, size
			}
		}
		if best < 0 {
			// Nothing left reaches anything uncovered, which happens only if a
			// feature appeared in no entry's coverage. Not possible from the
			// pass above, and cheap to guard: an infinite loop here would hang
			// a campaign rather than produce a wrong answer.
			break
		}
		chosen[best] = true
		for _, f := range covers[best] {
			delete(uncovered, f)
		}
	}

	rep.Covered = rep.Features - len(uncovered)
	for i, tc := range entries {
		if chosen[i] {
			rep.Keep = append(rep.Keep, tc)
			rep.AfterBytes += int64(len(tc.Bytes))
			continue
		}
		rep.Drop = append(rep.Drop, tc)
	}
	return rep
}

// Distill reduces the corpus in place and reports what it did.
//
// The entries that go are gone: this is the operation that makes a corpus
// smaller, and keeping them somewhere would be a corpus that is smaller only in
// the listing. What protects against a mistake is that every dropped entry
// reaches something a kept one also reaches, by construction.
//
// Removal reorders what is left, because Remove fills the hole with the last
// entry. That is safe here and would not be everywhere: the schedulers keep
// their state on the testcase rather than in an array beside the corpus, and
// the state model keys its traces by digest. An index is an identity for the
// length of one iteration and no longer.
func (c *Corpus) Distill(coverageOf func(*Testcase) []uint32) DistillReport {
	rep := Distill(append([]*Testcase(nil), c.entries...), coverageOf)

	drop := make(map[Digest]bool, len(rep.Drop))
	for _, tc := range rep.Drop {
		drop[tc.ID] = true
	}
	// Backwards, so removing one does not move an entry this loop has yet to
	// look at into a place it has already passed.
	for i := len(c.entries) - 1; i >= 0; i-- {
		if drop[c.entries[i].ID] {
			c.Remove(i)
		}
	}
	return rep
}
