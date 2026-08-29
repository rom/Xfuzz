package metrics

import (
	"sync"
	"time"
)

// Series is a bounded, downsampled history of snapshots.
//
// A campaign runs for days and reports every second. Keeping every point is a
// memory leak; keeping only the last N points loses the shape of the run, which
// is the thing a coverage-over-time chart exists to show. So the series keeps
// resolution where it matters — recent history in full, older history thinned —
// which is what a person actually reads: the last few minutes precisely, the
// last few days as a curve.
//
// Downsampling drops points rather than averaging them. A coverage curve is
// monotonic and an execution count is cumulative, so a retained real point is a
// true statement about the campaign, while an averaged one is a number that
// never happened.
type Series struct {
	mu sync.Mutex

	// buckets hold progressively coarser history. Each level keeps at most
	// perLevel points at its own interval; a point aging out of one level is
	// offered to the next.
	buckets [][]Snapshot

	retention time.Duration
	now       func() time.Time
	lastAt    []time.Time
}

// Series resolution. Four levels covering seconds to days: a week-long campaign
// keeps under a thousand points, and the last two minutes are still per-second.
var levelIntervals = []time.Duration{
	time.Second,
	15 * time.Second,
	5 * time.Minute,
	time.Hour,
}

// perLevel is how many points each level retains.
const perLevel = 120

// NewSeries returns a series that discards points older than retention. A zero
// retention keeps whatever the levels hold, which for the intervals above is
// about five days.
func NewSeries(retention time.Duration) *Series {
	return &Series{
		buckets:   make([][]Snapshot, len(levelIntervals)),
		lastAt:    make([]time.Time, len(levelIntervals)),
		retention: retention,
		now:       time.Now,
	}
}

// Add records a snapshot.
func (s *Series) Add(snap Snapshot) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if snap.At.IsZero() {
		snap.At = s.now()
	}
	for level, interval := range levelIntervals {
		last := s.lastAt[level]
		if !last.IsZero() && snap.At.Sub(last) < interval {
			// Too soon for this level, and therefore too soon for every coarser
			// one below it.
			break
		}
		s.lastAt[level] = snap.At
		s.buckets[level] = append(s.buckets[level], snap)
		if len(s.buckets[level]) > perLevel {
			s.buckets[level] = s.buckets[level][len(s.buckets[level])-perLevel:]
		}
	}
	s.expire(snap.At)
}

// expire drops points older than the retention window.
func (s *Series) expire(now time.Time) {
	if s.retention <= 0 {
		return
	}
	cutoff := now.Add(-s.retention)
	for level := range s.buckets {
		b := s.buckets[level]
		i := 0
		for i < len(b) && b[i].At.Before(cutoff) {
			i++
		}
		if i > 0 {
			s.buckets[level] = append(b[:0], b[i:]...)
		}
	}
}

// Points returns the history oldest first, deduplicated across levels.
//
// The coarse levels hold the same snapshots the fine ones do — a point is added
// to every level whose interval has elapsed — so the merge takes each instant
// once. Returning duplicates would put a visible step in every chart at the
// boundary where two levels overlap.
func (s *Series) Points() []Snapshot {
	s.mu.Lock()
	defer s.mu.Unlock()

	seen := make(map[int64]bool)
	var out []Snapshot
	// Coarsest first, so the oldest history leads; within the merge, an instant
	// already taken from a coarser level is skipped when the finer one repeats
	// it.
	for level := len(s.buckets) - 1; level >= 0; level-- {
		for _, p := range s.buckets[level] {
			k := p.At.UnixNano()
			if seen[k] {
				continue
			}
			seen[k] = true
			out = append(out, p)
		}
	}
	sortByTime(out)
	return out
}

// Len returns how many distinct points the series holds.
func (s *Series) Len() int { return len(s.Points()) }

func sortByTime(s []Snapshot) {
	// Insertion sort: the input is nearly ordered — each level is already
	// sorted and the levels are appended coarse to fine — so this is linear in
	// practice and allocates nothing.
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j].At.Before(s[j-1].At); j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}
