package corpus

import (
	"math"

	"github.com/rom/Xfuzz/pkg/feedback"
	"github.com/rom/Xfuzz/pkg/rng"
)

// Power schedules decide which seed to fuzz next and how much effort to spend
// on it.
//
// This is where a fuzzer's time actually goes. Two campaigns with identical
// mutators and identical coverage feedback differ by an order of magnitude in
// bugs found depending on whether the schedule keeps re-fuzzing the same easy
// seeds or spreads attention across the frontier.
//
// The schedules here follow AFL and AFLFast in shape, with the constants named
// rather than buried, because they are tuning parameters and will need tuning.

// Scheduler picks the next seed and its energy budget.
type Scheduler interface {
	Name() string

	// Next returns the index of the entry to fuzz.
	Next(c *Corpus, r *rng.Rand) (int, error)

	// Energy returns how many mutations to spend on an entry before moving on.
	Energy(c *Corpus, i int) int

	// Update records what came of fuzzing an entry.
	Update(c *Corpus, i int, s feedback.Score, admitted int)
}

// ErrEmptyCorpus is returned when there is nothing to schedule.
type ErrEmptyCorpus struct{}

func (ErrEmptyCorpus) Error() string { return "corpus: no entries to schedule" }

// RandScheduler picks uniformly at random with fixed energy.
//
// It is the control, not a recommendation: any schedule that cannot beat
// uniform random selection is not earning its complexity, and having it
// available makes that measurable.
type RandScheduler struct {
	// Fixed is the energy given to every entry.
	Fixed int
}

// NewRandScheduler returns a uniform scheduler.
func NewRandScheduler() *RandScheduler { return &RandScheduler{Fixed: 64} }

// Name implements Scheduler.
func (s *RandScheduler) Name() string { return "rand" }

// Next implements Scheduler.
func (s *RandScheduler) Next(c *Corpus, r *rng.Rand) (int, error) {
	if c.Len() == 0 {
		return 0, ErrEmptyCorpus{}
	}
	return r.Intn(c.Len()), nil
}

// Energy implements Scheduler.
func (s *RandScheduler) Energy(*Corpus, int) int { return s.Fixed }

// Update implements Scheduler.
func (s *RandScheduler) Update(c *Corpus, i int, _ feedback.Score, _ int) {
	c.entries[i].Meta.Fuzzed++
}

// RoundRobinScheduler walks the corpus in order, so every entry is fuzzed
// equally often. Useful for reproducible comparisons and for a first pass over
// an imported corpus.
type RoundRobinScheduler struct {
	Fixed int
	next  int
}

// NewRoundRobinScheduler returns a round-robin scheduler.
func NewRoundRobinScheduler() *RoundRobinScheduler { return &RoundRobinScheduler{Fixed: 64} }

// Name implements Scheduler.
func (s *RoundRobinScheduler) Name() string { return "round-robin" }

// Next implements Scheduler.
func (s *RoundRobinScheduler) Next(c *Corpus, _ *rng.Rand) (int, error) {
	if c.Len() == 0 {
		return 0, ErrEmptyCorpus{}
	}
	if s.next >= c.Len() {
		s.next = 0
	}
	i := s.next
	s.next++
	return i, nil
}

// Energy implements Scheduler.
func (s *RoundRobinScheduler) Energy(*Corpus, int) int { return s.Fixed }

// Update implements Scheduler.
func (s *RoundRobinScheduler) Update(c *Corpus, i int, _ feedback.Score, _ int) {
	c.entries[i].Meta.Fuzzed++
}

// Tuning constants for the weighted schedule. Named because they are the knobs
// a campaign will want to turn, and because unnamed magic numbers in a scheduler
// are how a fuzzer becomes impossible to reason about.
const (
	// BaseEnergy is the energy an average entry receives.
	BaseEnergy = 64

	// MaxEnergy caps a single entry's budget, so one seed cannot monopolise a
	// worker.
	MaxEnergy = 1600

	// MinEnergy floors it, so no entry is starved entirely.
	MinEnergy = 8

	// speedFactorCap bounds how much being fast or slow can move the score.
	speedFactorCap = 4.0

	// depthPenalty reduces energy for deeply derived entries, which tend to be
	// larger and more specialised than their ancestors.
	depthPenalty = 0.9
)

// FastScheduler favours entries that are cheap to run, have been fuzzed least,
// and have recently produced new coverage.
//
// The shape follows AFLFast: energy grows for seeds whose neighbourhood is
// under-explored and shrinks for seeds that have already had a lot of attention
// without repaying it. The point is to stop the schedule spending its whole
// budget on whichever seed happens to be first.
type FastScheduler struct {
	// ExploitRatio is how often to pick the current best entry rather than
	// sampling by weight. Pure exploitation stalls on a local maximum; pure
	// exploration ignores what the campaign has learned.
	ExploitRatio float64

	// Base and Max bound the energy.
	Base, Max int

	// PreferFast weights seeds by their measured execution time, so that at
	// equal value a seed running twice as fast is worth twice as much.
	//
	// It is off by default, and that default is not a hedge. Measured time
	// varies with machine load, so using it as a scheduling input makes seed
	// selection differ between two runs of the same campaign — and ASR-0008
	// requires that the same campaign file, seed and target produce an
	// identical sequence of executions, because a finding that cannot be
	// reproduced is not a finding.
	//
	// The heuristic is genuinely useful and stays available for campaigns that
	// value throughput over exact reproducibility. Everything else the schedule
	// weighs — size, coverage, times fuzzed, depth — is derived from the corpus
	// rather than from the clock, and is reproducible.
	PreferFast bool

	// Directed weights entries by how close they came to a directed campaign's
	// target, which is the half of directed fuzzing that coverage-guided
	// scheduling does not supply.
	//
	// A distance feedback decides which inputs to *keep*; without this, the
	// schedule then spends its budget on them no differently from anything else,
	// and a corpus of ten thousand entries of which four are near the target
	// gives those four a four-in-ten-thousand share of the machine. Direction
	// that is not spent is direction that does not arrive.
	//
	// Zero leaves the schedule undirected, which is what a campaign with no
	// target wants. One makes an entry at the target worth DirectedWeight times
	// as much as one as far away as anything gets.
	Directed float64
}

// DefaultDirectedWeight is how much closeness is worth when a campaign is
// directed.
//
// Eight, rather than something decisive. Direction has to bias the schedule
// without capturing it: a campaign that spends everything on its closest seeds
// stops exploring, and the route to a target usually runs through code that is
// not itself near the target — a parser has to accept the file before any of it
// reaches the function under investigation. AFLGo's annealing solves this by
// starting undirected and tightening over time; a fixed, moderate weight is the
// same trade without a schedule that depends on the clock (ASR-0008).
const DefaultDirectedWeight = 8.0

// NewFastScheduler returns a weighted schedule with defaults.
func NewFastScheduler() *FastScheduler {
	return &FastScheduler{ExploitRatio: 0.2, Base: BaseEnergy, Max: MaxEnergy}
}

// Name implements Scheduler.
func (s *FastScheduler) Name() string { return "fast" }

// Next implements Scheduler.
func (s *FastScheduler) Next(c *Corpus, r *rng.Rand) (int, error) {
	n := c.Len()
	if n == 0 {
		return 0, ErrEmptyCorpus{}
	}
	if n == 1 {
		return 0, nil
	}
	avg := c.Averages()

	if r.Chance(s.ExploitRatio) {
		best, bestW := 0, math.Inf(-1)
		for i := range c.entries {
			if w := s.weight(c.entries[i], avg); w > bestW {
				best, bestW = i, w
			}
		}
		return best, nil
	}

	// Weighted sampling in one pass, so selection costs a walk and no
	// allocation however large the corpus grows.
	total, chosen := 0.0, 0
	for i := range c.entries {
		w := s.weight(c.entries[i], avg)
		total += w
		if total > 0 && r.Float64()*total < w {
			chosen = i
		}
	}
	return chosen, nil
}

// weight scores an entry for selection. Higher is more deserving.
func (s *FastScheduler) weight(tc *Testcase, avg Averages) float64 {
	w := 1.0

	// Rarely fuzzed entries come first. The reciprocal, rather than a hard
	// ordering, keeps well-explored entries reachable instead of frozen out.
	w *= 1.0 / (1.0 + float64(tc.Meta.Fuzzed))

	// Fast entries are worth more, when the campaign has opted into weighing a
	// measurement that is not reproducible.
	if s.PreferFast && avg.ExecTime > 0 && tc.Meta.ExecTime > 0 {
		w *= clamp(avg.ExecTime/float64(tc.Meta.ExecTime), 1/speedFactorCap, speedFactorCap)
	}

	// Small entries are worth more too, and size is a property of the input
	// rather than of the machine: they mutate faster and minimise better.
	if avg.Size > 0 && tc.Meta.Size > 0 {
		w *= clamp(avg.Size/float64(tc.Meta.Size), 1/speedFactorCap, speedFactorCap)
	}

	// Entries that reached more of the map are more likely to be near a
	// frontier.
	if avg.Coverage > 0 {
		w *= clamp(float64(tc.Meta.Coverage)/avg.Coverage, 1/speedFactorCap, speedFactorCap)
	}

	// Entries that have produced children have proven themselves.
	w *= 1.0 + math.Log1p(float64(tc.Meta.Children))

	// Favoured entries — the minimal set covering everything known — get a
	// decisive boost.
	if tc.Meta.Favoured {
		w *= 4
	}

	// Entries that came closer to a directed campaign's target are worth more.
	// Score.Distance is normalised to 0 at the target and 1 as far away as
	// anything gets, so this rises smoothly as a campaign descends towards it.
	if s.Directed > 0 {
		w *= 1 + (s.Directed-1)*(1-clamp(tc.Meta.Score.Distance, 0, 1))
	}

	// Depth stands in for age, because wall-clock time must not influence a
	// fuzzing decision (ASR-0008).
	w *= math.Pow(depthPenalty, float64(tc.Meta.Depth))

	if w <= 0 || math.IsNaN(w) {
		return 1e-9
	}
	return w
}

// Energy implements Scheduler.
func (s *FastScheduler) Energy(c *Corpus, i int) int {
	tc := c.entries[i]
	avg := c.Averages()

	e := float64(s.Base)
	if avg.Coverage > 0 {
		e *= clamp(float64(tc.Meta.Coverage)/avg.Coverage, 0.25, 4)
	}
	// Halve the budget each time the entry is revisited, so attention moves on
	// rather than grinding a seed that has stopped paying.
	e /= math.Pow(2, math.Min(float64(tc.Meta.Fuzzed), 6))
	if tc.Meta.Favoured {
		e *= 4
	}
	return int(clamp(e, MinEnergy, float64(s.Max)))
}

// Update implements Scheduler.
func (s *FastScheduler) Update(c *Corpus, i int, score feedback.Score, admitted int) {
	tc := c.entries[i]
	tc.Meta.Fuzzed++
	tc.Meta.Children += uint64(admitted)
	if score.NewSignal > tc.Meta.Score.NewSignal {
		tc.Meta.Score = score
	}
}

func clamp(v, lo, hi float64) float64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// MarkFavoured recomputes the minimal set of entries covering everything the
// corpus knows, marking them favoured.
//
// This is AFL's "favored" idea: for each covered edge, keep the cheapest entry
// that reaches it. Fuzzing that subset preferentially is what stops a corpus of
// ten thousand entries from diluting attention a hundredfold, and it is the
// basis for culling later.
//
// coverageOf returns the entries an input reached; supplying it rather than
// storing per-entry coverage maps keeps a large corpus from holding a bitmap
// per entry.
func MarkFavoured(c *Corpus, coverageOf func(*Testcase) []uint32) {
	best := map[uint32]int{}
	cost := map[uint32]float64{}

	for i, tc := range c.entries {
		tc.Meta.Favoured = false
		// Size alone, not size times execution time: the favoured set is part of
		// the schedule, and the schedule must not depend on the clock (ASR-0008).
		w := float64(tc.Meta.Size)
		for _, edge := range coverageOf(tc) {
			if prev, ok := cost[edge]; !ok || w < prev {
				best[edge], cost[edge] = i, w
			}
		}
	}
	for _, i := range best {
		c.entries[i].Meta.Favoured = true
	}
}
