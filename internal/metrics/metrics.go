// Package metrics provides counters, historical series, and health diagnostics.
//
// The defining failure mode of a fuzzing campaign is silent: it runs for a week,
// looks busy, and finds nothing because the harness rejected every input, the
// target restarts on each execution, or instrumentation was never active. Named
// diagnostics exist to convert that invisible failure into a reported one.
//
// Retention is bounded and downsampled; an unbounded metric history is a memory
// leak with a dashboard attached.
package metrics

import (
	"sync"
	"time"
)

// Snapshot is a campaign's live counters at one instant.
//
// It is a plain struct rather than a map of names because these are the numbers
// every view shows, and a typo in a metric name should not be able to produce a
// dashboard panel that is quietly always zero.
type Snapshot struct {
	At time.Time `json:"at"`

	Execs     uint64  `json:"execs"`
	ExecsPerS float64 `json:"execs_per_second"`

	// Coverage is edges reached; MapDensity is the share of the map used, which
	// is the signal that the map is too small — as it saturates, distinct edges
	// start colliding and the campaign stops being able to tell paths apart.
	Coverage   int     `json:"coverage"`
	MapDensity float64 `json:"map_density"`

	// States and Transitions are protocol coverage on a stateful campaign,
	// reported separately from code coverage because they answer a different
	// question (ASR-0002). A campaign can hold code coverage flat while
	// discovering a new state, and that is exactly the case worth seeing rather
	// than folding into one number.
	States      int `json:"states,omitempty"`
	Transitions int `json:"transitions,omitempty"`

	// IllegalMoves counts transitions outside a declared model: the target
	// accepting a move its own protocol forbids.
	IllegalMoves int `json:"illegal_moves,omitempty"`

	CorpusSize  int   `json:"corpus_size"`
	CorpusBytes int64 `json:"corpus_bytes"`

	Findings int `json:"findings"`
	Buckets  int `json:"buckets"`

	Crashes      uint64 `json:"crashes"`
	Timeouts     uint64 `json:"timeouts"`
	HarnessError uint64 `json:"harness_errors"`

	// Stability is the share of executions that produce identical coverage for
	// identical input. Below about 90% a coverage-guided campaign is chasing
	// noise (ASR-0008).
	Stability float64 `json:"stability"`

	// Overhead is the share of wall-clock time spent outside the target.
	// ASR-0007 caps it at 10%.
	Overhead float64 `json:"overhead"`

	// CmpExecs and CmpAdmitted are what comparison substitution cost and what it
	// bought; SolverExecs and SolverAdmitted the same for the concolic stage.
	//
	// Reported separately from the totals because both stages are all-or-nothing
	// in a way the rest of the loop is not: on a target with no constants to
	// match, or with a solver that answers nothing useful, they spend executions
	// and admit nothing. An operator deciding whether to keep paying for one
	// needs the cost and the yield side by side, not folded into a rate.
	CmpExecs       uint64 `json:"cmp_execs,omitempty"`
	CmpAdmitted    uint64 `json:"cmp_admitted,omitempty"`
	SolverExecs    uint64 `json:"solver_execs,omitempty"`
	SolverAdmitted uint64 `json:"solver_admitted,omitempty"`

	// PluginCalls and PluginSeconds are how often the campaign crossed the
	// process boundary into an out-of-process extension and how long it waited
	// there in total.
	//
	// First class rather than folded into Overhead, because ADR-0010 promises
	// that a slow plugin is diagnosable rather than mysterious. Overhead alone
	// says the fuzzer is spending its time somewhere other than the target; it
	// does not say which extension, and "your campaign is slow" is not a
	// finding anyone can act on.
	PluginCalls   uint64  `json:"plugin_calls,omitempty"`
	PluginSeconds float64 `json:"plugin_seconds,omitempty"`

	// LastNewCoverage is when the campaign last learned something. It is the
	// number that says whether it is still working or merely still running.
	LastNewCoverage time.Time `json:"last_new_coverage"`

	Workers        int `json:"workers"`
	WorkersHealthy int `json:"workers_healthy"`
	WorkerRestarts int `json:"worker_restarts"`

	TriageQueued  uint64 `json:"triage_queued"`
	TriageDropped uint64 `json:"triage_dropped"`
}

// Collector accumulates a campaign's metrics.
//
// Every method is safe to call from any worker's reporting goroutine. None of
// them is on the fuzz loop: a worker reports its counters periodically, and the
// collector merges. Merging rather than sharing is what keeps the hot path free
// of synchronisation (ARCHITECTURE section 4).
type Collector struct {
	mu sync.Mutex

	current   Snapshot
	perWorker map[int]Snapshot

	series *Series
	start  time.Time
	now    func() time.Time
}

// NewCollector returns a collector with a bounded history.
func NewCollector(retention time.Duration) *Collector {
	now := time.Now()
	return &Collector{
		perWorker: map[int]Snapshot{},
		series:    NewSeries(retention),
		start:     now,
		now:       time.Now,
	}
}

// SetClock replaces the time source, for tests.
func (c *Collector) SetClock(f func() time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = f
	c.series.now = f
}

// Report records one worker's counters.
//
// Workers report absolute values rather than deltas. A delta lost in a restart
// is a number that stays wrong forever; an absolute value that arrives late is
// merely late, and the next one corrects it.
func (c *Collector) Report(worker int, s Snapshot) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if s.At.IsZero() {
		s.At = c.now()
	}
	// A restarted worker reports smaller numbers than it did before, because
	// its own counters legitimately reset. The campaign total is recomputed
	// from what every worker currently claims rather than accumulated, so a
	// restart shows up as that worker's contribution stepping down — not as a
	// campaign that lost half its executions and can never get them back.
	c.perWorker[worker] = s
	c.recompute()
}

// Forget drops a worker's contribution, for one that has ended.
func (c *Collector) Forget(worker int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.perWorker, worker)
	c.recompute()
}

// recompute rebuilds the campaign total from the per-worker reports.
func (c *Collector) recompute() {
	total := Snapshot{At: c.now(), Workers: len(c.perWorker)}

	var (
		stabilitySum float64
		overheadSum  float64
		rated        int
	)
	for _, s := range c.perWorker {
		total.Execs += s.Execs
		total.ExecsPerS += s.ExecsPerS
		total.Crashes += s.Crashes
		total.Timeouts += s.Timeouts
		total.HarnessError += s.HarnessError
		total.TriageQueued += s.TriageQueued
		total.TriageDropped += s.TriageDropped
		total.WorkerRestarts += s.WorkerRestarts

		// Coverage and the corpus are campaign-wide facts that every worker
		// observes through the shared corpus, so they are the maximum reported
		// rather than the sum. Summing them would multiply the campaign's
		// coverage by its worker count.
		total.Coverage = max(total.Coverage, s.Coverage)
		total.MapDensity = max(total.MapDensity, s.MapDensity)

		// Like coverage and unlike findings: every worker fuzzes the same
		// protocol, so the campaign has seen a state when any worker has. The
		// maximum under-counts when workers explore disjoint regions, which is
		// the honest floor — the alternative, summing, would report a
		// four-worker campaign as having found four times the protocol.
		total.States = max(total.States, s.States)
		total.Transitions = max(total.Transitions, s.Transitions)
		total.IllegalMoves = max(total.IllegalMoves, s.IllegalMoves)
		total.CorpusSize = max(total.CorpusSize, s.CorpusSize)
		total.CorpusBytes = max(total.CorpusBytes, s.CorpusBytes)

		// Findings are not shared: each worker reports only what it found
		// itself, so two workers with one finding each are two findings, and
		// the maximum would report one. Buckets are the other way — two
		// workers can reach the same bug — so the maximum is a floor rather
		// than an answer, and the campaign, which records every finding
		// centrally, refines it.
		total.Findings += s.Findings
		total.Buckets = max(total.Buckets, s.Buckets)

		// Summed, like findings and unlike coverage: each worker runs its own
		// plugin process, so the campaign's cost of crossing the boundary is
		// what all of them paid, not what the busiest one did.
		total.PluginCalls += s.PluginCalls
		total.PluginSeconds += s.PluginSeconds

		// Summed for the same reason: each worker runs its own stages, and what
		// the campaign spent on substitution or on a solver is what all of them
		// spent, not what the busiest one did.
		total.CmpExecs += s.CmpExecs
		total.CmpAdmitted += s.CmpAdmitted
		total.SolverExecs += s.SolverExecs
		total.SolverAdmitted += s.SolverAdmitted

		if s.LastNewCoverage.After(total.LastNewCoverage) {
			total.LastNewCoverage = s.LastNewCoverage
		}
		if s.Stability > 0 || s.Overhead > 0 {
			stabilitySum += s.Stability
			overheadSum += s.Overhead
			rated++
		}
		if s.WorkersHealthy > 0 {
			total.WorkersHealthy++
		}
	}
	if rated > 0 {
		total.Stability = stabilitySum / float64(rated)
		total.Overhead = overheadSum / float64(rated)
	}
	c.current = total
	c.series.Add(total)
}

// Snapshot returns the campaign's current counters.
func (c *Collector) Snapshot() Snapshot {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.current
}

// Workers returns each worker's last report.
func (c *Collector) Workers() map[int]Snapshot {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make(map[int]Snapshot, len(c.perWorker))
	for k, v := range c.perWorker {
		out[k] = v
	}
	return out
}

// History returns the downsampled series.
func (c *Collector) History() []Snapshot {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.series.Points()
}

// Elapsed is how long the campaign has been collecting.
func (c *Collector) Elapsed() time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now().Sub(c.start)
}
