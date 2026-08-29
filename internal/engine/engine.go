package engine

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"sort"
	"time"

	"github.com/rom/Xfuzz/pkg/codec"
	"github.com/rom/Xfuzz/pkg/corpus"
	"github.com/rom/Xfuzz/pkg/executor"
	"github.com/rom/Xfuzz/pkg/feedback"
	"github.com/rom/Xfuzz/pkg/ir"
	"github.com/rom/Xfuzz/pkg/mutate"
	"github.com/rom/Xfuzz/pkg/rng"
	"github.com/rom/Xfuzz/pkg/state"
)

// Config assembles one worker's fuzz loop.
type Config struct {
	// CampaignSeed and WorkerID derive every RNG stream. The same pair always
	// produces the same campaign (ASR-0008).
	CampaignSeed uint64
	WorkerID     uint32

	Executor  executor.Executor
	Observers []feedback.Observer
	Feedback  feedback.Feedback
	Objective feedback.Objective

	Corpus   *corpus.Corpus
	Schedule corpus.Scheduler
	Mutators *mutate.Scheduler
	Codec    codec.Codec
	Dict     *mutate.Dictionary

	// Suppress leaves chosen derivations inconsistent, so the campaign also
	// reaches the target's validation code (ASR-0014).
	Suppress ir.Suppress

	// MaxInputBytes and MaxChildren bound how far a mutation may inflate an
	// input.
	MaxInputBytes int
	MaxChildren   int

	// TrimBudget bounds how many extra executions may be spent shrinking one
	// newly admitted corpus entry. Zero disables trimming.
	//
	// Trimming is not a tidiness measure. Mutation grows inputs, and a mutator
	// picks a position uniformly, so a corpus entry that has drifted to fifty
	// bytes gets an eighth of the attention per byte that a six-byte one does.
	// Left untrimmed, a campaign's own successes dilute it: this was measured
	// stalling a comparison ladder two steps from the end, with the fuzzer
	// spending its budget on bytes that did not matter.
	TrimBudget int

	// State, when set, makes this a stateful campaign: the engine records the
	// protocol states each session traverses and lets them steer which message
	// it mutates (ADR-0006). Nil is a stateless campaign and costs the loop one
	// nil check.
	State *state.Guidance

	// Trace, when set, receives one line per execution. It is what makes the
	// determinism requirement checkable rather than merely asserted: two runs of
	// the same campaign must produce byte-identical traces.
	Trace io.Writer
}

// defaultTrimBudget is how many executions one newly admitted entry may spend
// being shrunk. It pays for itself many times over: every later mutation of that
// entry is concentrated on bytes that matter.
const defaultTrimBudget = 48

// Budget bounds a run.
type Budget struct {
	MaxExecs           uint64
	MaxTime            time.Duration
	MaxFindings        int
	StopOnFirstFinding bool

	// PlateauExecs stops the run after this many executions without new
	// coverage. Zero disables it. A campaign that has stopped learning is
	// spending machine time for nothing, and noticing that is what turns a
	// week-long run into an hour-long one.
	PlateauExecs uint64
}

// Stats is what a run produced.
type Stats struct {
	Execs        uint64
	Findings     int
	Buckets      int
	CorpusSize   int
	Coverage     int
	MapDensity   float64
	Elapsed      time.Duration
	ExecTime     time.Duration
	Crashes      uint64
	Timeouts     uint64
	HarnessError uint64
	Stability    float64
	TrimExecs    uint64
	TrimSaved    uint64
	StopReason   string

	// States and Transitions are protocol coverage, reported separately from
	// code coverage because they answer a different question (ASR-0002). A
	// campaign can hold code coverage flat while discovering a new state, and
	// that is the case worth seeing rather than averaging away.
	States      int
	Transitions int

	// IllegalMoves counts transitions outside a declared model: the target
	// accepting a move its own protocol forbids.
	IllegalMoves int
}

// ExecsPerSecond returns the achieved rate.
func (s Stats) ExecsPerSecond() float64 {
	if s.Elapsed <= 0 {
		return 0
	}
	return float64(s.Execs) / s.Elapsed.Seconds()
}

// Overhead is the share of wall-clock time spent outside the target: choosing a
// seed, mutating it, fixing it up, judging the result.
//
// ASR-0007 caps this at 10%. It is reported rather than assumed because Go
// makes it entirely possible to write a correct fuzzer whose own bookkeeping
// costs more than the program it is testing.
func (s Stats) Overhead() float64 {
	if s.Elapsed <= 0 {
		return 0
	}
	o := 1 - float64(s.ExecTime)/float64(s.Elapsed)
	if o < 0 {
		return 0
	}
	return o
}

// Finding is a recorded bug with the input that produced it.
type Finding struct {
	feedback.Finding
	Input  []byte
	Digest corpus.Digest
	Bucket string
	Execs  uint64
}

// Engine is one worker's fuzz loop.
//
// It is single-threaded and allocation-free in steady state. Everything that
// would slow it down — persistence, statistics aggregation, corpus sync — is
// somebody else's job, off this path (ARCHITECTURE section 4).
type Engine struct {
	cfg   Config
	arena *ir.Arena
	fixer *ir.Fixer
	mctx  *mutate.Ctx

	seedRand *rng.Rand
	spliceR  *rng.Rand

	findings []Finding
	buckets  map[string]int

	stats     Stats
	sinceNew  uint64
	firstSeen map[corpus.Digest]bool

	// coverage is the map observer, when the campaign has one. Trimming needs
	// it to tell whether a shorter input still goes to the same places.
	coverage *feedback.CoverageMap
	trimBuf  []byte
}

// New builds an engine, rejecting a configuration that cannot fuzz.
func New(cfg Config) (*Engine, error) {
	switch {
	case cfg.Executor == nil:
		return nil, errors.New("engine: no executor")
	case cfg.Feedback == nil:
		return nil, errors.New("engine: no feedback; use feedback.Never() for a campaign that only replays its seeds")
	case cfg.Objective == nil:
		return nil, errors.New("engine: no objective; a campaign with nothing to find cannot report anything")
	case cfg.Corpus == nil:
		return nil, errors.New("engine: no corpus")
	case cfg.Schedule == nil:
		return nil, errors.New("engine: no schedule")
	case cfg.Mutators == nil:
		return nil, errors.New("engine: no mutators")
	case cfg.Codec == nil:
		return nil, errors.New("engine: no codec")
	}

	arena := ir.NewArena()
	mctx := mutate.NewCtx(cfg.CampaignSeed, cfg.WorkerID, arena)
	mctx.Dict = cfg.Dict
	mctx.MaxBytes = cfg.MaxInputBytes
	mctx.MaxChildren = cfg.MaxChildren

	var covMap *feedback.CoverageMap
	for _, o := range cfg.Observers {
		if m, ok := o.(*feedback.CoverageMap); ok {
			covMap = m
			break
		}
	}
	if cfg.TrimBudget == 0 {
		cfg.TrimBudget = defaultTrimBudget
	}

	return &Engine{
		coverage:  covMap,
		cfg:       cfg,
		arena:     arena,
		fixer:     ir.NewFixer(),
		mctx:      mctx,
		seedRand:  rng.Derive(cfg.CampaignSeed, cfg.WorkerID, rng.StreamSeedSelect),
		spliceR:   rng.Derive(cfg.CampaignSeed, cfg.WorkerID, rng.StreamSplice),
		buckets:   map[string]int{},
		firstSeen: map[corpus.Digest]bool{},
	}, nil
}

// Findings returns the bugs recorded so far.
func (e *Engine) Findings() []Finding { return e.findings }

// Buckets returns the distinct finding signatures and how many findings landed
// in each.
//
// The count that matters is the number of buckets, not the number of findings:
// a productive campaign produces thousands of crashing inputs for a handful of
// bugs, and reporting the raw count would say a fuzzer found ten thousand bugs
// when it found four.
func (e *Engine) Buckets() map[string]int { return e.buckets }

// Stats returns the current counters.
func (e *Engine) Stats() Stats {
	s := e.stats
	s.CorpusSize = e.cfg.Corpus.Len()
	s.Findings = len(e.findings)
	s.Buckets = len(e.buckets)
	// Searched rather than asserted: once a campaign composes state guidance
	// alongside coverage the stack root is a combinator, and an assertion on it
	// reports no coverage at all for a campaign that is being guided by it.
	if f, ok := feedback.FindFeedback(e.cfg.Feedback, "coverage"); ok {
		if mf, ok := f.(*feedback.MapFeedback); ok {
			s.Coverage, s.MapDensity = mf.Covered(), mf.Density()
		}
	}
	if cov := e.cfg.State.Coverage(); cov.States > 0 || cov.Transitions > 0 {
		s.States, s.Transitions, s.IllegalMoves = cov.States, cov.Transitions, cov.Illegal
	}
	return s
}

// AddSeed admits an input as a starting point, running it once so the corpus
// entry carries real coverage and timing rather than placeholders.
func (e *Engine) AddSeed(ctx context.Context, data []byte, origin string) error {
	node, err := e.cfg.Codec.Decode(nil, data)
	if err != nil {
		return fmt.Errorf("engine: decoding a seed: %w", err)
	}
	encoded := ir.Encode(node)

	tc := corpus.NewTestcase(node, encoded)
	tc.Prov.Origin = origin
	if e.cfg.Corpus.Contains(tc.ID) {
		return nil
	}

	start := time.Now()
	ek, err := e.cfg.Executor.Run(ctx, executor.Input{Bytes: encoded, Node: node}, e.cfg.Observers)
	if err != nil {
		return fmt.Errorf("engine: running a seed: %w", err)
	}
	tc.Meta.ExecTime = time.Since(start)

	interesting, score, err := e.cfg.Feedback.IsInteresting(e.cfg.Observers, ek)
	if err != nil {
		return fmt.Errorf("engine: judging a seed: %w", err)
	}
	// Seeds are admitted whether or not they are novel: a corpus the operator
	// supplied is the starting point, and discarding a seed for covering nothing
	// new leaves the campaign with nothing to mutate.
	e.cfg.Feedback.Append()
	tc.Meta.Score = score
	tc.Meta.Coverage = e.currentCoverage()
	_ = interesting

	e.cfg.Corpus.Add(tc)
	return nil
}

// Run fuzzes until the budget is exhausted.
func (e *Engine) Run(ctx context.Context, b Budget) (Stats, error) {
	if e.cfg.Corpus.Len() == 0 {
		return e.Stats(), errors.New("engine: the corpus is empty; add at least one seed")
	}

	start := time.Now()
	deadline := time.Time{}
	if b.MaxTime > 0 {
		deadline = start.Add(b.MaxTime)
	}
	e.sinceNew = 0
	reason := "budget exhausted"

loop:
	for {
		switch {
		case ctx.Err() != nil:
			reason = "cancelled"
			break loop
		case b.MaxExecs > 0 && e.stats.Execs >= b.MaxExecs:
			break loop
		case !deadline.IsZero() && time.Now().After(deadline):
			reason = "time budget reached"
			break loop
		case b.MaxFindings > 0 && len(e.buckets) >= b.MaxFindings:
			reason = "finding budget reached"
			break loop
		case b.PlateauExecs > 0 && e.sinceNew >= b.PlateauExecs:
			reason = fmt.Sprintf("no new coverage in %d executions", b.PlateauExecs)
			break loop
		}

		i, err := e.cfg.Schedule.Next(e.cfg.Corpus, e.seedRand)
		if err != nil {
			return e.finish(start, "scheduler: "+err.Error()), err
		}
		parent := e.cfg.Corpus.At(i)
		energy := e.cfg.Schedule.Energy(e.cfg.Corpus, i)

		admitted, best, stop, err := e.fuzzOne(ctx, parent, energy, b)
		if err != nil {
			return e.finish(start, "error"), err
		}
		e.cfg.Schedule.Update(e.cfg.Corpus, i, best, admitted)
		if stop {
			reason = "first finding"
			break loop
		}
	}
	return e.finish(start, reason), nil
}

// fuzzOne spends one seed's energy budget.
func (e *Engine) fuzzOne(ctx context.Context, parent *corpus.Testcase, energy int, b Budget) (
	admitted int, best feedback.Score, stop bool, err error) {

	for k := 0; k < energy; k++ {
		if ctx.Err() != nil {
			return admitted, best, false, nil
		}
		if b.MaxExecs > 0 && e.stats.Execs >= b.MaxExecs {
			return admitted, best, false, nil
		}

		e.arena.Reset()
		tree := e.arena.Clone(parent.Input)
		e.mctx.Root = tree
		e.mctx.Donor = e.pickDonor(parent)

		// Which part of the input to change. For a stateless campaign that is
		// the whole thing; for a session it is one message, chosen by aiming at
		// a state worth exploring past (ADR-0006). The mutation scheduler
		// restricts itself to the root it is given, so this is the whole of the
		// state-then-message split.
		target, aimed := tree, state.Label("")
		if e.cfg.State != nil {
			target, aimed = e.cfg.State.Target(parent.ID, tree, e.mctx.Nodes)
		}

		ops := e.cfg.Mutators.Mutate(e.mctx, target)
		if len(ops) == 0 {
			continue
		}

		encoded, ferr := e.fixer.Fix(tree, e.cfg.Suppress)
		if ferr != nil {
			// A mutation produced a tree whose derivations cannot be resolved.
			// That is a normal outcome of structural mutation, not an error:
			// skip the input and carry on.
			continue
		}

		execStart := time.Now()
		ek, rerr := e.cfg.Executor.Run(ctx, executor.Input{Bytes: encoded, Node: tree}, e.cfg.Observers)
		elapsed := time.Since(execStart)
		e.stats.ExecTime += elapsed
		e.stats.Execs++
		e.sinceNew++

		if rerr != nil {
			e.stats.HarnessError++
			return admitted, best, false, fmt.Errorf("engine: %w", rerr)
		}
		switch ek {
		case feedback.ExitCrash:
			e.stats.Crashes++
		case feedback.ExitTimeout:
			e.stats.Timeouts++
		case feedback.ExitError:
			e.stats.HarnessError++
		}

		interesting, score, jerr := e.cfg.Feedback.IsInteresting(e.cfg.Observers, ek)
		if jerr != nil {
			return admitted, best, false, fmt.Errorf("engine: feedback: %w", jerr)
		}
		isFinding, finding, oerr := e.cfg.Objective.IsFinding(e.cfg.Observers, ek)
		if oerr != nil {
			return admitted, best, false, fmt.Errorf("engine: objective: %w", oerr)
		}

		e.trace(encoded, ek, interesting, isFinding)

		// The trace belongs to the input that produced it, so it is recorded
		// against the child when the child is kept and against the parent
		// otherwise: an entry's trace is the scheduler's evidence about where
		// that entry gets to, and evidence from a session nobody kept is
		// evidence about nothing.
		if e.cfg.State != nil && !interesting {
			e.cfg.State.Record(parent.ID)
		}

		if isFinding {
			e.record(finding, encoded)
		}
		if interesting {
			e.cfg.Feedback.Append()
			if id, ok := e.admit(parent, tree, encoded, score, elapsed, ops, aimed); ok {
				admitted++
				e.sinceNew = 0
				if e.cfg.State != nil {
					e.cfg.State.Record(id)
				}
			}
			if score.NewSignal > best.NewSignal {
				best = score
			}
		} else {
			e.cfg.Feedback.Discard()
		}
		e.cfg.Mutators.RecordOutcome(ops, interesting, isFinding)

		if isFinding && b.StopOnFirstFinding {
			return admitted, best, true, nil
		}
	}
	return admitted, best, false, nil
}

// admit copies an interesting input out of the arena and into the corpus.
func (e *Engine) admit(parent *corpus.Testcase, tree *ir.Node, encoded []byte,
	score feedback.Score, elapsed time.Duration, ops []mutate.Op, aimed state.Label) (corpus.Digest, bool) {

	trimmed := e.trim(encoded)

	tc := corpus.NewTestcase(ir.Copy(tree), trimmed)
	if !bytes.Equal(trimmed, encoded) {
		// The trimmed bytes are authoritative, so the stored tree has to match
		// them or replay would reproduce the untrimmed input.
		if node, derr := e.cfg.Codec.Decode(nil, trimmed); derr == nil {
			tc = corpus.NewTestcase(node, trimmed)
		}
	}
	if e.cfg.Corpus.Contains(tc.ID) {
		return tc.ID, false
	}
	tc.Meta.Score = score
	tc.Meta.ExecTime = elapsed
	tc.Meta.Depth = parent.Meta.Depth + 1
	tc.Meta.Coverage = e.currentCoverage()
	tc.Prov = corpus.Provenance{
		Parent: parent.ID,
		Worker: e.cfg.WorkerID,
		Ops:    convertOps(ops),
		State:  string(aimed),
	}
	return tc.ID, e.cfg.Corpus.Add(tc)
}

// trim shrinks a newly interesting input while it still reaches the same places.
//
// The method is AFL's: try removing runs, largest first, and keep a removal
// whenever the coverage signature is unchanged. It costs executions now and
// saves far more later, because every subsequent mutation of the entry lands on
// a byte that matters.
func (e *Engine) trim(input []byte) []byte {
	if e.cfg.TrimBudget <= 0 || e.coverage == nil || len(input) <= 2 {
		return input
	}

	// The signature of the input as it stands. The observers were armed and
	// harvested by the execution that just happened, so the map still holds it.
	want := e.coverage.Signature()

	cur := append(e.trimBuf[:0], input...)
	spent := 0

	for step := len(cur) / 4; step >= 1; step /= 2 {
		for pos := len(cur) - step; pos >= 0 && spent < e.cfg.TrimBudget; pos -= step {
			if len(cur)-step < 1 {
				break
			}
			candidate := make([]byte, 0, len(cur))
			candidate = append(candidate, cur[:pos]...)
			candidate = append(candidate, cur[pos+step:]...)

			ek, err := e.cfg.Executor.Run(context.Background(),
				executor.Input{Bytes: candidate}, e.cfg.Observers)
			spent++
			e.stats.Execs++
			e.stats.TrimExecs++
			if err != nil || ek == feedback.ExitError {
				break
			}
			if e.coverage.Signature() != want {
				continue
			}
			cur = append(cur[:0], candidate...)
			if pos > len(cur) {
				pos = len(cur)
			}
		}
		if spent >= e.cfg.TrimBudget {
			break
		}
	}

	e.trimBuf = cur
	if len(cur) == len(input) {
		return input
	}
	e.stats.TrimSaved += uint64(len(input) - len(cur))
	return append([]byte(nil), cur...)
}

func convertOps(ops []mutate.Op) []corpus.Op {
	if len(ops) == 0 {
		return nil
	}
	out := make([]corpus.Op, len(ops))
	for i, o := range ops {
		out[i] = corpus.Op{
			Mutator: o.Mutator,
			Path:    append([]int(nil), o.Path...),
			RandPos: o.RandPos,
		}
	}
	return out
}

// pickDonor chooses another corpus entry for crossover.
func (e *Engine) pickDonor(exclude *corpus.Testcase) *ir.Node {
	n := e.cfg.Corpus.Len()
	if n < 2 {
		return nil
	}
	for try := 0; try < 4; try++ {
		cand := e.cfg.Corpus.At(e.spliceR.Intn(n))
		if cand != exclude {
			return cand.Input
		}
	}
	return nil
}

func (e *Engine) currentCoverage() int {
	if mf, ok := e.cfg.Feedback.(*feedback.MapFeedback); ok {
		return mf.Covered()
	}
	return 0
}

// record files a finding into its bucket.
//
// Bucketing here is deliberately simple — the objective's kind and its stack
// frames — because full triage belongs to the pipeline in M4. What matters at
// this stage is that distinct bugs are counted separately, so a campaign that
// finds one bug ten thousand times is not mistaken for one that found ten
// thousand bugs.
func (e *Engine) record(f feedback.Finding, input []byte) {
	bucket := bucketKey(f)
	e.buckets[bucket]++
	// Only the first input for a bucket is kept. Storing every crashing input
	// for a bug already found is how a findings directory reaches a million
	// files overnight.
	if e.buckets[bucket] > 1 {
		return
	}
	e.findings = append(e.findings, Finding{
		Finding: f,
		Input:   append([]byte(nil), input...),
		Digest:  corpus.DigestOf(input),
		Bucket:  bucket,
		Execs:   e.stats.Execs,
	})
}

func bucketKey(f feedback.Finding) string {
	key := f.Kind
	if len(f.Frames) > 0 {
		// The innermost frames identify the bug; the outer ones vary with how it
		// was reached and would split one bug across many buckets.
		n := len(f.Frames)
		if n > 3 {
			n = 3
		}
		for _, fr := range f.Frames[:n] {
			key += "|" + fr
		}
		return key
	}
	if f.Summary != "" {
		return key + "|" + f.Summary
	}
	return key
}

// trace writes one line per execution, for the determinism check.
func (e *Engine) trace(encoded []byte, ek feedback.ExitKind, interesting, finding bool) {
	if e.cfg.Trace == nil {
		return
	}
	fmt.Fprintf(e.cfg.Trace, "%d %s %s %v %v\n",
		e.stats.Execs, corpus.DigestOf(encoded).Short(), ek, interesting, finding)
}

func (e *Engine) finish(start time.Time, reason string) Stats {
	e.stats.Elapsed = time.Since(start)
	s := e.Stats()
	s.StopReason = reason
	return s
}

// SortedBuckets returns the finding signatures in a stable order, for reports
// and tests.
func (e *Engine) SortedBuckets() []string {
	out := make([]string, 0, len(e.buckets))
	for k := range e.buckets {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Corpus returns the engine's corpus.
//
// Exposed so a worker can report newly admitted entries to the daemon, which
// owns the store. The engine deliberately does not persist anything itself: it
// is the hot loop, and everything that would slow it down is somebody else's
// job (ARCHITECTURE section 4).
func (e *Engine) Corpus() *corpus.Corpus { return e.cfg.Corpus }
