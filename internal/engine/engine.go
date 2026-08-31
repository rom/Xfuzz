package engine

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
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

	// Cmp, when set, turns on the comparison stage: the target's own comparison
	// operands are read after each execution and substituted back into the
	// input, which is what gets a campaign past a magic number or a checksum
	// (ADR-0007). Nil leaves the stage out of the list entirely, so a campaign
	// that did not ask for it pays nothing.
	Cmp *feedback.CmpObserver

	// Solver, when set, adds the concolic stage: an asynchronous solver running
	// alongside the loop, whose answers are executed as they arrive (ADR-0007).
	//
	// A campaign with one is not reproducible. Which solutions arrive before
	// which mutation round depends on how long the solver took, and that is
	// wall-clock — so ASR-0008's guarantee that the same campaign file, seed and
	// target produce an identical sequence of executions does not hold. It is
	// the second feature in the system to opt out of that, and like the first it
	// is off unless asked for.
	Solver Solver

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

	// CmpExecs and CmpAdmitted are what the comparison stage cost and what it
	// bought. Reported separately because the stage is the one part of the loop
	// whose value is all-or-nothing: on a target with no magic values it spends
	// executions and admits nothing, and an operator deciding whether to keep
	// paying for it needs the two numbers side by side rather than folded into
	// the totals.
	CmpExecs    uint64
	CmpAdmitted uint64

	// SolverExecs and SolverAdmitted are what the concolic stage cost and what
	// it bought, reported separately for the same reason the comparison stage's
	// are: a solver that answers nothing useful is a cost an operator should be
	// able to see and stop paying.
	SolverExecs    uint64
	SolverAdmitted uint64

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

	// concolic is the solver stage, held separately from the stage list because
	// it owns a goroutine and a process that have to be released.
	concolic *concolicStage

	// stages are the ways this campaign derives new inputs, in the order they
	// run. Fixed at construction: which stages exist is a property of the
	// configuration, and deciding it per seed would put a branch on the hot path
	// for a question whose answer never changes.
	stages []stage
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

	e := &Engine{
		coverage:  covMap,
		cfg:       cfg,
		arena:     arena,
		fixer:     ir.NewFixer(),
		mctx:      mctx,
		seedRand:  rng.Derive(cfg.CampaignSeed, cfg.WorkerID, rng.StreamSeedSelect),
		spliceR:   rng.Derive(cfg.CampaignSeed, cfg.WorkerID, rng.StreamSplice),
		buckets:   map[string]int{},
		firstSeen: map[corpus.Digest]bool{},
	}
	e.stages, e.concolic = stagesFor(cfg)
	return e, nil
}

// Close releases what the engine acquired.
//
// Only the solver, today: everything else the engine holds is owned by the
// caller that supplied it. It is safe to call on an engine that has none, so a
// caller never has to know whether the campaign was configured for one.
func (e *Engine) Close() error {
	if e.concolic != nil {
		return e.concolic.Close()
	}
	return nil
}

// SolverStats reports what the concolic stage cost and what it produced: queries
// sent, queries and answers dropped because one side was not keeping up,
// solutions produced, solver failures, and solutions executed.
func (e *Engine) SolverStats() (sent, dropped, solved, failed, executed uint64, ok bool) {
	if e.concolic == nil {
		return 0, 0, 0, 0, 0, false
	}
	sent, dropped, solved, failed, executed = e.concolic.Stats()
	return sent, dropped, solved, failed, executed, true
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

	// A seed is judged by the objectives like any other execution.
	//
	// It was not, and the gap was quiet in exactly the way that matters: an
	// operator who hands the fuzzer a reproducer as a seed — which is the
	// obvious thing to do with one — got a campaign that admitted it to the
	// corpus and said nothing, until a mutation happened to rediscover the same
	// bug. On a fast tier that is a few thousand executions and looks like
	// nothing; on the driver tier, at ten executions a second and with a
	// sequence alphabet, it can be never.
	if found, f, oerr := e.cfg.Objective.IsFinding(e.cfg.Observers, ek); oerr != nil {
		return fmt.Errorf("engine: judging a seed: %w", oerr)
	} else if found {
		e.record(f, encoded)
	}

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

	// The trace this seed produced, recorded against the seed. A trace is
	// evidence about where one input gets to, so it belongs to the input that
	// produced it and to no other — recording a mutant's trace against its
	// parent, which an earlier version did, leaves the scheduler aiming with a
	// map of somewhere else and quietly undoes the state-then-message split.
	if e.cfg.State != nil {
		e.cfg.State.Record(tc.ID)
	}

	e.cfg.Corpus.Add(tc)
	return nil
}

// CorpusLen returns how many entries the corpus holds.
func (e *Engine) CorpusLen() int { return e.cfg.Corpus.Len() }

// Distill re-measures every corpus entry and keeps the smallest subset that
// reaches everything the corpus reaches.
//
// Re-measured rather than remembered, and that is the expensive half: a corpus
// entry's stored coverage is a *count*, and keeping a bitmap per entry across a
// corpus of thousands costs more memory than the corpus. So this runs the
// corpus once, which for a fast target is seconds and for the driver tier is
// the reason a campaign should not do it often.
//
// It is a real removal (ASR-0013): what it drops is gone, and what makes that
// safe is that every dropped entry reaches something a kept one also reaches.
func (e *Engine) Distill(ctx context.Context) (corpus.DistillReport, error) {
	var rep corpus.DistillReport
	cov, ok := e.coverageMap()
	if !ok {
		return rep, errors.New("engine: distilling needs coverage: without it there " +
			"is no way to tell which entries are redundant, and dropping any of " +
			"them would be dropping them at random")
	}

	// Measured in full before anything is removed. A failure part-way through
	// would otherwise leave a corpus distilled against half an answer, which is
	// a corpus missing entries nothing has replaced.
	measured := make(map[corpus.Digest][]uint32, e.cfg.Corpus.Len())
	for i := 0; i < e.cfg.Corpus.Len(); i++ {
		if err := ctx.Err(); err != nil {
			return rep, err
		}
		tc := e.cfg.Corpus.At(i)
		if _, err := e.cfg.Executor.Run(ctx,
			executor.Input{Bytes: tc.Bytes, Node: tc.Input}, e.cfg.Observers); err != nil {
			return rep, fmt.Errorf("engine: measuring %s for distillation: %w", tc.ID, err)
		}
		e.stats.Execs++
		measured[tc.ID] = coveredIndices(cov.Buffer())
	}

	rep = e.cfg.Corpus.Distill(func(tc *corpus.Testcase) []uint32 { return measured[tc.ID] })
	return rep, nil
}

// coverageMap finds the map the campaign is guided by.
func (e *Engine) coverageMap() (*feedback.CoverageMap, bool) {
	for _, o := range e.cfg.Observers {
		if m, ok := o.(*feedback.CoverageMap); ok && m.Size() > 0 {
			return m, true
		}
	}
	return nil, false
}

// coveredIndices returns the entries of a coverage map that were touched.
//
// Indices rather than counts: distillation asks which features an input
// reached, and how many times it reached them is a different question that
// would split one feature into several and defeat the cover.
func coveredIndices(buf []byte) []uint32 {
	var out []uint32
	for i, v := range buf {
		if v != 0 {
			out = append(out, uint32(i))
		}
	}
	return out
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

		// Which entry to fuzz. A stateful campaign asks the state model first:
		// it picks a state worth exploring past and then an entry that is known
		// to reach it, which is the choice coverage cannot make (ADR-0006).
		// When it has nothing to say — no traces yet, or no entry reaching the
		// state it drew — the coverage scheduler decides, as it does throughout
		// a stateless campaign.
		var aim state.Aim
		i, ok := 0, false
		if e.cfg.State != nil {
			aim, ok = e.cfg.State.Seed(e.cfg.Corpus, e.seedRand)
			i = aim.Seed
		}
		if !ok {
			var err error
			if i, err = e.cfg.Schedule.Next(e.cfg.Corpus, e.seedRand); err != nil {
				return e.finish(start, "scheduler: "+err.Error()), err
			}
		}
		parent := e.cfg.Corpus.At(i)
		energy := e.cfg.Schedule.Energy(e.cfg.Corpus, i)

		// Every stage in turn, on the same seed. The seed's energy is the
		// mutation budget; the stages that derive inputs from what the target
		// said cost what they cost, which is bounded by the target's own
		// behaviour rather than by the schedule.
		in := stageInput{parent: parent, aim: aim, energy: energy, budget: b, deadline: deadline}
		var res stageResult
		for _, st := range e.stages {
			one, err := st.run(ctx, e, in)
			if err != nil {
				return e.finish(start, "error"), err
			}
			res.merge(one)
			if res.stop {
				break
			}
		}
		e.cfg.Schedule.Update(e.cfg.Corpus, i, res.best, res.admitted)
		if res.stop {
			reason = "first finding"
			break loop
		}
	}
	return e.finish(start, reason), nil
}

// candidate is one input a stage has produced and wants judged.
type candidate struct {
	tree    *ir.Node
	encoded []byte
	ops     []mutate.Op
	aimed   state.Label
}

// verdict is what judging a candidate produced.
type verdict struct {
	interesting bool
	finding     bool
	admitted    bool
	score       feedback.Score
}

// evaluate executes one candidate and applies the campaign's judgement to it.
//
// Every stage funnels through here, and that is the point: executing an input,
// counting it, asking the feedback whether it is worth keeping and the objective
// whether it is a bug, and admitting it, are the same six steps whichever stage
// produced the bytes. A second copy of them in the comparison stage would be a
// second place for the crash counter to be missed or the feedback state to be
// left uncommitted, and both are faults that show up as a campaign quietly
// finding less rather than as anything failing.
func (e *Engine) evaluate(ctx context.Context, parent *corpus.Testcase, c candidate) (verdict, error) {
	var v verdict

	execStart := time.Now()
	ek, rerr := e.cfg.Executor.Run(ctx, executor.Input{Bytes: c.encoded, Node: c.tree}, e.cfg.Observers)
	elapsed := time.Since(execStart)
	e.stats.ExecTime += elapsed
	e.stats.Execs++
	e.sinceNew++

	if rerr != nil {
		e.stats.HarnessError++
		return v, fmt.Errorf("engine: %w", rerr)
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
		return v, fmt.Errorf("engine: feedback: %w", jerr)
	}
	isFinding, finding, oerr := e.cfg.Objective.IsFinding(e.cfg.Observers, ek)
	if oerr != nil {
		return v, fmt.Errorf("engine: objective: %w", oerr)
	}

	e.trace(c.encoded, ek, interesting, isFinding)

	if isFinding {
		e.record(finding, c.encoded)
	}
	if interesting {
		e.cfg.Feedback.Append()
		if id, ok := e.admit(parent, c.tree, c.encoded, score, elapsed, c.ops, c.aimed); ok {
			v.admitted = true
			e.sinceNew = 0
			if e.cfg.State != nil {
				e.cfg.State.Record(id)
			}
		}
	} else {
		e.cfg.Feedback.Discard()
	}

	v.interesting, v.finding, v.score = interesting, isFinding, score
	return v, nil
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

	// And the states it reached, which coverage does not imply. A session that
	// authenticated and one that did not can cover identical edges — the
	// handshake's code is in the accumulated map either way — so trimming
	// against coverage alone is free to delete the handshake. Measured: a
	// corpus of four-message conversations collapsed to three-byte fragments
	// like "T \n", and the campaign lost every path past the funnel it had
	// spent minutes finding.
	wantStates := e.stateSignature()

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

			// Through the codec, so a candidate is delivered as the same
			// kind of thing the original was. Without it a session's trim
			// candidates arrive as one long message rather than a
			// conversation, the target replies once instead of four times,
			// and the comparison that decides whether to keep the reduction
			// is against an execution that never happened.
			in := executor.Input{Bytes: candidate}
			if node, derr := e.cfg.Codec.Decode(nil, candidate); derr == nil {
				in.Node = node
			}

			ek, err := e.cfg.Executor.Run(context.Background(), in, e.cfg.Observers)
			spent++
			e.stats.Execs++
			e.stats.TrimExecs++
			if err != nil || ek == feedback.ExitError {
				break
			}
			if e.coverage.Signature() != want || e.stateSignature() != wantStates {
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
	// Without frames, what the target said about itself is the best evidence
	// there is — better than a signal number, and on a black-box target the
	// only evidence at all. A summary like "target terminated abnormally" is
	// the same for every crash, so bucketing on it collapses a target's whole
	// bug set into one bucket and the engine, which keeps only the first input
	// per bucket, discards every bug after the first as a duplicate. That is
	// how a campaign finds four planted bugs and reports one.
	//
	// It errs toward splitting. Over-splitting costs a longer findings list and
	// is repaired by triage, which re-buckets from a minimised reproducer and
	// an execution it watched itself; over-merging loses bugs outright and
	// nothing downstream can recover them.
	if m := markerOf(f.Detail); m != "" {
		return key + "|" + m
	}
	if f.Summary != "" {
		return key + "|" + f.Summary
	}
	return key
}

// markerOf reduces a target's own output to something bucketable.
//
// The first non-empty line, with the parts that vary between runs of one bug
// replaced and the length capped: an assertion message names the bug, and the
// address or counter in it names this particular occurrence of it. Keeping the
// varying parts would give every crash its own bucket, which is the opposite
// failure and just as useless.
//
// What varies is addresses and long numbers, not numbers as such. A short
// number is usually part of what the message *says* — an assertion's line
// number, an error code, the index of a planted bug — and collapsing those
// merges bugs the target went to the trouble of telling apart. Measured on
// stateful_proto, whose four bugs each print their own number: collapsing every
// digit run reported all four as one bucket.
//
// It applies the same *rules* as triage's classifier — the address and digit
// normalisation, and control characters dropped — without being the same
// function. Two differences are deliberate: this one takes the first non-empty
// line where triage searches for a known prefix, and it caps at 64 bytes where
// triage allows 160. This marker is provisional by design, computed on the hot
// path from whatever the target happened to print; triage's is computed from a
// minimised reproducer and an execution it watched itself, and replaces this
// one. Where they disagree, triage is right, which is what re-bucketing is for.
//
// The control characters are not a matter of taste. This marker reaches the
// live bucket key, the event stream, and the line an operator watches scroll
// past during `xfuzz run` — and it comes verbatim from a program being driven
// into undefined behaviour, which SECURITY.md treats as hostile output. A
// target emitting an escape sequence would otherwise be choosing what that
// terminal does.
func markerOf(detail string) string {
	line := detail
	if i := strings.IndexAny(line, "\r\n"); i >= 0 {
		line = line[:i]
	}
	line = strings.TrimSpace(line)
	if line == "" {
		return ""
	}

	var b strings.Builder
	for i := 0; i < len(line) && b.Len() < maxMarkerBytes; {
		// Dropped rather than replaced with a space: this marker is capped at
		// 64 bytes and padding it with spaces spends that budget on nothing.
		// Bytes at or above 0x80 pass through — they are UTF-8 continuation
		// bytes, and cutting one produces mojibake.
		if line[i] < 0x20 || line[i] == 0x7f {
			i++
			continue
		}
		if n := hexAddrAt(line, i); n > 0 {
			b.WriteString("0xADDR")
			i += n
			continue
		}
		if n := digitsAt(line, i); n >= volatileDigits {
			b.WriteByte('#')
			i += n
			continue
		}
		b.WriteByte(line[i])
		i++
	}
	return strings.TrimSpace(b.String())
}

// volatileDigits is how long a digit run has to be before it is treated as
// varying rather than as part of the message. Five, because pids, offsets and
// counters reach it and line numbers, error codes and bug indices rarely do.
const volatileDigits = 5

// hexAddrAt reports the length of the 0x-prefixed address at i, or 0.
func hexAddrAt(s string, i int) int {
	if i+2 >= len(s) || s[i] != '0' || (s[i+1] != 'x' && s[i+1] != 'X') {
		return 0
	}
	j := i + 2
	for j < len(s) && isHexDigit(s[j]) {
		j++
	}
	if j == i+2 {
		return 0
	}
	return j - i
}

// digitsAt reports the length of the decimal run at i, or 0.
func digitsAt(s string, i int) int {
	j := i
	for j < len(s) && s[j] >= '0' && s[j] <= '9' {
		j++
	}
	return j - i
}

func isHexDigit(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

// maxMarkerBytes bounds a marker. A target that prints a paragraph on failure
// would otherwise put the paragraph in every report that names the bucket.
const maxMarkerBytes = 64

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

// stateSignature identifies the protocol states the last execution reached.
//
// The set rather than the sequence: trimming may legitimately remove a
// repetition, and requiring the exact order would refuse most useful
// reductions. What it must not do is lose a state, because that is the path the
// entry exists to preserve.
func (e *Engine) stateSignature() string {
	if e.cfg.State == nil {
		return ""
	}
	t := e.cfg.State.Trace()
	if t == nil {
		return ""
	}
	seen := make(map[state.Label]struct{}, len(t.States))
	labels := make([]string, 0, len(t.States))
	for _, l := range t.States {
		if _, dup := seen[l]; dup {
			continue
		}
		seen[l] = struct{}{}
		labels = append(labels, string(l))
	}
	sort.Strings(labels)
	return strings.Join(labels, ",")
}
