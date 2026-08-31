package engine

import (
	"context"
	"sync"
	"sync/atomic"

	"github.com/rom/Xfuzz/pkg/feedback"
)

// The concolic boundary.
//
// ADR-0007 puts full symbolic execution behind an asynchronous, non-blocking
// stage and defers the concrete backend to a later decision. This is that
// boundary: the interface a solver implements, the machinery that keeps it off
// the fuzz loop, and the degradation rules that make a solver's failure cost
// the campaign nothing.
//
// The asymmetry is the whole design. A fuzzer executes thousands of inputs a
// second; a solver takes seconds to answer one query. Anything that waits for
// the second inside the first is not a hybrid fuzzer, it is a solver with a
// mutation engine attached, running at the solver's rate. So the stage never
// waits: it hands a query over if there is room, collects whatever answers have
// arrived since last time, and returns. A solver that is slow simply
// contributes less; a solver that has died contributes nothing; neither changes
// what the loop does.
//
// The price is stated rather than hidden: a campaign with a solver is not
// reproducible. Which solutions arrive before which mutation round depends on
// how long the solver took, and that is wall-clock. ASR-0008 requires the same
// campaign file, seed and target to produce an identical sequence of executions,
// and this is the second feature in the system to opt out of that (the first is
// the schedule's PreferFast). Both are worth having and neither is a default.

// Xfuzz ships no symbolic backend. ADR-0007 defers the choice deliberately, and a
// placeholder behind this boundary would be worse than nothing: a placeholder
// answers queries, and a campaign would believe it. Supplying a solver is a
// later decision — most likely an extension speaking the plugin protocol
// (ADR-0010), which is where every other pluggable part of the engine lives.

// Solver turns what an execution did into inputs that would make it do something
// else.
//
// Deliberately not an SMT interface. What a solver is given is an input and the
// comparisons that execution performed; what it returns is candidate inputs.
// Whether it gets there by symbolic execution, by taint tracking, by a
// constraint solver, or by something nobody has written yet is not the engine's
// business — which is precisely what lets the concrete backend stay deferred
// (ADR-0007) without the boundary staying unbuilt.
type Solver interface {
	// Name identifies the solver in configuration and diagnostics.
	Name() string

	// Solve answers a query. It may take arbitrarily long and must honour the
	// context: the campaign ending is the one thing it has to react to promptly.
	//
	// An error is not a campaign failure. It is counted, reported, and the
	// campaign carries on without that answer.
	Solve(ctx context.Context, q Query) ([][]byte, error)

	// Close releases the solver.
	Close() error
}

// Query is what a solver is asked about.
type Query struct {
	// Input is the bytes that were executed.
	Input []byte

	// Cmps are the comparisons that execution performed, when the campaign
	// collects them. They are the path constraints in the form the engine
	// actually has: which values were compared against which, at which sites.
	Cmps []feedback.CmpRecord
}

// Bounds on the boundary. Every one of them exists to stop a slow or broken
// solver from costing the campaign anything but the answers it did not give.
const (
	// concolicQueueDepth is how many queries may be waiting. Small: a solver
	// that is behind should be given the campaign's *recent* state, not a
	// backlog from ten minutes ago, and a deep queue is a way of pretending a
	// slow solver is keeping up.
	concolicQueueDepth = 4

	// concolicResultDepth bounds the answers waiting to be executed.
	concolicResultDepth = 64

	// concolicPerRound bounds how many solutions one visit to the stage will
	// execute, so a solver that produced a hundred answers does not take the
	// seed's whole budget the moment they arrive.
	concolicPerRound = 16
)

// concolicStage runs a solver alongside the fuzz loop and executes whatever it
// produces.
type concolicStage struct {
	solver Solver

	queries chan Query
	results chan []byte

	// stats, all atomic because the worker goroutine writes them and the loop
	// reads them.
	sent     atomic.Uint64
	dropped  atomic.Uint64
	solved   atomic.Uint64
	failed   atomic.Uint64
	executed atomic.Uint64

	start sync.Once
	stop  context.CancelFunc
	done  chan struct{}
}

// newConcolicStage returns a stage over a solver.
func newConcolicStage(s Solver) *concolicStage {
	return &concolicStage{
		solver:  s,
		queries: make(chan Query, concolicQueueDepth),
		results: make(chan []byte, concolicResultDepth),
		done:    make(chan struct{}),
	}
}

func (s *concolicStage) name() string { return "concolic" }

// ensureRunning starts the solver goroutine on first use.
//
// On first use rather than at construction, because a campaign that never
// reaches this stage — one that ends in its first second, or is cancelled before
// it starts — should not have started a goroutine and a solver process to go
// with it.
func (s *concolicStage) ensureRunning(ctx context.Context) {
	s.start.Do(func() {
		// The solver's own context, derived from nothing: it outlives any one
		// call to run, and cancelling it is Close's job. Deriving it from the
		// caller's context would kill the solver the first time a stage
		// invocation's context was cancelled.
		solverCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
		s.stop = cancel
		go s.work(solverCtx)
	})
}

// work is the solver goroutine. It is the only thing that ever waits.
func (s *concolicStage) work(ctx context.Context) {
	defer close(s.done)
	for {
		select {
		case <-ctx.Done():
			return
		case q := <-s.queries:
			out, err := s.solver.Solve(ctx, q)
			if err != nil {
				// Degrade, do not fail. A solver that cannot answer is a
				// campaign running without a solver, which is a campaign.
				s.failed.Add(1)
				continue
			}
			for _, b := range out {
				if len(b) == 0 {
					continue
				}
				s.solved.Add(1)
				select {
				case s.results <- b:
				case <-ctx.Done():
					return
				default:
					// The loop has not kept up with this solver's output. The
					// answers being dropped are the newest, which is the right
					// ones to drop: the older ones are already queued and were
					// derived from a state the campaign has had longer to
					// explore.
					s.dropped.Add(1)
				}
			}
		}
	}
}

// run collects whatever the solver has produced and offers it the current seed.
//
// Neither half ever blocks. That is the entire contract, and it is why the
// channel operations here all have a default case.
func (s *concolicStage) run(ctx context.Context, e *Engine, in stageInput) (stageResult, error) {
	var res stageResult
	if s.solver == nil {
		return res, nil
	}
	s.ensureRunning(ctx)

	// Offer the seed. Dropped if the solver is behind, which is the normal state
	// of affairs and not worth reporting per occurrence.
	q := Query{Input: append([]byte(nil), in.parent.Bytes...)}
	if e.cfg.Cmp != nil {
		q.Cmps = append([]feedback.CmpRecord(nil), e.cfg.Cmp.Records()...)
	}
	select {
	case s.queries <- q:
		s.sent.Add(1)
	default:
		s.dropped.Add(1)
	}

	// Execute what has arrived.
	for i := 0; i < concolicPerRound; i++ {
		if ctx.Err() != nil {
			return res, nil
		}
		if in.budget.MaxExecs > 0 && e.stats.Execs >= in.budget.MaxExecs {
			return res, nil
		}
		if in.expired() {
			return res, nil
		}
		var b []byte
		select {
		case b = <-s.results:
		default:
			return res, nil
		}

		tree, ok := decodeCandidate(e, b)
		if !ok {
			continue
		}
		s.executed.Add(1)
		e.stats.SolverExecs++
		v, err := e.evaluate(ctx, in.parent, candidate{
			tree:    tree,
			encoded: b,
			ops:     substitutionOps("concolic:" + s.solver.Name()),
		})
		if err != nil {
			return res, err
		}
		if v.admitted {
			res.admitted++
			e.stats.SolverAdmitted++
		}
		if v.interesting && v.score.NewSignal > res.best.NewSignal {
			res.best = v.score
		}
		if v.finding && in.budget.StopOnFirstFinding {
			res.stop = true
			return res, nil
		}
	}
	return res, nil
}

// Close stops the solver and waits for it to finish.
//
// Bounded by the solver honouring its context, which the interface requires. A
// solver that ignores cancellation holds the campaign's shutdown open, which is
// visible and diagnosable — unlike being abandoned mid-query, which would leave
// a process running after the fuzzer had exited.
func (s *concolicStage) Close() error {
	if s.stop == nil {
		if s.solver != nil {
			return s.solver.Close()
		}
		return nil
	}
	s.stop()
	<-s.done
	return s.solver.Close()
}

// Stats reports what the solver cost and what it bought.
func (s *concolicStage) Stats() (sent, dropped, solved, failed, executed uint64) {
	return s.sent.Load(), s.dropped.Load(), s.solved.Load(), s.failed.Load(), s.executed.Load()
}
