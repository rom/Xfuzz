package engine

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rom/Xfuzz/pkg/codec"
	"github.com/rom/Xfuzz/pkg/corpus"
	"github.com/rom/Xfuzz/pkg/executor"
	"github.com/rom/Xfuzz/pkg/feedback"
	"github.com/rom/Xfuzz/pkg/mutate"
)

// The concolic boundary's whole contract is about time: a solver takes seconds
// and the loop runs thousands of times a second, and the loop must not care.
// That is not something a solver can be trusted to respect, so the tests here
// use solvers that misbehave in the specific ways a real one will — slow,
// broken, silent, prolific — and check that the campaign is unaffected by each.

// scriptedSolver behaves however a test needs it to.
type scriptedSolver struct {
	name    string
	delay   time.Duration
	err     error
	answers [][]byte
	calls   atomic.Int64
	closed  atomic.Bool
}

func (s *scriptedSolver) Name() string { return s.name }

func (s *scriptedSolver) Solve(ctx context.Context, _ Query) ([][]byte, error) {
	s.calls.Add(1)
	if s.delay > 0 {
		select {
		case <-time.After(s.delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if s.err != nil {
		return nil, s.err
	}
	out := make([][]byte, 0, len(s.answers))
	for _, a := range s.answers {
		out = append(out, append([]byte(nil), a...))
	}
	return out, nil
}

func (s *scriptedSolver) Close() error { s.closed.Store(true); return nil }

// solverEngine builds a campaign over a trivial in-process target, so that what
// is being measured is the boundary rather than a target.
func solverEngine(t *testing.T, solver Solver) *Engine {
	t.Helper()
	seen := map[byte]bool{}
	exec := executor.NewInProc("t0", func(b []byte) error {
		if len(b) > 0 {
			seen[b[0]] = true
		}
		return nil
	})

	e, err := New(Config{
		CampaignSeed:  1,
		Executor:      exec,
		Feedback:      feedback.Never(),
		Objective:     feedback.NewHangObjective("hang"),
		Corpus:        corpus.New(),
		Schedule:      corpus.NewFastScheduler(),
		Mutators:      mutate.Default(),
		Codec:         codec.Raw{},
		Solver:        solver,
		MaxInputBytes: 256,
		MaxChildren:   16,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close() })
	if err := e.AddSeed(t.Context(), []byte("seed"), "seed"); err != nil {
		t.Fatal(err)
	}
	return e
}

// TestASlowSolverDoesNotSlowTheLoop is the contract, stated as a measurement.
//
// The solver takes a second to answer one query. If the stage waited for it, a
// campaign of a few thousand executions would take hours; it must instead take
// the same time as one with no solver at all.
func TestASlowSolverDoesNotSlowTheLoop(t *testing.T) {
	slow := &scriptedSolver{name: "slow", delay: time.Second}

	withSolver := solverEngine(t, slow)
	start := time.Now()
	if _, err := withSolver.Run(t.Context(), Budget{MaxExecs: 5000}); err != nil {
		t.Fatal(err)
	}
	elapsed := time.Since(start)

	plain := solverEngine(t, nil)
	start = time.Now()
	if _, err := plain.Run(t.Context(), Budget{MaxExecs: 5000}); err != nil {
		t.Fatal(err)
	}
	baseline := time.Since(start)

	t.Logf("5000 executions took %v with a one-second solver and %v without one; "+
		"the solver was asked %d time(s)", elapsed, baseline, slow.calls.Load())

	// A generous margin: what is being ruled out is the loop *waiting*, which
	// would cost seconds per query and show up as orders of magnitude, not as a
	// percentage.
	if elapsed > baseline+2*time.Second {
		t.Errorf("the campaign took %v with a slow solver and %v without. The stage is "+
			"waiting for the solver, which makes the campaign run at the solver's rate "+
			"rather than the target's", elapsed, baseline)
	}
}

// TestABrokenSolverDegradesTheCampaignRatherThanBreakingIt is the other half of
// ADR-0007's requirement.
func TestABrokenSolverDegradesTheCampaignRatherThanBreakingIt(t *testing.T) {
	broken := &scriptedSolver{name: "broken", err: errors.New("the solver process died")}
	e := solverEngine(t, broken)

	stats, err := e.Run(t.Context(), Budget{MaxExecs: 2000})
	if err != nil {
		t.Fatalf("a solver that fails every query stopped the campaign: %v", err)
	}
	if stats.Execs < 2000 {
		t.Errorf("the campaign completed %d of 2000 executions", stats.Execs)
	}

	// The failures are counted, because a solver that never answers is a cost
	// an operator should be able to see and stop paying.
	waitFor(t, func() bool {
		_, _, _, failed, _, _ := e.SolverStats()
		return failed > 0
	}, "the solver's failures to be counted")
}

// TestSolutionsReachTheCampaign checks the boundary is not merely safe but
// useful: what a solver produces is executed and can be admitted.
func TestSolutionsReachTheCampaign(t *testing.T) {
	answers := [][]byte{[]byte("solution-one"), []byte("solution-two")}
	solver := &scriptedSolver{name: "scripted", answers: answers}
	e := solverEngine(t, solver)

	if _, err := e.Run(t.Context(), Budget{MaxExecs: 3000}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool {
		_, _, solved, _, executed, _ := e.SolverStats()
		return solved > 0 && executed > 0
	}, "the solver's answers to be executed")

	sent, dropped, solved, failed, executed, ok := e.SolverStats()
	if !ok {
		t.Fatal("a campaign with a solver reports no solver statistics")
	}
	t.Logf("sent=%d dropped=%d solved=%d failed=%d executed=%d", sent, dropped, solved, failed, executed)
	if e.Stats().SolverExecs == 0 {
		t.Error("no execution was attributed to the solver, so its answers were counted " +
			"as produced and never actually run")
	}
}

// TestTheStageNeverBlocksOnAProlificSolver checks the other direction of the
// asymmetry: a solver that answers faster than the loop consumes must not be
// able to wedge it.
func TestTheStageNeverBlocksOnAProlificSolver(t *testing.T) {
	var answers [][]byte
	for i := 0; i < 1000; i++ {
		answers = append(answers, []byte{byte(i), byte(i >> 8), 'x'})
	}
	solver := &scriptedSolver{name: "prolific", answers: answers}
	e := solverEngine(t, solver)

	done := make(chan struct{})
	go func() {
		defer close(done)
		if _, err := e.Run(t.Context(), Budget{MaxExecs: 3000}); err != nil {
			t.Error(err)
		}
	}()
	select {
	case <-done:
	case <-time.After(60 * time.Second):
		t.Fatal("the campaign did not finish; a solver producing more answers than the " +
			"loop consumes has blocked it")
	}
	_, dropped, solved, _, _, _ := e.SolverStats()
	t.Logf("the solver produced %d answers and %d were dropped", solved, dropped)
}

// TestClosingTheEngineStopsTheSolver keeps a campaign from leaving a solver
// process behind. A solver is an external process in every real configuration,
// and one that outlives its campaign is one an operator finds in ps a week
// later.
func TestClosingTheEngineStopsTheSolver(t *testing.T) {
	solver := &scriptedSolver{name: "slow", delay: 10 * time.Second}
	e := solverEngine(t, solver)

	if _, err := e.Run(t.Context(), Budget{MaxExecs: 200}); err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() { done <- e.Close() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("closing the engine: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Close did not return; the solver is not honouring cancellation and " +
			"nothing bounds the wait")
	}
	if !solver.closed.Load() {
		t.Error("the engine closed without closing its solver")
	}
}

// TestACampaignWithoutASolverIsUnchanged checks the boundary costs nothing when
// it is not used, which is the condition for having it at all.
func TestACampaignWithoutASolverIsUnchanged(t *testing.T) {
	e := solverEngine(t, nil)
	stats, err := e.Run(t.Context(), Budget{MaxExecs: 500})
	if err != nil {
		t.Fatal(err)
	}
	if stats.SolverExecs != 0 {
		t.Errorf("%d executions attributed to a solver that does not exist", stats.SolverExecs)
	}
	if _, _, _, _, _, ok := e.SolverStats(); ok {
		t.Error("a campaign with no solver reports solver statistics")
	}
	if err := e.Close(); err != nil {
		t.Errorf("closing a solverless engine: %v", err)
	}
}

// waitFor polls a condition, because the solver runs on its own schedule and the
// point of the boundary is that the loop does not synchronise with it.
func waitFor(t *testing.T, cond func() bool, what string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}
