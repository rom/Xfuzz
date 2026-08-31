package executor_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/rom/Xfuzz/pkg/executor"
	"github.com/rom/Xfuzz/pkg/feedback"
)

// fakeTracer stands in for a T5 backend, so the tier's own logic — arming
// observers, folding a trace, classifying an exit — is testable on a platform
// with no ptrace and with no external tool installed. What it cannot test is
// whether any real backend produces the right trace; internal/tracer does that.
type fakeTracer struct {
	name    string
	blocks  []uint64
	ordered bool
	res     executor.ProcResult
	err     error
	started bool
	closed  bool
	runs    int
	last    executor.ProcSpec
}

func (f *fakeTracer) Name() string                      { return f.name }
func (f *fakeTracer) Granularity() executor.Granularity { return executor.GranularityBlock }
func (f *fakeTracer) Start(context.Context) error       { f.started = true; return nil }
func (f *fakeTracer) Blocks() int                       { return len(f.blocks) }
func (f *fakeTracer) Close() error                      { f.closed = true; return nil }

func (f *fakeTracer) Trace(_ context.Context, spec executor.ProcSpec) (executor.Trace, error) {
	f.runs++
	f.last = spec
	if f.err != nil {
		return executor.Trace{}, f.err
	}
	return executor.Trace{Blocks: f.blocks, Ordered: f.ordered, Result: f.res}, nil
}

func TestEmulatedRefusesToRunBeforeItIsStarted(t *testing.T) {
	tr := &fakeTracer{name: "fake"}
	e := executor.NewEmulated("t5", tr, executor.ProcSpec{Path: "/nonexistent"})
	if _, err := e.Run(t.Context(), executor.Input{Bytes: []byte("x")}, nil); err == nil {
		t.Fatal("running an unstarted T5 executor succeeded")
	}
	if tr.runs != 0 {
		t.Error("the backend was asked to trace before it was started")
	}
}

func TestEmulatedFoldsATraceIntoTheCoverageMap(t *testing.T) {
	tr := &fakeTracer{name: "fake", blocks: []uint64{0x1000, 0x1040, 0x10c0}}
	e := executor.NewEmulated("t5", tr, executor.ProcSpec{Path: "/nonexistent"})
	cov := feedback.NewCoverageMap("coverage", 1<<16)
	e.Coverage = cov
	if err := e.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Run(t.Context(), executor.Input{Bytes: []byte("x")}, []feedback.Observer{cov}); err != nil {
		t.Fatal(err)
	}
	if got := cov.Covered(); got != 3 {
		t.Errorf("three blocks produced %d covered entries; distinct blocks must not "+
			"collide in a map this size or the signal disappears", got)
	}
}

// TestEmulatedDoesNotInventEdgesFromAnUnorderedTrace is the reason Trace carries
// the Ordered flag.
//
// A backend that reports a *set* of blocks — which is what one-shot breakpoints
// and a DRcov file both give — has no idea what ran after what. Folding that as
// though it were a path would key the map on transitions that never happened,
// and since the order such a backend reports is arbitrary, the same execution
// could produce different coverage twice. Block coverage is coarser and true.
func TestEmulatedDoesNotInventEdgesFromAnUnorderedTrace(t *testing.T) {
	blocks := []uint64{0x1000, 0x1040, 0x10c0, 0x1100}

	fold := func(order []uint64, ordered bool) uint64 {
		m := feedback.NewCoverageMap("m", 1<<16)
		executor.FoldTrace(m.Buffer(), order, ordered)
		return m.Signature()
	}

	forward := append([]uint64(nil), blocks...)
	reversed := []uint64{blocks[3], blocks[2], blocks[1], blocks[0]}

	if a, b := fold(forward, false), fold(reversed, false); a != b {
		t.Errorf("the same set of blocks in two orders folded to %#x and %#x as an "+
			"unordered trace; an unordered fold must not depend on the order", a, b)
	}
	if a, b := fold(forward, true), fold(reversed, true); a == b {
		t.Errorf("two different paths through the same blocks folded identically (%#x); "+
			"an ordered fold records transitions, and transitions are what differ", a)
	}
}

func TestEmulatedReportsTheBackendsExitStatus(t *testing.T) {
	cases := []struct {
		name string
		res  executor.ProcResult
		want feedback.ExitKind
	}{
		{"clean exit", executor.ProcResult{ExitCode: 0}, feedback.ExitOK},
		{"non-zero exit is not a fault", executor.ProcResult{ExitCode: 3}, feedback.ExitOK},
		{"a signal is a crash", executor.ProcResult{Signal: 11}, feedback.ExitCrash},
		{"a timeout is a hang", executor.ProcResult{TimedOut: true}, feedback.ExitTimeout},
		{"out of memory", executor.ProcResult{OOM: true}, feedback.ExitOOM},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tr := &fakeTracer{name: "fake", res: c.res}
			e := executor.NewEmulated("t5", tr, executor.ProcSpec{Path: "/nonexistent"})
			if err := e.Start(t.Context()); err != nil {
				t.Fatal(err)
			}
			ek, err := e.Run(t.Context(), executor.Input{Bytes: []byte("x")}, nil)
			if err != nil {
				t.Fatal(err)
			}
			if ek != c.want {
				t.Errorf("got %v, want %v", ek, c.want)
			}
		})
	}
}

// TestEmulatedSeparatesABackendFailureFromATargetFault holds the line ADR-0007
// draws: a harness that could not run is not a bug in the target, and recording
// it as one is how a fuzzer loses its credibility.
func TestEmulatedSeparatesABackendFailureFromATargetFault(t *testing.T) {
	tr := &fakeTracer{name: "fake", err: errors.New("the emulator is not installed")}
	e := executor.NewEmulated("t5", tr, executor.ProcSpec{Path: "/nonexistent"})
	if err := e.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	ek, err := e.Run(t.Context(), executor.Input{Bytes: []byte("x")}, nil)
	if err == nil {
		t.Fatal("a backend failure was not reported as an error")
	}
	if ek != feedback.ExitError {
		t.Errorf("a backend failure reported %v; only ExitError keeps it out of the findings", ek)
	}
}

func TestEmulatedDeliversTheInputTheTargetExpects(t *testing.T) {
	t.Run("stdin", func(t *testing.T) {
		tr := &fakeTracer{name: "fake"}
		e := executor.NewEmulated("t5", tr, executor.ProcSpec{Path: "/t", Args: []string{"/t"}})
		e.Delivery = executor.DeliverStdin
		if err := e.Start(t.Context()); err != nil {
			t.Fatal(err)
		}
		if _, err := e.Run(t.Context(), executor.Input{Bytes: []byte("hello")}, nil); err != nil {
			t.Fatal(err)
		}
		if string(tr.last.Stdin) != "hello" {
			t.Errorf("the backend was given stdin %q", tr.last.Stdin)
		}
	})

	t.Run("file", func(t *testing.T) {
		tr := &fakeTracer{name: "fake"}
		e := executor.NewEmulated("t5", tr, executor.ProcSpec{
			Path: "/t", Args: []string{"/t", "--in", executor.FilePlaceholder},
		})
		e.Delivery = executor.DeliverFile
		e.WorkDir = t.TempDir()
		if err := e.Start(t.Context()); err != nil {
			t.Fatal(err)
		}
		defer e.Close()
		if _, err := e.Run(t.Context(), executor.Input{Bytes: []byte("hello")}, nil); err != nil {
			t.Fatal(err)
		}
		if tr.last.Args[2] == executor.FilePlaceholder {
			t.Error("the placeholder was passed through unreplaced")
		}
	})

	t.Run("file with no placeholder is refused", func(t *testing.T) {
		tr := &fakeTracer{name: "fake"}
		e := executor.NewEmulated("t5", tr, executor.ProcSpec{Path: "/t", Args: []string{"/t"}})
		e.Delivery = executor.DeliverFile
		e.WorkDir = t.TempDir()
		if err := e.Start(t.Context()); err != nil {
			t.Fatal(err)
		}
		defer e.Close()
		if _, err := e.Run(t.Context(), executor.Input{Bytes: []byte("hello")}, nil); err == nil {
			t.Error("delivering by file with nowhere to put the path succeeded; " +
				"the target would have run against no input at all")
		}
	})
}

func TestEmulatedReportsItsTier(t *testing.T) {
	tr := &fakeTracer{name: "ptrace-bb", blocks: []uint64{1, 2, 3}}
	e := executor.NewEmulated("t5", tr, executor.ProcSpec{Path: "/t", Timeout: time.Second})
	e.Coverage = feedback.NewCoverageMap("m", 1<<16)
	c := e.Capabilities()
	if c.Tier != executor.TierEmulated {
		t.Errorf("tier %v, want %v", c.Tier, executor.TierEmulated)
	}
	if c.Backend != "ptrace-bb" {
		t.Errorf("backend %q", c.Backend)
	}
	if c.Granularity != executor.GranularityBlock {
		t.Errorf("granularity %v; a breakpoint backend resolves blocks, not edges", c.Granularity)
	}
	if !c.TimeoutEnforced {
		t.Error("timeouts reported as advisory; this tier kills its target")
	}
	if e.KnownBlocks() != 3 {
		t.Errorf("KnownBlocks %d", e.KnownBlocks())
	}
}
