package executor

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/rom/Xfuzz/pkg/feedback"
)

// Tests here cover the pure logic: capability reporting, input delivery,
// in-process execution, and wait-status decoding. Anything that starts a real
// process lives under internal/, because pkg/ cannot import the safety layer
// and the safety layer is the only thing permitted to spawn (ADR-0012).

func TestTierAndGranularityNames(t *testing.T) {
	for _, tier := range []Tier{TierInProc, TierPersistent, TierForkServer, TierProcPool,
		TierSubprocess, TierEmulated, TierSession, TierDriver} {
		if tier.String() == "unknown tier" {
			t.Errorf("tier %d has no name", tier)
		}
	}
	if Tier(99).String() != "unknown tier" {
		t.Error("an unrecognised tier should say so")
	}
	for _, g := range []Granularity{GranularityEdge, GranularityBlock, GranularityFunction, GranularityNone} {
		if g.String() == "unknown" {
			t.Errorf("granularity %d has no name", g)
		}
	}
	for _, r := range []ResetPolicy{ResetNone, ResetReconnect, ResetRestart, ResetSnapshot} {
		if r.String() == "unknown" {
			t.Errorf("reset policy %d has no name", r)
		}
	}
}

// TestCapsReportsHonestly matters because a campaign may require a minimum and
// refuse to start below it. That only works if the report is truthful.
func TestCapsReportsHonestly(t *testing.T) {
	c := Caps{Tier: TierInProc, Backend: "harness", Granularity: GranularityEdge, MapSize: 4096}
	s := c.String()
	if !strings.Contains(s, "in-process") || !strings.Contains(s, "harness") ||
		!strings.Contains(s, "edge") || !strings.Contains(s, "4096") {
		t.Errorf("Caps.String() = %q", s)
	}
	// An executor that cannot stop a hung target has to say so.
	if !strings.Contains(s, "timeouts advisory") {
		t.Errorf("a caps report without enforced timeouts must say so, got %q", s)
	}
	c.TimeoutEnforced = true
	if strings.Contains(c.String(), "advisory") {
		t.Error("an executor that does enforce timeouts should not claim otherwise")
	}
}

func TestProcResultExitKind(t *testing.T) {
	for _, tc := range []struct {
		name string
		res  ProcResult
		want feedback.ExitKind
	}{
		{"clean", ProcResult{}, feedback.ExitOK},
		{"nonzero exit is not a fault", ProcResult{ExitCode: 3}, feedback.ExitOK},
		{"signal", ProcResult{Signal: 11}, feedback.ExitCrash},
		{"timeout", ProcResult{TimedOut: true, Signal: 9}, feedback.ExitTimeout},
		{"oom", ProcResult{OOM: true}, feedback.ExitOOM},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.res.ExitKind(); got != tc.want {
				t.Errorf("ExitKind = %s, want %s", got, tc.want)
			}
		})
	}
}

func TestWaitStatusDecoding(t *testing.T) {
	for _, tc := range []struct {
		status uint32
		kind   feedback.ExitKind
		signal int
	}{
		{0x0000, feedback.ExitOK, 0},
		{0x0100, feedback.ExitOK, 0},
		{0x0b00 | 11, feedback.ExitCrash, 11},
		{6, feedback.ExitCrash, 6},
		{14, feedback.ExitCrash, 14},
		{0x7f, feedback.ExitOK, 0}, // stopped, not a fault
	} {
		if got := exitKindOfWaitStatus(tc.status); got != tc.kind {
			t.Errorf("status %#04x: kind = %s, want %s", tc.status, got, tc.kind)
		}
		if got := SignalOfWaitStatus(tc.status); got != tc.signal {
			t.Errorf("status %#04x: signal = %d, want %d", tc.status, got, tc.signal)
		}
	}
}

// --- in-process -------------------------------------------------------------

func TestInProcRunsAndRecoversPanics(t *testing.T) {
	var seen []byte
	e := NewInProc("harness", func(b []byte) error {
		seen = append(seen[:0], b...)
		if len(b) > 0 && b[0] == 'x' {
			panic("planted panic")
		}
		return nil
	})
	defer e.Close()

	ek, err := e.Run(context.Background(), Input{Bytes: []byte("ok")}, nil)
	if err != nil || ek != feedback.ExitOK {
		t.Fatalf("clean run = %s, %v", ek, err)
	}
	if string(seen) != "ok" {
		t.Errorf("the harness saw %q", seen)
	}

	ek, err = e.Run(context.Background(), Input{Bytes: []byte("x")}, nil)
	if err != nil {
		t.Fatalf("a panic must be an outcome, not an error: %v", err)
	}
	if ek != feedback.ExitCrash {
		t.Errorf("a panic produced %s, want crash", ek)
	}
	msg, stack := e.LastPanic()
	if !strings.Contains(msg, "planted panic") || stack == "" {
		t.Errorf("panic not captured: %q / %d bytes of stack", msg, len(stack))
	}
}

func TestInProcHarnessErrorIsNotAFinding(t *testing.T) {
	// A harness returning an error means the input was rejected before reaching
	// anything interesting. Treating that as a fault would fill the findings
	// with every malformed input.
	e := NewInProc("harness", func([]byte) error { return errors.New("rejected") })
	ek, err := e.Run(context.Background(), Input{Bytes: []byte("bad")}, nil)
	if err != nil || ek != feedback.ExitOK {
		t.Errorf("a rejected input produced %s, %v", ek, err)
	}
}

func TestInProcObserversAreArmedAndHarvested(t *testing.T) {
	cov := feedback.NewCoverageMap("cov", 64)
	e := NewInProc("harness", func([]byte) error {
		cov.Buffer()[7]++
		return nil
	})
	e.Coverage = cov

	obs := []feedback.Observer{cov}
	if _, err := e.Run(context.Background(), Input{Bytes: []byte("a")}, obs); err != nil {
		t.Fatal(err)
	}
	if cov.Hit(7) != 1 {
		t.Errorf("the harness's coverage was not retained: %d", cov.Hit(7))
	}
	// Pre must clear between executions, or counts accumulate across inputs and
	// every execution looks like it reached more than it did.
	if _, err := e.Run(context.Background(), Input{Bytes: []byte("b")}, obs); err != nil {
		t.Fatal(err)
	}
	if cov.Hit(7) != 1 {
		t.Errorf("coverage accumulated across executions: %d", cov.Hit(7))
	}
	if c := e.Capabilities(); c.Backend != "harness" || c.MapSize != 64 {
		t.Errorf("capabilities = %+v, want the harness coverage reported", c)
	}
}

func TestInProcTimeoutIsAdvisory(t *testing.T) {
	release := make(chan struct{})
	e := NewInProc("harness", func([]byte) error {
		<-release
		return nil
	})
	e.Timeout = 50 * time.Millisecond
	defer close(release)

	start := time.Now()
	ek, err := e.Run(context.Background(), Input{Bytes: nil}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if ek != feedback.ExitTimeout {
		t.Errorf("a hanging harness produced %s, want timeout", ek)
	}
	if time.Since(start) > 2*time.Second {
		t.Error("the timeout did not fire promptly")
	}
	// The run is abandoned, not stopped: Go cannot kill a goroutine. Counting
	// it is what lets a worker notice it is leaking and be restarted.
	if e.Abandoned() != 1 {
		t.Errorf("abandoned = %d, want 1", e.Abandoned())
	}
	if e.Capabilities().TimeoutEnforced {
		t.Error("in-process execution must not claim to enforce timeouts")
	}
}

func TestInProcRefusesImpossibleResets(t *testing.T) {
	e := NewInProc("harness", func([]byte) error { return nil })
	if err := e.Reset(ResetNone); err != nil {
		t.Errorf("ResetNone should succeed: %v", err)
	}
	// Refusing loudly beats ignoring silently: a stateful target fuzzed as
	// though it were stateless produces findings that do not reproduce.
	for _, p := range []ResetPolicy{ResetRestart, ResetSnapshot} {
		if err := e.Reset(p); err == nil {
			t.Errorf("%s reset should be refused in-process", p)
		}
	}
}

func TestPanicObjective(t *testing.T) {
	e := NewInProc("harness", func([]byte) error { panic("bang") })
	o := NewPanicObjective("panic", e)

	if hit, _, _ := o.IsFinding(nil, feedback.ExitOK); hit {
		t.Error("a clean exit is not a panic")
	}
	e.Run(context.Background(), Input{Bytes: nil}, nil)
	hit, f, err := o.IsFinding(nil, feedback.ExitCrash)
	if err != nil || !hit {
		t.Fatalf("the panic was not reported: %v %v", hit, err)
	}
	if f.Kind != "panic" || !strings.Contains(f.Summary, "bang") {
		t.Errorf("finding = %+v", f)
	}
	// Frames are what let distinct panics bucket apart.
	if len(f.Frames) == 0 {
		t.Error("no stack frames were extracted")
	}
	for _, fr := range f.Frames {
		if strings.HasPrefix(fr, "runtime.") {
			t.Errorf("runtime frames should be stripped, got %q", fr)
		}
	}
}

// --- delivery ---------------------------------------------------------------

// fakeSpawner records what it was asked to run without starting anything.
type fakeSpawner struct {
	last ProcSpec
	res  ProcResult
	err  error
}

func (f *fakeSpawner) Run(_ context.Context, spec ProcSpec) (ProcResult, error) {
	f.last = spec
	return f.res, f.err
}
func (f *fakeSpawner) Start(context.Context, ProcSpec) (Handle, error) {
	return nil, errors.New("not supported")
}
func (f *fakeSpawner) IsolationLevel() string { return "none" }

func TestSubprocessDeliversByStdin(t *testing.T) {
	sp := &fakeSpawner{}
	e := NewSubprocess("sub", sp, ProcSpec{Path: "/bin/true", Args: []string{"/bin/true"}})
	defer e.Close()

	if _, err := e.Run(context.Background(), Input{Bytes: []byte("payload")}, nil); err != nil {
		t.Fatal(err)
	}
	if string(sp.last.Stdin) != "payload" {
		t.Errorf("stdin = %q, want the input", sp.last.Stdin)
	}
	if e.Executions() != 1 {
		t.Errorf("executions = %d", e.Executions())
	}
}

func TestSubprocessDeliversByFile(t *testing.T) {
	sp := &fakeSpawner{}
	e := NewSubprocess("sub", sp, ProcSpec{
		Path: "/bin/cat", Args: []string{"/bin/cat", "--flag", FilePlaceholder},
	})
	e.Delivery = DeliverFile
	e.WorkDir = t.TempDir()
	defer e.Close()

	if _, err := e.Run(context.Background(), Input{Bytes: []byte("file payload")}, nil); err != nil {
		t.Fatal(err)
	}
	replaced := false
	for _, a := range sp.last.Args {
		if strings.Contains(a, "input") {
			replaced = true
		}
		if a == FilePlaceholder {
			t.Error("the placeholder was left unreplaced")
		}
	}
	if !replaced {
		t.Errorf("no argument received the input path: %v", sp.last.Args)
	}
}

// TestSubprocessRefusesFileDeliveryWithNoPlaceholder guards a silent failure:
// appending the path would run the target against no input at all, and look
// exactly like a campaign that simply finds nothing.
func TestSubprocessRefusesFileDeliveryWithNoPlaceholder(t *testing.T) {
	e := NewSubprocess("sub", &fakeSpawner{}, ProcSpec{
		Path: "/bin/cat", Args: []string{"/bin/cat", "--flag"},
	})
	e.Delivery = DeliverFile
	e.WorkDir = t.TempDir()
	defer e.Close()

	_, err := e.Run(context.Background(), Input{Bytes: []byte("x")}, nil)
	if err == nil || !strings.Contains(err.Error(), FilePlaceholder) {
		t.Errorf("expected an error naming the placeholder, got %v", err)
	}
}

func TestSubprocessDeliversByArgument(t *testing.T) {
	sp := &fakeSpawner{}
	e := NewSubprocess("sub", sp, ProcSpec{Path: "/bin/echo", Args: []string{"/bin/echo"}})
	e.Delivery = DeliverArg
	defer e.Close()

	if _, err := e.Run(context.Background(), Input{Bytes: []byte("as-an-arg")}, nil); err != nil {
		t.Fatal(err)
	}
	if sp.last.Args[len(sp.last.Args)-1] != "as-an-arg" {
		t.Errorf("args = %v", sp.last.Args)
	}
}

func TestSubprocessPublishesTheSharedRegion(t *testing.T) {
	sp := &fakeSpawner{}
	e := NewSubprocess("sub", sp, ProcSpec{Path: "/bin/true"})
	e.Shm = fakeShm{id: "/dev/shm/xfuzz-test"}
	defer e.Close()

	if _, err := e.Run(context.Background(), Input{Bytes: nil}, nil); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, kv := range sp.last.Env {
		if kv == ShmEnvVar+"=/dev/shm/xfuzz-test" {
			found = true
		}
	}
	if !found {
		t.Errorf("the shared region was not published to the child: %v", sp.last.Env)
	}
}

type fakeShm struct{ id string }

func (f fakeShm) Bytes() []byte { return nil }
func (f fakeShm) ID() string    { return f.id }
func (f fakeShm) Close() error  { return nil }

func TestSubprocessReportsHarnessFailure(t *testing.T) {
	sp := &fakeSpawner{err: errors.New("could not start")}
	e := NewSubprocess("sub", sp, ProcSpec{Path: "/nonexistent"})
	defer e.Close()

	ek, err := e.Run(context.Background(), Input{Bytes: nil}, nil)
	if err == nil {
		t.Fatal("a spawn failure must be reported as an error")
	}
	// It must not be a fault: infrastructure failures are not findings.
	if ek != feedback.ExitError {
		t.Errorf("exit kind = %s, want error", ek)
	}
}

func TestSubprocessRecordsOutputAndTiming(t *testing.T) {
	sp := &fakeSpawner{res: ProcResult{
		Stdout: []byte("out"), Stderr: []byte("err"),
		ExitCode: 2, Signal: 6, Duration: 7 * time.Millisecond,
	}}
	out := feedback.NewOutputObserver("out")
	timing := feedback.NewTimingObserver("time")
	e := NewSubprocess("sub", sp, ProcSpec{Path: "/bin/true"})
	e.Output = out
	defer e.Close()

	ek, err := e.Run(context.Background(), Input{Bytes: nil},
		[]feedback.Observer{out, timing})
	if err != nil {
		t.Fatal(err)
	}
	if ek != feedback.ExitCrash {
		t.Errorf("exit kind = %s, want crash", ek)
	}
	if out.Combined() != "outerr" || out.Signal() != 6 {
		t.Errorf("output = %q signal %d", out.Combined(), out.Signal())
	}
	if timing.Elapsed() != 7*time.Millisecond {
		t.Errorf("timing = %v, want the spawner's measurement", timing.Elapsed())
	}
}
