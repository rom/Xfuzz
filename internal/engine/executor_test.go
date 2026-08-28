package engine

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/rom/Xfuzz/internal/platform"
	"github.com/rom/Xfuzz/internal/safety"
	"github.com/rom/Xfuzz/pkg/executor"
	"github.com/rom/Xfuzz/pkg/feedback"
)

// These exercise the executor tiers against real processes. They live under
// internal/ because pkg/ cannot import the safety layer, and the safety layer
// is the only thing permitted to start a process (ADR-0012). That is the
// layering working as intended rather than an inconvenience: a test that could
// spawn a process from pkg/executor would mean production code could too.

func newShm(t testing.TB, size int) executor.SharedMemory {
	t.Helper()
	p := platform.NewSharedMemoryProvider()
	if !p.Available() {
		t.Skip("shared memory is not available on this platform")
	}
	shm, err := p.Create(size)
	if err != nil {
		t.Fatalf("creating shared memory: %v", err)
	}
	t.Cleanup(func() { shm.Close() })
	return shm
}

func TestSubprocessRunsATarget(t *testing.T) {
	target := buildTarget(t, "simple_parser")
	sp := safety.NewSpawner()

	out := feedback.NewOutputObserver("out")
	e := executor.NewSubprocess("sub", sp, executor.ProcSpec{
		Path: target, Args: []string{target}, Timeout: 5 * time.Second,
	})
	e.Output = out
	defer e.Close()

	// A benign input exits normally.
	ek, err := e.Run(context.Background(), executor.Input{Bytes: []byte("Z\x00")}, []feedback.Observer{out})
	if err != nil {
		t.Fatal(err)
	}
	if ek != feedback.ExitOK {
		t.Errorf("benign input produced %s, want ok", ek)
	}

	// The planted bug is a crash.
	ek, err = e.Run(context.Background(), executor.Input{Bytes: []byte("A\xff")}, []feedback.Observer{out})
	if err != nil {
		t.Fatal(err)
	}
	if ek != feedback.ExitCrash {
		t.Errorf("the planted bug produced %s, want crash", ek)
	}
	if !strings.Contains(out.Combined(), "XFUZZ-BUG-1") {
		t.Errorf("output did not identify the bug: %q", out.Combined())
	}
	if out.Signal() == 0 {
		t.Error("a crash must report the terminating signal")
	}
}

func TestSubprocessCollectsCoverage(t *testing.T) {
	target := buildTarget(t, "simple_parser")
	shm := newShm(t, feedback.DefaultMapSize)

	cov := feedback.NewCoverageMap("cov", feedback.DefaultMapSize)
	cov.SetBuffer(shm.Bytes())
	cov.SetBackend("sancov")

	e := executor.NewSubprocess("sub", safety.NewSpawner(), executor.ProcSpec{
		Path: target, Args: []string{target}, Timeout: 5 * time.Second,
	})
	e.Coverage, e.Shm, e.Backend = cov, shm, "sancov"
	defer e.Close()

	obs := []feedback.Observer{cov}
	if _, err := e.Run(context.Background(), executor.Input{Bytes: []byte("Z\x00")}, obs); err != nil {
		t.Fatal(err)
	}
	shallow := countCovered(cov)
	if shallow == 0 {
		t.Fatal("no coverage was recorded; the target is not instrumented, or the " +
			"shared map is not reaching it")
	}

	// A deeper input must reach more of the program.
	if _, err := e.Run(context.Background(), executor.Input{Bytes: []byte("C\x00\x10\x20\x30\x00")}, obs); err != nil {
		t.Fatal(err)
	}
	deep := countCovered(cov)
	if deep <= shallow {
		t.Errorf("an input reaching further covered %d entries against %d for a shallow one; "+
			"coverage is not discriminating between paths", deep, shallow)
	}
}

func TestForkServerRunsAndDetectsCrashes(t *testing.T) {
	target := buildTarget(t, "simple_parser")
	shm := newShm(t, feedback.DefaultMapSize)

	cov := feedback.NewCoverageMap("cov", feedback.DefaultMapSize)
	cov.SetBuffer(shm.Bytes())

	fs := executor.NewForkServer("fs", safety.NewSpawner(), executor.ProcSpec{
		Path: target, Args: []string{target},
	})
	fs.Coverage, fs.Shm, fs.Timeout = cov, shm, 2*time.Second
	defer fs.Close()

	if err := fs.Start(context.Background()); err != nil {
		t.Fatalf("starting the fork server: %v", err)
	}
	if c := fs.Capabilities(); c.Tier != executor.TierForkServer || c.Granularity != executor.GranularityEdge {
		t.Errorf("capabilities = %s, want the fork server tier with edge coverage", c)
	}

	obs := []feedback.Observer{cov}
	cases := []struct {
		name  string
		input []byte
		want  feedback.ExitKind
	}{
		{"benign", []byte("Z\x00"), feedback.ExitOK},
		{"bug 1", []byte("A\xff"), feedback.ExitCrash},
		{"benign again", []byte("Z\x00"), feedback.ExitOK},
		{"bug 2", []byte("B\x00\x00\xff"), feedback.ExitCrash},
		{"benign once more", []byte("Z\x00"), feedback.ExitOK},
	}
	for _, tc := range cases {
		ek, err := fs.Run(context.Background(), executor.Input{Bytes: tc.input}, obs)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if ek != tc.want {
			t.Errorf("%s: got %s, want %s", tc.name, ek, tc.want)
		}
	}

	// Recovering after a crash is the property that matters: the server has to
	// survive its children dying, or a campaign stops at the first bug.
	if countCovered(cov) == 0 {
		t.Error("no coverage after a run through the fork server")
	}
	execs, _, restarts := fs.Stats()
	if execs != uint64(len(cases)) {
		t.Errorf("ran %d executions, expected %d", execs, len(cases))
	}
	if restarts != 1 {
		t.Errorf("the fork server restarted %d times; it should have survived the crashes", restarts-1)
	}
}

func TestForkServerRejectsAnUninstrumentedTarget(t *testing.T) {
	if !haveClang() {
		t.Skip("clang is not installed")
	}
	// /bin/true is a real program with no Xfuzz runtime. The handshake must fail
	// with an error naming the cause, because the alternative is a campaign that
	// runs for a week against a target it was never actually driving.
	fs := executor.NewForkServer("fs", safety.NewSpawner(), executor.ProcSpec{
		Path: "/bin/true", Args: []string{"/bin/true"},
	})
	defer fs.Close()

	err := fs.Start(context.Background())
	if err == nil {
		t.Fatal("expected the handshake to fail against an uninstrumented target")
	}
	if !strings.Contains(err.Error(), "xfuzz-cc") {
		t.Errorf("the error should say how to fix it, got: %v", err)
	}
}

func TestSpawnerEnforcesTimeouts(t *testing.T) {
	sp := safety.NewSpawner()
	res, err := sp.Run(context.Background(), executor.ProcSpec{
		Path: "/bin/sleep", Args: []string{"/bin/sleep", "30"},
		Timeout: 200 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.TimedOut {
		t.Error("a sleeping target must be reported as timed out")
	}
	if res.ExitKind() != feedback.ExitTimeout {
		t.Errorf("exit kind = %s, want timeout", res.ExitKind())
	}
	if res.Duration > 5*time.Second {
		t.Errorf("the timeout took %v to fire", res.Duration)
	}
	// A timeout kill must not be reported as a crash; every slow input would
	// otherwise become a spurious finding.
	if res.Signal != 0 {
		t.Errorf("a timeout reported signal %d; it must not look like a crash", res.Signal)
	}
}

func TestSpawnerReportsIsolationHonestly(t *testing.T) {
	// The level reported has to be what is enforced, not what is planned: a
	// campaign may require a minimum and refuse to run below it, and that is
	// only protection if the level is computed from the mechanisms the host
	// actually provides.
	sp := safety.NewSpawner()
	got := sp.IsolationLevel()
	if _, err := safety.ParseLevel(got); err != nil {
		t.Fatalf("the spawner reported %q, which is not an isolation level: %v", got, err)
	}

	caps := platform.DetectSandbox()
	if !caps.UserNS && !caps.Seccomp && got == "strong" {
		t.Errorf("the host provides neither user namespaces nor seccomp (%s) "+
			"but the spawner reports %q", caps, got)
	}
	if !strings.Contains(sp.Explain(), got) {
		t.Errorf("Explain() does not mention the level in force:\n%s", sp.Explain())
	}
}

func TestWaitStatusDecoding(t *testing.T) {
	cases := []struct {
		status uint32
		want   feedback.ExitKind
		signal int
	}{
		{0x0000, feedback.ExitOK, 0},     // exited 0
		{0x0100, feedback.ExitOK, 0},     // exited 1
		{0x000b, feedback.ExitCrash, 11}, // SIGSEGV
		{0x0006, feedback.ExitCrash, 6},  // SIGABRT
		{0x007f, feedback.ExitOK, 0},     // stopped, not a fault
	}
	for _, tc := range cases {
		if got := executor.SignalOfWaitStatus(tc.status); got != tc.signal {
			t.Errorf("status %#04x: signal = %d, want %d", tc.status, got, tc.signal)
		}
	}
}
