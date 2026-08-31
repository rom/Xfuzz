package tracer_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/rom/Xfuzz/internal/platform"
	"github.com/rom/Xfuzz/internal/safety"
	"github.com/rom/Xfuzz/internal/testenv"
	"github.com/rom/Xfuzz/internal/tracer"
	"github.com/rom/Xfuzz/pkg/executor"
	"github.com/rom/Xfuzz/pkg/feedback"
)

// The fixture: a comparison ladder deep enough that reaching the bottom by luck
// is impossible, so a campaign that reaches it did so on coverage. It is built
// from C and stripped, because the point of the whole tier is a target whose
// source and symbols the fuzzer does not have.
const ladderSrc = `
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(void) {
	char b[64];
	size_t n = fread(b, 1, sizeof b - 1, stdin);
	b[n] = 0;
	if (n < 4) return 0;
	if (b[0] != 'F') return 1;
	if (b[1] != 'U') return 2;
	if (b[2] != 'Z') return 3;
	if (b[3] != 'Z') return 4;
	abort();
}
`

func buildStripped(t *testing.T, src string) string {
	t.Helper()
	cc, err := exec.LookPath("clang")
	if err != nil {
		if cc, err = exec.LookPath("gcc"); err != nil {
			t.Skip("no C compiler; the binary-only tier needs a native target")
		}
	}
	dir := testenv.ReachableDir(t)
	in := filepath.Join(dir, "t.c")
	if err := os.WriteFile(in, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "target")
	if b, err := exec.Command(cc, "-O0", "-o", out, in).CombinedOutput(); err != nil {
		t.Skipf("compiling the fixture failed (%v): %s", err, b)
	}
	if strip, err := exec.LookPath("strip"); err == nil {
		if b, err := exec.Command(strip, out).CombinedOutput(); err != nil {
			t.Logf("strip failed (%v): %s; continuing with symbols", err, b)
		}
	}
	if err := os.Chmod(out, 0o755); err != nil {
		t.Fatal(err)
	}
	return out
}

func newTracedExecutor(t *testing.T, target string) (*executor.Emulated, *tracer.Ptrace, *feedback.CoverageMap) {
	t.Helper()
	if !platform.TraceSupported() {
		t.Skip("this host does not permit tracing a child by ptrace")
	}
	tr := tracer.NewPtrace(safety.NewSpawner(), target)
	e := executor.NewEmulated("t5", tr, executor.ProcSpec{
		Path: target, Args: []string{target}, Timeout: 5 * time.Second, CaptureOutput: true,
	})
	cov := feedback.NewCoverageMap("coverage", feedback.DefaultMapSize)
	cov.SetBackend(tr.Name())
	e.Coverage = cov
	e.Output = feedback.NewOutputObserver("output")
	if err := e.Start(t.Context()); err != nil {
		t.Skipf("the ptrace-bb backend will not start here: %v", err)
	}
	t.Cleanup(func() { e.Close() })
	return e, tr, cov
}

// TestPtraceSeesDifferentBlocksForDifferentInputs is the claim the tier exists
// to make: with no instrumentation, no symbols and no source, an input that goes
// further into the program produces more coverage than one that does not.
func TestPtraceSeesDifferentBlocksForDifferentInputs(t *testing.T) {
	target := buildStripped(t, ladderSrc)
	e, tr, cov := newTracedExecutor(t, target)
	t.Logf("%d blocks instrumented", tr.Blocks())
	if tr.Blocks() == 0 {
		t.Fatal("no blocks were instrumented, so nothing here can measure anything")
	}

	covered := func(in string) int {
		cov.Reset()
		if _, err := e.Run(t.Context(), executor.Input{Bytes: []byte(in)}, nil); err != nil {
			t.Fatalf("running %q: %v", in, err)
		}
		return cov.Covered()
	}

	shallow := covered("xxxx")
	deep := covered("FUZZ")
	t.Logf("%q covered %d entries, %q covered %d", "xxxx", shallow, "FUZZ", deep)

	if shallow == 0 {
		t.Fatal("an input that runs the program at all covered nothing; " +
			"the breakpoints are not firing")
	}
	if deep <= shallow {
		t.Errorf("the input that reaches the bottom of the ladder covered %d entries "+
			"and the one rejected at the first comparison covered %d; without more "+
			"coverage for going further, this backend gives a campaign nothing to "+
			"climb", deep, shallow)
	}
}

// TestPtraceCoverageIsDeterministic is the property that makes the whole tier
// usable, and the one most easily lost.
//
// Every execution loads the target at a different address, because the kernel
// randomises it. A backend that reported the addresses its breakpoints fired at
// would produce a different coverage map on every run of the same input: every
// input would look new, the corpus would fill with duplicates, and no finding
// would reproduce (ASR-0008). Normalising to link-time addresses is what
// prevents that, and this is the test that would catch its removal.
func TestPtraceCoverageIsDeterministic(t *testing.T) {
	target := buildStripped(t, ladderSrc)
	e, _, cov := newTracedExecutor(t, target)

	sig := func() uint64 {
		cov.Reset()
		if _, err := e.Run(t.Context(), executor.Input{Bytes: []byte("FUZZ")}, nil); err != nil {
			t.Fatal(err)
		}
		return cov.Signature()
	}
	first := sig()
	for i := 0; i < 4; i++ {
		if got := sig(); got != first {
			t.Fatalf("run %d produced coverage signature %#x, run 0 produced %#x; "+
				"the same input must produce the same coverage or the corpus is noise",
				i+1, got, first)
		}
	}
}

// TestPtraceReportsACrashAsACrash separates the two things a T5 backend must not
// conflate: the target misbehaving, and the tracer failing.
func TestPtraceReportsACrashAsACrash(t *testing.T) {
	target := buildStripped(t, ladderSrc)
	e, _, _ := newTracedExecutor(t, target)

	ek, err := e.Run(t.Context(), executor.Input{Bytes: []byte("FUZZ")}, nil)
	if err != nil {
		t.Fatalf("the harness failed on the crashing input: %v", err)
	}
	if ek != feedback.ExitCrash {
		t.Errorf("the input that reaches abort() reported %v, not a crash", ek)
	}

	ek, err = e.Run(t.Context(), executor.Input{Bytes: []byte("xxxx")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if ek != feedback.ExitOK {
		t.Errorf("an input the program rejects cleanly reported %v", ek)
	}
}

// TestPtraceEnforcesItsTimeout checks a hanging target is stopped and reported
// as a hang rather than as a crash or a wedged worker.
func TestPtraceEnforcesItsTimeout(t *testing.T) {
	target := buildStripped(t, `
#include <stdio.h>
int main(void){ char b[8]; size_t n=fread(b,1,sizeof b,stdin); if(n>0&&b[0]=='H') for(;;); return 0; }
`)
	if !platform.TraceSupported() {
		t.Skip("this host does not permit tracing a child by ptrace")
	}
	tr := tracer.NewPtrace(safety.NewSpawner(), target)
	e := executor.NewEmulated("t5", tr, executor.ProcSpec{
		Path: target, Args: []string{target}, Timeout: 700 * time.Millisecond,
	})
	if err := e.Start(t.Context()); err != nil {
		t.Skipf("the ptrace-bb backend will not start here: %v", err)
	}
	defer e.Close()

	start := time.Now()
	ek, err := e.Run(t.Context(), executor.Input{Bytes: []byte("H")}, nil)
	if err != nil {
		t.Fatalf("the harness failed on the hanging input: %v", err)
	}
	if ek != feedback.ExitTimeout {
		t.Errorf("a target that loops forever reported %v, not a timeout", ek)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("the timeout took %v to fire; a tier that cannot stop a hang stops the campaign", d)
	}
}

// TestPtraceHonoursACancelledContext keeps the tier interruptible. A campaign
// that is stopping must not have to wait out one more execution of a target that
// runs for the whole timeout.
func TestPtraceHonoursACancelledContext(t *testing.T) {
	target := buildStripped(t, ladderSrc)
	e, _, _ := newTracedExecutor(t, target)

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := e.Run(ctx, executor.Input{Bytes: []byte("FUZZ")}, nil); err == nil {
		t.Error("running under a cancelled context succeeded")
	}
}
