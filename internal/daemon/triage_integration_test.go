//go:build integration

// Triage against a real instrumented target, behind the integration tag
// because it compiles one.

package daemon

import (
	"context"
	"strings"
	"testing"

	"github.com/rom/Xfuzz/internal/testenv"
)

// A target that aborts is reported as having aborted, whichever tier ran it.
//
// The trap this guards is a kernel behaviour rather than a bug in the code that
// looks wrong: the first process in a PID namespace is PID 1, and the kernel
// discards signals sent to PID 1 from inside its own namespace unless a handler
// is installed. abort(3) raises SIGABRT at itself, so under a naive sandbox the
// abort does nothing and glibc falls back to a null dereference — turning every
// assertion failure into a segmentation fault, filed under the wrong bug, with
// nothing anywhere reporting an error.
//
// It is checked here rather than in the sandbox's own tests because this is
// where it bites: triage runs the one-shot tier, so a finding the fork server
// recorded as SIGABRT would be re-run and reclassified as SIGSEGV, and
// minimisation would then preserve the wrong failure class.
func TestAbortIsNotReportedAsASegmentationFault(t *testing.T) {
	target := testenv.BuildTarget(t, "simple_parser")
	tr := triageForTarget(t, target)

	// The input a campaign against this target finds first: it reaches the
	// planted bug that ends in abort().
	out, err := tr.Run(context.Background(), []byte{'A', 0xed})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	t.Logf("exit=%v signal=%d output=%q", out.Exit, out.Signal, out.Output)

	if !strings.Contains(out.Output, "XFUZZ-BUG-1") {
		t.Fatalf("the input did not reach the planted bug; output was %q", out.Output)
	}
	const sigabrt, sigsegv = 6, 11
	if out.Signal == sigsegv {
		t.Fatalf("an abort() was reported as a segmentation fault: the target is PID 1 " +
			"in a PID namespace, so its own SIGABRT is discarded and glibc falls back " +
			"to a null dereference")
	}
	if out.Signal != sigabrt {
		t.Errorf("signal = %d, want %d (SIGABRT)", out.Signal, sigabrt)
	}
}
