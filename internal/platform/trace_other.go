//go:build !linux

package platform

import (
	"os/exec"
	"runtime"
)

// Block tracing by breakpoint is Linux-only, as ADR-0002 says of the ptrace-bb
// backend.
//
// macOS has ptrace, but not the parts this needs: PT_ATTACH cannot read or write
// another process's memory, which is exactly the operation planting a breakpoint
// requires, and the Mach interfaces that can are gated behind a code-signing
// entitlement that a fuzzer downloaded from anywhere cannot have. Windows has a
// debugging API with the necessary primitives, and it is a different program
// with different structure rather than a port of this one.
//
// Reported as unavailable rather than approximated: a campaign that asked for
// block coverage and silently received none would look like a target with no
// branches.

// TraceSupported reports whether this host can trace a target by breakpoint.
func TraceSupported() bool { return false }

// EnableTrace is a no-op where tracing is unavailable.
func EnableTrace(*exec.Cmd) {}

// TraceRun reports that this platform cannot trace by breakpoint.
func TraceRun(int, TraceOptions) (TraceOutcome, error) {
	return TraceOutcome{}, ErrTraceUnsupported
}

// LockTracingThread keeps the same shape as the Linux build so callers need no
// build constraint of their own.
func LockTracingThread() func() {
	runtime.LockOSThread()
	return runtime.UnlockOSThread
}
