package platform

import (
	"fmt"
	"time"
)

// Block tracing by breakpoint: the portable half.
//
// The T5 tier watches a program run rather than asking it what it did, and the
// cheapest way to watch a native binary with no dependency beyond the kernel is
// to put a trap instruction at the start of every basic block and see which ones
// fire. That is what ADR-0002 calls the ptrace-bb backend and describes as the
// low-fidelity fallback, and low-fidelity is the honest word: it reports blocks
// rather than edges, and it reports each block once rather than counting.
//
// One-shot is what makes it affordable. A breakpoint costs a pair of context
// switches every time it fires, so a loop with a breakpoint in its body would
// cost a context switch per iteration and the target would run thousands of
// times slower. Removing each breakpoint the first time it fires bounds the
// total cost of an execution at one stop per block reached, however long the
// program runs — which turns an unusable mechanism into one that costs a
// constant per unit of new coverage.
//
// What that gives up is hit counts. A block entered once and a block entered a
// million times are indistinguishable, so the bucketing that coverage-guided
// fuzzing normally uses to tell "went round the loop twice" from "went round it
// two hundred times" is not available at this tier. The map feedback still works
// on the set of blocks reached; it is simply a coarser signal, and Granularity
// says so rather than leaving a campaign to infer it from disappointing results.

// TraceOutcome is what one traced execution produced.
type TraceOutcome struct {
	// Hits are the link-time addresses of the blocks that were entered, in the
	// order their breakpoints fired. Link-time, not runtime: address-space
	// layout randomisation moves a position-independent image on every
	// execution, and coverage recorded against a base that changes is coverage
	// that never repeats.
	Hits []uint64

	// Base is where the image was loaded, for diagnostics. Zero for a
	// non-position-independent executable, whose link-time addresses are already
	// the addresses it runs at.
	Base uint64

	ExitCode int
	Signal   int
	TimedOut bool

	// Planted is how many breakpoints were successfully written. A target whose
	// text is unwritable, or whose layout does not match the image, plants
	// fewer than it was asked to, and a campaign running against no breakpoints
	// at all is one that will report no coverage for any input.
	Planted int
}

// ErrTraceUnsupported reports a host where breakpoint tracing cannot work.
var ErrTraceUnsupported = fmt.Errorf("platform: block tracing by breakpoint needs ptrace, which this platform does not provide")

// TraceOptions configure one traced execution.
type TraceOptions struct {
	// Exe is the path of the program whose blocks are to be traced. It matters
	// because the process being traced is usually not that program yet: it is
	// the sandbox helper, which becomes the target by exec, and breakpoints must
	// be planted against the final image rather than the first one.
	Exe string

	// Blocks are link-time block start addresses, from static analysis of Exe.
	Blocks []uint64

	// PIE says the image is position-independent, so the addresses in Blocks are
	// offsets from a load base the kernel chooses per execution rather than
	// absolute addresses.
	PIE bool

	// Timeout bounds the execution. Zero means no bound, which for a fuzzer is
	// never the right answer and is therefore never what a caller passes.
	Timeout time.Duration
}
