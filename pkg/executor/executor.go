package executor

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/rom/Xfuzz/pkg/feedback"
	"github.com/rom/Xfuzz/pkg/ir"
)

// Tier identifies an execution strategy from ADR-0009. Rates span six orders of
// magnitude; the core loop does not know which tier it is running on.
type Tier uint8

// The execution tiers, fastest first.
const (
	TierInProc     Tier = iota // T0: direct call into a Go harness
	TierPersistent             // T1: long-lived harness looping over inputs
	TierForkServer             // T2: fork server plus shared-memory coverage
	TierProcPool               // T3: pre-spawned process pool
	TierSubprocess             // T4: one exec per input
	TierEmulated               // T5: emulation or dynamic instrumentation
	TierSession                // T6: connection-oriented protocol sessions
	TierDriver                 // T7: GUI and TUI drivers
)

var tierNames = [...]string{
	TierInProc: "T0 in-process", TierPersistent: "T1 persistent",
	TierForkServer: "T2 fork server", TierProcPool: "T3 process pool",
	TierSubprocess: "T4 subprocess", TierEmulated: "T5 emulated",
	TierSession: "T6 session", TierDriver: "T7 driver",
}

func (t Tier) String() string {
	if int(t) < len(tierNames) && tierNames[t] != "" {
		return tierNames[t]
	}
	return "unknown tier"
}

// Granularity is how precisely an instrumentation backend locates execution.
type Granularity uint8

// Coverage granularities, most precise first.
const (
	GranularityEdge Granularity = iota
	GranularityBlock
	GranularityFunction
	GranularityNone
)

var granularityNames = [...]string{
	GranularityEdge: "edge", GranularityBlock: "block",
	GranularityFunction: "function", GranularityNone: "none",
}

func (g Granularity) String() string {
	if int(g) < len(granularityNames) {
		return granularityNames[g]
	}
	return "unknown"
}

// Caps describes what an executor can do, so a campaign can require a minimum
// and refuse to start below it rather than discovering the shortfall from a
// week of flat coverage (ADR-0009).
type Caps struct {
	Tier        Tier
	Backend     string // instrumentation backend: sancov, forkserver, gocov, blackbox
	Granularity Granularity
	MapSize     int
	Platform    string

	// Deterministic reports whether repeating an input reproduces its coverage.
	// A target that fails this corrupts the corpus silently, so it is measured
	// rather than assumed (ASR-0008).
	Deterministic bool

	// TimeoutEnforced reports whether the executor can actually stop a hung
	// target. In-process execution cannot, and pretending otherwise turns one
	// bad input into a stuck worker.
	TimeoutEnforced bool
}

func (c Caps) String() string {
	var b strings.Builder
	b.WriteString(c.Tier.String())
	if c.Backend != "" {
		fmt.Fprintf(&b, ", %s coverage (%s", c.Backend, c.Granularity)
		if c.MapSize > 0 {
			fmt.Fprintf(&b, ", %d entries", c.MapSize)
		}
		b.WriteString(")")
	}
	if !c.TimeoutEnforced {
		b.WriteString(", timeouts advisory")
	}
	return b.String()
}

// ResetPolicy is what happens to the target between executions.
//
// It is an explicit contract because the fuzzer's correctness assumptions
// depend on which one holds: a stateful target fuzzed as though it were
// stateless produces findings that do not reproduce (ADR-0006, ADR-0009).
type ResetPolicy uint8

// Reset policies.
const (
	ResetNone      ResetPolicy = iota // state carries over deliberately
	ResetReconnect                    // drop and re-establish the connection
	ResetRestart                      // restart the target process
	ResetSnapshot                     // restore a checkpoint
)

var resetNames = [...]string{
	ResetNone: "none", ResetReconnect: "reconnect",
	ResetRestart: "restart", ResetSnapshot: "snapshot",
}

func (r ResetPolicy) String() string {
	if int(r) < len(resetNames) {
		return resetNames[r]
	}
	return "unknown"
}

// Input is what an executor delivers to a target.
//
// Bytes is the encoded form and is what nearly every executor uses. Node is the
// structure, which session and driver executors need in order to deliver a
// sequence of messages or events rather than one blob.
type Input struct {
	Bytes []byte
	Node  *ir.Node
}

// Executor runs a target with an input and reports what happened.
type Executor interface {
	// Name identifies the executor in configuration and diagnostics.
	Name() string

	// Run executes once, arming the observers before and harvesting after.
	//
	// The returned error means the harness failed, not that the target
	// misbehaved: a crashing target is a successful execution reporting
	// ExitCrash. Conflating the two turns infrastructure faults into findings.
	Run(ctx context.Context, in Input, obs []feedback.Observer) (feedback.ExitKind, error)

	// Reset restores the target to a known state.
	Reset(ResetPolicy) error

	// Capabilities describes what this executor provides.
	Capabilities() Caps

	// Close releases the target and any resources it holds.
	Close() error
}

// --- the spawn boundary -----------------------------------------------------

// ProcSpec describes a process to launch.
type ProcSpec struct {
	// Path is the executable.
	Path string

	// Args is the complete argv, including argv[0]. When empty it defaults to
	// Path alone.
	//
	// The whole argv rather than just the arguments, because that is what a
	// campaign file writes — ["./target", "--mode=parse", "@@"] — and a
	// convention where argv[0] is implied invites passing it twice, which
	// silently shifts every argument the target sees.
	Args []string

	Env []string
	Dir string

	// Stdin is written to the process for a one-shot run.
	Stdin []byte

	// StdinFile connects the process's standard input directly to an open file.
	//
	// A fork server needs this rather than Stdin: the descriptor is inherited
	// across the fork, so seeking the file in the fuzzer moves the offset the
	// forked child will read from. That shared file description is what lets one
	// long-lived server serve a new input on every execution without a new pipe
	// or a new process.
	StdinFile *os.File

	// Timeout bounds the run. Zero means no bound.
	Timeout time.Duration

	// MemLimitBytes caps the process's address space. Zero means no cap.
	MemLimitBytes int64

	// ExtraFiles become descriptors 3, 4, ... in the child, which is how a fork
	// server's control and status pipes are handed over.
	ExtraFiles []*os.File

	// CaptureOutput collects stdout and stderr. Off by default: a target that
	// writes on every execution makes capture the dominant cost.
	CaptureOutput bool

	// StderrFile connects the process's standard error to an open file.
	//
	// A fork server needs this because its children inherit its descriptors:
	// there is no per-execution pipe to read. Pointing stderr at a file the
	// fuzzer truncates before each run and reads after gives per-execution
	// output at the cost of two cheap syscalls, which is what makes a sanitizer
	// report or a target's own diagnostic usable at fork-server speed.
	StderrFile *os.File

	// Quarantine asks for the strongest isolation available, for a target
	// believed hostile.
	Quarantine bool
}

// ProcResult is how a process ended.
type ProcResult struct {
	ExitCode int
	Signal   int
	Stdout   []byte
	Stderr   []byte
	Duration time.Duration
	TimedOut bool
	OOM      bool
}

// ExitKind classifies the result for the feedback pipeline.
func (r ProcResult) ExitKind() feedback.ExitKind {
	switch {
	case r.TimedOut:
		return feedback.ExitTimeout
	case r.OOM:
		return feedback.ExitOOM
	case r.Signal != 0:
		return feedback.ExitCrash
	}
	return feedback.ExitOK
}

// Handle is a running process an executor talks to over its lifetime, which is
// what a fork server or a persistent harness needs.
type Handle interface {
	// Pid returns the process identifier.
	Pid() int

	// Control returns the descriptor the fuzzer writes commands to, and Status
	// the one it reads replies from. These are the ExtraFiles' peer ends.
	Control() *os.File
	Status() *os.File

	// Wait blocks until the process exits.
	Wait() (ProcResult, error)

	// Kill terminates it.
	Kill() error
}

// Spawner creates processes.
//
// It is an interface declared here and implemented in internal/safety, rather
// than executors calling os/exec directly, because ADR-0012 makes isolation
// mandatory: every process an executor starts must pass through the safety
// layer, and the only way to guarantee that structurally is to leave executors
// no other way to start one. The architecture lint enforces the same rule from
// the other side.
type Spawner interface {
	// Run executes a process to completion.
	Run(ctx context.Context, spec ProcSpec) (ProcResult, error)

	// Start launches a long-lived process and returns a handle to it.
	Start(ctx context.Context, spec ProcSpec) (Handle, error)

	// IsolationLevel reports the confinement actually in force: strong,
	// moderate, or minimal. A campaign may require a minimum and refuse to run
	// below it, so that "supported on this platform" never silently means
	// "unprotected on this platform".
	IsolationLevel() string
}

// SharedMemory is a region a target writes coverage into.
//
// Coverage transport has to be shared memory rather than a pipe: at five
// thousand executions a second, serialising a 64 KB map per run would cost more
// than the executions themselves (ASR-0007).
type SharedMemory interface {
	// Bytes returns the mapped region.
	Bytes() []byte

	// ID returns the identifier a child process uses to attach, passed through
	// the environment.
	ID() string

	// Close unmaps and removes the region.
	Close() error
}

// SharedMemoryProvider creates shared regions. Implemented in
// internal/platform, for the same reason Spawner is implemented in
// internal/safety: the mechanism is OS-specific and must not leak into portable
// code.
type SharedMemoryProvider interface {
	Create(size int) (SharedMemory, error)
	Available() bool
}
