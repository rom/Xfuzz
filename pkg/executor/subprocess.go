package executor

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/rom/Xfuzz/pkg/feedback"
)

// Delivery is how an input reaches the target.
type Delivery uint8

// The delivery mechanisms.
const (
	DeliverStdin Delivery = iota // written to the process's standard input
	DeliverFile                  // written to a file whose path replaces a placeholder
	DeliverArg                   // passed as a command-line argument
)

// FilePlaceholder is the token replaced by the input file's path, matching the
// AFL convention so existing command lines work unchanged (ASR-0013).
const FilePlaceholder = "@@"

// ShmEnvVar names the environment variable carrying the coverage region's
// identifier to an instrumented child.
const ShmEnvVar = "XFUZZ_SHM_ID"

// BlockShmEnvVar names the environment variable carrying the block-trace
// region's identifier.
//
// A third region, for the same reason there is a second: directed fuzzing costs
// a store per basic block executed, several times what the coverage update
// costs, and a campaign that is not directed should not pay it.
const BlockShmEnvVar = "XFUZZ_BB_ID"

// CmpShmEnvVar names the environment variable carrying the comparison table's
// identifier.
//
// A second variable rather than a second field in the first, because the two
// regions are separately optional: comparison logging costs a write per
// comparison and a campaign that does not need it should not pay for it, while
// a campaign that does should not need a different build of the target to get
// it. A target that is not given this one never writes a comparison.
const CmpShmEnvVar = "XFUZZ_CMP_ID"

// CounterShmEnvVar names the environment variable carrying the inline-counter
// region's identifier.
//
// A fourth region, for a compiler that instruments by incrementing an array
// rather than by calling back. The target maps its own array onto this region,
// so what the fuzzer reads is the array itself rather than a copy of it — which
// is why an execution that crashes still reports its coverage.
const CounterShmEnvVar = "XFUZZ_CNT_ID"

// Subprocess is the T4 executor: one process per input.
//
// It is the slowest tier with a process boundary and the one that always works.
// Every other tier needs something of the target — a Go harness, an
// instrumented build, a fork server — while this one needs only a command line.
// Keeping it available unconditionally is what makes "point Xfuzz at this
// binary" a supported starting point rather than a setup project.
type Subprocess struct {
	name    string
	spawner Spawner
	spec    ProcSpec

	// Delivery selects how the input reaches the target.
	Delivery Delivery

	// WorkDir holds the input file when delivering by file. It is created if
	// absent and cleaned up on Close.
	WorkDir string

	// Output, when set, receives the process's exit status and output. Capture
	// costs a little per execution and is what sanitizer objectives read.
	Output *feedback.OutputObserver

	// Coverage, when set together with Shm, is pointed at the shared region the
	// instrumented target writes into, so no copy happens per execution.
	Coverage *feedback.CoverageMap
	Shm      SharedMemory

	// CmpShm is the comparison table, when the campaign asked for one, and
	// BlockShm the block trace a directed campaign reads.
	CmpShm   SharedMemory
	BlockShm SharedMemory

	// CounterShm is the inline-counter region, for a target whose compiler
	// increments an array instead of calling back.
	CounterShm SharedMemory

	// Backend names the instrumentation in use, for reporting.
	Backend string

	inputPath string
	ownedDir  bool
	execs     uint64
}

// NewSubprocess returns a T4 executor.
func NewSubprocess(name string, spawner Spawner, spec ProcSpec) *Subprocess {
	return &Subprocess{name: name, spawner: spawner, spec: spec, Backend: "blackbox"}
}

// Name implements Executor.
func (e *Subprocess) Name() string { return e.name }

// Capabilities implements Executor.
func (e *Subprocess) Capabilities() Caps {
	c := Caps{
		Tier:            TierSubprocess,
		Backend:         e.Backend,
		Platform:        runtime.GOOS + "/" + runtime.GOARCH,
		Granularity:     GranularityNone,
		TimeoutEnforced: true,
		// A fresh process per input, so nothing carries over by construction.
		Deterministic: true,
	}
	if e.Coverage != nil {
		c.Granularity = GranularityEdge
		c.MapSize = e.Coverage.Size()
	}
	return c
}

// Executions returns how many runs this executor has performed.
func (e *Subprocess) Executions() uint64 { return e.execs }

// prepare returns the spec for one execution, with the input delivered.
func (e *Subprocess) prepare(in Input) (ProcSpec, error) {
	spec := e.spec
	spec.CaptureOutput = e.Output != nil

	if e.Shm != nil {
		spec.Env = append(append([]string(nil), spec.Env...), ShmEnvVar+"="+e.Shm.ID())
	}
	if e.CmpShm != nil {
		spec.Env = append(append([]string(nil), spec.Env...), CmpShmEnvVar+"="+e.CmpShm.ID())
	}
	if e.CounterShm != nil {
		spec.Env = append(append([]string(nil), spec.Env...), CounterShmEnvVar+"="+e.CounterShm.ID())
	}
	if e.BlockShm != nil {
		spec.Env = append(append([]string(nil), spec.Env...), BlockShmEnvVar+"="+e.BlockShm.ID())
	}

	switch e.Delivery {
	case DeliverStdin:
		spec.Stdin = in.Bytes

	case DeliverFile:
		if err := e.ensureWorkDir(); err != nil {
			return spec, err
		}
		if err := os.WriteFile(e.inputPath, in.Bytes, 0o600); err != nil {
			return spec, fmt.Errorf("writing the input file: %w", err)
		}
		args := make([]string, len(spec.Args))
		replaced := false
		for i, a := range spec.Args {
			if strings.Contains(a, FilePlaceholder) {
				args[i] = strings.ReplaceAll(a, FilePlaceholder, e.inputPath)
				replaced = true
				continue
			}
			args[i] = a
		}
		if !replaced {
			// Appending silently would run the target against no input at all
			// and look like a campaign that simply finds nothing.
			return spec, fmt.Errorf("executor %s delivers by file but no argument contains %s",
				e.name, FilePlaceholder)
		}
		spec.Args = args

	case DeliverArg:
		spec.Args = append(append([]string(nil), spec.Args...), string(in.Bytes))
	}
	return spec, nil
}

func (e *Subprocess) ensureWorkDir() error {
	if e.inputPath != "" {
		return nil
	}
	dir := e.WorkDir
	if dir == "" {
		d, err := os.MkdirTemp("", "xfuzz-exec-")
		if err != nil {
			return fmt.Errorf("creating a work directory: %w", err)
		}
		dir, e.ownedDir = d, true
		e.WorkDir = d
	} else if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("creating %s: %w", dir, err)
	}
	e.inputPath = filepath.Join(dir, "input")
	return nil
}

// Run implements Executor.
func (e *Subprocess) Run(ctx context.Context, in Input, obs []feedback.Observer) (feedback.ExitKind, error) {
	spec, err := e.prepare(in)
	if err != nil {
		return feedback.ExitError, err
	}

	if err := Arm(obs, in); err != nil {
		return feedback.ExitError, err
	}

	res, err := e.spawner.Run(ctx, spec)
	if err != nil {
		return feedback.ExitError, fmt.Errorf("executor %s: %w", e.name, err)
	}
	e.execs++

	ek := res.ExitKind()
	if e.Output != nil {
		e.Output.Record(res.Stdout, res.Stderr, res.ExitCode, res.Signal)
	}
	for _, o := range obs {
		if err := o.Post(ek); err != nil {
			return feedback.ExitError, fmt.Errorf("harvesting %s: %w", o.Name(), err)
		}
	}
	// After Post, not before: a timing observer measures for itself during Post,
	// and the spawner's figure is the better one — it is the process's lifetime
	// rather than the executor's call, so it excludes the cost of delivering the
	// input and collecting the result.
	recordDuration(obs, res.Duration)
	return ek, nil
}

// recordDuration overrides any timing observer with an authoritative
// measurement.
func recordDuration(obs []feedback.Observer, d time.Duration) {
	for _, o := range obs {
		if t, ok := o.(*feedback.TimingObserver); ok {
			t.Record(d)
		}
	}
}

// Reset implements Executor. Every execution already gets a fresh process, so
// there is nothing to restore.
func (e *Subprocess) Reset(ResetPolicy) error { return nil }

// Close implements Executor.
func (e *Subprocess) Close() error {
	if e.ownedDir && e.WorkDir != "" {
		return os.RemoveAll(e.WorkDir)
	}
	return nil
}

// Timeout returns the per-execution time budget.
func (e *Subprocess) Timeout() time.Duration { return e.spec.Timeout }
