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

// Trace is what a T5 backend reports about one execution: the addresses of the
// basic blocks the target actually entered.
//
// Addresses, not a coverage map. Every backend at this tier produces block
// identities in its own units — a breakpoint hit, a translation block, a
// DRcov entry — and folding them into a map is one piece of arithmetic that
// every backend would otherwise repeat, subtly differently. Doing it once here
// is also what makes coverage from different backends comparable at all.
type Trace struct {
	// Blocks are the block start addresses that were entered, in the order they
	// were entered where the backend can say, and in an arbitrary order where it
	// cannot. Order matters: edge coverage is a property of transitions.
	Blocks []uint64

	// Ordered reports whether Blocks is a sequence or a set. A backend that
	// records only "these blocks ran" — which is what one-shot breakpoints give,
	// and what a DRcov file holds — sets this false, and the fold degrades from
	// edge coverage to block coverage rather than inventing transitions that
	// never happened.
	Ordered bool

	// Result is how the process ended.
	Result ProcResult
}

// Tracer runs a target under instrumentation and reports which blocks it
// entered.
//
// The interface is declared here and implemented under internal/, for the same
// reason Spawner is: every backend at this tier is either OS-specific
// (ptrace) or depends on an external tool (QEMU, Frida), and neither belongs in
// portable code. It also means a backend cannot start a process except through
// the Spawner it was given.
type Tracer interface {
	// Name identifies the backend: ptrace-bb, qemu, frida.
	Name() string

	// Granularity is what this backend can actually resolve. A T5 backend
	// reports block granularity at best, and saying so is what stops a campaign
	// from being configured as though it had edges.
	Granularity() Granularity

	// Start prepares the backend, and is where an unavailable external tool or
	// an unanalysable target is reported — before a campaign begins rather than
	// after an hour of flat coverage.
	Start(ctx context.Context) error

	// Trace runs the target once against a prepared process specification.
	Trace(ctx context.Context, spec ProcSpec) (Trace, error)

	// Blocks returns how many blocks the backend knows about, which is the
	// denominator for any coverage figure it produces. Zero means the backend
	// discovers blocks as it goes and cannot say.
	Blocks() int

	// Close releases whatever the backend holds.
	Close() error
}

// Emulated is the T5 executor: a target run under emulation or dynamic
// instrumentation, for a binary nobody can rebuild.
//
// It is the tier for the case ADR-0002 calls out as the reason the backend
// interface exists at all — a stripped native binary, where the only available
// signal comes from watching the program run rather than from asking it. That
// costs one to two orders of magnitude against the fork server, which is why it
// is the fifth tier and not the first; what it buys is that the target needs
// nothing at all from its author.
type Emulated struct {
	name   string
	tracer Tracer
	spec   ProcSpec

	// Delivery selects how the input reaches the target.
	Delivery Delivery

	// WorkDir holds the input file when delivering by file.
	WorkDir string

	// Output, when set, receives the process's exit status and output.
	Output *feedback.OutputObserver

	// Coverage, when set, receives the folded block trace. Unlike the
	// instrumented tiers there is no shared region: the backend reports blocks
	// and this executor writes the map itself, so the map is owned here and
	// nothing outside the fuzzer ever touches it.
	Coverage *feedback.CoverageMap

	inputPath string
	ownedDir  bool
	execs     uint64
	started   bool
}

// NewEmulated returns a T5 executor over a tracing backend. Start must be called
// before Run.
func NewEmulated(name string, tracer Tracer, spec ProcSpec) *Emulated {
	return &Emulated{name: name, tracer: tracer, spec: spec}
}

// Name implements Executor.
func (e *Emulated) Name() string { return e.name }

// Start prepares the backend.
func (e *Emulated) Start(ctx context.Context) error {
	if e.started {
		return nil
	}
	if err := e.tracer.Start(ctx); err != nil {
		return fmt.Errorf("executor %s: %s backend: %w", e.name, e.tracer.Name(), err)
	}
	e.started = true
	return nil
}

// Capabilities implements Executor.
func (e *Emulated) Capabilities() Caps {
	c := Caps{
		Tier:            TierEmulated,
		Backend:         e.tracer.Name(),
		Platform:        runtime.GOOS + "/" + runtime.GOARCH,
		Granularity:     GranularityNone,
		TimeoutEnforced: true,
		// A fresh process per input under every backend at this tier, so nothing
		// carries over between executions.
		Deterministic: true,
	}
	if e.Coverage != nil {
		c.Granularity = e.tracer.Granularity()
		c.MapSize = e.Coverage.Size()
	}
	return c
}

// Executions returns how many runs this executor has performed.
func (e *Emulated) Executions() uint64 { return e.execs }

// Run implements Executor.
func (e *Emulated) Run(ctx context.Context, in Input, obs []feedback.Observer) (feedback.ExitKind, error) {
	if !e.started {
		return feedback.ExitError, fmt.Errorf("executor %s: Start was not called", e.name)
	}
	spec, err := e.prepare(in)
	if err != nil {
		return feedback.ExitError, err
	}
	if err := Arm(obs, in); err != nil {
		return feedback.ExitError, err
	}

	tr, err := e.tracer.Trace(ctx, spec)
	if err != nil {
		return feedback.ExitError, fmt.Errorf("executor %s: %s backend: %w", e.name, e.tracer.Name(), err)
	}
	e.execs++

	if e.Coverage != nil {
		FoldTrace(e.Coverage.Buffer(), tr.Blocks, tr.Ordered)
	}
	// A directed campaign wants the addresses themselves, not the folded map:
	// distance to a target is a property of an address, and the fold hashes it
	// away. This tier already has them, which is why directed fuzzing against a
	// binary nobody can rebuild works at all.
	for _, o := range obs {
		if s, ok := o.(BlockSink); ok {
			s.RecordBlocks(tr.Blocks)
		}
	}

	res := tr.Result
	ek := res.ExitKind()
	if e.Output != nil {
		e.Output.Record(res.Stdout, res.Stderr, res.ExitCode, res.Signal)
	}
	for _, o := range obs {
		if err := o.Post(ek); err != nil {
			return feedback.ExitError, fmt.Errorf("harvesting %s: %w", o.Name(), err)
		}
	}
	recordDuration(obs, res.Duration)
	return ek, nil
}

// FoldTrace writes a block trace into a coverage map.
//
// The scheme is the runtime's, deliberately: a block's identity is its address
// hashed across the map, and the index written is the previous identity shifted
// right one, XOR the current. That is what makes the entry an *edge* rather than
// a block — it is the transition that carries the information — and using the
// same scheme here means a corpus measured under source instrumentation and one
// measured under a tracer are describing the same kind of thing.
//
// An unordered trace cannot say which transitions happened, only which blocks
// ran. It is folded as block coverage: each block's own identity, with no
// previous location. Fabricating transitions from an arbitrary order would
// manufacture novelty out of nothing, and every input would look interesting
// once.
func FoldTrace(m []byte, blocks []uint64, ordered bool) {
	if len(m) == 0 {
		return
	}
	mask := uint64(len(m) - 1)
	if len(m)&(len(m)-1) != 0 {
		// A non-power-of-two map cannot be masked, and modulo on the hot path is
		// not worth the generality: the callers all use a power of two.
		mask = 0
	}
	idx := func(v uint64) uint64 {
		if mask != 0 {
			return v & mask
		}
		return v % uint64(len(m))
	}

	if !ordered {
		for _, b := range blocks {
			i := idx(SpreadAddr(b))
			if m[i] < 255 {
				m[i]++
			}
		}
		return
	}
	var prev uint64
	for _, b := range blocks {
		loc := SpreadAddr(b)
		i := idx(prev ^ loc)
		if m[i] < 255 {
			m[i]++
		}
		prev = loc >> 1
	}
}

// SpreadAddr turns a block address into a map identity.
//
// Addresses are the opposite of uniformly distributed: a function's blocks sit
// within a few dozen bytes of each other, and its neighbours within a few
// hundred. Indexing on the low bits would pack a whole function into a handful
// of map entries and collide most of them, which is invisible from the outside —
// coverage simply reports nothing new for an input that genuinely went somewhere
// new. The same mixing function the runtime uses, for the same reason, and so
// that the two produce comparable maps.
func SpreadAddr(a uint64) uint64 {
	x := uint32(a) ^ uint32(a>>32)
	x ^= x >> 16
	x *= 0x7FEB352D
	x ^= x >> 15
	x *= 0x846CA68B
	x ^= x >> 16
	return uint64(x)
}

// prepare returns the spec for one execution, with the input delivered. It is
// the T4 logic, shared rather than copied: how an input reaches a target is a
// property of the target, not of the tier running it.
func (e *Emulated) prepare(in Input) (ProcSpec, error) {
	spec := e.spec
	spec.CaptureOutput = e.Output != nil

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
			return spec, fmt.Errorf("executor %s delivers by file but no argument contains %s",
				e.name, FilePlaceholder)
		}
		spec.Args = args

	case DeliverArg:
		spec.Args = append(append([]string(nil), spec.Args...), string(in.Bytes))
	}
	return spec, nil
}

func (e *Emulated) ensureWorkDir() error {
	if e.inputPath != "" {
		return nil
	}
	dir := e.WorkDir
	if dir == "" {
		d, err := os.MkdirTemp("", "xfuzz-t5-")
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

// Reset implements Executor. A fresh process per input, so there is nothing to
// restore.
func (e *Emulated) Reset(ResetPolicy) error { return nil }

// Close implements Executor.
func (e *Emulated) Close() error {
	err := e.tracer.Close()
	if e.ownedDir && e.WorkDir != "" {
		if rerr := os.RemoveAll(e.WorkDir); err == nil {
			err = rerr
		}
	}
	return err
}

// Timeout returns the per-execution time budget.
func (e *Emulated) Timeout() time.Duration { return e.spec.Timeout }

// KnownBlocks returns how many blocks the backend can distinguish, which is the
// denominator for a coverage percentage at this tier.
func (e *Emulated) KnownBlocks() int { return e.tracer.Blocks() }
