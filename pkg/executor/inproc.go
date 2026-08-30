package executor

import (
	"context"
	"fmt"
	"runtime"
	"runtime/debug"
	"time"

	"github.com/rom/Xfuzz/pkg/feedback"
)

// Harness is a target called directly, in the fuzzer's own process.
//
// Returning an error is not a finding: it is how a harness says "this input was
// rejected before reaching anything interesting". A finding is a panic, or
// whatever an objective in the campaign's stack recognises.
type Harness func(data []byte) error

// InProc is the T0 executor: it calls a Go function with no process boundary at
// all.
//
// It is the fastest tier by an order of magnitude and the least safe. There is
// no isolation: a harness that corrupts memory corrupts the fuzzer, and one
// that hangs hangs the worker, because Go cannot stop a running goroutine. That
// is why worker parallelism is process-based (ADR-0015) — a wedged T0 worker is
// killed and restarted by the daemon rather than taking the campaign with it.
//
// Use it for Go targets and for harnesses under the operator's control. For
// anything else, T2 or T4 pay a little throughput for a process boundary.
type InProc struct {
	name string
	fn   Harness

	// Timeout bounds an execution. Enforcing it needs a goroutine per run,
	// which roughly doubles the per-execution cost, so it is off by default.
	// Even enabled it is advisory: the run is abandoned, not stopped, and the
	// goroutine leaks until the harness returns.
	Timeout time.Duration

	// PanicIsCrash treats a recovered panic as a crash rather than a harness
	// error. This is what a Go target's memory-safety equivalent looks like:
	// index out of range, nil dereference, integer divide by zero.
	PanicIsCrash bool

	// Coverage, when set, is reported as this executor's capability so the
	// engine knows the tier is guided rather than black-box. The harness is
	// responsible for writing into it.
	Coverage *feedback.CoverageMap

	abandoned int
	lastPanic string
	lastStack string
}

// NewInProc returns a T0 executor over a Go harness.
func NewInProc(name string, fn Harness) *InProc {
	return &InProc{name: name, fn: fn, PanicIsCrash: true}
}

// Name implements Executor.
func (e *InProc) Name() string { return e.name }

// Capabilities implements Executor.
func (e *InProc) Capabilities() Caps {
	c := Caps{
		Tier:     TierInProc,
		Backend:  "none",
		Platform: runtime.GOOS + "/" + runtime.GOARCH,
		// A Go harness is deterministic unless it reads the clock or the map
		// iteration order; the engine measures this rather than trusting it.
		Deterministic: true,
		// Never true for T0: the run can be abandoned, not stopped.
		TimeoutEnforced: false,
		Granularity:     GranularityNone,
	}
	if e.Coverage != nil {
		c.Backend = "harness"
		c.Granularity = GranularityEdge
		c.MapSize = e.Coverage.Size()
	}
	return c
}

// Abandoned returns how many executions exceeded their timeout and were left
// running. A campaign with a rising count is leaking goroutines and needs its
// worker restarted.
func (e *InProc) Abandoned() int { return e.abandoned }

// LastPanic returns the message and stack of the most recent recovered panic,
// which is what the crash objective reports.
func (e *InProc) LastPanic() (string, string) { return e.lastPanic, e.lastStack }

// Run implements Executor.
func (e *InProc) Run(ctx context.Context, in Input, obs []feedback.Observer) (feedback.ExitKind, error) {
	if err := Arm(obs, in); err != nil {
		return feedback.ExitError, err
	}
	e.lastPanic, e.lastStack = "", ""

	var ek feedback.ExitKind
	if e.Timeout <= 0 {
		ek = e.call(in.Bytes)
	} else {
		ek = e.callWithTimeout(ctx, in.Bytes)
	}

	for _, o := range obs {
		if err := o.Post(ek); err != nil {
			return feedback.ExitError, fmt.Errorf("harvesting %s: %w", o.Name(), err)
		}
	}
	return ek, nil
}

func (e *InProc) call(data []byte) (ek feedback.ExitKind) {
	defer func() {
		r := recover()
		if r == nil {
			return
		}
		e.lastPanic = fmt.Sprint(r)
		e.lastStack = string(debug.Stack())
		if e.PanicIsCrash {
			ek = feedback.ExitCrash
		} else {
			ek = feedback.ExitError
		}
	}()
	if err := e.fn(data); err != nil {
		// A rejected input is a normal outcome, not a fault.
		return feedback.ExitOK
	}
	return feedback.ExitOK
}

func (e *InProc) callWithTimeout(ctx context.Context, data []byte) feedback.ExitKind {
	done := make(chan feedback.ExitKind, 1)
	go func() { done <- e.call(data) }()

	timer := time.NewTimer(e.Timeout)
	defer timer.Stop()
	select {
	case ek := <-done:
		return ek
	case <-timer.C:
		e.abandoned++
		return feedback.ExitTimeout
	case <-ctx.Done():
		e.abandoned++
		return feedback.ExitError
	}
}

// Reset implements Executor. In-process execution has no state of its own to
// restore; a harness that carries state between calls must reset it itself,
// which is why ResetRestart is refused rather than silently ignored.
func (e *InProc) Reset(p ResetPolicy) error {
	switch p {
	case ResetNone:
		return nil
	case ResetRestart, ResetSnapshot:
		return fmt.Errorf("executor %s: %s reset is not possible in-process; "+
			"use T2 or T4 for a target that needs a fresh process", e.name, p)
	}
	return nil
}

// Close implements Executor.
func (e *InProc) Close() error { return nil }

// PanicObjective reports a recovered panic from an in-process harness as a
// finding, with the Go stack as its frames so that distinct panics bucket
// apart.
type PanicObjective struct {
	name string
	e    *InProc
}

// NewPanicObjective returns an objective over an in-process executor.
func NewPanicObjective(name string, e *InProc) *PanicObjective {
	return &PanicObjective{name: name, e: e}
}

// Name implements feedback.Objective.
func (o *PanicObjective) Name() string { return o.name }

// IsFinding implements feedback.Objective.
func (o *PanicObjective) IsFinding(_ []feedback.Observer, ek feedback.ExitKind) (bool, feedback.Finding, error) {
	if ek != feedback.ExitCrash {
		return false, feedback.Finding{}, nil
	}
	msg, stack := o.e.LastPanic()
	if msg == "" {
		return false, feedback.Finding{}, nil
	}
	return true, feedback.Finding{
		Kind:    "panic",
		Summary: msg,
		Detail:  stack,
		Frames:  goFrames(stack),
	}, nil
}

// goFrames extracts function names from a Go stack trace, innermost first,
// skipping the runtime and this package's own recovery machinery so that two
// panics from the same target location bucket together.
func goFrames(stack string) []string {
	var out []string
	skip := true
	for _, line := range splitLines(stack) {
		if len(line) == 0 || line[0] == '\t' || line[0] == ' ' {
			continue
		}
		name := line
		if i := indexByte(name, '('); i > 0 {
			name = name[:i]
		}
		switch {
		case hasPrefix(name, "runtime."), hasPrefix(name, "panic"):
			continue
		case hasPrefix(name, "github.com/rom/Xfuzz/pkg/executor."):
			skip = false
			continue
		}
		if skip {
			continue
		}
		out = append(out, name)
		if len(out) >= 16 {
			break
		}
	}
	return out
}

func splitLines(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}

func indexByte(s string, c byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return i
		}
	}
	return -1
}

func hasPrefix(s, p string) bool { return len(s) >= len(p) && s[:len(p)] == p }
