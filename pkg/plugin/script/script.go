// Package script runs campaign-local logic in Starlark.
//
// It is the third extension tier (ADR-0010): a researcher iterating on an
// oracle should not need a compiler, and a campaign should be able to carry the
// one predicate that makes sense only for this target without anyone building
// a plugin for it.
//
// Starlark rather than a general scripting language, for two specific reasons.
// It is hermetic by construction — no filesystem, no network, no clock, no
// process — which matters because a campaign file may be untrusted (ASR-0010).
// And it is deterministic: the same script on the same input gives the same
// answer on every run, which a campaign that is required to replay cannot do
// without (ASR-0008). A language that could read the time would quietly destroy
// both.
//
// What Starlark is not is unbounded. A hermetic language can still loop
// forever, and it can still build a gigabyte string. Both are bounded here, and
// a script that exceeds either budget fails its campaign with a message naming
// which budget and where.
package script

import (
	"errors"
	"fmt"
	"runtime/metrics"
	"sync"

	"go.starlark.net/starlark"
	"go.starlark.net/syntax"
)

// Limits bound one call into a script.
type Limits struct {
	// Steps is the total abstract computation steps one call may take. A
	// script that exceeds it is cancelled: an oracle that has not decided
	// within a bounded amount of work is not slow, it is looping.
	Steps uint64

	// Allocs is how many bytes one call may allocate.
	//
	// Starlark's own guard is a hard 1 GiB per single operation, which stops
	// `"x" * 10**12` and nothing else: a loop that concatenates is bounded only
	// by the step count, and steps are cheap relative to bytes. So the budget
	// is enforced here, by sampling the runtime's allocation counter.
	Allocs int64

	// Quantum is how many steps pass between budget checks. It is the trade
	// between the cost of sampling and how far past its budget a script can get
	// before it is stopped.
	Quantum uint64
}

// DefaultLimits are the budgets a campaign gets when it names none.
//
// Generous for an oracle, which examines one execution's output and decides,
// and tight enough that a runaway script is stopped in milliseconds rather than
// taking the worker with it.
func DefaultLimits() Limits {
	return Limits{
		Steps:   1 << 22, // about four million
		Allocs:  64 << 20,
		Quantum: 1 << 14,
	}
}

func (l Limits) withDefaults() Limits {
	d := DefaultLimits()
	if l.Steps == 0 {
		l.Steps = d.Steps
	}
	if l.Allocs == 0 {
		l.Allocs = d.Allocs
	}
	if l.Quantum == 0 || l.Quantum > l.Steps {
		l.Quantum = min(d.Quantum, l.Steps)
	}
	return l
}

// Options configure a script.
type Options struct {
	// Limits bound each call. The zero value takes the defaults.
	Limits Limits

	// Config is the campaign's settings for this script, readable as the
	// module-level `config` dict.
	Config map[string]string

	// Seed is the campaign seed, readable as `seed`. A script that makes a
	// pseudo-random choice must derive it from this and nothing else — there is
	// no other source, which is the point.
	Seed uint64

	// MaxOutputBytes bounds a single value a script returns. Without it a
	// script that stayed inside its allocation budget could still hand back a
	// finding whose detail is the whole budget.
	MaxOutputBytes int
}

// DefaultMaxOutputBytes bounds one returned value.
const DefaultMaxOutputBytes = 1 << 20

// Script is a loaded Starlark module.
//
// One script serves every extension a campaign takes from it, and calls are
// serialised: a Starlark thread is not safe for concurrent use, and a worker
// has one fuzz loop, so a mutex here costs nothing and removes a whole class of
// question.
type Script struct {
	name    string
	globals starlark.StringDict
	limits  Limits
	opts    Options

	mu     sync.Mutex
	thread *starlark.Thread
	said   []string
}

// ErrBudget is returned when a script exceeded a limit. It is separate from an
// ordinary script error because it says something different: the script is not
// wrong, it is too expensive, and the fix is a different script rather than a
// corrected one.
var ErrBudget = errors.New("script: budget exhausted")

// Load parses and executes a Starlark module, returning it ready to call.
//
// Executing at load time is how Starlark modules work — the top level defines
// the functions — and it is also where a syntax error or a bad constant should
// surface: at campaign startup, named with a line number, rather than on the
// four-thousandth execution.
func Load(name string, src []byte, opts Options) (*Script, error) {
	if opts.MaxOutputBytes <= 0 {
		opts.MaxOutputBytes = DefaultMaxOutputBytes
	}
	s := &Script{name: name, limits: opts.Limits.withDefaults(), opts: opts}
	s.thread = s.newThread()

	predeclared := starlark.StringDict{
		"config":  configDict(opts.Config),
		"seed":    starlark.MakeUint64(opts.Seed),
		"finding": starlark.NewBuiltin("finding", makeFinding),
	}

	globals, err := starlark.ExecFileOptions(&syntax.FileOptions{
		Set:             true,
		While:           false,
		TopLevelControl: false,
		GlobalReassign:  false,
		Recursion:       false,
	}, s.thread, name, src, predeclared)
	if err != nil {
		return nil, s.wrap(err)
	}
	globals.Freeze()
	s.globals = globals
	return s, nil
}

// newThread builds a thread with the budgets armed and every door closed.
func (s *Script) newThread() *starlark.Thread {
	t := &starlark.Thread{Name: s.name}

	// No module loading. Starlark's load() reads whatever the host lets it,
	// and a hermetic language with a filesystem-backed loader is not hermetic;
	// leaving Load nil makes load() an error rather than a hole.
	t.Load = nil

	// print goes into a buffer the campaign can read back, not to a stream. A
	// script that printed to the worker's standard error would interleave with
	// the target's output, which is the one thing triage reads.
	t.Print = func(_ *starlark.Thread, msg string) {
		if len(s.said) < maxPrints {
			s.said = append(s.said, msg)
		}
	}
	return t
}

// maxPrints bounds how many lines of a script's own output are kept. Enough to
// debug with, not enough for a print inside a loop to become the campaign's
// memory profile.
const maxPrints = 64

// Name is the label the campaign gave this script.
func (s *Script) Name() string { return s.name }

// Printed returns what the script printed, most recent last.
func (s *Script) Printed() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.said...)
}

// Has reports whether the module defines a callable of this name.
func (s *Script) Has(fn string) bool {
	v, ok := s.globals[fn]
	if !ok {
		return false
	}
	_, callable := v.(starlark.Callable)
	return callable
}

// Names lists the callables the module defines, for an error that says what is
// available rather than only what is missing.
func (s *Script) Names() []string {
	var out []string
	for name, v := range s.globals {
		if _, ok := v.(starlark.Callable); ok {
			out = append(out, name)
		}
	}
	sortStrings(out)
	return out
}

// call invokes a function under the budgets.
func (s *Script) call(fn string, args ...starlark.Value) (starlark.Value, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	v, ok := s.globals[fn]
	if !ok {
		return nil, fmt.Errorf("script %s: no function named %q; it defines %v", s.name, fn, s.Names())
	}
	callable, ok := v.(starlark.Callable)
	if !ok {
		return nil, fmt.Errorf("script %s: %s is not a function", s.name, fn)
	}

	// A thread's step count accumulates, so each call starts from where the
	// last one ended. The budget is per call, so it is measured as a delta.
	t := s.thread
	t.Uncancel()
	startSteps := t.Steps
	startAllocs := allocatedBytes()
	var over string

	t.SetMaxExecutionSteps(startSteps + s.limits.Quantum)
	t.OnMaxSteps = func(th *starlark.Thread) {
		switch {
		case th.Steps-startSteps >= s.limits.Steps:
			over = fmt.Sprintf("more than %d steps", s.limits.Steps)
			th.Cancel(over)
		case allocatedBytes()-startAllocs >= s.limits.Allocs:
			over = fmt.Sprintf("more than %d bytes", s.limits.Allocs)
			th.Cancel(over)
		default:
			th.SetMaxExecutionSteps(th.Steps + s.limits.Quantum)
		}
	}

	res, err := starlark.Call(t, callable, args, nil)
	if err != nil {
		if over != "" {
			return nil, fmt.Errorf("%w: %s: %s allocated or executed by %s",
				ErrBudget, s.name, over, fn)
		}
		return nil, s.wrap(err)
	}
	return res, nil
}

// wrap turns a Starlark error into one that names the script and keeps the
// backtrace, which is the only thing that says *where* in a script it failed.
func (s *Script) wrap(err error) error {
	var eval *starlark.EvalError
	if errors.As(err, &eval) {
		return fmt.Errorf("script %s: %s\n%s", s.name, eval.Msg, eval.Backtrace())
	}
	return fmt.Errorf("script %s: %w", s.name, err)
}

// allocSample is the runtime counter the allocation budget is measured against.
//
// Cumulative bytes allocated by the whole process, not by this goroutine — Go
// exposes no per-goroutine figure. It is close enough to be a real bound
// because a worker is its own process (ADR-0015) and the fuzz loop is blocked
// inside this call: what the counter moves by while a script runs is what the
// script allocated, give or take the garbage collector's own bookkeeping. Read
// through runtime/metrics rather than runtime.ReadMemStats, which stops the
// world and would cost more than the script.
var allocSample = struct {
	mu      sync.Mutex
	samples []metrics.Sample
}{samples: []metrics.Sample{{Name: "/gc/heap/allocs:bytes"}}}

func allocatedBytes() int64 {
	allocSample.mu.Lock()
	defer allocSample.mu.Unlock()
	metrics.Read(allocSample.samples)
	if allocSample.samples[0].Value.Kind() != metrics.KindUint64 {
		return 0
	}
	return int64(allocSample.samples[0].Value.Uint64())
}

// configDict exposes the campaign's settings, frozen so a script cannot use it
// as a place to keep state between calls.
//
// That restriction is deliberate and is the honest limit of this tier: module
// globals are frozen after load, so a script cannot accumulate anything. An
// oracle does not need to. A feedback does — novelty *is* accumulated state —
// which is why feedbacks belong to the plugin tier, where a process can
// remember.
func configDict(config map[string]string) *starlark.Dict {
	d := starlark.NewDict(len(config))
	keys := make([]string, 0, len(config))
	for k := range config {
		keys = append(keys, k)
	}
	sortStrings(keys)
	for _, k := range keys {
		d.SetKey(starlark.String(k), starlark.String(config[k]))
	}
	d.Freeze()
	return d
}

func sortStrings(xs []string) {
	for i := 1; i < len(xs); i++ {
		for j := i; j > 0 && xs[j] < xs[j-1]; j-- {
			xs[j], xs[j-1] = xs[j-1], xs[j]
		}
	}
}

// truncate bounds a string a script produced.
func truncate(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	return s[:limit] + "\n... truncated at " + fmt.Sprint(limit) + " bytes"
}
