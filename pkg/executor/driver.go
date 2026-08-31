package executor

import (
	"context"
	"fmt"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/rom/Xfuzz/pkg/feedback"
	"github.com/rom/Xfuzz/pkg/ir"
)

// Driver is the T7 tier: a program driven by interaction events rather than fed
// an input.
//
// It differs from every other tier on three axes at once, which is what
// ADR-0013 says makes it the most unusual domain. The input is a *sequence of
// events* rather than data. The interface is inherently stateful — screens,
// focus, modes — so the same keystroke means different things at different
// moments. And it runs at ten to a hundredth of an execution per second, five to
// six orders of magnitude below a parser, which changes what a scheduler should
// do and what a statistics layer may assume.
//
// What it shares with everything else is the whole rest of the machine: the same
// corpus, the same mutation operators over an IR Repeat, the same feedback
// stack, the same triage. That reuse is the strongest available evidence that
// the abstractions are right, and it is why GUI fuzzing is a driver behind the
// executor interface rather than a second product.
type Driver struct {
	name    string
	backend DriverBackend
	opts    DriverOptions

	// Output receives whatever the target wrote and how it ended.
	Output *feedback.OutputObserver

	// UI, when set, receives the observed interface state after each event, so
	// a campaign can treat a novel screen as new coverage.
	UI UISink

	execs   uint64
	started bool
}

// UISink is an observer that wants the interface state.
//
// Structural, like InputSink and BlockSink: pkg/feedback must not depend on
// pkg/executor, so the observer declares the method and never names this.
type UISink interface {
	RecordUI(state []byte)
}

// Settler is a backend that knows when the interface has finished redrawing.
//
// Optional, and worth implementing wherever it is possible: without it the tier
// waits DriverOptions.Settle after every event, which is a guess that is either
// too slow for the ordinary redraw or too fast for the one that matters.
type Settler interface {
	// Settle returns once the interface is quiet, or once ctx is done.
	Settle(ctx context.Context)
}

// DriverBackend is one way of driving an interface.
//
// The mechanisms ADR-0013 lists differ completely — a pseudo-terminal and a
// terminal emulator, an accessibility tree with synthetic input, a browser's
// debugging protocol — and they agree on exactly this: start the program,
// deliver an event, observe the state, and stop.
type DriverBackend interface {
	// Name identifies the backend: tui, gui-atspi, gui-win, gui-mac, web.
	Name() string

	// Start launches the target and waits for it to settle.
	Start(ctx context.Context) error

	// Send delivers one event.
	Send(ctx context.Context, e Event) error

	// State returns the observed interface state: a screen buffer, a widget
	// tree, a DOM. Its form is the backend's business; what the campaign does
	// with it is hash it and ask whether it has seen it before.
	State() []byte

	// Alive reports whether the target is still running, and Result how it
	// ended once it is not.
	Alive() bool
	Result() ProcResult

	// Reset restarts the target. It is the only reset a GUI has, and it is
	// expensive enough to be the dominant cost of a campaign (ADR-0013).
	Reset() error

	// Close stops the target and releases the backend.
	Close() error
}

// EventKind is what an event does.
type EventKind uint8

// The event kinds. Deliberately small: these are what every backend can express,
// and a kind only one of them supports would be a kind the corpus cannot carry
// between them.
const (
	EventKey    EventKind = iota // a named key: enter, tab, up, ctrl-c
	EventText                    // literal text typed
	EventClick                   // a pointer press at a position
	EventWait                    // let the target settle
	EventResize                  // change the interface's size
)

var eventKindNames = [...]string{
	EventKey: "key", EventText: "text", EventClick: "click",
	EventWait: "wait", EventResize: "resize",
}

func (k EventKind) String() string {
	if int(k) < len(eventKindNames) {
		return eventKindNames[k]
	}
	return "unknown"
}

// Event is one interaction.
type Event struct {
	Kind EventKind

	// Text is the key name for EventKey and the literal for EventText.
	Text string

	// X and Y are a position for EventClick and a size for EventResize.
	X, Y int

	// Delay is how long EventWait waits.
	Delay time.Duration
}

func (e Event) String() string {
	switch e.Kind {
	case EventKey:
		return "key " + e.Text
	case EventText:
		return "text " + strconv.Quote(e.Text)
	case EventClick:
		return fmt.Sprintf("click %d,%d", e.X, e.Y)
	case EventWait:
		return "wait " + e.Delay.String()
	case EventResize:
		return fmt.Sprintf("resize %dx%d", e.X, e.Y)
	}
	return "event"
}

// DriverOptions configure the tier.
type DriverOptions struct {
	// Timeout bounds one whole sequence.
	Timeout time.Duration

	// Settle is how long to wait after each event before observing the state.
	//
	// It is the tier's throughput, and it cannot be avoided: an interface
	// redraws asynchronously, so observing immediately after a keystroke reads
	// the screen as it was. Too short and every state is a half-drawn one; too
	// long and the campaign runs at a tenth of the rate it could.
	Settle time.Duration

	// MaxEvents bounds one sequence, since a mutator will grow it.
	MaxEvents int

	// Reset is what happens between sequences. For an interface this is
	// restarting the program, and it is the dominant cost.
	Reset ResetPolicy
}

// Defaults for the tier.
const (
	DefaultDriverTimeout   = 30 * time.Second
	DefaultDriverSettle    = 50 * time.Millisecond
	DefaultDriverMaxEvents = 256
)

// NewDriver returns the T7 tier over a backend.
func NewDriver(name string, backend DriverBackend, opts DriverOptions) *Driver {
	if opts.Timeout <= 0 {
		opts.Timeout = DefaultDriverTimeout
	}
	if opts.Settle <= 0 {
		opts.Settle = DefaultDriverSettle
	}
	if opts.MaxEvents <= 0 {
		opts.MaxEvents = DefaultDriverMaxEvents
	}
	if opts.Reset == ResetNone {
		opts.Reset = ResetRestart
	}
	return &Driver{name: name, backend: backend, opts: opts}
}

// Name implements Executor.
func (e *Driver) Name() string { return e.name }

// Executions returns how many sequences have run.
func (e *Driver) Executions() uint64 { return e.execs }

// Start launches the target.
func (e *Driver) Start(ctx context.Context) error {
	if e.started {
		return nil
	}
	if err := e.backend.Start(ctx); err != nil {
		return fmt.Errorf("executor %s: %s driver: %w", e.name, e.backend.Name(), err)
	}
	e.started = true
	return nil
}

// Capabilities implements Executor.
func (e *Driver) Capabilities() Caps {
	return Caps{
		Tier:        TierDriver,
		Backend:     e.backend.Name(),
		Granularity: GranularityNone,
		Platform:    runtime.GOOS + "/" + runtime.GOARCH,
		// An interface is not deterministic: it has animation, timers, a clock
		// on the status bar. What makes a TUI finding crisp is that the *screen*
		// can be normalised, not that the program is reproducible.
		Deterministic:   false,
		TimeoutEnforced: true,
	}
}

// Reset implements Executor.
func (e *Driver) Reset(p ResetPolicy) error {
	if p == ResetNone {
		return nil
	}
	return e.backend.Reset()
}

// Close implements Executor.
func (e *Driver) Close() error { return e.backend.Close() }

// Run implements Executor: it delivers one sequence of events.
func (e *Driver) Run(ctx context.Context, in Input, obs []feedback.Observer) (feedback.ExitKind, error) {
	if !e.started {
		return feedback.ExitError, fmt.Errorf("executor %s: Start was not called", e.name)
	}
	if err := Arm(obs, in); err != nil {
		return feedback.ExitError, err
	}
	e.execs++

	ctx, cancel := context.WithTimeout(ctx, e.opts.Timeout)
	defer cancel()

	// A fresh program per sequence unless the campaign said otherwise. An
	// interface accumulates state by design — that is what makes it an
	// interface — so without a reset every sequence starts wherever the last one
	// left off and no finding reproduces.
	if e.opts.Reset != ResetNone {
		if err := e.backend.Reset(); err != nil {
			return feedback.ExitError, fmt.Errorf("executor %s: resetting: %w", e.name, err)
		}
	}

	events := DecodeEvents(in.Node, in.Bytes)
	if len(events) > e.opts.MaxEvents {
		events = events[:e.opts.MaxEvents]
	}

	// The screen the reset left the program showing, before any event. It is a
	// state like any other, and the state every sequence starts from — so
	// without it the campaign has no transitions out of the one screen it can
	// always reach, and an oracle asking whether a program can get *back* has
	// nothing to compare against.
	if e.UI != nil {
		e.UI.RecordUI(e.backend.State())
	}

	start := time.Now()
	ek := feedback.ExitOK
	for _, ev := range events {
		if ctx.Err() != nil {
			ek = feedback.ExitTimeout
			break
		}
		if !e.backend.Alive() {
			// The program ended part-way through the sequence. Whether that is a
			// crash or a clean exit is the backend's result to say.
			break
		}
		if err := e.backend.Send(ctx, ev); err != nil {
			return feedback.ExitError, fmt.Errorf("executor %s: %v: %w", e.name, ev, err)
		}
		e.settle(ctx, ev)
		// After every event, not once at the end. A single state per sequence
		// gives the campaign screens and no *transitions*, and it is the
		// transitions that carry the signal: a target with a dozen screens has a
		// hundred and forty-four ordered pairs, and the bugs live in the pairs
		// nobody expected to be reachable (ADR-0006, ADR-0013).
		if e.UI != nil {
			e.UI.RecordUI(e.backend.State())
		}
	}

	elapsed := time.Since(start)
	state := e.backend.State()

	res := e.backend.Result()
	if ek == feedback.ExitOK {
		ek = res.ExitKind()
	}
	if e.Output != nil {
		// The screen is the output. For an interface there is rarely anything on
		// standard error, and what a finding needs to be actionable is what the
		// screen said when it went wrong.
		e.Output.Record(state, res.Stderr, res.ExitCode, res.Signal)
	}
	for _, o := range obs {
		if err := o.Post(ek); err != nil {
			return feedback.ExitError, fmt.Errorf("harvesting %s: %w", o.Name(), err)
		}
	}
	recordDuration(obs, elapsed)
	return ek, nil
}

// settle waits for the interface to redraw.
func (e *Driver) settle(ctx context.Context, ev Event) {
	if s, ok := e.backend.(Settler); ok {
		// A backend that can tell when the interface went quiet is strictly
		// better than a fixed interval, and by a lot: most events redraw in a
		// millisecond and the occasional one takes a hundred, so any single
		// number is either too slow for the common case or too fast for the
		// case that matters.
		if ev.Kind == EventWait && ev.Delay > 0 {
			e.pause(ctx, ev.Delay)
		}
		s.Settle(ctx)
		return
	}
	d := e.opts.Settle
	if ev.Kind == EventWait && ev.Delay > d {
		d = ev.Delay
	}
	e.pause(ctx, d)
}

func (e *Driver) pause(ctx context.Context, d time.Duration) {
	if d <= 0 {
		return
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-ctx.Done():
	}
}

// DecodeEvents reads a sequence of events from a tree, or from its bytes.
//
// From the tree when the codec produced one, so a mutator that reordered or
// duplicated events works on events rather than on characters. From the bytes
// otherwise, which is what a hand-written seed file looks like.
func DecodeEvents(root *ir.Node, raw []byte) []Event {
	if root != nil && root.Kind == ir.KindRepeat {
		out := make([]Event, 0, len(root.Children))
		for _, child := range root.Children {
			if ev, ok := ParseEvent(string(ir.AppendEncode(nil, child))); ok {
				out = append(out, ev)
			}
		}
		if len(out) > 0 {
			return out
		}
	}
	var out []Event
	for _, line := range strings.Split(string(raw), "\n") {
		if ev, ok := ParseEvent(line); ok {
			out = append(out, ev)
		}
	}
	return out
}

// ParseEvent reads one event from its textual form.
//
// Text, because a sequence of interactions is something a person writes by hand
// when they are seeding a campaign, reads when they are triaging a finding, and
// edits when they are minimising one. A binary encoding would be smaller and
// would make every one of those a tooling problem.
//
//	key enter
//	text hello world
//	click 10 4
//	wait 200ms
//	resize 80 24
func ParseEvent(line string) (Event, bool) {
	line = strings.TrimSpace(strings.TrimSuffix(line, "\r"))
	if line == "" || strings.HasPrefix(line, "#") {
		return Event{}, false
	}
	verb, rest, _ := strings.Cut(line, " ")
	rest = strings.TrimSpace(rest)

	switch strings.ToLower(verb) {
	case "key":
		if rest == "" {
			return Event{}, false
		}
		return Event{Kind: EventKey, Text: rest}, true
	case "text":
		return Event{Kind: EventText, Text: rest}, true
	case "click":
		x, y, ok := twoInts(rest)
		if !ok {
			return Event{}, false
		}
		return Event{Kind: EventClick, X: x, Y: y}, true
	case "wait":
		d, err := time.ParseDuration(rest)
		if err != nil {
			return Event{}, false
		}
		return Event{Kind: EventWait, Delay: d}, true
	case "resize":
		x, y, ok := twoInts(rest)
		if !ok {
			return Event{}, false
		}
		return Event{Kind: EventResize, X: x, Y: y}, true
	}
	// A line that is not an event is text typed literally, which is what makes
	// an ordinary file of input a usable seed.
	return Event{Kind: EventText, Text: line}, true
}

func twoInts(s string) (int, int, bool) {
	a, b, ok := strings.Cut(s, " ")
	if !ok {
		return 0, 0, false
	}
	x, err1 := strconv.Atoi(strings.TrimSpace(a))
	y, err2 := strconv.Atoi(strings.TrimSpace(b))
	if err1 != nil || err2 != nil {
		return 0, 0, false
	}
	return x, y, true
}
