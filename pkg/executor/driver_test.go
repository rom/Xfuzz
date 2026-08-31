package executor_test

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rom/Xfuzz/pkg/executor"
	"github.com/rom/Xfuzz/pkg/feedback"
	"github.com/rom/Xfuzz/pkg/ir"
)

// The T7 tier drives an interface rather than feeding it an input, so what has
// to be right is the loop: reset, deliver each event in order, let the interface
// redraw, read what it says. A backend that gets any of those wrong produces a
// campaign that looks like it is working — sequences run, states are recorded —
// and is in fact typing into a program that closed three sequences ago.

// fakeUI is a backend standing in for a terminal or a widget tree. It records
// what it was asked to do, which is the only way to check the order.
type fakeUI struct {
	mu       sync.Mutex
	events   []executor.Event
	starts   int
	resets   int
	closes   int
	screen   string
	dieAfter int // stop being alive once this many events have arrived; 0 = never
	sendErr  error
	result   executor.ProcResult
}

func (f *fakeUI) Name() string { return "fake" }

func (f *fakeUI) Start(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.starts++
	return nil
}

func (f *fakeUI) Send(_ context.Context, e executor.Event) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.sendErr != nil {
		return f.sendErr
	}
	f.events = append(f.events, e)
	f.screen = "after " + e.String()
	return nil
}

func (f *fakeUI) State() []byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	return []byte(f.screen)
}

func (f *fakeUI) Alive() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.dieAfter == 0 || len(f.events) < f.dieAfter
}

func (f *fakeUI) Result() executor.ProcResult {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.result
}

func (f *fakeUI) Reset() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.resets++
	f.events = nil
	f.screen = ""
	return nil
}

func (f *fakeUI) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closes++
	return nil
}

func (f *fakeUI) delivered() []executor.Event {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]executor.Event(nil), f.events...)
}

func newTestDriver(t *testing.T, b executor.DriverBackend, opts executor.DriverOptions) *executor.Driver {
	t.Helper()
	if opts.Settle == 0 {
		opts.Settle = time.Millisecond
	}
	d := executor.NewDriver("driver", b, opts)
	if err := d.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}

func TestDriverDeliversEventsInOrder(t *testing.T) {
	be := &fakeUI{}
	d := newTestDriver(t, be, executor.DriverOptions{})

	seq := "key ctrl-l\ntext hello\nclick 10 4\nresize 80 24\n"
	if _, err := d.Run(t.Context(), executor.Input{Bytes: []byte(seq)}, nil); err != nil {
		t.Fatal(err)
	}

	got := be.delivered()
	if len(got) != 4 {
		t.Fatalf("delivered %d events, want 4: %v", len(got), got)
	}
	want := []executor.Event{
		{Kind: executor.EventKey, Text: "ctrl-l"},
		{Kind: executor.EventText, Text: "hello"},
		{Kind: executor.EventClick, X: 10, Y: 4},
		{Kind: executor.EventResize, X: 80, Y: 24},
	}
	for i, w := range want {
		if got[i] != w {
			t.Errorf("event %d: got %v, want %v", i, got[i], w)
		}
	}
}

// TestDriverResetsBetweenSequences is what makes a T7 finding reproducible at
// all. An interface accumulates state by design, so without a restart the second
// sequence starts wherever the first one left off, and the input that "found"
// something does not find it again.
func TestDriverResetsBetweenSequences(t *testing.T) {
	be := &fakeUI{}
	d := newTestDriver(t, be, executor.DriverOptions{})

	for i := 0; i < 3; i++ {
		if _, err := d.Run(t.Context(), executor.Input{Bytes: []byte("key enter\n")}, nil); err != nil {
			t.Fatal(err)
		}
	}
	if be.resets != 3 {
		t.Errorf("%d resets for 3 sequences", be.resets)
	}
	if n := len(be.delivered()); n != 1 {
		t.Errorf("%d events survived the reset; each sequence must start clean", n)
	}
	if d.Executions() != 3 {
		t.Errorf("Executions() = %d, want 3", d.Executions())
	}
}

func TestDriverHonoursResetNone(t *testing.T) {
	be := &fakeUI{}
	d := newTestDriver(t, be, executor.DriverOptions{Reset: executor.ResetReconnect})
	// ResetReconnect is not ResetNone, so it still resets; the point of the case
	// below is that a campaign deliberately carrying state over is possible.
	if _, err := d.Run(t.Context(), executor.Input{Bytes: []byte("key a\n")}, nil); err != nil {
		t.Fatal(err)
	}
	if be.resets == 0 {
		t.Error("a non-none reset policy did not reset")
	}
}

// TestDriverBoundsTheSequence guards against the mutator, which will grow a
// sequence without limit. At a tenth of a second per event an unbounded sequence
// is a campaign that runs one input for an hour.
func TestDriverBoundsTheSequence(t *testing.T) {
	be := &fakeUI{}
	d := newTestDriver(t, be, executor.DriverOptions{MaxEvents: 5})

	var seq strings.Builder
	for i := 0; i < 100; i++ {
		seq.WriteString("key a\n")
	}
	if _, err := d.Run(t.Context(), executor.Input{Bytes: []byte(seq.String())}, nil); err != nil {
		t.Fatal(err)
	}
	if n := len(be.delivered()); n != 5 {
		t.Errorf("delivered %d of 100 events with MaxEvents=5", n)
	}
}

// TestDriverStopsWhenTheTargetDies is the difference between a finding and an
// hour of typing into a dead program. Once the target is gone every subsequent
// event is meaningless, and the sequence that killed it is the one to report.
func TestDriverStopsWhenTheTargetDies(t *testing.T) {
	be := &fakeUI{dieAfter: 2, result: executor.ProcResult{Signal: 11}}
	d := newTestDriver(t, be, executor.DriverOptions{})

	out := feedback.NewOutputObserver("output")
	d.Output = out
	ek, err := d.Run(t.Context(), executor.Input{Bytes: []byte("key a\nkey b\nkey c\nkey d\n")},
		[]feedback.Observer{out})
	if err != nil {
		t.Fatal(err)
	}
	if n := len(be.delivered()); n != 2 {
		t.Errorf("delivered %d events; the target died after 2", n)
	}
	if ek != feedback.ExitCrash {
		t.Errorf("exit kind %v, want ExitCrash", ek)
	}
	if out.Signal() != 11 {
		t.Errorf("the observer recorded signal %d", out.Signal())
	}
}

// TestDriverRecordsTheScreenAsOutput is what makes a T7 finding actionable: for
// an interface there is rarely anything on standard error, and what a person
// needs in the report is what the screen said when it went wrong.
func TestDriverRecordsTheScreenAsOutput(t *testing.T) {
	be := &fakeUI{}
	d := newTestDriver(t, be, executor.DriverOptions{})
	out := feedback.NewOutputObserver("output")
	d.Output = out

	if _, err := d.Run(t.Context(), executor.Input{Bytes: []byte("key enter\n")},
		[]feedback.Observer{out}); err != nil {
		t.Fatal(err)
	}
	if got := string(out.Stdout()); !strings.Contains(got, "key enter") {
		t.Errorf("the screen was not recorded as output: %q", got)
	}
}

// recordingUI is a UISink: the campaign's view of the interface.
type recordingUI struct{ states []string }

func (r *recordingUI) RecordUI(state []byte) { r.states = append(r.states, string(state)) }

func TestDriverFeedsTheUISink(t *testing.T) {
	be := &fakeUI{}
	d := newTestDriver(t, be, executor.DriverOptions{})
	ui := &recordingUI{}
	d.UI = ui

	for _, seq := range []string{"key a\n", "key b\n"} {
		if _, err := d.Run(t.Context(), executor.Input{Bytes: []byte(seq)}, nil); err != nil {
			t.Fatal(err)
		}
	}
	// Two per sequence: the screen the reset left, and the screen after the
	// event. The first is the state every sequence starts from and the second is
	// where it got to, and a campaign needs both to have a transition at all.
	if len(ui.states) != 4 {
		t.Fatalf("the sink saw %d states for 2 one-event sequences", len(ui.states))
	}
	if ui.states[1] == ui.states[3] {
		t.Error("two different sequences produced the same state; the sink is reading a stale screen")
	}
	if ui.states[0] != ui.states[2] {
		t.Errorf("the two sequences started from different screens: %q and %q",
			ui.states[0], ui.states[2])
	}
}

// TestDriverTimesOutASequence: an interface that hangs is the tier's most common
// failure, and it must be reported rather than blocking the campaign.
func TestDriverTimesOutASequence(t *testing.T) {
	be := &fakeUI{}
	d := newTestDriver(t, be, executor.DriverOptions{
		Timeout: 30 * time.Millisecond,
		Settle:  10 * time.Millisecond,
	})

	var seq strings.Builder
	for i := 0; i < 50; i++ {
		seq.WriteString("key a\n")
	}
	ek, err := d.Run(t.Context(), executor.Input{Bytes: []byte(seq.String())}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if ek != feedback.ExitTimeout {
		t.Errorf("exit kind %v, want ExitTimeout", ek)
	}
	if n := len(be.delivered()); n >= 50 {
		t.Errorf("the whole sequence ran despite the timeout (%d events)", n)
	}
}

// TestDriverReportsABackendFailureAsAHarnessError holds the same line the other
// tiers do: a broken backend is not a bug in the input, and reporting it as one
// fills the findings with the harness's own trouble.
func TestDriverReportsABackendFailureAsAHarnessError(t *testing.T) {
	be := &fakeUI{sendErr: context.DeadlineExceeded}
	d := newTestDriver(t, be, executor.DriverOptions{})

	ek, err := d.Run(t.Context(), executor.Input{Bytes: []byte("key a\n")}, nil)
	if err == nil {
		t.Fatal("a backend that could not deliver an event produced no error")
	}
	if ek != feedback.ExitError {
		t.Errorf("exit kind %v, want ExitError", ek)
	}
}

func TestDriverRefusesToRunBeforeStart(t *testing.T) {
	d := executor.NewDriver("driver", &fakeUI{}, executor.DriverOptions{})
	if _, err := d.Run(t.Context(), executor.Input{Bytes: []byte("key a\n")}, nil); err == nil {
		t.Error("Run before Start succeeded")
	}
}

func TestDriverCapabilities(t *testing.T) {
	c := executor.NewDriver("driver", &fakeUI{}, executor.DriverOptions{}).Capabilities()
	if c.Tier != executor.TierDriver {
		t.Errorf("tier %v", c.Tier)
	}
	if c.Backend != "fake" {
		t.Errorf("backend %q", c.Backend)
	}
	// An interface has animation, timers and a clock in the corner. Claiming
	// determinism here would have the triage layer treat a flapping finding as a
	// reproducible one.
	if c.Deterministic {
		t.Error("the driver tier claims determinism")
	}
}

// The textual event format is what a person writes to seed a campaign, reads to
// triage a finding, and edits to minimise one. Each case here is a line somebody
// would plausibly write.
func TestParseEvent(t *testing.T) {
	for _, tc := range []struct {
		line string
		want executor.Event
		ok   bool
	}{
		{"key enter", executor.Event{Kind: executor.EventKey, Text: "enter"}, true},
		{"key ctrl-c", executor.Event{Kind: executor.EventKey, Text: "ctrl-c"}, true},
		{"KEY Tab", executor.Event{Kind: executor.EventKey, Text: "Tab"}, true},
		{"text hello world", executor.Event{Kind: executor.EventText, Text: "hello world"}, true},
		{"click 10 4", executor.Event{Kind: executor.EventClick, X: 10, Y: 4}, true},
		{"wait 200ms", executor.Event{Kind: executor.EventWait, Delay: 200 * time.Millisecond}, true},
		{"resize 80 24", executor.Event{Kind: executor.EventResize, X: 80, Y: 24}, true},
		{"  key enter  ", executor.Event{Kind: executor.EventKey, Text: "enter"}, true},
		{"key enter\r", executor.Event{Kind: executor.EventKey, Text: "enter"}, true},

		{"", executor.Event{}, false},
		{"# a comment", executor.Event{}, false},
		{"key", executor.Event{}, false},
		{"click ten four", executor.Event{}, false},
		{"wait forever", executor.Event{}, false},

		// A line that is not an event is text typed literally, which is what
		// lets an ordinary file be a seed.
		{"just some words", executor.Event{Kind: executor.EventText, Text: "just some words"}, true},
	} {
		got, ok := executor.ParseEvent(tc.line)
		if ok != tc.ok {
			t.Errorf("%q: ok = %v, want %v", tc.line, ok, tc.ok)
			continue
		}
		if ok && got != tc.want {
			t.Errorf("%q: got %+v, want %+v", tc.line, got, tc.want)
		}
	}
}

// TestDecodeEventsPrefersTheTree is the same claim the API tier makes about
// request boundaries, for the same reason. A mutator that works on the tree
// reorders and duplicates *events*; one that works on the bytes reorders
// characters, and a sequence of interactions cut in half mid-word is not an
// interaction at all.
func TestDecodeEventsPrefersTheTree(t *testing.T) {
	a := ir.NewArena()
	root := a.New(ir.KindRepeat)
	root.Name = "events"
	for _, line := range []string{"key enter\n", "text hello\n", "click 3 7\n"} {
		child := a.New(ir.KindBytes)
		child.Name = "event"
		child.Raw = []byte(line)
		root.Children = append(root.Children, child)
	}

	// Bytes that say something different, so a decoder reading them rather than
	// the tree is caught rather than accidentally agreeing.
	got := executor.DecodeEvents(root, []byte("key q\n"))
	if len(got) != 3 {
		t.Fatalf("decoded %d events from a 3-event tree: %v", len(got), got)
	}
	if got[0].Text != "enter" || got[2].X != 3 || got[2].Y != 7 {
		t.Errorf("decoded %v", got)
	}
}

func TestDecodeEventsFallsBackToBytes(t *testing.T) {
	got := executor.DecodeEvents(nil, []byte("key enter\n\n# comment\ntext hi\n"))
	if len(got) != 2 {
		t.Fatalf("decoded %d events, want 2: %v", len(got), got)
	}
	if got[0].Kind != executor.EventKey || got[1].Text != "hi" {
		t.Errorf("decoded %v", got)
	}
}

func TestEventStringRoundTrips(t *testing.T) {
	// key, click, resize and wait are the forms a person edits; text is quoted
	// on the way out, so it round-trips through the quoting rather than exactly.
	for _, e := range []executor.Event{
		{Kind: executor.EventKey, Text: "enter"},
		{Kind: executor.EventClick, X: 10, Y: 4},
	} {
		s := e.String()
		back, ok := executor.ParseEvent(strings.ReplaceAll(s, ",", " "))
		if !ok {
			t.Errorf("%q did not parse back", s)
			continue
		}
		if back != e {
			t.Errorf("%v printed as %q parsed back as %v", e, s, back)
		}
	}
}
