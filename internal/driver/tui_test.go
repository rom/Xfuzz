package driver_test

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rom/Xfuzz/internal/driver"
	"github.com/rom/Xfuzz/internal/safety"
	"github.com/rom/Xfuzz/internal/testenv"
	"github.com/rom/Xfuzz/pkg/executor"
	"github.com/rom/Xfuzz/pkg/feedback"
)

// Everything here drives a real terminal program through a real pseudo-terminal.
// A fake backend can prove the tier's loop is right, which pkg/executor's own
// tests do; only a real one can prove that a program which takes the alternate
// screen, goes into raw mode, hides the cursor and redraws on SIGWINCH is a
// program this driver can actually operate.

func newTUI(t *testing.T, opts driver.TUIOptions) *driver.TUI {
	t.Helper()
	if !safety.PTYSupported() {
		t.Skip("no pseudo-terminal support on this host")
	}
	dir := testenv.ReachableDir(t)
	opts.Path = testenv.BuildAt(t, filepath.Join(dir, "tui_menu"), "./testdata/targets/go/tui_menu")
	if opts.Cols == 0 {
		opts.Cols, opts.Rows = 60, 20
	}
	// Unconfined: the claim under test is the terminal, and a namespace that
	// refuses to start the target would fail the test for an unrelated reason.
	// The confined path is internal/safety's own to test, and StartPTY goes
	// through the same command builder as every other spawn.
	d := driver.NewTUI(safety.NewTrustedSpawner(), opts)
	t.Cleanup(func() { d.Close() })
	return d
}

// awaitScreen waits for the screen to say something, settling as it goes.
//
// One settle is not a guarantee that a program has drawn. Settle returns when
// the terminal has been quiet for the settle window, and a program that has not
// been scheduled yet has been perfectly quiet — so on a loaded machine the
// first read can come back before the first frame. Measured: the initial screen
// was missing on a two-core runner, in a test that had passed everywhere else.
//
// Bounded, so a program that never draws still fails rather than hanging, and
// the failure still shows the screen it did have.
func awaitScreen(t *testing.T, d *driver.TUI, want string) string {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		got := string(d.State())
		if strings.Contains(got, want) || time.Now().After(deadline) {
			return got
		}
		d.Settle(t.Context())
	}
}

func TestTUIStartsAProgramAndReadsItsScreen(t *testing.T) {
	d := newTUI(t, driver.TUIOptions{})
	if err := d.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	screen := string(d.State())
	if !strings.Contains(screen, "tui_menu") || !strings.Contains(screen, "1) items") {
		t.Fatalf("the program's first screen was not read:\n%s", screen)
	}
	// The program took the alternate buffer, which is what a full-screen
	// program does and what an emulator without it would miss entirely.
	if s := d.Screen(); s == nil || !s.Alternate {
		t.Error("the alternate screen buffer was not entered")
	}
	if s := d.Screen(); s != nil && s.CursorVisible {
		t.Error("the program hid the cursor and the emulator did not notice")
	}
}

func send(t *testing.T, d *driver.TUI, line string) {
	t.Helper()
	ev, ok := executor.ParseEvent(line)
	if !ok {
		t.Fatalf("%q is not an event", line)
	}
	if err := d.Send(t.Context(), ev); err != nil {
		t.Fatal(err)
	}
	d.Settle(t.Context())
}

// TestTUINavigates is the whole tier in miniature: a keystroke reaches the
// program, the program redraws, and the emulator holds what it drew.
func TestTUINavigates(t *testing.T) {
	d := newTUI(t, driver.TUIOptions{})
	if err := d.Start(t.Context()); err != nil {
		t.Fatal(err)
	}

	send(t, d, "key 1")
	if got := string(d.State()); !strings.Contains(got, "alpha") {
		t.Fatalf("the list did not open:\n%s", got)
	}
	if got := string(d.State()); !strings.Contains(got, "selected: alpha") {
		t.Fatalf("the selection is not on the first item:\n%s", got)
	}

	send(t, d, "key down")
	if got := string(d.State()); !strings.Contains(got, "selected: beta") {
		t.Fatalf("the arrow key did not move the selection:\n%s", got)
	}
	// An arrow key is three bytes and which three depends on a mode the program
	// sets. Getting it wrong types a literal "B", which in this program does
	// nothing at all — so the assertion above is the one that catches it.

	send(t, d, "key escape")
	if got := string(d.State()); !strings.Contains(got, "1) items") {
		t.Fatalf("escape did not return to the menu:\n%s", got)
	}
}

// TestTUIFindsThePlantedBug is the tier earning its place. No single keystroke
// reaches this: it takes a sequence, in order, and that is why the unit of input
// for T7 is a sequence of events rather than a buffer of bytes.
func TestTUIFindsThePlantedBug(t *testing.T) {
	d := newTUI(t, driver.TUIOptions{})
	if err := d.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	for _, line := range []string{
		"key 1",    // open the list
		"key down", // move to the second item
		"key down", // and to the third, which is the last
		"key d",    // delete it, leaving the selection past the end
	} {
		send(t, d, line)
	}

	if d.Alive() {
		t.Fatalf("the program survived deleting the last item:\n%s", d.State())
	}
	// The screen is the diagnostic. A terminal program's standard error *is* the
	// terminal, so the panic is on the screen and nowhere else.
	res := d.Result()
	if !strings.Contains(string(res.Stderr), "panic") {
		t.Errorf("the crash left no trace on the screen:\n%s", res.Stderr)
	}
	if res.ExitCode == 0 {
		t.Errorf("a program that panicked exited %d", res.ExitCode)
	}
}

// TestTUIResetRestarts is what makes a T7 finding reproducible. A terminal
// program's state is its own memory and the only interface for clearing it is
// exit, so a driver that did not restart would have every sequence start
// wherever the last one stopped.
func TestTUIResetRestarts(t *testing.T) {
	d := newTUI(t, driver.TUIOptions{})
	if err := d.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	send(t, d, "key 1")
	send(t, d, "key down")
	if got := string(d.State()); !strings.Contains(got, "selected: beta") {
		t.Fatalf("setup failed:\n%s", got)
	}

	if err := d.Reset(); err != nil {
		t.Fatal(err)
	}
	got := string(d.State())
	if !strings.Contains(got, "1) items") {
		t.Errorf("after a reset the program is not back at its first screen:\n%s", got)
	}
	if strings.Contains(got, "selected:") {
		t.Errorf("state survived the reset:\n%s", got)
	}
	if !d.Alive() {
		t.Error("the restarted program is not running")
	}
}

// TestTUIResizeReachesTheProgram checks the whole path: the ioctl, the SIGWINCH
// the kernel sends because of it, the program's redraw, and the emulator's own
// dimensions. A size is an input — a program that draws correctly at sixty
// columns and misaligns at thirty has a bug only one of them finds.
func TestTUIResizeReachesTheProgram(t *testing.T) {
	d := newTUI(t, driver.TUIOptions{Cols: 60, Rows: 20})
	if err := d.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	if got := awaitScreen(t, d, "60x20"); !strings.Contains(got, "60x20") {
		t.Fatalf("the program did not see its initial size:\n%s", got)
	}

	send(t, d, "resize 32 12")
	if got := awaitScreen(t, d, "32x12"); !strings.Contains(got, "32x12") {
		t.Errorf("the program was not told about the resize:\n%s", got)
	}
	if s := d.Screen(); s.Cols != 32 || s.Rows != 12 {
		t.Errorf("the emulator is %dx%d", s.Cols, s.Rows)
	}
}

// TestTUIIgnoresAClickTheProgramNeverAskedFor. A mouse report delivered to a
// program that did not enable tracking is not a click: it is an escape sequence
// arriving as ordinary keystrokes, which navigates menus and types characters,
// and makes the same click mean something different every time.
func TestTUIIgnoresAClickTheProgramNeverAskedFor(t *testing.T) {
	d := newTUI(t, driver.TUIOptions{})
	if err := d.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	before := string(d.State())
	send(t, d, "click 5 3")
	if got := string(d.State()); got != before {
		t.Errorf("a click changed a program with no mouse tracking:\nbefore:\n%s\nafter:\n%s",
			before, got)
	}
}

// uiStates is a UISink: what a campaign sees of the interface.
type uiStates struct{ seen []string }

func (u *uiStates) RecordUI(state []byte) { u.seen = append(u.seen, string(state)) }

// TestTUIThroughTheExecutorTier is the claim ADR-0013 rests on: a GUI campaign
// is the ordinary machine with a different executor behind it. Nothing below is
// specific to terminals.
func TestTUIThroughTheExecutorTier(t *testing.T) {
	be := newTUI(t, driver.TUIOptions{})
	out := feedback.NewOutputObserver("output")
	ui := &uiStates{}
	e := executor.NewDriver("tui", be, executor.DriverOptions{Timeout: 20 * time.Second})
	e.Output, e.UI = out, ui
	if err := e.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	defer e.Close()

	// A sequence that ends somewhere, and a sequence that ends somewhere else.
	for _, seq := range []string{
		"key 1\nkey down\n",
		"key 2\n",
	} {
		ek, err := e.Run(t.Context(), executor.Input{Bytes: []byte(seq)},
			[]feedback.Observer{out})
		if err != nil {
			t.Fatal(err)
		}
		if ek != feedback.ExitOK {
			t.Errorf("%q exited %v", seq, ek)
		}
	}
	// The screen the reset left, then one per event: a single state per sequence
	// gives the campaign screens and no transitions, and the transitions are
	// where the signal is.
	if len(ui.seen) != 5 {
		t.Fatalf("the campaign saw %d states for a 2-event sequence and a 1-event one",
			len(ui.seen))
	}
	if !strings.Contains(ui.seen[0], "1) items") {
		t.Errorf("the sequence did not start from the menu:\n%s", ui.seen[0])
	}
	if !strings.Contains(ui.seen[2], "selected: beta") {
		t.Errorf("the first sequence ended at:\n%s", ui.seen[2])
	}
	if !strings.Contains(ui.seen[4], "no settings yet") {
		t.Errorf("the second sequence ended at:\n%s", ui.seen[4])
	}
	// Each sequence restarted the program, which is what makes the second one's
	// state a function of the second one's events alone.
	if e.Executions() != 2 {
		t.Errorf("Executions() = %d", e.Executions())
	}
}

// TestTUIFindsThePlantedBugThroughTheTier is the end-to-end claim: an event
// sequence in a corpus, run by the T7 tier, produces a finding an oracle can
// read.
func TestTUIFindsThePlantedBugThroughTheTier(t *testing.T) {
	be := newTUI(t, driver.TUIOptions{})
	out := feedback.NewOutputObserver("output")
	e := executor.NewDriver("tui", be, executor.DriverOptions{Timeout: 20 * time.Second})
	e.Output = out
	if err := e.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	defer e.Close()

	seq := "key 1\nkey down\nkey down\nkey d\nkey j\n"
	if _, err := e.Run(t.Context(), executor.Input{Bytes: []byte(seq)},
		[]feedback.Observer{out}); err != nil {
		t.Fatal(err)
	}
	if out.ExitCode() == 0 {
		t.Errorf("the sequence that kills the program reported exit 0:\n%s", out.Combined())
	}
	if !strings.Contains(out.Combined(), "panic") {
		t.Errorf("the finding carries no diagnostic:\n%s", out.Combined())
	}
}

func TestTUIReportsAMissingProgram(t *testing.T) {
	if !safety.PTYSupported() {
		t.Skip("no pseudo-terminal support on this host")
	}
	d := driver.NewTUI(safety.NewTrustedSpawner(), driver.TUIOptions{
		Path: filepath.Join(testenv.ReachableDir(t), "does-not-exist"),
	})
	defer d.Close()
	if err := d.Start(t.Context()); err == nil {
		t.Error("starting a program that is not there succeeded")
	}
}
