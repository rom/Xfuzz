package driver

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rom/Xfuzz/internal/atspi"
	"github.com/rom/Xfuzz/internal/safety"
	"github.com/rom/Xfuzz/internal/testenv"
	"github.com/rom/Xfuzz/pkg/executor"
)

// guiFixture starts the GTK target under the desktop driver.
func guiFixture(t *testing.T) *GUI {
	t.Helper()
	python := testenv.Desktop(t)
	script := filepath.Join(testenv.RepoRoot(t), "testdata", "targets", "gui", "gtk_form.py")

	spawner := safety.NewSpawner()
	// The application needs the display and the session bus, which are in this
	// process's environment and not in the campaign file. A desktop campaign
	// inherits them the same way.
	spawner.Sandbox = &safety.Sandbox{Network: true}

	d := NewGUI(spawner, GUIOptions{
		Path:         python,
		Args:         []string{python, script},
		StartTimeout: 30 * time.Second,
		Settle:       150 * time.Millisecond,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	t.Cleanup(cancel)
	if err := d.Start(ctx); err != nil {
		t.Fatalf("starting the application: %v", err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}

// widgetCentre returns the middle of a named widget, in the window-relative
// coordinates a click event carries.
//
// Looked up rather than hard-coded, because a toolkit lays a form out to suit
// its theme and a test that guessed pixels would be a test of this machine's
// font. A campaign clicks wherever the mutator says, which is the point of the
// tier; a test has to hit what it means to hit.
func widgetCentre(t *testing.T, d *GUI, name string) (int, int) {
	t.Helper()
	s := d.cur
	ox, oy, _ := s.windowOrigin()
	var found func(r atspi.Ref, depth int) (int, int, bool)
	found = func(r atspi.Ref, depth int) (int, int, bool) {
		if depth > 8 {
			return 0, 0, false
		}
		if label, err := s.conn.Label(r); err == nil && label == name {
			x, y, w, h, err := s.conn.Extents(r)
			if err == nil && w > 0 && h > 0 {
				return int(x - ox + w/2), int(y - oy + h/2), true
			}
		}
		kids, err := s.conn.Children(r)
		if err != nil {
			return 0, 0, false
		}
		for _, k := range kids {
			if x, y, ok := found(k, depth+1); ok {
				return x, y, true
			}
		}
		return 0, 0, false
	}
	x, y, ok := found(s.app, 0)
	if !ok {
		t.Fatalf("no widget named %q in the tree:\n%s", name, d.State())
	}
	return x, y
}

func guiSend(t *testing.T, d *GUI, evs ...executor.Event) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	for _, e := range evs {
		if err := d.Send(ctx, e); err != nil {
			t.Fatalf("%v: %v", e, err)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func TestGUIReadsTheApplicationsTree(t *testing.T) {
	d := guiFixture(t)
	state := string(d.State())
	for _, want := range []string{"frame", "text#query", "push button#go", "label#status"} {
		if !strings.Contains(state, want) {
			t.Errorf("the tree does not contain %q:\n%s", want, state)
		}
	}
	if !strings.Contains(state, "[empty]") {
		t.Errorf("an empty entry is not reported as empty:\n%s", state)
	}
}

func TestGUIStateSeparatesScreensButNotKeystrokes(t *testing.T) {
	// The property the state model rests on, asserted for a third backend.
	// Typing must not create a new state — otherwise every sequence reaches
	// somewhere new and the model learns nothing — and activating something
	// must.
	d := guiFixture(t)
	before := string(d.State())

	ex, ey := widgetCentre(t, d, "query")
	guiSend(t, d,
		executor.Event{Kind: executor.EventClick, X: ex, Y: ey},
		executor.Event{Kind: executor.EventText, Text: "hello"},
	)
	typed := string(d.State())
	if !strings.Contains(typed, "[set]") {
		t.Fatalf("the text never reached the field, so this test proves nothing:\n%s", typed)
	}
	if strings.Contains(typed, "hello") {
		t.Errorf("the typed text reached the fingerprint, so every keystroke is a "+
			"new state:\n%s", typed)
	}

	bx, by := widgetCentre(t, d, "go")
	guiSend(t, d, executor.Event{Kind: executor.EventClick, X: bx, Y: by})
	opened := string(d.State())
	if opened == before {
		t.Errorf("activating the button did not change the state, so the campaign "+
			"is blind to the transition:\n%s", opened)
	}
	if !strings.Contains(opened, "panel open") {
		t.Errorf("the panel's text is not in the tree:\n%s", opened)
	}
}

func TestGUISkipsWhatAtSpiCannotDo(t *testing.T) {
	// Two things a mutator produces constantly and this backend cannot deliver.
	// Both are properties of the input rather than failures of the harness, and
	// reporting either as a harness failure ends the campaign.
	d := guiFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	for _, e := range []executor.Event{
		{Kind: executor.EventKey, Text: "eykm-226"},
		{Kind: executor.EventKey, Text: "ctrl-c"},
		{Kind: executor.EventResize, X: 400, Y: 300},
	} {
		err := d.Send(ctx, e)
		if err == nil {
			t.Errorf("%v was accepted", e)
			continue
		}
		if !isSkip(err) {
			t.Errorf("%v was reported as a harness failure: %v", e, err)
		}
	}
	if !d.Alive() {
		t.Fatal("the application died over an undeliverable event")
	}
}

func TestGUIResetRestartsTheApplication(t *testing.T) {
	// The only reset a desktop application has. Without it every sequence
	// starts wherever the last one left off and no finding reproduces.
	d := guiFixture(t)
	ex, ey := widgetCentre(t, d, "query")
	bx, by := widgetCentre(t, d, "go")
	guiSend(t, d,
		executor.Event{Kind: executor.EventClick, X: ex, Y: ey},
		executor.Event{Kind: executor.EventText, Text: "left behind"},
		executor.Event{Kind: executor.EventClick, X: bx, Y: by},
	)
	dirty := string(d.State())
	if !strings.Contains(dirty, "panel open") {
		t.Fatalf("the button was never activated, so this test proves nothing:\n%s", dirty)
	}

	if err := d.Reset(); err != nil {
		t.Fatalf("resetting: %v", err)
	}
	clean := string(d.State())
	if strings.Contains(clean, "panel open") {
		t.Errorf("the reset left the previous sequence's screen in place:\n%s", clean)
	}
	if !strings.Contains(clean, "[empty]") {
		t.Errorf("the reset left text in the entry:\n%s", clean)
	}
}

func TestGUIKeysymsCoverTheSharedVocabulary(t *testing.T) {
	// A corpus is a corpus: a sequence recorded against a terminal or a browser
	// has to mean the same thing here.
	for _, name := range []string{
		"enter", "tab", "escape", "space", "backspace", "delete", "insert",
		"home", "end", "pageup", "pagedown", "up", "down", "left", "right",
		"f1", "f12", "a", "7",
	} {
		if _, err := GUIKeysym(name); err != nil {
			t.Errorf("the desktop backend does not know %q: %v", name, err)
		}
	}
}

func TestGUIRefusesAModifierRatherThanApproximatingIt(t *testing.T) {
	// Sending the unmodified key instead would deliver a keystroke nobody asked
	// for, and a finding from it would not reproduce by hand.
	for _, name := range []string{"ctrl-c", "alt-f4", "meta-x"} {
		if sym, err := GUIKeysym(name); err == nil {
			t.Errorf("GUIKeysym(%q) = %#x, want a refusal", name, sym)
		}
	}
	// Shift on a printable key is its upper case, which is not a held modifier.
	if sym, err := GUIKeysym("shift-a"); err != nil || sym != 'A' {
		t.Errorf("GUIKeysym(shift-a) = %#x, %v; want 'A'", sym, err)
	}
}
