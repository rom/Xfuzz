package driver_test

import (
	"strings"
	"testing"
	"time"

	"github.com/rom/Xfuzz/internal/driver"
	"github.com/rom/Xfuzz/pkg/executor"
	"github.com/rom/Xfuzz/pkg/feedback"
	"github.com/rom/Xfuzz/pkg/state"
)

// The end of ADR-0013's argument, against a real program: a GUI campaign is
// stateful fuzzing where the states are screens, and it is the same machine.
// Nothing below is specific to terminals except the backend that is plugged in.

type uiCampaign struct {
	e     *executor.Driver
	obs   *state.Observer
	model *state.Model
	fb    *state.Feedback
	out   *feedback.OutputObserver
}

func newUICampaign(t *testing.T) *uiCampaign {
	t.Helper()
	be := newTUI(t, driver.TUIOptions{Cols: 40, Rows: 12})

	c := &uiCampaign{
		obs:   state.NewObserver("ui", state.NewScreenFn()),
		model: state.NewModel(),
		out:   feedback.NewOutputObserver("output"),
	}
	c.fb = state.NewFeedback("ui-state", c.obs, c.model)
	c.e = executor.NewDriver("tui", be, executor.DriverOptions{Timeout: 30 * time.Second})
	c.e.Output, c.e.UI = c.out, c.obs
	if err := c.e.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.e.Close() })
	return c
}

// run executes one event sequence and reports whether the state feedback found
// it interesting.
func (c *uiCampaign) run(t *testing.T, seq string) bool {
	t.Helper()
	obs := []feedback.Observer{c.out, c.obs}
	if _, err := c.e.Run(t.Context(), executor.Input{Bytes: []byte(seq)}, obs); err != nil {
		t.Fatal(err)
	}
	got, _, err := c.fb.IsInteresting(obs, feedback.ExitOK)
	if err != nil {
		t.Fatal(err)
	}
	if got {
		c.fb.Append()
	} else {
		c.fb.Discard()
	}
	return got
}

// TestUIStateFeedbackFindsScreensAndTransitions is the claim: a novel screen and
// a novel move between two known screens are both new coverage, and a walk the
// campaign has already made is not.
func TestUIStateFeedbackFindsScreensAndTransitions(t *testing.T) {
	c := newUICampaign(t)

	if !c.run(t, "key 1\n") {
		t.Fatal("the first sequence found nothing; the campaign has no signal at all")
	}
	if c.run(t, "key 1\n") {
		t.Error("the same sequence was interesting twice")
	}
	if !c.run(t, "key 2\n") {
		t.Error("a screen the campaign had never seen was not interesting")
	}
	// A move between two screens it has each seen separately.
	if !c.run(t, "key 1\nkey enter\n") {
		t.Error("a transition into a new screen was not interesting")
	}

	cov := c.model.Coverage()
	if cov.States < 4 {
		t.Errorf("the campaign found %d screens: %s", cov.States, c.model.Explain(80))
	}
	if cov.Transitions < 4 {
		t.Errorf("the campaign found %d transitions", cov.Transitions)
	}
	// The model keeps an exemplar screen per state, which is what makes a bad
	// normalisation visible rather than a number nobody can act on.
	if ex := c.model.Explain(120); !strings.Contains(ex, "items") {
		t.Errorf("the state model cannot explain itself:\n%s", ex)
	}
}

// TestUIStateNormalisationMergesACounter. The detail screen carries a counter
// that increments on every keystroke. Without normalisation each press is a new
// state and the campaign spends its entire budget on one screen.
func TestUIStateNormalisationMergesACounter(t *testing.T) {
	c := newUICampaign(t)
	c.run(t, "key 1\nkey enter\n")
	before := c.model.Coverage().States

	// Six more keystrokes in the detail screen, each of which changes the
	// counter it draws and nothing else.
	c.run(t, "key 1\nkey enter\nkey a\nkey a\nkey a\nkey a\nkey a\nkey a\n")
	after := c.model.Coverage().States

	if after > before {
		t.Errorf("a counter produced %d new states:\n%s", after-before, c.model.Explain(120))
	}
}

// TestUITrapObjectiveFindsTheUnrecoverableScreen is the second planted bug, and
// the one no crash detector can see: the process is alive, the exit status is
// zero, the screen still looks like a screen, and nothing dismisses it.
func TestUITrapObjectiveFindsTheUnrecoverableScreen(t *testing.T) {
	c := newUICampaign(t)
	trap := feedback.NewUITrapObjective("ui-trap", c.obs)
	trap.MinEntries, trap.MinTail = 2, 3
	// So the finding names the screen rather than its hash, which is the
	// difference between a bug somebody can act on and one filed against
	// "state 7".
	trap.Exemplar = func(l string) (string, bool) {
		b, ok := c.model.Exemplar(state.Label(l))
		return string(b), ok
	}

	// A sequence that goes out and comes back, so the oracle learns that leaving
	// a screen is something this program can do.
	c.run(t, "key 2\nkey escape\n")

	// Into the confirmation, and then four attempts to leave it.
	seq := "key 2\nkey x\nkey escape\nkey q\nkey enter\nkey n\n"
	var found bool
	var f feedback.Finding
	for i := 0; i < 3 && !found; i++ {
		c.run(t, seq)
		var err error
		found, f, err = trap.IsFinding(nil, feedback.ExitOK)
		if err != nil {
			t.Fatal(err)
		}
	}
	if !found {
		t.Fatalf("a screen that escape, q, enter and n all fail to dismiss was not "+
			"reported as unrecoverable.\nstates: %v\nmodel:\n%s",
			c.obs.StateLabels(), c.model.Explain(80))
	}
	if f.Kind != "ui-trap" {
		t.Errorf("kind %q", f.Kind)
	}
	if !strings.Contains(f.Detail, "Reset everything?") {
		t.Errorf("the finding does not show the screen nothing dismisses:\n%s", f.Detail)
	}
	t.Logf("%s\n%s", f.Summary, f.Detail)

	// And the program is still running, which is the whole point.
	if !c.e.Capabilities().Deterministic && string(c.out.Stdout()) == "" {
		t.Error("no screen was recorded")
	}
	if !strings.Contains(string(c.out.Stdout()), "Reset everything?") {
		t.Errorf("the sequence did not end in the confirmation:\n%s", c.out.Stdout())
	}
}

// TestUIUnresponsiveObjectiveFindsTheSameScreenFromTheOtherSide. The trap and
// the hang are different judgements about the same evidence — one asks whether
// anything ever left, the other whether anything changed — and a screen that
// swallows every keystroke answers both.
func TestUIUnresponsiveObjectiveFindsTheSameScreenFromTheOtherSide(t *testing.T) {
	c := newUICampaign(t)
	obj := feedback.NewUIUnresponsiveObjective("ui-hang", c.obs)
	obj.Streak = 4

	c.run(t, "key 2\nkey x\nkey escape\nkey q\nkey enter\nkey n\nkey escape\n")
	found, f, err := obj.IsFinding(nil, feedback.ExitOK)
	if err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Fatalf("five keystrokes into a screen that ignores all of them was not "+
			"reported.\nstates: %v", c.obs.StateLabels())
	}
	if f.Kind != "ui-unresponsive" {
		t.Errorf("kind %q", f.Kind)
	}
	t.Logf("%s", f.Summary)
}

// TestUIDiagnosticObjectiveFindsTheCrashOnScreen closes the loop on the first
// planted bug from the oracle's side: the tier records the screen as the
// execution's output, and the diagnostic is read from there.
func TestUIDiagnosticObjectiveFindsTheCrashOnScreen(t *testing.T) {
	c := newUICampaign(t)
	obj := feedback.NewUIDiagnosticObjective("ui-diagnostic", c.out)

	c.run(t, "key 1\nkey down\nkey down\nkey d\n")
	found, f, err := obj.IsFinding(nil, feedback.ExitOK)
	if err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Fatalf("the stack trace the program left on screen was not reported:\n%s",
			c.out.Stdout())
	}
	if f.Kind != "ui-diagnostic" {
		t.Errorf("kind %q", f.Kind)
	}
	if len(f.Frames) == 0 {
		t.Error("no frames were recovered from the screen; the finding will not bucket")
	}
	t.Logf("%s\nframes: %v", f.Summary, f.Frames)
}
