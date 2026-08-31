package state_test

import (
	"strings"
	"testing"

	"github.com/rom/Xfuzz/pkg/feedback"
	"github.com/rom/Xfuzz/pkg/state"
)

// Screen normalisation is the tuning problem ADR-0013 warns about, with two bad
// failure modes: too aggressive and two distinct screens become one state, too
// weak and every clock tick is a new one. Each case here is one of those two
// failures, made concrete.

func label(t *testing.T, screen string) state.Label {
	t.Helper()
	return state.NewScreenFn().Label([]byte(screen))
}

// TestTheClockIsNotAState is the failure that makes UI-state feedback useless
// without normalisation: a status bar with a clock in it gives a program a new
// state every second, for ever, and the campaign spends its whole budget on
// them.
func TestTheClockIsNotAState(t *testing.T) {
	a := label(t, "inbox\n----\n12 messages\n\n 09:41:02  connected")
	b := label(t, "inbox\n----\n13 messages\n\n 09:41:03  connected")
	if a != b {
		t.Errorf("a clock tick made a new state: %s vs %s", a, b)
	}
}

// TestASpinnerIsNotAState. A spinner changes ten times a second and says nothing
// about which screen is showing.
func TestASpinnerIsNotAState(t *testing.T) {
	frames := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
	first := label(t, "loading "+frames[0]+"\nplease wait")
	for _, f := range frames[1:] {
		if got := label(t, "loading "+f+"\nplease wait"); got != first {
			t.Errorf("spinner frame %q produced state %s, want %s", f, got, first)
		}
	}
	// The ASCII spinner too, but only when it is standing alone: those four
	// characters are also box drawing, path separators and dashes.
	first = label(t, "working | done")
	for _, f := range []string{"/", "-", "\\"} {
		if got := label(t, "working "+f+" done"); got != first {
			t.Errorf("ASCII spinner %q produced state %s, want %s", f, got, first)
		}
	}
}

// TestABoxIsStillAState is the other half of the same claim. Collapsing every
// pipe and dash would erase most of what a TUI draws, and two different dialogs
// would become one state.
func TestABoxIsStillAState(t *testing.T) {
	a := label(t, "|save file?|\n|-----------|")
	b := label(t, "|quit now?|\n|---------|")
	if a == b {
		t.Error("two different dialogs collapsed into one state")
	}
	// A path is content, not decoration.
	if label(t, "opening /etc/hosts") == label(t, "opening /var/log") {
		t.Error("two different paths collapsed into one state")
	}
}

// TestAProgressBarIsNotAState: a download at 30% and the same download at 70%
// are the same screen.
func TestAProgressBarIsNotAState(t *testing.T) {
	a := label(t, "downloading\n[████████░░░░░░░░░░░░] 40%")
	b := label(t, "downloading\n[██████████████░░░░░░] 70%")
	if a != b {
		t.Errorf("a progress bar made a new state: %s vs %s", a, b)
	}
	// And one that has finished is still the same screen, not a third state.
	c := label(t, "downloading\n[████████████████████] 100%")
	if a != c {
		t.Errorf("a completed bar made a new state: %s vs %s", a, c)
	}
}

// TestDifferentScreensAreDifferentStates guards the other failure mode. A
// normalisation that merged these would leave a campaign blind to every
// transition the program can make.
func TestDifferentScreensAreDifferentStates(t *testing.T) {
	screens := []string{
		"menu\n1) items\n2) settings",
		"items\n> alpha\n  beta",
		"items\n  alpha\n> beta",
		"settings\nno settings yet",
		"Reset everything?\n[ yes ]  [ no ]",
	}
	seen := map[state.Label]string{}
	for _, s := range screens {
		l := label(t, s)
		if prev, ok := seen[l]; ok {
			t.Errorf("these two screens share state %s:\n%s\n---\n%s", l, prev, s)
		}
		seen[l] = s
	}
}

func TestScreenFnIsDeterministic(t *testing.T) {
	screen := "inbox\n----\n 09:41:02  ⠹  [███░░░] 50%\nfrom alice"
	first := label(t, screen)
	for i := 0; i < 16; i++ {
		if got := label(t, screen); got != first {
			t.Fatalf("run %d produced %s, want %s", i, got, first)
		}
	}
}

func TestScreenFnName(t *testing.T) {
	if got := state.NewScreenFn().Name(); got != "screen" {
		t.Errorf("Name() = %q", got)
	}
	// The normalisers are nameable, because ADR-0013 requires the normalisation
	// to be inspectable and per-target tunable.
	for _, n := range []string{"digits", "spinner", "runs", "space"} {
		if state.NormaliserNamed(n) == nil {
			t.Errorf("the campaign file cannot name the %q step", n)
		}
	}
}

func TestCollapseRunsLeavesContentAlone(t *testing.T) {
	got := string(state.CollapseRuns{}.Normalise([]byte("aaa bbbb --- ###")))
	if !strings.Contains(got, "aaa") || !strings.Contains(got, "bbbb") {
		t.Errorf("alphanumeric runs were collapsed: %q", got)
	}
	if strings.Contains(got, "---") || strings.Contains(got, "###") {
		t.Errorf("decorative runs survived: %q", got)
	}
}

// TestRecordUIFeedsTheSameModel is ADR-0013's claim held to literally: a
// sequence of screens builds a trace through the same state machine a protocol
// session builds, using the same observer, the same model and the same feedback.
func TestRecordUIFeedsTheSameModel(t *testing.T) {
	obs := state.NewObserver("ui", state.NewScreenFn())
	model := state.NewModel()
	fb := state.NewFeedback("ui-state", obs, model)

	run := func(screens ...string) bool {
		if err := obs.Pre(); err != nil {
			t.Fatal(err)
		}
		for _, s := range screens {
			obs.RecordUI([]byte(s))
		}
		got, _, err := fb.IsInteresting(nil, feedback.ExitOK)
		if err != nil {
			t.Fatal(err)
		}
		if got {
			fb.Append()
		} else {
			fb.Discard()
		}
		return got
	}

	if !run("menu", "items", "detail") {
		t.Fatal("the first sequence of screens was not interesting")
	}
	// The same walk again adds nothing.
	if run("menu", "items", "detail") {
		t.Error("walking the same screens again was interesting")
	}
	// A different order is a different set of transitions, which is the point:
	// a program with a dozen screens has a hundred and forty-four ordered pairs
	// and the bugs live in the ones nobody expected to be reachable.
	if !run("menu", "detail", "items") {
		t.Error("a new transition between known screens was not interesting")
	}

	states, _ := model.States()
	if len(states) != 3 { // the three screens; Start is not one of them
		t.Errorf("the model holds %d states: %v", len(states), states)
	}
	// The model keeps an exemplar per state, which is what makes a bad
	// clustering visible rather than a number nobody can act on.
	if ex := model.Explain(64); !strings.Contains(ex, "menu") {
		t.Errorf("the model cannot explain itself:\n%s", ex)
	}
}
