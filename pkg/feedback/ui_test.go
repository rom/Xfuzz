package feedback_test

import (
	"strings"
	"testing"

	"github.com/rom/Xfuzz/pkg/feedback"
)

// An interface fails in three ways that leave the process alive and the exit
// status zero: it shows a stack trace and carries on, it stops repainting and
// leaves a screen that looks like a screen, and it reaches somewhere with no way
// out. Each oracle here has one job, including the job of not reporting the
// ordinary case.

// fakeTrace is a StateTrace: what a state observer says about one execution.
type fakeTrace struct{ labels []string }

func (f *fakeTrace) StateLabels() []string { return f.labels }

func TestUIDiagnosticObjectiveReportsARuntimeErrorOnScreen(t *testing.T) {
	obs := feedback.NewOutputObserver("output")
	obj := feedback.NewUIDiagnosticObjective("ui", obs)

	for _, tc := range []struct {
		name   string
		screen string
		want   bool
	}{
		{"an ordinary screen", "tui_menu\n--------\n1) items\n2) settings", false},
		{"go", "panic: runtime error: index out of range [3]\n\ngoroutine 1 [running]:", true},
		{"python", "Traceback (most recent call last):\n  File \"x.py\", line 4", true},
		{"java", "Exception in thread \"main\" java.lang.NullPointerException", true},
		{"rust", "thread 'main' panicked at src/main.rs:12:5", true},
		{"c++", "terminate called after throwing an instance of 'std::out_of_range'", true},
		{"assert", "app: main.c:42: draw: Assertion `row < rows' failed.", true},
		{"sanitizer", "==1234==ERROR: AddressSanitizer: heap-buffer-overflow", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			obs.Record([]byte(tc.screen), nil, 0, 0)
			got, f, err := obj.IsFinding(nil, feedback.ExitOK)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("reported %v, want %v for:\n%s", got, tc.want, tc.screen)
			}
			if got && f.Kind != "ui-diagnostic" {
				t.Errorf("kind %q", f.Kind)
			}
		})
	}
}

// TestUIDiagnosticObjectiveReportsOnce. A program left showing its stack trace
// shows it on every sequence that ends there, and a campaign that filed each one
// would bury its own finding.
func TestUIDiagnosticObjectiveReportsOnce(t *testing.T) {
	obs := feedback.NewOutputObserver("output")
	obj := feedback.NewUIDiagnosticObjective("ui", obs)
	screen := "panic: bad index\n\ngoroutine 1 [running]:\nmain.draw()\n\t/x/main.go:12"

	obs.Record([]byte(screen), nil, 0, 0)
	got, f, _ := obj.IsFinding(nil, feedback.ExitOK)
	if !got {
		t.Fatal("the first occurrence was not reported")
	}
	if len(f.Frames) == 0 {
		t.Error("no frames were recovered; the finding will not bucket with its own kind")
	}
	obs.Record([]byte(screen), nil, 0, 0)
	if got, _, _ := obj.IsFinding(nil, feedback.ExitOK); got {
		t.Error("the same diagnostic was reported twice")
	}
	// A different one still is.
	obs.Record([]byte("panic: a different failure"), nil, 0, 0)
	if got, _, _ := obj.IsFinding(nil, feedback.ExitOK); !got {
		t.Error("deduplication silenced a different diagnostic")
	}
}

// TestUIUnresponsiveObjective is the failure with no other symptom: the process
// is alive, nothing crashed, the last screen is still there, and every keystroke
// since has gone nowhere.
func TestUIUnresponsiveObjectiveReportsAnInterfaceThatStopped(t *testing.T) {
	tr := &fakeTrace{}
	obj := feedback.NewUIUnresponsiveObjective("ui", tr)
	obj.Streak = 4

	// Responsive: every event changed the screen.
	tr.labels = []string{"start", "a", "b", "c", "d", "e", "f", "g"}
	if got, _, _ := obj.IsFinding(nil, feedback.ExitOK); got {
		t.Error("a responsive sequence was reported")
	}

	// Responsive, then stuck.
	tr.labels = []string{"start", "a", "b", "c", "c", "c", "c", "c", "c"}
	got, f, err := obj.IsFinding(nil, feedback.ExitOK)
	if err != nil {
		t.Fatal(err)
	}
	if !got {
		t.Fatal("an interface that ignored six consecutive events was not reported")
	}
	if f.Kind != "ui-unresponsive" {
		t.Errorf("kind %q", f.Kind)
	}
	if !strings.Contains(f.Summary, "c") {
		t.Errorf("summary %q does not name the state", f.Summary)
	}
}

// TestUIUnresponsiveObjectiveIgnoresAScreenThatNeverChanged is what separates a
// hang from a program that simply ignores keys it does not bind. A screen that
// was never responsive is not evidence that it stopped being.
func TestUIUnresponsiveObjectiveIgnoresAScreenThatNeverChanged(t *testing.T) {
	tr := &fakeTrace{labels: []string{"start", "a", "a", "a", "a", "a", "a", "a", "a", "a"}}
	obj := feedback.NewUIUnresponsiveObjective("ui", tr)
	obj.Streak = 4
	if got, _, _ := obj.IsFinding(nil, feedback.ExitOK); got {
		t.Error("a static screen was reported as an interface that stopped responding")
	}
}

func TestUIUnresponsiveObjectiveIgnoresAShortRun(t *testing.T) {
	tr := &fakeTrace{labels: []string{"start", "a", "b", "b", "b"}}
	obj := feedback.NewUIUnresponsiveObjective("ui", tr)
	obj.Streak = 8
	if got, _, _ := obj.IsFinding(nil, feedback.ExitOK); got {
		t.Error("three unchanged events was reported as a hang")
	}
}

// TestUITrapObjective is the state with no path back: a modal nothing dismisses,
// a mode with no exit. A person hitting one closes the program and files a bug;
// a fuzzer without this oracle records a normal execution and moves on.
func TestUITrapObjectiveReportsAStateNothingLeaves(t *testing.T) {
	tr := &fakeTrace{}
	obj := feedback.NewUITrapObjective("ui", tr)
	obj.MinEntries, obj.MinTail = 2, 3

	run := func(labels ...string) (bool, feedback.Finding) {
		tr.labels = labels
		got, f, err := obj.IsFinding(nil, feedback.ExitOK)
		if err != nil {
			t.Fatal(err)
		}
		return got, f
	}

	// A sequence that goes out and comes home. "menu" is home: it is what the
	// reset leaves showing.
	if got, _ := run("start", "menu", "list", "detail", "list", "menu"); got {
		t.Error("a sequence that returned home was reported")
	}
	if obj.Home() != "menu" {
		t.Fatalf("home is %q", obj.Home())
	}
	// A first visit to the modal. Not enough evidence yet.
	if got, _ := run("start", "menu", "list", "modal", "modal", "modal", "modal"); got {
		t.Error("a state was called a trap on its first visit")
	}
	// A second, with several events spent trying to leave.
	got, f := run("start", "menu", "list", "modal", "modal", "modal", "modal")
	if !got {
		t.Fatal("a state entered twice, never left, with four events spent in it, was not reported")
	}
	if f.Kind != "ui-trap" {
		t.Errorf("kind %q", f.Kind)
	}
	if !strings.Contains(f.Summary, "modal") || !strings.Contains(f.Summary, "menu") {
		t.Errorf("summary %q names neither the trap nor home", f.Summary)
	}
}

// TestUITrapObjectiveForgivesAStateAnythingHasEverLeft. Every sequence ends
// somewhere; a screen a sequence happened to stop on is not a trap, and the only
// way to tell the two apart is to have seen something get back.
func TestUITrapObjectiveForgivesAStateAnythingHasEverLeft(t *testing.T) {
	tr := &fakeTrace{}
	obj := feedback.NewUITrapObjective("ui", tr)
	obj.MinEntries, obj.MinTail = 2, 3

	run := func(labels ...string) bool {
		tr.labels = labels
		got, _, _ := obj.IsFinding(nil, feedback.ExitOK)
		return got
	}
	run("start", "menu", "help", "menu")                         // help has a way out
	run("start", "menu", "list", "help", "help", "help", "help") // and a run in it
	if run("start", "menu", "list", "help", "help", "help", "help") {
		t.Error("a state something had escaped from was reported as a trap")
	}
	if !obj.Escaped("help") {
		t.Error("the escape was not recorded")
	}
}

func TestUITrapObjectiveIgnoresAShortStay(t *testing.T) {
	tr := &fakeTrace{}
	obj := feedback.NewUITrapObjective("ui", tr)
	obj.MinEntries, obj.MinTail = 1, 4
	tr.labels = []string{"start", "menu", "list", "end"}
	if got, _, _ := obj.IsFinding(nil, feedback.ExitOK); got {
		t.Error("one event after arriving was enough to call a state a trap")
	}
}

func TestUITrapObjectiveSaysNothingAboutHome(t *testing.T) {
	tr := &fakeTrace{}
	obj := feedback.NewUITrapObjective("ui", tr)
	obj.MinEntries, obj.MinTail = 1, 1
	for i := 0; i < 5; i++ {
		tr.labels = []string{"start", "menu", "menu", "menu", "menu"}
		if got, _, _ := obj.IsFinding(nil, feedback.ExitOK); got {
			t.Fatal("the state every sequence starts and ends in was called a trap")
		}
	}
}
