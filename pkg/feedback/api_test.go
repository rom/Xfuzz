package feedback_test

import (
	"strings"
	"testing"
	"time"

	"github.com/rom/Xfuzz/pkg/feedback"
)

// A service fails differently from a parser: it answers 500, or answers 200 with
// a body that violates its own contract, or takes four seconds over something
// that took forty milliseconds, or hands identity B an object belonging to
// identity A. None of those is a signal, all of them are bugs, and each oracle
// here has one job — including the job of *not* reporting the ordinary case,
// which is what stops a campaign burying its own findings.

func TestStatusObjectiveReportsServerErrorsAndNotClientOnes(t *testing.T) {
	obs := feedback.NewOutputObserver("output")
	obj := feedback.NewStatusObjective("status", obs)

	for _, tc := range []struct {
		status int
		want   bool
	}{
		{200, false},
		{201, false},
		{400, false}, // the service saying the fuzzer sent nonsense
		{404, false},
		{422, false},
		{429, false},
		{500, true},
		{502, true},
		{503, true},
	} {
		obs.Record([]byte("body"), nil, tc.status, 0)
		got, f, err := obj.IsFinding(nil, feedback.ExitOK)
		if err != nil {
			t.Fatal(err)
		}
		if got != tc.want {
			t.Errorf("status %d reported %v, want %v", tc.status, got, tc.want)
		}
		if got && !strings.Contains(f.Summary, "answered") {
			t.Errorf("status %d: summary %q", tc.status, f.Summary)
		}
	}
}

func TestStatusObjectiveCanBeToldToIgnoreOne(t *testing.T) {
	obs := feedback.NewOutputObserver("output")
	obj := feedback.NewStatusObjective("status", obs)
	obj.Ignore[501] = true

	obs.Record(nil, nil, 501, 0)
	if got, _, _ := obj.IsFinding(nil, feedback.ExitOK); got {
		t.Error("an ignored status was reported")
	}
	obs.Record(nil, nil, 500, 0)
	if got, _, _ := obj.IsFinding(nil, feedback.ExitOK); !got {
		t.Error("ignoring one status silenced the others")
	}
}

// TestSchemaObjectiveReportsATypeChangeAndNotANewField is the distinction that
// makes this oracle usable. Services add fields; a fuzzer that reported every
// one would report a finding for the first response of every endpoint. A field
// whose *type* changed means one code path serialises differently from another,
// which is where this class of bug lives.
func TestSchemaObjectiveReportsATypeChangeAndNotANewField(t *testing.T) {
	obs := feedback.NewOutputObserver("output")
	obj := feedback.NewSchemaObjective("schema", obs)
	obj.Warmup = 2

	feed := func(body string) (bool, feedback.Finding) {
		obs.Record([]byte("HTTP 200\n"+body), nil, 200, 0)
		got, f, err := obj.IsFinding(nil, feedback.ExitOK)
		if err != nil {
			t.Fatal(err)
		}
		return got, f
	}

	feed(`{"id":"a","count":1}`)
	feed(`{"id":"b","count":2}`)
	feed(`{"id":"c","count":3}`)

	// A new field is not a violation.
	if got, f := feed(`{"id":"d","count":4,"extra":"new"}`); got {
		t.Errorf("a new field was reported as a violation: %s", f.Summary)
	}
	// A changed type is.
	got, f := feed(`{"id":"e","count":"five"}`)
	if !got {
		t.Fatal("count changing from a number to a string was not reported")
	}
	if !strings.Contains(f.Summary, "count") {
		t.Errorf("summary %q does not name the field", f.Summary)
	}
	if f.Kind != "schema-violation" {
		t.Errorf("kind %q", f.Kind)
	}

	// And it is reported once, not on every response after it.
	if got, _ := feed(`{"id":"f","count":"six"}`); got {
		t.Error("the same type change was reported twice")
	}
}

func TestSchemaObjectiveSaysNothingBeforeItHasANorm(t *testing.T) {
	obs := feedback.NewOutputObserver("output")
	obj := feedback.NewSchemaObjective("schema", obs)

	obs.Record([]byte(`HTTP 200
{"a":1}`), nil, 200, 0)
	if got, _, _ := obj.IsFinding(nil, feedback.ExitOK); got {
		t.Error("the first response of a campaign was a schema violation")
	}
}

// TestLatencyObjectiveLearnsTheNorm checks the oracle measures against the
// service's own behaviour rather than a threshold somebody guessed. Forty
// milliseconds is alarming for a health check and unremarkable for a report.
func TestLatencyObjectiveLearnsTheNorm(t *testing.T) {
	timing := feedback.NewTimingObserver("timing")
	obj := feedback.NewLatencyObjective("latency", timing)
	obj.Warmup = 8
	obj.Factor = 10

	feed := func(d time.Duration) bool {
		timing.Record(d)
		got, _, err := obj.IsFinding(nil, feedback.ExitOK)
		if err != nil {
			t.Fatal(err)
		}
		return got
	}

	for i := 0; i < 8; i++ {
		if feed(10 * time.Millisecond) {
			t.Fatalf("a finding during warm-up, at response %d", i)
		}
	}
	// Within the norm.
	if feed(30 * time.Millisecond) {
		t.Error("three times the mean was reported as an outlier")
	}
	// Far outside it.
	if !feed(2 * time.Second) {
		t.Error("two hundred times the mean was not reported")
	}
	// And one outlier must not raise the bar for the next.
	if !feed(2 * time.Second) {
		t.Error("the first outlier was folded into the norm, hiding the second")
	}
}

// TestAuthorizationObjectiveIsTheClassCapturesMakeReachable. A capture carries
// identity, so a session recorded as one identity can be replayed with another's
// credentials, and a request that still succeeds is one whose authorization
// check does not exist.
func TestAuthorizationObjectiveReportsAccessThatShouldHaveBeenRefused(t *testing.T) {
	obs := feedback.NewOutputObserver("output")
	obj := feedback.NewAuthorizationObjective("authorization", obs)

	// A session the campaign is making no claim about: an ordinary fuzzing run.
	obj.Expected = feedback.AuthUnknown
	obs.Record(nil, nil, 200, 0)
	if got, _, _ := obj.IsFinding(nil, feedback.ExitOK); got {
		t.Error("an ordinary session was reported as an authorization finding")
	}

	// The owner's own session succeeding is correct.
	obj.Identity, obj.Expected = "alice", feedback.AuthAllowed
	obs.Record(nil, nil, 200, 0)
	if got, _, _ := obj.IsFinding(nil, feedback.ExitOK); got {
		t.Error("the owning identity succeeding was reported")
	}

	// Another identity being refused is correct.
	obj.Identity, obj.Expected = "mallory", feedback.AuthDenied
	obs.Record(nil, nil, 403, 0)
	if got, _, _ := obj.IsFinding(nil, feedback.ExitOK); got {
		t.Error("a refusal was reported as a finding")
	}

	// Another identity succeeding is the bug.
	obs.Record([]byte(`{"secret":"alice's data"}`), nil, 200, 0)
	got, f, err := obj.IsFinding(nil, feedback.ExitOK)
	if err != nil {
		t.Fatal(err)
	}
	if !got {
		t.Fatal("a session replayed as an identity with no access answered 200 and was " +
			"not reported; this is the BOLA/IDOR class and it is invisible to crash fuzzing")
	}
	if f.Kind != "authorization" {
		t.Errorf("kind %q", f.Kind)
	}
	if !strings.Contains(f.Summary, "mallory") {
		t.Errorf("summary %q does not name the identity", f.Summary)
	}
}

// TestAuthorizationObjectiveLearnsWhichEndpointsAreProtected is what stops a
// public endpoint from being reported. A service answering 200 to everyone is
// not a finding, and the only way to tell it from a broken check is to have seen
// the endpoint refuse somebody.
func TestAuthorizationObjectiveLearnsWhichEndpointsAreProtected(t *testing.T) {
	obs := feedback.NewOutputObserver("output")
	obj := feedback.NewAuthorizationObjective("authorization", obs)

	if obj.Protected("/health") {
		t.Error("an endpoint nothing has been observed on is reported as protected")
	}
	obj.Observe("/health", 200)
	if obj.Protected("/health") {
		t.Error("an endpoint that has only ever answered 200 is reported as protected")
	}
	obj.Observe("/items/1", 403)
	if !obj.Protected("/items/1") {
		t.Error("an endpoint that refused an identity is not reported as protected")
	}
}
