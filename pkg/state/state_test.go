package state

import (
	"strings"
	"testing"

	"github.com/rom/Xfuzz/pkg/corpus"
	"github.com/rom/Xfuzz/pkg/feedback"
	"github.com/rom/Xfuzz/pkg/rng"
)

// A trace is a sequence of states with one more entry than it has transitions,
// because it starts somewhere before the first message.
func TestTraceCountsTransitionsNotStates(t *testing.T) {
	tr := NewTrace()
	if tr.Len() != 0 || tr.Current() != Start {
		t.Fatalf("a fresh trace is %v with %d transitions", tr.Current(), tr.Len())
	}
	tr.Observe("greeting")
	tr.Observe("auth-ok")

	if got := tr.Len(); got != 2 {
		t.Errorf("two responses made %d transitions, want 2", got)
	}
	if got := tr.Current(); got != "auth-ok" {
		t.Errorf("current = %v, want auth-ok", got)
	}
	want := []Transition{{Start, "greeting"}, {"greeting", "auth-ok"}}
	got := tr.Transitions()
	if len(got) != len(want) {
		t.Fatalf("transitions = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("transition %d = %v, want %v", i, got[i], want[i])
		}
	}
}

// IndexOf answers the scheduler's question — which message got us here — rather
// than where the state sits in the trace, which is one higher.
func TestTraceIndexOfIsAMessageIndex(t *testing.T) {
	tr := NewTrace()
	tr.Observe("a") // message 0
	tr.Observe("b") // message 1
	tr.Observe("c") // message 2

	for _, tc := range []struct {
		label Label
		want  int
	}{{"a", 0}, {"b", 1}, {"c", 2}, {"nowhere", -1}} {
		if got := tr.IndexOf(tc.label); got != tc.want {
			t.Errorf("IndexOf(%v) = %d, want %d", tc.label, got, tc.want)
		}
	}
	// Start is not produced by any message, so asking for it is meaningless
	// rather than message zero.
	if got := tr.IndexOf(Start); got != -1 {
		t.Errorf("IndexOf(start) = %d; no message produced it", got)
	}
}

func TestStatusFnReadsTheLeadingToken(t *testing.T) {
	for _, tc := range []struct {
		name string
		fn   StateFn
		resp string
		want Label
	}{
		{"smtp", NewStatusFn(), "250 OK\r\n", "250"},
		{"ftp multiline", NewStatusFn(), "220-welcome\r\n220 ready\r\n", "220-welcome"},
		{"redis", NewStatusFn(), "+OK\r\n", "+OK"},
		{"http", &StatusFn{Prefix: "HTTP/1.1"}, "HTTP/1.1 404 Not Found\r\n", "404"},
		{"http wrong version", &StatusFn{Prefix: "HTTP/1.1"}, "HTTP/2 200\r\n", ""},
		{"empty", NewStatusFn(), "", ""},
		// Prose is not a status. Taking it as one gives every distinct error
		// message its own state, which is the failure ADR-0006 warns about.
		{"prose", NewStatusFn(), "unfortunately that did not work\r\n", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.fn.Label([]byte(tc.resp)); got != tc.want {
				t.Errorf("Label(%q) = %q, want %q", tc.resp, got, tc.want)
			}
		})
	}
}

// The fingerprint has to survive the parts of a response that vary for reasons
// unrelated to state, and still separate responses that differ in shape.
//
// Both halves matter and they pull against each other: normalising too little
// gives every nonce its own state, normalising too much merges states that are
// genuinely distinct. This pins the balance the defaults strike.
func TestFingerprintIgnoresNoiseAndKeepsShape(t *testing.T) {
	fn := NewFingerprintFn()

	same := []string{
		"SESSION 4815 READY\r\n",
		"SESSION 162342 READY\r\n",
		"SESSION 0 READY\r\n",
	}
	first := fn.Label([]byte(same[0]))
	for _, s := range same[1:] {
		if got := fn.Label([]byte(s)); got != first {
			t.Errorf("a session id changed the state: %q gave %q, %q gave %q",
				same[0], first, s, got)
		}
	}

	// The same shape with a different word is a different state: the word is
	// what the target is telling us.
	if got := fn.Label([]byte("SESSION 4815 DENIED\r\n")); got == first {
		t.Errorf("READY and DENIED share the state %q", got)
	}
	// And an echo of the client's own input does not make a state.
	a := fn.Label([]byte(`ERR unknown command "frobnicate"` + "\r\n"))
	b := fn.Label([]byte(`ERR unknown command "wibble"` + "\r\n"))
	if a != b {
		t.Errorf("an echoed argument changed the state: %q against %q", a, b)
	}
}

func TestModelCountsStatesAndTransitionsSeparately(t *testing.T) {
	m := NewModel()

	tr := NewTrace()
	tr.Observe("a")
	tr.Observe("b")
	if n := m.Record(tr, nil); n.NewStates != 2 || n.NewTransitions != 2 {
		t.Fatalf("first trace added %+v, want 2 states and 2 transitions", n)
	}

	// Same states, different order: no new states, but a new move — which is
	// the whole reason transitions are counted separately.
	tr2 := NewTrace()
	tr2.Observe("b")
	tr2.Observe("a")
	n := m.Record(tr2, nil)
	if n.NewStates != 0 {
		t.Errorf("re-visiting known states reported %d new", n.NewStates)
	}
	if n.NewTransitions != 2 {
		t.Errorf("two new moves reported %d", n.NewTransitions)
	}

	cov := m.Coverage()
	if cov.States != 2 || cov.Transitions != 4 {
		t.Errorf("coverage = %+v, want 2 states and 4 transitions", cov)
	}
}

// A trace that reaches the same new state twice found one state.
func TestModelDoesNotDoubleCountWithinOneTrace(t *testing.T) {
	m := NewModel()
	tr := NewTrace()
	tr.Observe("a")
	tr.Observe("b")
	tr.Observe("a")
	if n := m.Record(tr, nil); n.NewStates != 2 {
		t.Errorf("a trace visiting a, b, a reported %d new states, want 2", n.NewStates)
	}
}

// A declared model turns an unexpected move into a reportable event rather than
// ordinary exploration.
func TestDeclaredModelFlagsMovesItDoesNotPermit(t *testing.T) {
	m := NewModel()
	m.Declare(nil, []Transition{{Start, "greeting"}, {"greeting", "auth-ok"}})

	legal := NewTrace()
	legal.Observe("greeting")
	legal.Observe("auth-ok")
	if n := m.Record(legal, nil); len(n.Illegal) != 0 {
		t.Errorf("a declared path was reported illegal: %v", n.Illegal)
	}

	// Straight to authenticated without the greeting: the target accepted a
	// move its own protocol forbids, which is what this is for.
	skipped := NewTrace()
	skipped.Observe("auth-ok")
	n := m.Record(skipped, nil)
	if len(n.Illegal) != 1 || n.Illegal[0] != (Transition{Start, "auth-ok"}) {
		t.Errorf("illegal = %v, want one start->auth-ok", n.Illegal)
	}
	if m.Coverage().Illegal != 1 {
		t.Errorf("coverage did not record the illegal move: %+v", m.Coverage())
	}
}

// Inspect must not record, or a feedback that judges an input and is then
// overruled marks the state explored by a session nobody kept.
func TestInspectDoesNotRecord(t *testing.T) {
	m := NewModel()
	tr := NewTrace()
	tr.Observe("a")

	if n := m.Inspect(tr); !n.Any() {
		t.Fatal("a new state was not reported as new")
	}
	if got := m.Coverage().States; got != 0 {
		t.Errorf("Inspect recorded %d states; it must only look", got)
	}
	if n := m.Inspect(tr); !n.Any() {
		t.Error("the second Inspect found nothing new, so the first recorded")
	}
}

// The feedback's contract: interesting once, and only committed when told.
func TestFeedbackCommitsOnlyOnAppend(t *testing.T) {
	obs := NewObserver("state", NewStatusFn())
	m := NewModel()
	fb := NewFeedback("state", obs, m)

	obs.Pre()
	obs.Response([]byte("220 hello\r\n"))

	ok, score, err := fb.IsInteresting(nil, feedback.ExitOK)
	if err != nil || !ok {
		t.Fatalf("a new state was not interesting: ok=%v err=%v", ok, err)
	}
	if score.NewSignal != 2 {
		t.Errorf("score.NewSignal = %d, want 2 (one state, one transition)", score.NewSignal)
	}

	// Overruled by the composition: the model must be untouched, so the next
	// session that reaches the state is still admitted.
	fb.Discard()
	if got := m.Coverage().States; got != 0 {
		t.Fatalf("Discard left %d states in the model", got)
	}

	ok, _, _ = fb.IsInteresting(nil, feedback.ExitOK)
	if !ok {
		t.Fatal("after Discard the same state was no longer interesting")
	}
	fb.Append()
	if got := m.Coverage().States; got != 1 {
		t.Fatalf("Append recorded %d states, want 1", got)
	}
	if ok, _, _ := fb.IsInteresting(nil, feedback.ExitOK); ok {
		t.Error("a state already in the model was still interesting")
	}
}

// A fault ends the session in a state of its own, so a crash is attributable to
// where the target was rather than merged into the last thing it said.
func TestObserverRecordsAFaultAsAState(t *testing.T) {
	obs := NewObserver("state", NewStatusFn())
	obs.Pre()
	obs.Response([]byte("250 ok\r\n"))
	if err := obs.Post(feedback.ExitCrash); err != nil {
		t.Fatal(err)
	}
	if got := obs.Trace().Current(); got != Closed {
		t.Errorf("after a crash the trace ends at %q, want %q", got, Closed)
	}
}

func TestObserverKeepsAnExemplarPerState(t *testing.T) {
	obs := NewObserver("state", NewStatusFn())
	obs.Pre()
	obs.Response([]byte("250 first\r\n"))
	obs.Response([]byte("250 second\r\n"))

	ex := obs.Exemplars()
	if got := string(ex["250"]); got != "250 first\r\n" {
		t.Errorf("exemplar = %q, want the first response that produced the label", got)
	}
}

// The scheduler aims past the state it targeted, because the point of reaching
// a state is exploring beyond it.
func TestSchedulerAimsPastTheTargetedState(t *testing.T) {
	m := NewModel()
	tr := NewTrace()
	tr.Observe("greeting") // message 0
	tr.Observe("auth-ok")  // message 1
	tr.Observe("data")     // message 2
	m.Record(tr, nil)

	s := NewScheduler(m)
	s.Explore = 1 // always aim, so the distribution under test is the aiming one
	r := rng.New(0xB0A7)

	var aimed, atOrAfter int
	for i := 0; i < 2000; i++ {
		c := s.Pick(tr, 3, "", r)
		if c.Target == "" {
			continue
		}
		aimed++
		if at := tr.IndexOf(c.Target); c.Message >= at {
			atOrAfter++
		}
	}
	if aimed == 0 {
		t.Fatal("the scheduler never aimed at a state")
	}
	if ratio := float64(atOrAfter) / float64(aimed); ratio < 0.7 || ratio > 0.9 {
		t.Errorf("%.0f%% of aimed choices landed at or after the target; "+
			"the tail bias is %.0f%%", 100*ratio, 100*s.TailBias)
	}
}

// An entry that has never run has no trace, and that is ordinary rather than an
// error: it means there is nothing to aim with.
func TestSchedulerFallsBackWithoutATrace(t *testing.T) {
	s := NewScheduler(NewModel())
	r := rng.New(1)
	for i := 0; i < 100; i++ {
		c := s.Pick(nil, 4, "", r)
		if c.Message < 0 || c.Message >= 4 {
			t.Fatalf("Pick with no trace chose message %d of 4", c.Message)
		}
		if c.Target != "" {
			t.Fatalf("Pick with no trace claimed to aim at %q", c.Target)
		}
	}
	if c := s.Pick(nil, 0, "", r); c.Message != -1 {
		t.Errorf("an empty session chose message %d, want -1", c.Message)
	}
}

// Reports must not depend on map iteration order, or two runs of one campaign
// produce different output and nobody can diff them.
func TestExplainIsStable(t *testing.T) {
	m := NewModel()
	tr := NewTrace()
	for _, l := range []Label{"zeta", "alpha", "mu", "beta"} {
		tr.Observe(l)
	}
	m.Record(tr, map[Label][]byte{"alpha": []byte("A first\r\n")})

	first := m.Explain(16)
	for i := 0; i < 20; i++ {
		if got := m.Explain(16); got != first {
			t.Fatalf("Explain differs between calls:\n%s\n---\n%s", first, got)
		}
	}
	if !strings.Contains(first, `"A first\r\n"`) {
		t.Errorf("Explain does not show the exemplar:\n%s", first)
	}
	// Alphabetical, so a state is findable in a long list.
	if i, j := strings.Index(first, "alpha"), strings.Index(first, "beta"); i > j {
		t.Errorf("states are not in a stable order:\n%s", first)
	}
}

func TestTraceStoreIsBounded(t *testing.T) {
	s := NewTraceStore()
	s.max = 4
	tr := NewTrace()
	tr.Observe("a")

	var d [32]byte
	for i := 0; i < 20; i++ {
		d[0] = byte(i)
		s.Put(d, tr)
	}
	if s.Len() > 4 {
		t.Errorf("the store holds %d traces against a bound of 4", s.Len())
	}
	// And what it returns is a copy: a caller mutating the live trace must not
	// rewrite what the store handed out earlier.
	d[0] = 19
	got := s.Get(d)
	if got == nil {
		t.Fatal("the last trace stored was not retrievable")
	}
	tr.Observe("b")
	if got.Len() != 1 {
		t.Errorf("the stored trace followed a later mutation: %v", got)
	}
}

// Seed selection is the half of ADR-0006's scheduler that decides *which*
// session gets a budget. Without it the state choice is inert: the entry comes
// from coverage, most entries never reach the state, and the message choice
// falls back to "anywhere" — which is the funnel problem the scheduler exists
// to solve.
func TestSchedulerPicksSeedsThatReachTheState(t *testing.T) {
	m := NewModel()

	reaches := NewTrace()
	reaches.Observe("greeting")
	reaches.Observe("authenticated")
	m.Record(reaches, nil)

	stops := NewTrace()
	stops.Observe("greeting")
	m.Record(stops, nil)
	// "greeting" is now the common state and "authenticated" the rare one.
	for i := 0; i < 10; i++ {
		m.Record(stops, nil)
	}

	c := corpus.New()
	traces := NewTraceStore()
	for i := 0; i < 20; i++ {
		tc := &corpus.Testcase{ID: corpus.Digest{byte(i)}, Bytes: []byte{byte(i)}}
		if !c.Add(tc) {
			t.Fatalf("entry %d was not admitted", i)
		}
		// One entry in twenty reaches the rare state, which is roughly the
		// proportion measured on a real stateful campaign's corpus.
		if i == 7 {
			traces.Put(tc.ID, reaches)
		} else {
			traces.Put(tc.ID, stops)
		}
	}

	s := NewScheduler(m)
	s.Explore = 1
	r := rng.New(0x5EED)

	var aimed, atSeven int
	for i := 0; i < 500; i++ {
		aim, ok := s.PickSeed(traces, c, r)
		if !ok {
			continue
		}
		aimed++
		if aim.State == "authenticated" {
			if aim.Seed != 7 {
				t.Fatalf("aiming at the rare state chose entry %d, which never reaches it", aim.Seed)
			}
			atSeven++
		}
		if aim.State == "" {
			t.Fatal("PickSeed reported a choice with no state behind it")
		}
	}
	if aimed == 0 {
		t.Fatal("the scheduler never made a state-informed seed choice")
	}
	if atSeven == 0 {
		t.Error("the rare state was never aimed at, so seed selection never used the model")
	}
}

// A seed chosen for reaching a state, then mutated at a message chosen for a
// different state, is a seed chosen at random with extra steps. Pick honours the
// aim it is given rather than drawing again.
func TestSchedulerHonoursTheSeedsAim(t *testing.T) {
	m := NewModel()
	tr := NewTrace()
	tr.Observe("greeting")      // message 0
	tr.Observe("authenticated") // message 1
	tr.Observe("stored")        // message 2
	m.Record(tr, nil)
	// Make "greeting" look rare, so an unaimed Pick would prefer it and the two
	// cases are distinguishable.
	for i := 0; i < 50; i++ {
		other := NewTrace()
		other.Observe("authenticated")
		other.Observe("stored")
		m.Record(other, nil)
	}

	s := NewScheduler(m)
	s.Explore = 1
	r := rng.New(7)
	for i := 0; i < 200; i++ {
		c := s.Pick(tr, 3, "authenticated", r)
		if c.Target != "authenticated" {
			t.Fatalf("Pick aimed at %q despite being handed \"authenticated\"", c.Target)
		}
	}
}

// PickSeed must decline rather than guess: a campaign with no traces, or aiming
// at a state nothing reaches, has to leave the choice to coverage.
func TestSchedulerDeclinesWithoutCandidates(t *testing.T) {
	s := NewScheduler(NewModel())
	s.Explore = 1
	r := rng.New(3)

	if _, ok := s.PickSeed(NewTraceStore(), corpus.New(), r); ok {
		t.Error("PickSeed claimed a choice on an empty corpus")
	}

	m := NewModel()
	reached := NewTrace()
	reached.Observe("only-state")
	m.Record(reached, nil)

	c := corpus.New()
	tc := &corpus.Testcase{ID: corpus.Digest{1}, Bytes: []byte{1}}
	c.Add(tc)
	traces := NewTraceStore()
	traces.Put(tc.ID, NewTrace()) // ran, but reached nothing

	s = NewScheduler(m)
	s.Explore = 1
	for i := 0; i < 50; i++ {
		if _, ok := s.PickSeed(traces, c, r); ok {
			t.Fatal("PickSeed chose an entry that never reached the state it aimed at")
		}
	}
}
