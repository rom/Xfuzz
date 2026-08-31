package learn

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// A simulated protocol, so the learner can be checked against a machine whose
// answer is known.
//
// Checked against a *known* machine and not merely "it produced something": the
// property that matters is that the learner recovers the target's behaviour
// exactly, and a test that only asserted the state count would pass for a
// machine with the right shape and the wrong transitions.

// login is the protocol every stateful example is: nothing works until you
// authenticate, and logging out puts it back.
type login struct {
	// calls counts membership queries and seen records which words were asked,
	// so a test can assert the learner never asks the same question twice.
	calls int
	seen  map[string]int
}

func (l *login) Output(_ context.Context, word []string) ([]string, error) {
	l.calls++
	if l.seen == nil {
		l.seen = map[string]int{}
	}
	l.seen[strings.Join(word, ",")]++
	out := make([]string, 0, len(word))
	authed := false
	for _, in := range word {
		switch {
		case in == "auth" && !authed:
			authed = true
			out = append(out, "ok")
		case in == "auth":
			out = append(out, "already")
		case in == "logout" && authed:
			authed = false
			out = append(out, "bye")
		case in == "logout":
			out = append(out, "denied")
		case authed:
			out = append(out, "data")
		default:
			out = append(out, "denied")
		}
	}
	return out, nil
}

var loginAlphabet = []string{"auth", "read", "logout"}

func TestLearnRecoversASimpleProtocol(t *testing.T) {
	target := &login{}
	m, rep, err := Learn(context.Background(), target, Options{
		Alphabet: loginAlphabet, Seed: 1,
	})
	if err != nil {
		t.Fatalf("Learn: %v", err)
	}
	if rep.Partial {
		t.Fatalf("learning did not settle: %s", rep.Why)
	}
	if m.States() != 2 {
		t.Fatalf("learned %d states, want 2 (before and after authentication):\n%s",
			m.States(), m.Dot())
	}

	// The machine must agree with the target on words it was never asked, which
	// is the whole claim: a model that only reproduced its own queries would be
	// a lookup table.
	check := &login{}
	for _, word := range [][]string{
		{"read"},
		{"auth", "read"},
		{"auth", "auth", "read"},
		{"auth", "logout", "read"},
		{"logout", "auth", "read", "read", "logout", "read"},
		{"read", "read", "auth", "read"},
	} {
		want, _ := check.Output(context.Background(), word)
		got := m.Run(word)
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("on %v the machine says %v, the target says %v", word, got, want)
		}
	}
}

func TestLearnFindsAnAccessSequenceForEveryState(t *testing.T) {
	// This is what makes a learned machine useful to a fuzzer rather than
	// merely interesting: a recipe for reaching each state, which is what a
	// stateful campaign is short of.
	target := &login{}
	m, _, err := Learn(context.Background(), target, Options{Alphabet: loginAlphabet, Seed: 2})
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Access) != m.States() {
		t.Fatalf("%d access sequences for %d states", len(m.Access), m.States())
	}
	check := &login{}
	for i, access := range m.Access {
		// Running the access word must land in the state it claims.
		s := 0
		for _, a := range access {
			s = m.Trans[s][a]
		}
		if s != i {
			t.Errorf("the access word for state %d reaches state %d", i, s)
		}
		// And it must be a word the target actually accepts, not a fabrication.
		if _, err := check.Output(context.Background(), access); err != nil {
			t.Errorf("access word %v: %v", access, err)
		}
	}
	if len(m.Reachable()[0]) != 0 {
		t.Error("the shortest access sequence is not the empty word, which is the " +
			"initial state and always reachable")
	}
}

// counter is a target with no finite machine: its answer depends on how many
// messages it has seen. A learner without a bound would chase it forever.
type counter struct{}

func (counter) Output(_ context.Context, word []string) ([]string, error) {
	out := make([]string, 0, len(word))
	for i := range word {
		out = append(out, string(rune('a'+i%26)))
	}
	return out, nil
}

func TestLearnStopsOnATargetWithNoFiniteMachine(t *testing.T) {
	m, rep, err := Learn(context.Background(), counter{}, Options{
		Alphabet: []string{"x", "y"}, MaxStates: 6, Seed: 3,
	})
	if err != nil {
		t.Fatalf("Learn: %v", err)
	}
	if !rep.Partial {
		t.Fatal("a target whose state depends on a counter was learned exactly")
	}
	if m == nil || m.States() == 0 {
		t.Fatal("nothing was returned; a partial machine is still worth having")
	}
	if !strings.Contains(rep.Why, "counter") && !strings.Contains(rep.Why, "maximum") {
		t.Errorf("the report does not say why it stopped: %q", rep.Why)
	}
}

func TestLearnCachesRatherThanReasking(t *testing.T) {
	// Every query is a reset and a session. The table asks the same words over
	// and over as it grows, and a learner that did not cache would cost an
	// order of magnitude more against a target where that actually hurts.
	target := &login{}
	_, rep, err := Learn(context.Background(), target, Options{Alphabet: loginAlphabet, Seed: 4})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Cached == 0 {
		t.Fatal("no query was answered from the cache")
	}
	if target.calls != rep.Queries {
		t.Errorf("the target saw %d queries, the report says %d", target.calls, rep.Queries)
	}
	// The property the cache exists for: no word ever reaches the target twice.
	// The table asks the same prefixes repeatedly as it grows, and the
	// equivalence search draws words the table already covered.
	for word, n := range target.seen {
		if n > 1 {
			t.Errorf("the word %q was run against the target %d times", word, n)
		}
	}
}

func TestLearnIsReproducible(t *testing.T) {
	// Two runs of the same campaign against the same target must ask the same
	// questions and reach the same machine (ASR-0008).
	first, r1, err := Learn(context.Background(), &login{}, Options{Alphabet: loginAlphabet, Seed: 99})
	if err != nil {
		t.Fatal(err)
	}
	second, r2, err := Learn(context.Background(), &login{}, Options{Alphabet: loginAlphabet, Seed: 99})
	if err != nil {
		t.Fatal(err)
	}
	if first.Dot() != second.Dot() {
		t.Fatalf("two runs learned different machines:\n%s\n---\n%s", first.Dot(), second.Dot())
	}
	if r1.Queries != r2.Queries {
		t.Errorf("the two runs asked %d and %d questions", r1.Queries, r2.Queries)
	}
}

// refusing stops answering part-way, which is what a target that crashed does.
type refusing struct{ after int }

func (r *refusing) Output(_ context.Context, word []string) ([]string, error) {
	if r.after <= 0 {
		return nil, errors.New("the target stopped answering")
	}
	r.after--
	out := make([]string, len(word))
	for i := range out {
		out[i] = "ok"
	}
	return out, nil
}

func TestLearnReturnsWhatItHasWhenTheTargetDies(t *testing.T) {
	// A target that dies mid-learning is a campaign that should still start
	// from what was learned, and be told the machine is incomplete.
	m, rep, err := Learn(context.Background(), &refusing{after: 3}, Options{
		Alphabet: []string{"a", "b"}, Seed: 5,
	})
	if err != nil {
		t.Fatalf("a dead target was reported as a learning failure: %v", err)
	}
	if !rep.Partial {
		t.Fatal("a machine learned from a target that stopped answering was called complete")
	}
	if !strings.Contains(rep.Why, "stopped answering") {
		t.Errorf("the report does not say what happened: %q", rep.Why)
	}
	if m == nil {
		t.Fatal("nothing was returned")
	}
}

func TestLearnRefusesAnEmptyAlphabet(t *testing.T) {
	if _, _, err := Learn(context.Background(), &login{}, Options{}); !errors.Is(err, ErrNoAlphabet) {
		t.Fatalf("an empty alphabet was accepted: %v", err)
	}
}

func TestLearnRejectsATeacherThatMiscounts(t *testing.T) {
	// A Mealy teacher answers exactly one output per input. One that does not
	// is a harness bug, and treating its answer as data would produce a machine
	// describing nothing.
	_, rep, err := Learn(context.Background(), shortTeacher{}, Options{
		Alphabet: []string{"a"}, Seed: 6,
	})
	if err != nil {
		t.Fatalf("Learn: %v", err)
	}
	if !rep.Partial || !strings.Contains(rep.Why, "one output per input") {
		t.Fatalf("a miscounting teacher was accepted: %+v", rep)
	}
}

type shortTeacher struct{}

func (shortTeacher) Output(_ context.Context, word []string) ([]string, error) {
	return nil, nil
}

func TestDotIsStable(t *testing.T) {
	// A diagram that reordered itself between runs could not be compared with
	// the last one.
	m, _, err := Learn(context.Background(), &login{}, Options{Alphabet: loginAlphabet, Seed: 7})
	if err != nil {
		t.Fatal(err)
	}
	first := m.Dot()
	for i := 0; i < 5; i++ {
		if m.Dot() != first {
			t.Fatal("Dot rendered the same machine two different ways")
		}
	}
	if !strings.Contains(first, "digraph learned") || !strings.Contains(first, "auth / ok") {
		t.Errorf("the diagram does not describe the machine:\n%s", first)
	}
}

// twoStep is the machine that separates a working Mealy learner from a broken
// one: two of its states agree on every single symbol and differ only two
// symbols later.
//
// s0 -a-> s1 -a-> s2, and from s2 a "b" answers "boom" where everywhere else it
// answers "ok". So s0 and s1 have identical rows while the columns are the
// alphabet, and no number of new *rows* separates them — only a longer column
// does. A learner that answered a counterexample by adding access sequences
// would find the same counterexample for ever, and, because every word in it is
// already cached, would spin without spending a query.
type twoStep struct{}

func (twoStep) Output(_ context.Context, word []string) ([]string, error) {
	out := make([]string, 0, len(word))
	s := 0
	for _, in := range word {
		switch {
		case in == "a" && s == 0:
			s, out = 1, append(out, "ok")
		case in == "a" && s == 1:
			s, out = 2, append(out, "ok")
		case in == "a":
			out = append(out, "ok")
		case in == "b" && s == 2:
			s, out = 0, append(out, "boom")
		default:
			s, out = 0, append(out, "ok")
		}
	}
	return out, nil
}

func TestLearnSeparatesStatesOnlyALongSuffixDistinguishes(t *testing.T) {
	m, rep, err := Learn(context.Background(), twoStep{}, Options{
		Alphabet: []string{"a", "b"}, Seed: 21,
		// Small on purpose: with the wrong counterexample handling this test
		// does not fail, it hangs, and a bound turns that into a failure.
		MaxQueries: 3000, MaxStates: 8,
	})
	if err != nil {
		t.Fatalf("Learn: %v", err)
	}
	if rep.Partial {
		t.Fatalf("learning did not settle: %s", rep.Why)
	}
	if m.States() != 3 {
		t.Fatalf("learned %d states, want 3:\n%s", m.States(), m.Dot())
	}
	check := twoStep{}
	for _, word := range [][]string{
		{"a", "a", "b"}, {"a", "b"}, {"b", "a", "a", "b"}, {"a", "a", "a", "b"},
	} {
		want, _ := check.Output(context.Background(), word)
		if got := m.Run(word); strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("on %v the machine says %v, the target says %v", word, got, want)
		}
	}
}
