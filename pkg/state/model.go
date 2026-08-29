package state

import (
	"fmt"
	"strings"
	"sync"
)

// Model is a target's protocol state machine: what it can be doing, and which
// moves between those things are legal.
//
// Declared and inferred models are the same object, deliberately (ADR-0006). A
// campaign can start with nothing declared and let the model fill in from what
// the target says, then declare the parts inference gets wrong, without changing
// anything downstream. What a declaration adds is not a different model but an
// expectation: a transition outside a declared model is itself a finding-shaped
// event, because the target accepted a move its own protocol forbids.
type Model struct {
	mu sync.Mutex

	// declared holds what the campaign said the protocol is. Empty means
	// "everything observed is legal", which is the inferred case.
	declaredStates map[Label]bool
	declaredMoves  map[Transition]bool

	states      map[Label]int
	transitions map[Transition]int

	// exemplar keeps the first response that produced each label.
	//
	// The answer to "why does this campaign have four hundred states". Without
	// it a bad clustering is a number nobody can act on; with it, two exemplars
	// side by side show immediately which normalisation is missing, which is
	// what ADR-0006 means by inference being inspectable.
	exemplar map[Label][]byte

	// illegal counts transitions the declared model does not permit.
	illegal map[Transition]int
}

// NewModel returns an empty model: everything is inferred and nothing is
// declared illegal.
func NewModel() *Model {
	return &Model{
		states:      map[Label]int{},
		transitions: map[Transition]int{},
		exemplar:    map[Label][]byte{},
		illegal:     map[Transition]int{},
	}
}

// Declare fixes the states and transitions the protocol is supposed to have.
//
// The states are taken from the transitions as well as the list, so a
// declaration only has to name its moves.
func (m *Model) Declare(states []Label, moves []Transition) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.declaredStates == nil {
		m.declaredStates = map[Label]bool{}
		m.declaredMoves = map[Transition]bool{}
	}
	m.declaredStates[Start] = true
	for _, s := range states {
		m.declaredStates[s] = true
	}
	for _, t := range moves {
		m.declaredMoves[t] = true
		m.declaredStates[t.From] = true
		m.declaredStates[t.To] = true
	}
}

// IsDeclared reports whether the model carries an expectation at all.
func (m *Model) IsDeclared() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.declaredMoves) > 0
}

// Novelty is what a trace added to the model.
type Novelty struct {
	// NewStates and NewTransitions are the counts this trace contributed.
	NewStates      int
	NewTransitions int

	// Illegal counts transitions a declared model does not permit. They are
	// reported separately from novelty because they mean something different: a
	// new transition is exploration, an illegal one is the target doing
	// something its protocol says it will not.
	Illegal []Transition
}

// Any reports whether the trace was interesting.
func (n Novelty) Any() bool { return n.NewStates > 0 || n.NewTransitions > 0 }

// Inspect reports what a trace would add, without recording it.
//
// Separate from Record because feedback has to be able to ask "is this
// interesting" and only afterwards be told whether to keep it. A model that
// folded every trace in as it judged it would find each state interesting once
// and then never again, including when the composition it sits in rejected the
// input (see feedback.Feedback).
func (m *Model) Inspect(t *Trace) Novelty {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.inspect(t)
}

func (m *Model) inspect(t *Trace) Novelty {
	var n Novelty
	// Within one trace as well as against the model: a session that reaches the
	// same new state twice found one state, not two.
	seenStates := map[Label]bool{}
	seenMoves := map[Transition]bool{}

	for _, s := range t.States {
		if s == Start {
			continue
		}
		if m.states[s] == 0 && !seenStates[s] {
			seenStates[s] = true
			n.NewStates++
		}
	}
	for _, tr := range t.Transitions() {
		if m.transitions[tr] == 0 && !seenMoves[tr] {
			seenMoves[tr] = true
			n.NewTransitions++
		}
		if len(m.declaredMoves) > 0 && !m.declaredMoves[tr] {
			n.Illegal = append(n.Illegal, tr)
		}
	}
	return n
}

// Record folds a trace into the model and returns what it added.
func (m *Model) Record(t *Trace, exemplars map[Label][]byte) Novelty {
	m.mu.Lock()
	defer m.mu.Unlock()

	n := m.inspect(t)
	for _, s := range t.States {
		if s == Start {
			continue
		}
		m.states[s]++
		if _, ok := m.exemplar[s]; !ok {
			if ex, have := exemplars[s]; have {
				m.exemplar[s] = append([]byte(nil), ex...)
			}
		}
	}
	for _, tr := range t.Transitions() {
		m.transitions[tr]++
	}
	for _, tr := range n.Illegal {
		m.illegal[tr]++
	}
	return n
}

// Coverage is what the campaign has explored of the protocol.
type Coverage struct {
	States      int
	Transitions int

	// DeclaredStates and DeclaredTransitions are what the campaign said exists,
	// or zero when nothing was declared. Reported alongside the observed counts
	// so that "23 states" can be read as progress rather than as a bare number.
	DeclaredStates      int
	DeclaredTransitions int

	// Illegal counts distinct transitions outside a declared model.
	Illegal int
}

// Coverage returns the campaign's state coverage.
func (m *Model) Coverage() Coverage {
	m.mu.Lock()
	defer m.mu.Unlock()
	return Coverage{
		States:              len(m.states),
		Transitions:         len(m.transitions),
		DeclaredStates:      len(m.declaredStates),
		DeclaredTransitions: len(m.declaredMoves),
		Illegal:             len(m.illegal),
	}
}

// States returns every state seen, in a stable order, with visit counts.
func (m *Model) States() ([]Label, map[Label]int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	counts := make(map[Label]int, len(m.states))
	for k, v := range m.states {
		counts[k] = v
	}
	return sortedLabels(m.states), counts
}

// Transitions returns every transition seen, in a stable order, with counts.
func (m *Model) Transitions() ([]Transition, map[Transition]int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	counts := make(map[Transition]int, len(m.transitions))
	for k, v := range m.transitions {
		counts[k] = v
	}
	return sortedTransitions(m.transitions), counts
}

// Illegal returns the transitions a declared model does not permit, with counts.
func (m *Model) Illegal() ([]Transition, map[Transition]int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	counts := make(map[Transition]int, len(m.illegal))
	for k, v := range m.illegal {
		counts[k] = v
	}
	return sortedTransitions(m.illegal), counts
}

// Exemplar returns the first response that produced a label.
func (m *Model) Exemplar(l Label) ([]byte, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, ok := m.exemplar[l]
	return b, ok
}

// Rarest returns the states visited least often, fewest first.
//
// What the scheduler biases toward. A state reached once in a million sessions
// is where the unexplored protocol is; a state reached in every session is the
// idle loop.
func (m *Model) Rarest(n int) []Label {
	labels, counts := m.States()
	// Stable: sortedLabels already ordered them, so equal counts keep that
	// order rather than whatever the sort happens to do.
	for i := 1; i < len(labels); i++ {
		for j := i; j > 0 && counts[labels[j]] < counts[labels[j-1]]; j-- {
			labels[j], labels[j-1] = labels[j-1], labels[j]
		}
	}
	if n > 0 && len(labels) > n {
		labels = labels[:n]
	}
	return labels
}

// Explain renders the model as a person reads it.
//
// The state graph in text, for the CLI and for a finding report. The exemplars
// are included because a state label is a hash and a hash explains nothing:
// seeing what the target actually said is how somebody decides whether the
// clustering is right.
func (m *Model) Explain(maxExemplar int) string {
	labels, counts := m.States()
	moves, moveCounts := m.Transitions()
	illegal, _ := m.Illegal()

	var b strings.Builder
	fmt.Fprintf(&b, "states      %d\n", len(labels))
	for _, l := range labels {
		fmt.Fprintf(&b, "  %-14s %8d visit(s)", l, counts[l])
		if ex, ok := m.Exemplar(l); ok && maxExemplar > 0 {
			fmt.Fprintf(&b, "  %q", excerpt(ex, maxExemplar))
		}
		b.WriteString("\n")
	}
	fmt.Fprintf(&b, "transitions %d\n", len(moves))
	for _, t := range moves {
		fmt.Fprintf(&b, "  %-24s %8d\n", t, moveCounts[t])
	}
	if len(illegal) > 0 {
		fmt.Fprintf(&b, "outside the declared model %d\n", len(illegal))
		for _, t := range illegal {
			fmt.Fprintf(&b, "  %s\n", t)
		}
	}
	return b.String()
}

// excerpt renders a response for a human, printably and briefly.
//
// Line endings and tabs are left as themselves: the caller quotes the result
// with %q, which escapes them once and legibly. Escaping them here as well
// produced "A first\\r\\n", which reads as a bug in the tool rather than as the
// target's own reply.
func excerpt(b []byte, n int) string {
	if len(b) > n {
		b = b[:n]
	}
	out := make([]rune, 0, len(b))
	for _, c := range b {
		switch {
		case c == '\n' || c == '\r' || c == '\t':
			out = append(out, rune(c))
		case c < 0x20 || c > 0x7e:
			out = append(out, '.')
		default:
			out = append(out, rune(c))
		}
	}
	return string(out)
}
