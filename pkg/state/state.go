package state

import (
	"fmt"
	"sort"
	"strings"
)

// Label is an observed protocol state.
//
// A string rather than an integer because a label has to be readable in a
// finding, a report, and the console's state graph. "auth-ok" tells somebody
// what the target was doing when it crashed; state 7 does not, and a bug
// reported against state 7 is a bug nobody can act on (ADR-0006).
type Label string

// Unknown is the label for a response no state function could classify.
//
// Named rather than empty so that "the target said something we could not read"
// is visible in the state graph instead of silently merging into whatever
// preceded it. A campaign whose graph is mostly Unknown has a state function
// that does not fit its protocol, which is a diagnosis rather than a mystery.
const Unknown Label = "?"

// Closed is the label for a target that ended the connection.
//
// A state of its own because it is one: a protocol that hangs up is telling you
// something, and a session that reaches it has explored a path that a session
// which kept talking did not.
const Closed Label = "closed"

// Start is the label a session is in before the target has said anything.
const Start Label = "start"

// Transition is a move between two states, which is the thing a stateful
// campaign is actually exploring.
//
// States alone are a poor measure: a target with five states has twenty-five
// possible ordered pairs, and the bugs live in the pairs nobody expected to be
// reachable — the reset that works mid-transaction, the second handshake on an
// authenticated connection.
type Transition struct{ From, To Label }

func (t Transition) String() string { return string(t.From) + "->" + string(t.To) }

// Trace is the sequence of states one session passed through.
//
// It always begins at Start, so a trace of n responses has n+1 entries and
// exactly n transitions. Keeping the implicit first state explicit means the
// first response is an ordinary transition rather than a special case, and the
// first message of a session is as schedulable as any other.
type Trace struct {
	States []Label
}

// NewTrace returns a trace positioned at Start.
func NewTrace() *Trace { return &Trace{States: []Label{Start}} }

// Observe appends a state to the trace.
func (t *Trace) Observe(l Label) {
	if l == "" {
		l = Unknown
	}
	t.States = append(t.States, l)
}

// Reset returns the trace to Start, reusing its storage.
func (t *Trace) Reset() { t.States = append(t.States[:0], Start) }

// Current returns the state the session is in now.
func (t *Trace) Current() Label {
	if len(t.States) == 0 {
		return Start
	}
	return t.States[len(t.States)-1]
}

// Len returns how many transitions the trace holds.
func (t *Trace) Len() int {
	if len(t.States) == 0 {
		return 0
	}
	return len(t.States) - 1
}

// Transitions returns the moves the trace made, in order.
func (t *Trace) Transitions() []Transition {
	if len(t.States) < 2 {
		return nil
	}
	out := make([]Transition, 0, len(t.States)-1)
	for i := 1; i < len(t.States); i++ {
		out = append(out, Transition{From: t.States[i-1], To: t.States[i]})
	}
	return out
}

// Reached reports whether the trace visited a state.
func (t *Trace) Reached(l Label) bool {
	for _, s := range t.States {
		if s == l {
			return true
		}
	}
	return false
}

// IndexOf returns the message index that first produced a state, or -1.
//
// Message index, not state index: the scheduler asks "which message do I mutate
// to explore past this state", and the answer is the one that got there. The
// trace's first entry is Start, which no message produced, so the arithmetic is
// off by one and is done here rather than at every call site.
func (t *Trace) IndexOf(l Label) int {
	for i := 1; i < len(t.States); i++ {
		if t.States[i] == l {
			return i - 1
		}
	}
	return -1
}

func (t *Trace) String() string {
	parts := make([]string, len(t.States))
	for i, s := range t.States {
		parts[i] = string(s)
	}
	return strings.Join(parts, " -> ")
}

// sortedLabels returns labels in a stable order.
//
// Every report that lists states goes through this. Map iteration order must
// never reach a report, or two runs of the same campaign produce different
// output and nobody can diff them (ASR-0008).
func sortedLabels(m map[Label]int) []Label {
	out := make([]Label, 0, len(m))
	for l := range m {
		out = append(out, l)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// sortedTransitions returns transitions in a stable order.
func sortedTransitions(m map[Transition]int) []Transition {
	out := make([]Transition, 0, len(m))
	for t := range m {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].From != out[j].From {
			return out[i].From < out[j].From
		}
		return out[i].To < out[j].To
	})
	return out
}

func (l Label) String() string { return string(l) }

// ErrNoStateFn is returned when state guidance is asked for without a way to
// label a response.
var ErrNoStateFn = fmt.Errorf("state: no state function configured, so responses cannot be labelled")
