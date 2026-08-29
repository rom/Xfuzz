package feedback

import (
	"fmt"
	"strings"
)

// ExitKind is how one execution ended.
//
// It lives here rather than in pkg/executor because the core must not depend on
// how inputs are delivered (ARCHITECTURE section 2); executors import feedback,
// never the reverse.
type ExitKind uint8

// The ways an execution can end.
const (
	ExitOK      ExitKind = iota // the target returned normally
	ExitCrash                   // fatal signal or unhandled fault
	ExitTimeout                 // exceeded its time budget
	ExitOOM                     // exceeded its memory budget
	ExitError                   // the harness failed; not the target's fault
)

var exitNames = [...]string{
	ExitOK: "ok", ExitCrash: "crash", ExitTimeout: "timeout",
	ExitOOM: "oom", ExitError: "error",
}

func (e ExitKind) String() string {
	if int(e) < len(exitNames) && exitNames[e] != "" {
		return exitNames[e]
	}
	return "unknown"
}

// IsFault reports whether the target itself misbehaved, as opposed to the
// harness failing. An ExitError must never be recorded as a finding: reporting
// infrastructure failures as bugs is how a fuzzer loses its credibility.
func (e ExitKind) IsFault() bool {
	return e == ExitCrash || e == ExitTimeout || e == ExitOOM
}

// Observer records raw signal during one execution.
//
// An observer does not judge. Separating recording from interpretation is what
// lets the same coverage map serve a coverage-guided campaign, a directed one,
// and a differential comparison without three copies of the collection code.
type Observer interface {
	// Name identifies the observer so feedbacks can find the one they need.
	Name() string

	// Pre arms the observer immediately before the target runs.
	Pre() error

	// Post harvests after the target returns.
	Post(ExitKind) error

	// Reset clears accumulated state.
	Reset()
}

// Find returns the observer with the given name.
//
// Feedbacks resolve their observer once at construction where they can; this is
// for the cases where the set is only known per execution.
func Find(obs []Observer, name string) (Observer, bool) {
	for _, o := range obs {
		if o.Name() == name {
			return o, true
		}
	}
	return nil, false
}

// Score is what a feedback reports about an input, beyond a yes or no.
//
// The scheduler consumes a vector rather than a single number so that novelty,
// distance to a target, and a campaign's own custom signal can be weighed
// together (ADR-0007). A scalar here would force directed and coverage-guided
// fuzzing into separate engines.
type Score struct {
	// NewSignal counts previously unseen entries — new edges, new states, new
	// response shapes.
	NewSignal int

	// Novelty is a normalised 0..1 measure of how much of the input's signal was
	// new.
	Novelty float64

	// Distance is how far the execution stayed from a directed campaign's target
	// locations. Lower is closer. Zero when direction is not in use.
	Distance float64

	// Custom carries a campaign-defined value from a plugin or script feedback.
	Custom float64
}

// Add merges another score into this one, for combinators.
func (s *Score) Add(o Score) {
	s.NewSignal += o.NewSignal
	if o.Novelty > s.Novelty {
		s.Novelty = o.Novelty
	}
	if o.Distance > s.Distance {
		s.Distance = o.Distance
	}
	s.Custom += o.Custom
}

// Feedback decides whether an input is worth keeping, and owns the novelty
// state that makes the answer meaningful.
//
// The Append/Discard pair exists because "is this interesting" and "commit that
// it happened" must be separable: an input can be interesting to one feedback in
// a stack and rejected by the composition, and a feedback that had already
// folded the input into its novelty state would then never find it interesting
// again.
type Feedback interface {
	Name() string

	// IsInteresting judges the execution just observed.
	IsInteresting(obs []Observer, ek ExitKind) (bool, Score, error)

	// Append commits the state observed by the most recent IsInteresting.
	Append()

	// Discard rolls that state back.
	Discard()
}

// Finding describes why an execution is a bug.
type Finding struct {
	// Kind is a short classification: crash, hang, oom, sanitizer, oracle.
	Kind string

	// Signal is the fatal signal number, when there was one.
	Signal int

	// Summary is a one-line description.
	Summary string

	// Detail carries the full diagnostic, such as a sanitizer report.
	Detail string

	// Frames are the stack frames, innermost first, when they could be
	// recovered. Bucketing uses these.
	Frames []string
}

func (f Finding) String() string {
	var b strings.Builder
	b.WriteString(f.Kind)
	if f.Summary != "" {
		b.WriteString(": ")
		b.WriteString(f.Summary)
	}
	if f.Signal != 0 {
		fmt.Fprintf(&b, " (signal %d)", f.Signal)
	}
	return b.String()
}

// Objective decides whether an execution is a finding.
//
// It is separate from Feedback because the same observation answers the two
// questions differently: a crash is a finding and usually a poor seed, while a
// novel edge is a good seed and not a finding (ADR-0007).
type Objective interface {
	Name() string
	IsFinding(obs []Observer, ek ExitKind) (bool, Finding, error)
}

// --- the algebra ------------------------------------------------------------

// All is interesting only when every child is. It short-circuits, so order the
// cheap feedbacks first.
func All(fs ...Feedback) Feedback { return &combinator{name: "all", fs: fs, all: true} }

// Any is interesting when at least one child is. It evaluates every child, since
// each must see the execution to maintain its own novelty state.
func Any(fs ...Feedback) Feedback { return &combinator{name: "any", fs: fs} }

// Fast evaluates cheap before expensive and stops as soon as cheap says no. It
// is All with the ordering made explicit at the call site.
func Fast(cheap, expensive Feedback) Feedback {
	return &combinator{name: "fast", fs: []Feedback{cheap, expensive}, all: true}
}

type combinator struct {
	name  string
	fs    []Feedback
	all   bool
	fired []bool // which children reported interesting, for Append
}

func (c *combinator) Name() string {
	parts := make([]string, len(c.fs))
	for i, f := range c.fs {
		parts[i] = f.Name()
	}
	return c.name + "(" + strings.Join(parts, ", ") + ")"
}

func (c *combinator) IsInteresting(obs []Observer, ek ExitKind) (bool, Score, error) {
	if cap(c.fired) < len(c.fs) {
		c.fired = make([]bool, len(c.fs))
	}
	c.fired = c.fired[:len(c.fs)]

	var total Score
	result := c.all
	for i, f := range c.fs {
		c.fired[i] = false
		if c.all && !result {
			// Short-circuited: the remaining children never saw this execution,
			// so they must not be told to commit anything.
			continue
		}
		ok, s, err := f.IsInteresting(obs, ek)
		if err != nil {
			return false, Score{}, fmt.Errorf("%s: %w", f.Name(), err)
		}
		c.fired[i] = ok
		total.Add(s)
		if c.all {
			result = result && ok
		} else {
			result = result || ok
		}
	}
	return result, total, nil
}

// Children implements Composite.
func (c *combinator) Children() []Feedback { return c.fs }

func (c *combinator) Append() {
	for i, f := range c.fs {
		if i < len(c.fired) && c.fired[i] {
			f.Append()
		} else {
			f.Discard()
		}
	}
}

func (c *combinator) Discard() {
	for _, f := range c.fs {
		f.Discard()
	}
}

// Composite is a feedback built from others. Implemented by the combinators, so
// that a caller can reach a specific feedback inside a stack.
type Composite interface {
	// Children returns the feedbacks this one is built from.
	Children() []Feedback
}

// FindFeedback returns the feedback with the given name from within a stack.
//
// Necessary because a feedback stack is a tree and the members a report needs
// are at its leaves: the map feedback holds the coverage counts, and once state
// guidance is composed alongside it the stack root is a combinator rather than
// the map feedback itself. A type assertion on the root then quietly fails, and
// the campaign reports zero coverage while being guided by it — which is
// exactly what happened, and is the kind of defect that survives a long time
// because nothing errors.
func FindFeedback(f Feedback, name string) (Feedback, bool) {
	if f == nil {
		return nil, false
	}
	if f.Name() == name {
		return f, true
	}
	c, ok := f.(Composite)
	if !ok {
		return nil, false
	}
	for _, kid := range c.Children() {
		if found, ok := FindFeedback(kid, name); ok {
			return found, true
		}
	}
	return nil, false
}

// Not inverts a feedback. The inner feedback's novelty state is still
// maintained, so "not covered before" stays meaningful across executions.
func Not(f Feedback) Feedback { return &negate{f: f} }

type negate struct{ f Feedback }

func (n *negate) Name() string { return "not(" + n.f.Name() + ")" }

func (n *negate) IsInteresting(obs []Observer, ek ExitKind) (bool, Score, error) {
	ok, s, err := n.f.IsInteresting(obs, ek)
	return !ok, s, err
}

// Children implements Composite.
func (n *negate) Children() []Feedback { return []Feedback{n.f} }

func (n *negate) Append()  { n.f.Append() }
func (n *negate) Discard() { n.f.Discard() }

// Never is a feedback that admits nothing. It is the identity for Any and the
// way to express a black-box campaign that keeps only its seeds.
func Never() Feedback { return constant{v: false, name: "never"} }

// Always admits everything, which is what a campaign wants when the corpus is
// supplied rather than discovered.
func Always() Feedback { return constant{v: true, name: "always"} }

type constant struct {
	v    bool
	name string
}

func (c constant) Name() string { return c.name }
func (c constant) IsInteresting([]Observer, ExitKind) (bool, Score, error) {
	return c.v, Score{}, nil
}
func (c constant) Append()  {}
func (c constant) Discard() {}
