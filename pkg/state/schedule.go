package state

import (
	"github.com/rom/Xfuzz/pkg/corpus"
	"github.com/rom/Xfuzz/pkg/ir"
	"github.com/rom/Xfuzz/pkg/rng"
)

// Scheduler chooses which part of a session to fuzz.
//
// The split ADR-0006 calls for: pick a state to target, then pick which message
// in the session to mutate. It matters because the alternative — mutating a
// uniformly random message of a uniformly random session — spends nearly all of
// its budget on the handshake, which is the part that must stay valid for
// anything past it to be reachable at all. A session is a funnel, and a fuzzer
// that does not know it is a funnel keeps kicking the entrance.
//
// The two choices are separable on purpose. Which state to aim for is a question
// about the protocol and is answered from the model; which message to change to
// get there is a question about this session and is answered from its trace.
type Scheduler struct {
	model *Model

	// Explore is the probability of aiming for a rare state rather than
	// mutating wherever the session happens to allow it. Neither extreme is
	// right: always aiming means the campaign only ever perturbs the tail of
	// each session, and never aiming is the funnel problem above.
	Explore float64

	// RareStates is how many of the least-visited states are candidates.
	RareStates int

	// TailBias is the probability of mutating at or after the targeted state
	// rather than before it.
	//
	// High, because the point of reaching a state is to explore *past* it: a
	// mutation before the target state usually breaks the path that got there,
	// and the session lands somewhere already explored. It is not 1 because
	// breaking the path is occasionally exactly right — that is how a campaign
	// discovers the target accepts a message out of order.
	TailBias float64
}

// Default scheduling constants. Named rather than buried: they are tuning
// parameters and stateful campaigns will need them tuned.
const (
	DefaultExplore    = 0.7
	DefaultRareStates = 8
	DefaultTailBias   = 0.8
)

// NewScheduler returns a scheduler with the default bias.
func NewScheduler(m *Model) *Scheduler {
	if m == nil {
		m = NewModel()
	}
	return &Scheduler{
		model:      m,
		Explore:    DefaultExplore,
		RareStates: DefaultRareStates,
		TailBias:   DefaultTailBias,
	}
}

// Choice is where in a session to mutate, and why.
type Choice struct {
	// Message is the index of the message to mutate, or -1 for "anywhere",
	// which is what a session with no usable trace gets.
	Message int

	// Target is the state the choice was aiming for, empty when it was not
	// aiming at one. Recorded so a corpus entry's provenance can say what the
	// scheduler was trying to do, which is the difference between a campaign
	// whose choices can be reviewed and one whose choices cannot.
	Target Label
}

// Pick chooses which message of a session to mutate.
//
// trace is the session's own trace from when it was last executed, and may be
// nil for an entry that has never run — a fresh seed, or one imported from a
// corpus. That case is not an error: it means there is nothing to aim with, so
// the choice is "anywhere", and the session will have a trace the next time.
func (s *Scheduler) Pick(trace *Trace, messages int, r *rng.Rand) Choice {
	if messages <= 0 {
		return Choice{Message: -1}
	}
	if trace == nil || trace.Len() == 0 || !r.Chance(s.Explore) {
		return Choice{Message: r.Intn(messages)}
	}

	target := s.pickState(r)
	if target == "" {
		return Choice{Message: r.Intn(messages)}
	}

	at := trace.IndexOf(target)
	if at < 0 {
		// This session never reached the state we are aiming for, so there is
		// no informed place to cut. Mutating at random would be a coin flip
		// dressed up as a decision; saying so is better.
		return Choice{Message: r.Intn(messages)}
	}
	if at >= messages {
		at = messages - 1
	}

	if at == 0 || r.Chance(s.TailBias) {
		// At or after the state: explore onwards from it. Also the only option
		// when the state was the first thing the target said, since there is no
		// message before that one.
		return Choice{Message: at + r.Intn(messages-at), Target: target}
	}
	// Strictly before it: try to reach the state a different way, or not at
	// all. The two branches partition the session, so the bias means what it
	// says rather than being diluted by an overlap at the boundary.
	return Choice{Message: r.Intn(at), Target: target}
}

// pickState chooses a state to aim for, biased toward the rarely visited.
func (s *Scheduler) pickState(r *rng.Rand) Label {
	rare := s.model.Rarest(s.RareStates)
	if len(rare) == 0 {
		return ""
	}
	// Uniform among the rarest rather than weighted by how rare: the counts are
	// visit counts, and weighting by them would concentrate everything on the
	// single least-visited state, which is usually an error path that leads
	// nowhere. Being in the tail is the signal; the ordering within it is noise.
	return rare[r.Intn(len(rare))]
}

// Messages returns how many messages a session input holds.
//
// A session is a Repeat node (ADR-0005), so this is its child count. A
// non-session input is a session of one, which is what makes the same scheduler
// correct for stateless campaigns rather than something to switch off.
func Messages(n *ir.Node) int {
	if n == nil {
		return 0
	}
	if n.Kind == ir.KindRepeat {
		return len(n.Children)
	}
	return 1
}

// SessionOf returns the Repeat node holding a session's messages, or nil.
func SessionOf(n *ir.Node) *ir.Node {
	if n != nil && n.Kind == ir.KindRepeat {
		return n
	}
	return nil
}

// TraceStore keeps the trace each corpus entry last produced.
//
// Kept beside the corpus rather than inside a Testcase because a trace is a
// property of an execution, not of an input: the same session against a target
// in a different mood traverses different states, and burying that in the corpus
// entry would make the entry's identity depend on when it last ran. The store is
// also the natural place for it to be dropped, since it is a cache and a
// campaign that loses it loses only guidance, never a testcase.
type TraceStore struct {
	traces map[corpus.Digest]*Trace
	max    int
}

// DefaultTraceStoreSize bounds how many traces are retained.
const DefaultTraceStoreSize = 4096

// NewTraceStore returns a bounded trace cache.
func NewTraceStore() *TraceStore {
	return &TraceStore{traces: map[corpus.Digest]*Trace{}, max: DefaultTraceStoreSize}
}

// Put records the trace an entry produced.
func (s *TraceStore) Put(id corpus.Digest, t *Trace) {
	if s == nil || t == nil {
		return
	}
	if len(s.traces) >= s.max {
		// Dropped wholesale rather than evicted one by one. This is a cache
		// over a corpus that only grows, so any eviction policy cheap enough to
		// run here is close to arbitrary; clearing is arbitrary too and is
		// honest about it, and the traces refill as entries are fuzzed.
		clear(s.traces)
	}
	s.traces[id] = copyTrace(t)
}

// Get returns an entry's last trace, or nil.
func (s *TraceStore) Get(id corpus.Digest) *Trace {
	if s == nil {
		return nil
	}
	return s.traces[id]
}

// Len reports how many traces are held.
func (s *TraceStore) Len() int {
	if s == nil {
		return 0
	}
	return len(s.traces)
}
