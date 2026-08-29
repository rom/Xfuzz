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

	// candidates is the scratch list PickSeed builds each call. A worker's
	// scheduler is used by one goroutine, so reusing it keeps seed selection
	// allocation-free on a path that runs once per seed.
	candidates []int
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

// Aim is one scheduling decision: which corpus entry to fuzz, and the state it
// was chosen for.
//
// The two travel together because separating them wastes both. A seed chosen
// for reaching a state, then mutated at a message chosen for a *different*
// state, is a seed chosen at random with extra steps.
type Aim struct {
	// Seed is the corpus index to fuzz.
	Seed int

	// State is what that entry was chosen for, and what the message choice
	// should go on to aim past. Empty when the choice was not state-informed.
	State Label
}

// PickSeed chooses which corpus entry to fuzz, aiming at a state.
//
// ADR-0006's scheduler is three choices, not two: which state to aim for, which
// entry can reach it, and which of that entry's messages to change. Picking the
// state without picking the entry leaves the first choice inert, because the
// entry then comes from the coverage scheduler, and an entry that never reached
// the state has no informed place to cut — so the message choice degrades to
// "anywhere" on nearly every execution.
//
// Measured on stateful_proto: 8 of 148 corpus entries carried a complete
// handshake, so a campaign whose seeds were chosen by coverage alone spent
// roughly 95% of its budget on entries that could not reach the state it was
// aiming at, and the bug behind the handshake stayed unreached.
//
// Reports false when there is no informed choice to make — no trace, no rare
// state, or no entry that reached it. That is the common case early on and it
// is not a failure: the campaign's own scheduler decides, which is what keeps
// coverage in charge of the part of the corpus the state model says nothing
// about yet.
func (s *Scheduler) PickSeed(traces *TraceStore, c *corpus.Corpus, r *rng.Rand) (Aim, bool) {
	if c == nil || c.Len() == 0 || traces.Len() == 0 {
		return Aim{}, false
	}
	if !r.Chance(s.Explore) {
		return Aim{}, false
	}
	target := s.pickState(r)
	if target == "" {
		return Aim{}, false
	}

	s.candidates = s.candidates[:0]
	for i := 0; i < c.Len(); i++ {
		if t := traces.Get(c.At(i).ID); t != nil && t.Reached(target) {
			s.candidates = append(s.candidates, i)
		}
	}
	if len(s.candidates) == 0 {
		return Aim{}, false
	}
	// Uniform among the entries that reach the state, for the reason pickState
	// is uniform among the rare states: what distinguishes these entries is
	// their coverage, and coverage already has a scheduler of its own — this
	// one exists to say something coverage cannot.
	return Aim{Seed: s.candidates[r.Intn(len(s.candidates))], State: target}, true
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
//
// aim is the state seed selection chose this entry for, or empty when the entry
// was chosen some other way and the state is this function's to pick.
func (s *Scheduler) Pick(trace *Trace, messages int, aim Label, r *rng.Rand) Choice {
	if messages <= 0 {
		return Choice{Message: -1}
	}
	if trace == nil || trace.Len() == 0 {
		return Choice{Message: r.Intn(messages)}
	}

	// An aim from seed selection is honoured rather than re-rolled: this entry
	// was chosen because it reaches that state, and picking a different one now
	// would throw that away.
	target := aim
	if target == "" {
		if !r.Chance(s.Explore) {
			return Choice{Message: r.Intn(messages)}
		}
		target = s.pickState(r)
	}
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
	rare := s.model.Rarest(s.rareCount())
	if len(rare) == 0 {
		return ""
	}
	// Uniform among the rarest rather than weighted by how rare: the counts are
	// visit counts, and weighting by them would concentrate everything on the
	// single least-visited state, which is usually an error path that leads
	// nowhere. Being in the tail is the signal; the ordering within it is noise.
	return rare[r.Intn(len(rare))]
}

// rareCount is how many states count as the tail of *this* model.
//
// A fixed count is a bias only on a model large enough to have a tail. Measured
// on stateful_proto: eleven states, of which "the eight rarest" is nearly all
// of them, so aiming at a rare state was very close to aiming at a uniformly
// random one and the whole bias was inert exactly where the model is small
// enough to explore. A fraction keeps the tail a tail at every size; the
// configured count remains the ceiling, because on a large model the tail is
// long and mostly noise.
func (s *Scheduler) rareCount() int {
	n := s.model.Size()
	if n <= 0 {
		return s.RareStates
	}
	tail := (n + rareDivisor - 1) / rareDivisor
	if tail < minRareStates {
		tail = minRareStates
	}
	if s.RareStates > 0 && tail > s.RareStates {
		tail = s.RareStates
	}
	return tail
}

// The tail is a third of the model, and never narrower than two states: one
// would make the choice a fixed point rather than a bias, and a campaign would
// aim at the same state until its count caught up with the next.
const (
	rareDivisor   = 3
	minRareStates = 2
)

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
