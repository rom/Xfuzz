package state

import (
	"github.com/rom/Xfuzz/pkg/corpus"
	"github.com/rom/Xfuzz/pkg/ir"
	"github.com/rom/Xfuzz/pkg/rng"
)

// Guidance is everything a stateful campaign needs inside the fuzz loop, in one
// place.
//
// Assembled by whatever builds the campaign and handed to the engine as a
// single optional field, so that the loop has one branch for "is this campaign
// stateful" rather than four. A nil Guidance is a stateless campaign and every
// method below tolerates it, which is what keeps the state machinery out of the
// hot path of a file-fuzzing run entirely.
type Guidance struct {
	Observer  *Observer
	Model     *Model
	Scheduler *Scheduler
	Traces    *TraceStore

	// SequenceRate is how often the whole session is mutated rather than one
	// message of it.
	//
	// It has to be non-zero or the sequence operators never act: they apply to
	// a Repeat node, and a mutation rooted at one message cannot see the
	// sequence containing it. It has to be well below one or the campaign
	// spends its budget rearranging messages it has not yet made valid. What
	// this number really trades is exploring the shape of a session against
	// exploring its contents.
	SequenceRate float64
}

// DefaultSequenceRate is how often the session as a whole is mutated.
const DefaultSequenceRate = 0.25

// NewGuidance assembles state guidance around a state function.
func NewGuidance(fn StateFn) *Guidance {
	m := NewModel()
	return &Guidance{
		Observer:     NewObserver("state", fn),
		Model:        m,
		Scheduler:    NewScheduler(m),
		Traces:       NewTraceStore(),
		SequenceRate: DefaultSequenceRate,
	}
}

// Target chooses the subtree to mutate for one execution.
//
// Returning a node rather than an index is what makes the state-then-message
// split cost the engine nothing: the mutation scheduler already restricts itself
// to the root it is given, so handing it one message is the whole of "mutate
// that message". The session tree stays available to operators that need
// whole-tree context, because that is a different field.
//
// The returned label is what the scheduler was aiming for, or empty. It is
// recorded in the corpus entry's provenance, which is the difference between a
// campaign whose choices can be reviewed afterwards and one whose cannot.
//
// aim carries the state this entry was selected for by Seed, so that the two
// halves of the decision agree.
func (g *Guidance) Target(aim Aim, parent corpus.Digest, tree *ir.Node, r *rng.Rand) (*ir.Node, Label) {
	if g == nil || tree == nil {
		return tree, ""
	}
	session := SessionOf(tree)
	if session == nil || len(session.Children) == 0 {
		// Not a session, or an empty one: there is nothing to choose between.
		return tree, ""
	}
	if r.Chance(g.SequenceRate) {
		// The sequence itself, so insert, delete, reorder and duplicate have
		// somewhere to act.
		return tree, ""
	}

	c := g.Scheduler.Pick(g.Traces.Get(parent), len(session.Children), aim.State, r)
	if c.Message < 0 || c.Message >= len(session.Children) {
		return tree, ""
	}
	return session.Children[c.Message], c.Target
}

// Seed chooses which corpus entry to fuzz next, from the state up.
//
// Reports false when the state model has nothing to say — early on, or for a
// rare state no entry reaches — and the campaign's coverage scheduler picks
// instead. Both schedulers are needed: coverage grows the corpus, and this one
// decides which of what coverage found is worth spending a budget on.
func (g *Guidance) Seed(c *corpus.Corpus, r *rng.Rand) (Aim, bool) {
	if g == nil {
		return Aim{}, false
	}
	return g.Scheduler.PickSeed(g.Traces, c, r)
}

// Record stores the trace the last execution produced, against the entry that
// produced it.
func (g *Guidance) Record(id corpus.Digest) {
	if g == nil {
		return
	}
	g.Traces.Put(id, g.Observer.Trace())
}

// Coverage returns how much of the protocol the campaign has explored.
func (g *Guidance) Coverage() Coverage {
	if g == nil {
		return Coverage{}
	}
	return g.Model.Coverage()
}

// Trace returns the trace of the execution just observed.
func (g *Guidance) Trace() *Trace {
	if g == nil {
		return nil
	}
	return g.Observer.Trace()
}

// Declare fixes the protocol's own state machine, from a campaign file.
func (g *Guidance) Declare(moves []Transition) {
	if g == nil || len(moves) == 0 {
		return
	}
	g.Model.Declare(nil, moves)
}
