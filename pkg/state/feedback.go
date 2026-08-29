package state

import "github.com/rom/Xfuzz/pkg/feedback"

// Feedback admits a session that reached a new state or made a new move.
//
// This is the whole point of ADR-0006. Code coverage cannot guide stateful
// fuzzing on its own: two sessions can execute identical lines while leaving the
// target in entirely different states, and the bug lives in the state. Composed
// with coverage under the algebra of ADR-0007 — usually Any, so either signal
// keeps a session — it gives the campaign a reason to keep the handshake that
// unlocked a new region of the protocol even though the handshake code itself
// was already covered.
type Feedback struct {
	name  string
	obs   *Observer
	model *Model

	// pending is what the last IsInteresting saw, held until Append or Discard
	// says whether to keep it.
	pending    *Trace
	pendingEx  map[Label][]byte
	pendingNov Novelty
}

// NewFeedback returns state feedback over a model and the observer feeding it.
func NewFeedback(name string, obs *Observer, model *Model) *Feedback {
	if model == nil {
		model = NewModel()
	}
	return &Feedback{name: name, obs: obs, model: model}
}

// Name implements feedback.Feedback.
func (f *Feedback) Name() string { return f.name }

// Model returns the model this feedback maintains.
func (f *Feedback) Model() *Model { return f.model }

// IsInteresting implements feedback.Feedback.
func (f *Feedback) IsInteresting(_ []feedback.Observer, _ feedback.ExitKind) (bool, feedback.Score, error) {
	t := f.obs.Trace()
	nov := f.model.Inspect(t)

	f.pending = copyTrace(t)
	f.pendingEx = copyExemplars(f.obs.Exemplars())
	f.pendingNov = nov

	score := feedback.Score{NewSignal: nov.NewStates + nov.NewTransitions}
	if n := t.Len(); n > 0 {
		// Novelty is the fraction of this session's moves that were new, which
		// is what makes a two-message session that discovered both of its
		// transitions rank above a fifty-message session that discovered two.
		score.Novelty = float64(nov.NewTransitions) / float64(n)
	}
	return nov.Any(), score, nil
}

// Append implements feedback.Feedback: fold the pending trace into the model.
func (f *Feedback) Append() {
	if f.pending == nil {
		return
	}
	f.model.Record(f.pending, f.pendingEx)
	f.pending, f.pendingEx = nil, nil
}

// Discard implements feedback.Feedback: forget the pending trace.
//
// The model is deliberately not updated. A session rejected by the composition
// this feedback sits in must leave the model as it found it, or the state it
// reached is marked seen and no later session is ever admitted for reaching it —
// the state would be recorded as explored by a session nobody kept.
func (f *Feedback) Discard() { f.pending, f.pendingEx = nil, nil }

// LastNovelty returns what the most recent judgement found, for reporting.
func (f *Feedback) LastNovelty() Novelty { return f.pendingNov }

func copyTrace(t *Trace) *Trace {
	return &Trace{States: append([]Label(nil), t.States...)}
}

func copyExemplars(m map[Label][]byte) map[Label][]byte {
	out := make(map[Label][]byte, len(m))
	for k, v := range m {
		out[k] = append([]byte(nil), v...)
	}
	return out
}
