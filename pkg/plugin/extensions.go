package plugin

import (
	"fmt"
	"slices"

	"github.com/rom/Xfuzz/pkg/feedback"
)

// Feedback is a plugin-backed feedback.
//
// It satisfies feedback.Feedback exactly, which is the point of the three-tier
// model: the engine cannot tell a plugin feedback from a native one, so nothing
// in the hot loop grows a special case (ADR-0010).
type Feedback struct {
	host *Host
	name string
}

// NewFeedback resolves a feedback the plugin declared.
func (h *Host) NewFeedback(name string) (*Feedback, error) {
	if err := h.check(name, h.provides.Feedbacks, "feedback"); err != nil {
		return nil, err
	}
	return &Feedback{host: h, name: name}, nil
}

// Name identifies the feedback in configuration, stats and provenance. It is
// qualified by the plugin's label so two plugins may provide the same name.
func (f *Feedback) Name() string { return f.host.opts.Label + ":" + f.name }

// IsInteresting asks the plugin.
func (f *Feedback) IsInteresting(obs []feedback.Observer, ek feedback.ExitKind) (bool, feedback.Score, error) {
	v, err := f.judge(OpJudge, Observe(obs, ek))
	if err != nil {
		return false, feedback.Score{}, err
	}
	return v.Interesting, v.score(), nil
}

// Append commits the state the plugin accumulated for the last judgement, and
// Discard rolls it back.
//
// Neither can report an error, which is exactly why they do not talk to the
// plugin here: the settlement rides on the next call, and any failure surfaces
// there, where there is a caller to return it to. A campaign that ends before
// the next call has the commit flushed by Close.
func (f *Feedback) Append()  { f.host.settle(f.name, true) }
func (f *Feedback) Discard() { f.host.settle(f.name, false) }

// Objective is a plugin-backed objective: it decides whether an execution is a
// finding. It holds no state, so there is nothing to commit.
type Objective struct {
	host *Host
	name string
}

// NewObjective resolves an objective the plugin declared.
func (h *Host) NewObjective(name string) (*Objective, error) {
	if err := h.check(name, h.provides.Objectives, "objective"); err != nil {
		return nil, err
	}
	return &Objective{host: h, name: name}, nil
}

// Name identifies the objective.
func (o *Objective) Name() string { return o.host.opts.Label + ":" + o.name }

// IsFinding asks the plugin.
func (o *Objective) IsFinding(obs []feedback.Observer, ek feedback.ExitKind) (bool, feedback.Finding, error) {
	v, err := o.host.judgeOne(OpFinding, o.name, Observe(obs, ek))
	if err != nil {
		return false, feedback.Finding{}, err
	}
	if v.Finding == nil {
		return false, feedback.Finding{}, nil
	}
	found := v.Finding.finding()
	if found.Kind == "" {
		// A finding with no kind cannot be bucketed, filed, or reported
		// honestly, and inventing a kind here would put words in the plugin's
		// mouth. Naming the objective is the least misleading thing available.
		found.Kind = "oracle"
	}
	return true, found, nil
}

// judge sends one observation and returns the single verdict.
func (f *Feedback) judge(op Op, ob Observation) (Verdict, error) {
	return f.host.judgeOne(op, f.name, ob)
}

// judgeOne is the one-observation form of the batch call.
//
// The batch exists on the wire because a caller with many observations — a
// corpus being re-evaluated after a feedback changed, a triage pass over every
// finding — should pay one round trip rather than thousands. The fuzz loop
// itself has exactly one execution to judge at the moment it must decide, so on
// the hot path a batch of one is not a compromise, it is the honest shape.
func (h *Host) judgeOne(op Op, name string, ob Observation) (Verdict, error) {
	vs, err := h.Judge(op, name, []Observation{ob})
	if err != nil {
		return Verdict{}, err
	}
	return vs[0], nil
}

// Judge asks an extension about a batch of observations, returning one verdict
// per observation in the same order.
func (h *Host) Judge(op Op, name string, batch []Observation) ([]Verdict, error) {
	if len(batch) == 0 {
		return nil, nil
	}
	var resp Response
	if err := h.call(&Request{Op: op, Name: name, Batch: batch}, &resp); err != nil {
		return nil, err
	}
	if len(resp.Verdicts) != len(batch) {
		return nil, h.fail(fmt.Errorf("%s answered %d of %d observations; "+
			"a verdict per observation, in order, is the contract",
			name, len(resp.Verdicts), len(batch)))
	}
	return resp.Verdicts, nil
}

// check resolves a name against what the plugin declared.
//
// Resolving at startup is what turns a typo in a campaign file into a refusal
// before the first execution. A feedback that silently never fires produces a
// campaign that runs to completion and measures the wrong thing.
func (h *Host) check(name string, declared []string, kind string) error {
	if err := h.Err(); err != nil {
		return err
	}
	if slices.Contains(declared, name) {
		return nil
	}
	if len(declared) == 0 {
		return fmt.Errorf("plugin %s: no %s named %q; it provides no %ss at all",
			h.opts.Label, kind, name, kind)
	}
	return fmt.Errorf("plugin %s: no %s named %q; it provides %v",
		h.opts.Label, kind, name, declared)
}
