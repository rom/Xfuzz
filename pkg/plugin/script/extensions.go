package script

import (
	"bytes"
	"fmt"

	"go.starlark.net/starlark"

	"github.com/rom/Xfuzz/pkg/feedback"
	"github.com/rom/Xfuzz/pkg/ir"
	"github.com/rom/Xfuzz/pkg/mutate"
	"github.com/rom/Xfuzz/pkg/plugin"
	"github.com/rom/Xfuzz/pkg/state"
)

// Objective is a Starlark oracle.
//
// This is the tier's reason for existing. Every project has an invariant that
// only makes sense for that project — "the length field must match what was
// read", "this response must never contain the admin token" — and no fuzzer can
// know what it is. Writing that down should take a campaign file and four
// lines, not a plugin and a build.
type Objective struct {
	script *Script
	fn     string

	// failed is the sticky error. An oracle that raised once will raise again
	// on the next execution and the one after; reporting it every time would
	// bury the campaign in identical errors, and continuing as if it had said
	// "no" would be worse — a campaign that silently stopped checking.
	failed error
}

// NewObjective binds a function in the module as an objective.
func (s *Script) NewObjective(fn string) (*Objective, error) {
	if !s.Has(fn) {
		return nil, fmt.Errorf("script %s: no function named %q; it defines %v", s.name, fn, s.Names())
	}
	return &Objective{script: s, fn: fn}, nil
}

// Name identifies the objective, qualified by the script it came from.
func (o *Objective) Name() string { return o.script.name + ":" + o.fn }

// Err returns the failure that took this oracle out of service.
//
// The campaign asks, once a slice, exactly as it asks a plugin host — an
// extension that has stopped judging must not be something a campaign only
// discovers from the absence of findings.
func (o *Objective) Err() error { return o.failed }

// IsFinding implements feedback.Objective.
func (o *Objective) IsFinding(obs []feedback.Observer, ek feedback.ExitKind) (bool, feedback.Finding, error) {
	if o.failed != nil {
		return false, feedback.Finding{}, o.failed
	}
	v, err := o.script.call(o.fn, observation{plugin.Observe(obs, ek)})
	if err != nil {
		o.failed = err
		return false, feedback.Finding{}, err
	}
	is, found, err := o.script.asFinding(v)
	if err != nil {
		o.failed = err
		return false, feedback.Finding{}, err
	}
	return is, found, nil
}

// Mutator is a Starlark mutation operator.
//
// Like the plugin tier it rewrites a payload's bytes, and like the plugin tier
// it is asked for a batch — for a different reason. A plugin batches to
// amortise a process boundary; a script batches to amortise the interpreter's
// call overhead and the conversion of the input into a Starlark value, which
// for a large payload is the dominant cost of a small mutation.
type Mutator struct {
	script *Script
	fn     string
	batch  int

	src    []byte
	queue  [][]byte
	failed error
}

// NewMutator binds a function in the module as a mutation operator.
func (s *Script) NewMutator(fn string) (*Mutator, error) {
	if !s.Has(fn) {
		return nil, fmt.Errorf("script %s: no function named %q; it defines %v", s.name, fn, s.Names())
	}
	return &Mutator{script: s, fn: fn, batch: DefaultBatch}, nil
}

// DefaultBatch is how many variants a script mutator is asked for at once.
const DefaultBatch = 16

// SetBatch changes the batch size. Zero restores the default.
func (m *Mutator) SetBatch(n int) {
	if n <= 0 {
		n = DefaultBatch
	}
	m.batch = n
}

// Name identifies the operator, qualified by the script it came from.
func (m *Mutator) Name() string { return m.script.name + ":" + m.fn }

// Kind classifies the operator. A script rewrites payload bytes, whatever it
// does inside.
func (m *Mutator) Kind() mutate.Kind { return mutate.KindByte }

// Err returns the failure that took this operator out of service.
//
// Mutate cannot return an error, so a script that raises would otherwise stop
// mutating and say nothing. The campaign asks here.
func (m *Mutator) Err() error { return m.failed }

// CanApply implements mutate.Mutator.
func (m *Mutator) CanApply(c *mutate.Ctx, n *ir.Node) bool {
	return m.failed == nil && mutate.IsPayload(n)
}

// Mutate implements mutate.Mutator.
func (m *Mutator) Mutate(c *mutate.Ctx, n *ir.Node) bool {
	if m.failed != nil {
		return false
	}
	if !bytes.Equal(m.src, n.Raw) {
		m.queue = m.queue[:0]
	}
	if len(m.queue) == 0 && !m.refill(c, n) {
		return false
	}

	for len(m.queue) > 0 {
		v := m.queue[len(m.queue)-1]
		m.queue = m.queue[:len(m.queue)-1]

		if !n.FitsLen(len(v)) || (c.MaxBytes > 0 && len(v) > c.MaxBytes) {
			continue
		}
		if bytes.Equal(v, n.Raw) {
			continue
		}
		n.Raw = c.Arena.CopyBytes(v)
		return true
	}
	return false
}

func (m *Mutator) refill(c *mutate.Ctx, n *ir.Node) bool {
	res, err := m.script.call(m.fn,
		starlark.Bytes(n.Raw),
		starlark.MakeUint64(c.Rand.Uint64()),
		starlark.MakeInt(m.batch),
		starlark.MakeInt(c.MaxBytes),
	)
	if err != nil {
		m.failed = err
		return false
	}
	out, err := m.script.asByteList(res, m.batch)
	if err != nil {
		m.failed = err
		return false
	}
	if len(out) == 0 {
		return false
	}
	m.src = append(m.src[:0], n.Raw...)
	m.queue = append(m.queue[:0], out...)
	return true
}

// StateFn is a Starlark state function: it turns one protocol response into a
// state label.
//
// The other thing this tier is for. A protocol nobody has heard of still has a
// shape, and someone who knows it can write "the third byte is the status" far
// faster than they can explain it to a state-inference heuristic (ADR-0006).
type StateFn struct {
	script *Script
	fn     string
	failed error
}

// NewStateFn binds a function in the module as a state function.
func (s *Script) NewStateFn(fn string) (*StateFn, error) {
	if !s.Has(fn) {
		return nil, fmt.Errorf("script %s: no function named %q; it defines %v", s.name, fn, s.Names())
	}
	return &StateFn{script: s, fn: fn}, nil
}

// Name identifies the function in configuration and reports.
func (f *StateFn) Name() string { return f.script.name + ":" + f.fn }

// Err returns the failure that took this function out of service.
func (f *StateFn) Err() error { return f.failed }

// Label implements state.StateFn.
//
// An empty label means "cannot tell", which is what a raising script gets: the
// trace records Unknown rather than a guess, and the campaign learns about the
// error from Err rather than from a state machine full of nonsense.
func (f *StateFn) Label(resp []byte) state.Label {
	if f.failed != nil {
		return ""
	}
	v, err := f.script.call(f.fn, starlark.Bytes(resp))
	if err != nil {
		f.failed = err
		return ""
	}
	b, ok := asBytes(v)
	if !ok {
		if _, none := v.(starlark.NoneType); none {
			return ""
		}
		f.failed = fmt.Errorf("script %s: the state function returned %s, want a string",
			f.script.name, v.Type())
		return ""
	}
	return state.Label(f.script.text(string(b)))
}
