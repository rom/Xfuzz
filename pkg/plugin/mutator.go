package plugin

import (
	"bytes"

	"github.com/rom/Xfuzz/pkg/ir"
	"github.com/rom/Xfuzz/pkg/mutate"
)

// Mutator is a plugin-backed mutation operator.
//
// It is where batching earns its place. A feedback must answer about the
// execution that just happened, so it is called once per execution whatever the
// protocol allows. A mutator has no such constraint: asked for one variant it
// can just as easily produce thirty-two, and the engine will want them all
// within the next thirty-two iterations. One round trip then covers a batch,
// and the per-mutation cost of the process boundary drops by that factor
// (ADR-0010).
type Mutator struct {
	host *Host
	name string

	// batch is how many variants are requested at once. Larger amortises more
	// and stales sooner: every variant after the engine moves to another node
	// is thrown away.
	batch int

	// src is the payload the queued variants were derived from. When the engine
	// offers a different one the queue is stale, because a variant of the wrong
	// input is not a mutation, it is a substitution.
	src   []byte
	queue [][]byte
}

// DefaultBatch is how many variants a plugin mutator is asked for at once.
//
// Chosen so the round trip is amortised without holding variants long enough to
// go stale: the engine typically applies several operators to one node before
// moving on, and a batch this size survives that without hoarding.
const DefaultBatch = 32

// NewMutator resolves a mutator the plugin declared.
func (h *Host) NewMutator(name string) (*Mutator, error) {
	if err := h.check(name, h.provides.Mutators, "mutator"); err != nil {
		return nil, err
	}
	return &Mutator{host: h, name: name, batch: DefaultBatch}, nil
}

// SetBatch changes how many variants are requested at once. Zero restores the
// default.
func (m *Mutator) SetBatch(n int) {
	if n <= 0 {
		n = DefaultBatch
	}
	m.batch = n
}

// Name identifies the operator in configuration, provenance and per-operator
// stats, qualified by the plugin's label.
func (m *Mutator) Name() string { return m.host.opts.Label + ":" + m.name }

// Kind classifies the operator for weighting and reporting. A plugin rewrites
// payload bytes, whatever it does inside.
func (m *Mutator) Kind() mutate.Kind { return mutate.KindByte }

// CanApply implements mutate.Mutator.
//
// A failed plugin declines everything. That is not the campaign quietly
// carrying on without it: the host holds the error, the worker checks it, and
// the campaign fails. Declining here only stops the scheduler spending its
// budget on an operator that cannot act between the failure and the check.
func (m *Mutator) CanApply(c *mutate.Ctx, n *ir.Node) bool {
	return m.host.Err() == nil && mutate.IsPayload(n)
}

// Mutate implements mutate.Mutator.
//
// It cannot report an error — no operator can — so a failure is recorded on the
// host and this returns false, the same answer a native operator gives when it
// has nothing to offer. The difference is that the host's error is sticky and
// the campaign asks for it.
func (m *Mutator) Mutate(c *mutate.Ctx, n *ir.Node) bool {
	if !bytes.Equal(m.src, n.Raw) {
		m.queue = m.queue[:0]
	}
	if len(m.queue) == 0 && !m.refill(c, n) {
		return false
	}

	for len(m.queue) > 0 {
		v := m.queue[len(m.queue)-1]
		m.queue = m.queue[:len(m.queue)-1]

		// A variant that breaks the node's bounds is dropped rather than
		// trimmed. Truncating would file the plugin's name against something it
		// did not propose, and a four-byte chunk type cut down from five is not
		// what the plugin meant either way.
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

// refill asks the plugin for a fresh batch of variants of this payload.
func (m *Mutator) refill(c *mutate.Ctx, n *ir.Node) bool {
	req := &Request{
		Op:       OpMutate,
		Name:     m.name,
		Input:    n.Raw,
		Count:    m.batch,
		MaxBytes: c.MaxBytes,

		// The seed comes from the operator-parameter stream, so a plugin's
		// choices replay with the campaign like a native operator's do
		// (ASR-0008). Drawing it here rather than reusing the campaign seed is
		// what keeps two calls from producing the same batch.
		Seed: c.Rand.Uint64(),
	}
	var resp Response
	if err := m.host.call(req, &resp); err != nil {
		m.host.fail(err)
		return false
	}
	if len(resp.Outputs) == 0 {
		return false
	}
	m.src = append(m.src[:0], n.Raw...)
	m.queue = append(m.queue[:0], resp.Outputs...)
	return true
}
