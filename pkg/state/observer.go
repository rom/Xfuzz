package state

import "github.com/rom/Xfuzz/pkg/feedback"

// Observer records the states a session passed through.
//
// It is the session executor that feeds it: after each message is delivered and
// a reply read, the executor calls Response with what came back, and this
// labels it and extends the trace. Recording and judging stay separate, as they
// do for coverage — the same trace serves the feedback that decides whether to
// keep the session, the scheduler that decides what to fuzz next, and the
// finding report that says which state the target crashed in.
type Observer struct {
	name string
	fn   StateFn

	trace *Trace

	// exemplars holds the first response seen for each label in this session,
	// so the model can keep one for labels it has not seen before.
	exemplars map[Label][]byte

	// maxExemplar bounds what is retained. A response can be megabytes and the
	// point of an exemplar is to be read by a person.
	maxExemplar int
}

// DefaultMaxExemplar is how much of a response is kept to explain a state.
const DefaultMaxExemplar = 256

// NewObserver returns an observer that labels responses with fn.
func NewObserver(name string, fn StateFn) *Observer {
	if fn == nil {
		fn = NewConstantFn()
	}
	return &Observer{
		name:        name,
		fn:          fn,
		trace:       NewTrace(),
		exemplars:   map[Label][]byte{},
		maxExemplar: DefaultMaxExemplar,
	}
}

// Name implements feedback.Observer.
func (o *Observer) Name() string { return o.name }

// Pre implements feedback.Observer: a new session starts at Start.
func (o *Observer) Pre() error { o.Reset(); return nil }

// Post implements feedback.Observer.
//
// Nothing to harvest: the trace was built during the session, message by
// message, because that is the only time the responses exist. What Post does is
// record how the session ended — a target that hung up is in a state, and a
// session that ends because the target died is in a different one.
func (o *Observer) Post(ek feedback.ExitKind) error {
	if ek.IsFault() {
		o.trace.Observe(Closed)
	}
	return nil
}

// Reset implements feedback.Observer.
func (o *Observer) Reset() {
	o.trace.Reset()
	clear(o.exemplars)
}

// Response records the target's reply to one message.
//
// No return value on purpose. It is called by the session executor through an
// interface, and an interface that spoke in state labels would put this package
// into pkg/executor's imports for the sake of a value the caller can read from
// the trace anyway.
func (o *Observer) Response(resp []byte) {
	l := o.fn.Label(resp)
	if l == "" {
		l = Unknown
	}
	o.trace.Observe(l)
	if _, ok := o.exemplars[l]; !ok && len(resp) > 0 {
		n := min(len(resp), o.maxExemplar)
		o.exemplars[l] = append([]byte(nil), resp[:n]...)
	}
}

// Hangup records that the target closed the connection.
func (o *Observer) Hangup() { o.trace.Observe(Closed) }

// Trace returns the session's trace. It is reused between sessions, so a caller
// that needs it later must copy it.
func (o *Observer) Trace() *Trace { return o.trace }

// Exemplars returns the responses that produced this session's labels.
func (o *Observer) Exemplars() map[Label][]byte { return o.exemplars }

// Fn returns the state function in use, for reports.
func (o *Observer) Fn() StateFn { return o.fn }
