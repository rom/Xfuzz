package daemon

import (
	"sync"
	"sync/atomic"
	"time"
)

// EventKind classifies what happened.
type EventKind string

// The event kinds a campaign publishes.
const (
	// EventMetrics carries a metrics snapshot. High rate, coalescable: only the
	// latest matters, so a subscriber that falls behind should see the newest
	// figure rather than a queue of stale ones.
	EventMetrics EventKind = "metrics"

	// EventCoverage reports new coverage. Moderate rate.
	EventCoverage EventKind = "coverage"

	// EventCorpus reports a newly admitted corpus entry. This is also how
	// corpus sync works: siblings subscribe and pull what they missed.
	EventCorpus EventKind = "corpus"

	// EventFinding reports a crash, hang, or oracle violation. Low rate and
	// never dropped — a lost finding is the one event nobody can reconstruct.
	EventFinding EventKind = "finding"

	// EventTriage reports a finding's triage outcome.
	EventTriage EventKind = "triage"

	// EventWorker reports a worker starting, dying, or restarting.
	EventWorker EventKind = "worker"

	// EventCampaign reports a lifecycle transition.
	EventCampaign EventKind = "campaign"

	// EventLog carries a human-readable line.
	EventLog EventKind = "log"
)

// coalescable lists the kinds where only the newest event matters.
//
// Coalescing is the difference between a browser tab that falls behind and one
// that shows a stale number: for metrics, "the value now" is the whole content,
// so a subscriber that missed ten updates wants the eleventh, not all eleven.
var coalescable = map[EventKind]bool{
	EventMetrics:  true,
	EventCoverage: true,
}

// undroppable lists the kinds that must reach every subscriber even if it means
// blocking the publisher's *delivery goroutine* — never the engine.
//
// A finding is the one event nobody can reconstruct from a later one. Everything
// else is either a snapshot (the next one supersedes it) or recoverable from the
// store.
var undroppable = map[EventKind]bool{
	EventFinding:  true,
	EventCampaign: true,
}

// Event is one thing that happened in a campaign.
type Event struct {
	Kind     EventKind `json:"kind"`
	Campaign string    `json:"campaign"`
	Worker   int       `json:"worker,omitempty"`
	At       time.Time `json:"at"`

	// Seq is a per-bus sequence number. A subscriber that sees a gap knows it
	// missed something and by how much, which is what makes a lossy stream
	// honest rather than merely lossy.
	Seq uint64 `json:"seq"`

	// Data is the kind-specific payload.
	Data any `json:"data,omitempty"`
}

// Bus fans events out to subscribers.
//
// It is lossy by design (ARCHITECTURE section 9). A browser on a slow link, a
// CLI paused at a breakpoint, or a subscriber that simply stopped reading must
// never be able to slow the campaign down — so a subscriber that cannot keep up
// loses events and is told how many, rather than the engine waiting for it.
type Bus struct {
	mu     sync.RWMutex
	subs   map[int]*subscription
	nextID int
	seq    atomic.Uint64

	// interval bounds how often a coalescing subscriber is woken. Zero delivers
	// as fast as events arrive.
	interval time.Duration
}

// NewBus returns a bus that wakes coalescing subscribers at most every interval.
func NewBus(interval time.Duration) *Bus {
	return &Bus{subs: map[int]*subscription{}, interval: interval}
}

// Subscription is a client's view of the stream.
type Subscription struct {
	bus *Bus
	id  int
	sub *subscription
}

type subscription struct {
	ch    chan Event
	kinds map[EventKind]bool

	mu       sync.Mutex
	pending  map[EventKind]Event // newest event per coalescable kind
	dropped  atomic.Uint64
	closed   bool
	interval time.Duration
	timer    *time.Timer
}

// Subscribe returns a stream of the given kinds, or of everything when none are
// named.
//
// depth bounds the queue. It is small on purpose: a deep queue does not stop a
// subscriber falling behind, it only delays the moment anyone notices, and by
// then the events being delivered describe a campaign minutes in the past.
func (b *Bus) Subscribe(depth int, kinds ...EventKind) *Subscription {
	if depth <= 0 {
		depth = 64
	}
	s := &subscription{
		ch:       make(chan Event, depth),
		pending:  map[EventKind]Event{},
		interval: b.interval,
	}
	if len(kinds) > 0 {
		s.kinds = make(map[EventKind]bool, len(kinds))
		for _, k := range kinds {
			s.kinds[k] = true
		}
	}

	b.mu.Lock()
	id := b.nextID
	b.nextID++
	b.subs[id] = s
	b.mu.Unlock()

	return &Subscription{bus: b, id: id, sub: s}
}

// Events returns the channel to read from. It is closed when the subscription
// is cancelled.
func (s *Subscription) Events() <-chan Event { return s.sub.ch }

// Dropped returns how many events this subscriber missed.
//
// Exposed so a client can say so rather than silently showing an incomplete
// picture. A lossy stream that does not report its losses is indistinguishable
// from a quiet campaign.
func (s *Subscription) Dropped() uint64 { return s.sub.dropped.Load() }

// Close cancels the subscription.
func (s *Subscription) Close() {
	s.bus.mu.Lock()
	delete(s.bus.subs, s.id)
	s.bus.mu.Unlock()

	s.sub.mu.Lock()
	if !s.sub.closed {
		s.sub.closed = true
		if s.sub.timer != nil {
			s.sub.timer.Stop()
		}
		close(s.sub.ch)
	}
	s.sub.mu.Unlock()
}

// Publish delivers an event to every interested subscriber.
//
// It never blocks. That is the contract the whole design rests on: Publish is
// called from a worker's reporting path, and a fuzzing campaign that stalls
// because a browser tab is slow is a fuzzing campaign nobody will run under
// observation.
func (b *Bus) Publish(e Event) {
	if e.At.IsZero() {
		e.At = time.Now()
	}
	e.Seq = b.seq.Add(1)

	b.mu.RLock()
	subs := make([]*subscription, 0, len(b.subs))
	for _, s := range b.subs {
		if s.wants(e.Kind) {
			subs = append(subs, s)
		}
	}
	b.mu.RUnlock()

	for _, s := range subs {
		s.deliver(e)
	}
}

// Subscribers returns how many subscriptions are live.
func (b *Bus) Subscribers() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.subs)
}

func (s *subscription) wants(k EventKind) bool {
	return s.kinds == nil || s.kinds[k]
}

func (s *subscription) deliver(e Event) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}

	// Coalescable kinds are held and flushed on a timer, so a subscriber sees
	// the latest value at a rate it can read rather than every value at a rate
	// it cannot.
	if coalescable[e.Kind] && s.interval > 0 {
		_, waiting := s.pending[e.Kind]
		s.pending[e.Kind] = e
		if !waiting && s.timer == nil {
			s.timer = time.AfterFunc(s.interval, s.flush)
		}
		s.mu.Unlock()
		return
	}
	s.mu.Unlock()

	s.send(e)
}

func (s *subscription) flush() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	batch := make([]Event, 0, len(s.pending))
	for k, e := range s.pending {
		batch = append(batch, e)
		delete(s.pending, k)
	}
	s.timer = nil
	s.mu.Unlock()

	for _, e := range batch {
		s.send(e)
	}
}

// How long an undroppable event keeps trying, and how often. A subscriber that
// has not read for five seconds is not going to, and the event is in the store
// regardless.
const (
	undroppableWait  = 5 * time.Second
	undroppableRetry = time.Millisecond
)

// send hands an event to one subscriber, or gives up.
//
// Every send is made under the subscription's lock, which is also what Close
// takes before closing the channel. That is the whole of the correctness here:
// a send on a closed channel is a panic, not a lost event, and it would happen
// in the daemon's publish path, which every worker report goes through.
//
// Holding the lock costs nothing for an ordinary event, because that send is
// non-blocking by construction. An undroppable one retries instead of blocking,
// so it never holds the lock while waiting — a Close that had to wait out a
// slow subscriber would be a shutdown that hangs on a browser tab.
func (s *subscription) send(e Event) {
	if undroppable[e.Kind] {
		// In a goroutine of its own, so that "must arrive" never becomes "the
		// campaign waits": the publisher is a worker's reporting path.
		go s.sendUndroppable(e)
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	select {
	case s.ch <- e:
	default:
		s.dropped.Add(1)
	}
}

func (s *subscription) sendUndroppable(e Event) {
	deadline := time.Now().Add(undroppableWait)
	for {
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			return
		}
		select {
		case s.ch <- e:
			s.mu.Unlock()
			return
		default:
		}
		s.mu.Unlock()

		if time.Now().After(deadline) {
			s.dropped.Add(1)
			return
		}
		time.Sleep(undroppableRetry)
	}
}
