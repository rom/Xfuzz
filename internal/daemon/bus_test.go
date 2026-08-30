package daemon

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestBusDeliversToInterestedSubscribers(t *testing.T) {
	b := NewBus(0)
	all := b.Subscribe(16)
	defer all.Close()
	findings := b.Subscribe(16, EventFinding)
	defer findings.Close()

	b.Publish(Event{Kind: EventLog, Data: "hello"})
	b.Publish(Event{Kind: EventFinding, Data: "crash"})

	if got := drain(all.Events(), 2, 200*time.Millisecond); len(got) != 2 {
		t.Fatalf("the unfiltered subscriber got %d events, want 2", len(got))
	}
	got := drain(findings.Events(), 1, 200*time.Millisecond)
	if len(got) != 1 || got[0].Kind != EventFinding {
		t.Fatalf("the filtered subscriber got %v", got)
	}
}

func TestBusNumbersEventsSoAGapIsVisible(t *testing.T) {
	// A lossy stream that does not report its losses is indistinguishable from
	// a quiet campaign.
	b := NewBus(0)
	s := b.Subscribe(2)
	defer s.Close()

	for i := 0; i < 50; i++ {
		b.Publish(Event{Kind: EventLog, Data: i})
	}
	got := drain(s.Events(), 50, 100*time.Millisecond)
	if len(got) >= 50 {
		t.Fatalf("a depth-2 subscriber received %d of 50 events; nothing was dropped", len(got))
	}
	if s.Dropped() == 0 {
		t.Fatal("events were dropped but the count is zero")
	}
	if uint64(len(got))+s.Dropped() != 50 {
		t.Errorf("received %d + dropped %d != 50", len(got), s.Dropped())
	}
	for i := 1; i < len(got); i++ {
		if got[i].Seq <= got[i-1].Seq {
			t.Fatalf("sequence numbers are not increasing: %d then %d", got[i-1].Seq, got[i].Seq)
		}
	}
}

func TestPublishNeverBlocksOnASubscriberThatStoppedReading(t *testing.T) {
	// This is the contract the whole design rests on: Publish is called from a
	// worker's reporting path, and a campaign that stalls because a browser tab
	// is slow is a campaign nobody will run under observation.
	b := NewBus(0)
	stuck := b.Subscribe(1)
	defer stuck.Close()

	done := make(chan struct{})
	go func() {
		for i := 0; i < 10_000; i++ {
			b.Publish(Event{Kind: EventLog, Data: i})
		}
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Publish blocked on a subscriber that stopped reading")
	}
	if stuck.Dropped() == 0 {
		t.Error("nothing was reported as dropped")
	}
}

func TestCoalescingKeepsTheNewestValue(t *testing.T) {
	// For a metrics snapshot "the value now" is the whole content, so a
	// subscriber that missed ten updates wants the eleventh, not all eleven.
	b := NewBus(20 * time.Millisecond)
	s := b.Subscribe(64, EventMetrics)
	defer s.Close()

	for i := 0; i < 100; i++ {
		b.Publish(Event{Kind: EventMetrics, Data: i})
	}
	got := drain(s.Events(), 100, 200*time.Millisecond)
	if len(got) == 0 {
		t.Fatal("coalescing delivered nothing")
	}
	if len(got) > 5 {
		t.Fatalf("100 metrics updates produced %d deliveries; they are not being coalesced", len(got))
	}
	last := got[len(got)-1]
	if last.Data.(int) != 99 {
		t.Fatalf("the delivered value is %v, not the newest", last.Data)
	}
}

func TestFindingsAreNotDropped(t *testing.T) {
	// A finding is the one event nobody can reconstruct from a later one.
	b := NewBus(0)
	s := b.Subscribe(1, EventFinding)
	defer s.Close()

	const n = 20
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < n; i++ {
			b.Publish(Event{Kind: EventFinding, Data: i})
		}
	}()

	got := drain(s.Events(), n, 3*time.Second)
	wg.Wait()
	if len(got) != n {
		t.Fatalf("received %d of %d findings against a depth-1 queue; dropped %d",
			len(got), n, s.Dropped())
	}
}

func TestClosedSubscriptionStopsReceiving(t *testing.T) {
	b := NewBus(0)
	s := b.Subscribe(8)
	s.Close()

	if b.Subscribers() != 0 {
		t.Fatalf("subscribers = %d after close", b.Subscribers())
	}
	// Publishing after a close must not panic on the closed channel.
	b.Publish(Event{Kind: EventLog})
	b.Publish(Event{Kind: EventFinding})
	time.Sleep(50 * time.Millisecond)

	if _, open := <-s.Events(); open {
		t.Fatal("the channel is still open after Close")
	}
}

func TestCloseIsIdempotent(t *testing.T) {
	b := NewBus(0)
	s := b.Subscribe(4)
	s.Close()
	s.Close()
}

func TestBusIsSafeUnderConcurrentUse(t *testing.T) {
	b := NewBus(5 * time.Millisecond)
	var wg sync.WaitGroup

	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 500; j++ {
				b.Publish(Event{Kind: EventMetrics, Data: j})
				b.Publish(Event{Kind: EventLog, Data: j})
			}
		}()
	}
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s := b.Subscribe(8)
			defer s.Close()
			deadline := time.After(200 * time.Millisecond)
			for {
				select {
				case <-s.Events():
				case <-deadline:
					return
				}
			}
		}()
	}
	wg.Wait()
}

// drain reads up to n events, giving up after the deadline.
func drain(ch <-chan Event, n int, wait time.Duration) []Event {
	var out []Event
	deadline := time.After(wait)
	for len(out) < n {
		select {
		case e, ok := <-ch:
			if !ok {
				return out
			}
			out = append(out, e)
		case <-deadline:
			return out
		}
	}
	return out
}

// M7's memory criterion, measured at the mechanism rather than by staging a
// 100k exec/s campaign this host cannot produce.
//
// What the criterion is really about is that a browser can never make the
// engine wait, and can never make the daemon hold work on its behalf
// (ASR-0012). Both follow from one property: what a subscriber is *delivered*
// is bounded by the coalescing interval, not by how fast the campaign
// publishes. Publish an unreasonable number of metrics events and the
// subscriber should see a handful — one per interval — with the rest collapsed
// into the newest, and the queue behind it should never grow.
func TestDeliveryIsBoundedByTheIntervalNotThePublishRate(t *testing.T) {
	const interval = 20 * time.Millisecond
	b := NewBus(interval)

	sub := b.Subscribe(64)
	defer sub.Close()

	// A reader that keeps up, so that anything the subscriber does not receive
	// was collapsed by the server rather than left in a queue.
	var received atomic.Int64
	var newest atomic.Int64
	done := make(chan struct{})
	go func() {
		defer close(done)
		for e := range sub.Events() {
			received.Add(1)
			if n, ok := e.Data.(int); ok {
				newest.Store(int64(n))
			}
		}
	}()

	const published = 20_000
	start := time.Now()
	for i := 1; i <= published; i++ {
		b.Publish(Event{Kind: EventMetrics, Data: i})
	}
	elapsed := time.Since(start)

	// Long enough for the last coalesced batch to flush.
	time.Sleep(4 * interval)
	sub.Close()
	<-done

	got := received.Load()
	// One per interval, plus slack for the first event through and the final
	// flush. The point is the shape — bounded by time — not an exact count.
	ceiling := int64(elapsed/interval) + 8
	if got > ceiling {
		t.Errorf("a subscriber was delivered %d of %d events published in %s; "+
			"delivery is tracking the publish rate rather than the %s interval, "+
			"which is how a browser comes to back-pressure the engine",
			got, published, elapsed.Round(time.Millisecond), interval)
	}
	if got == 0 {
		t.Error("a subscriber that kept up was delivered nothing")
	}

	// And what it did get is the newest value, not the oldest: a coalescing
	// bus that delivered the first of each batch would be showing a number
	// that is not merely late but wrong.
	if n := newest.Load(); n < published/2 {
		t.Errorf("the newest value delivered was %d of %d published; "+
			"coalescing is keeping the stale event rather than the fresh one", n, published)
	}
	t.Logf("%d events published in %s, %d delivered, newest %d",
		published, elapsed.Round(time.Millisecond), got, newest.Load())
}

// A finding is the one event nobody can reconstruct from a later one, so it is
// never coalesced away however fast the campaign is publishing around it.
func TestFindingsAreNeverCollapsed(t *testing.T) {
	b := NewBus(5 * time.Millisecond)
	sub := b.Subscribe(64)
	defer sub.Close()

	var findings atomic.Int64
	done := make(chan struct{})
	go func() {
		defer close(done)
		for e := range sub.Events() {
			if e.Kind == EventFinding {
				findings.Add(1)
			}
		}
	}()

	const want = 5
	for i := 0; i < want; i++ {
		for j := 0; j < 200; j++ {
			b.Publish(Event{Kind: EventMetrics, Data: j})
		}
		b.Publish(Event{Kind: EventFinding, Data: i})
	}
	time.Sleep(200 * time.Millisecond)
	sub.Close()
	<-done

	if got := findings.Load(); got != want {
		t.Errorf("%d of %d findings reached the subscriber; a lost finding is the "+
			"one event nobody can reconstruct", got, want)
	}
}
