package daemon

import (
	"sync"
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
