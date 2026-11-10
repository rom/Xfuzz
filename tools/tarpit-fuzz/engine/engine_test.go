package engine

import (
	"context"
	"io"
	"math/rand"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// An echo server that "dies" (stops accepting) after the Nth connection,
// which is what the engine's liveness probe must see.
type flakyServer struct {
	ln       net.Listener
	diesAt   int32
	accepted int32
	dead     atomic.Bool
}

func newFlakyServer(t *testing.T, diesAt int) *flakyServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &flakyServer{ln: ln, diesAt: int32(diesAt)}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			n := atomic.AddInt32(&s.accepted, 1)
			if n >= s.diesAt {
				// Close the listener: a subsequent dial will refuse, which the
				// engine's alive() check reports as a crash.
				s.dead.Store(true)
				ln.Close()
				c.Close()
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				c.SetDeadline(time.Now().Add(200 * time.Millisecond))
				buf := make([]byte, 1024)
				n, _ := c.Read(buf)
				if n > 0 {
					_, _ = io.WriteString(c, "ok\n")
				}
			}(c)
		}
	}()
	return s
}

// TestEngineFindsAPlantedCrash is the primary claim the engine must meet: a
// listener that stops accepting after some number of payloads is filed as a
// finding, naming which iteration tripped it, and the run reports it. A
// fuzzer that reports "no findings" against a server that died is worse than
// one that never runs: it builds confidence the sensor does not deserve.
func TestEngineFindsAPlantedCrash(t *testing.T) {
	srv := newFlakyServer(t, 5)
	addr := srv.ln.Addr().(*net.TCPAddr)

	cat := []Protocol{{Name: "flaky", Transport: "tcp", DefaultPort: addr.Port, Seeds: [][]byte{[]byte("hello\n")}}}
	cfg := Config{Target: "127.0.0.1", Iterations: 20, Rounds: 1, Concurrency: 1, Timeout: 200 * time.Millisecond, Seed: 1}
	eng := New(cfg, cat)
	s := eng.Run(context.Background())

	if s.Crashes == 0 {
		t.Fatalf("a server that stopped accepting at payload 5 was not recorded as a crash: %+v", s)
	}
	if len(s.Findings) == 0 || !strings.Contains(s.Findings[0].Reason, "liveness") {
		t.Errorf("finding does not name a liveness loss: %+v", s.Findings)
	}
}

// TestFilteredRunsOnlyEnabledProtocols is the toggle claim.
func TestFilteredRunsOnlyEnabledProtocols(t *testing.T) {
	// A target port that is closed: any protocol pointed at it is skipped.
	cat := []Protocol{
		{Name: "a", Transport: "tcp", DefaultPort: 1},
		{Name: "b", Transport: "tcp", DefaultPort: 2},
		{Name: "c", Transport: "udp", DefaultPort: 3},
	}
	cfg := Config{Target: "127.0.0.1", Iterations: 1, Rounds: 1, Concurrency: 1,
		Timeout: 50 * time.Millisecond, Seed: 1,
		Enabled: map[string]bool{"a": true, "udp:c": true}}
	s := New(cfg, cat).Run(context.Background())
	if s.Ran != 2 {
		t.Errorf("Ran = %d, want 2 (a + udp:c enabled; b excluded)", s.Ran)
	}
}

// TestDisableSubtractsFromEnabled covers the common CLI shape "--enable
// everything --disable one thing".
func TestDisableSubtractsFromEnabled(t *testing.T) {
	cat := []Protocol{
		{Name: "a", Transport: "tcp", DefaultPort: 1},
		{Name: "b", Transport: "tcp", DefaultPort: 2},
	}
	cfg := Config{Target: "127.0.0.1", Iterations: 1, Rounds: 1, Concurrency: 1,
		Timeout: 50 * time.Millisecond, Seed: 1,
		Disabled: map[string]bool{"tcp:a": true}}
	s := New(cfg, cat).Run(context.Background())
	if s.Ran != 1 {
		t.Errorf("Ran = %d, want 1 (a disabled)", s.Ran)
	}
}

// TestDumbAndSmartAreBothRun confirms the kind loop actually visits each
// configured kind — a smart generator that returns a sentinel pattern must
// turn up in the sent bytes.
func TestDumbAndSmartAreBothRun(t *testing.T) {
	var sentSmart, sentDumb atomic.Bool
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				c.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
				buf := make([]byte, 64)
				n, _ := c.Read(buf)
				if n > 0 {
					if string(buf[:n]) == "SMART-MARKER" {
						sentSmart.Store(true)
					} else {
						sentDumb.Store(true)
					}
				}
			}(c)
		}
	}()

	addr := ln.Addr().(*net.TCPAddr)
	cat := []Protocol{{
		Name: "p", Transport: "tcp", DefaultPort: addr.Port,
		Seeds: [][]byte{[]byte("hello")},
		Smart: func(*rand.Rand) []byte { return []byte("SMART-MARKER") },
	}}
	cfg := Config{Target: "127.0.0.1", Iterations: 5, Rounds: 1, Concurrency: 1,
		Timeout: 100 * time.Millisecond, Seed: 1,
		Kinds: []Kind{KindDumb, KindSmart}}
	New(cfg, cat).Run(context.Background())

	if !sentSmart.Load() {
		t.Error("the smart generator never fired")
	}
	if !sentDumb.Load() {
		t.Error("the dumb mutator never fired")
	}
}
