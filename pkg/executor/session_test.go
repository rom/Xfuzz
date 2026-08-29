package executor

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rom/Xfuzz/pkg/feedback"
	"github.com/rom/Xfuzz/pkg/ir"
)

// plainDialer is the unconfined dialer these tests use.
//
// In a campaign this is the scope guard, and it is the only way this package can
// reach the network at all. Here it is a bare dialer against a listener on
// loopback that the test itself owns.
type plainDialer struct{}

func (plainDialer) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, network, address)
}

// echoServer is a line protocol with one piece of state: it answers differently
// once it has seen HELLO.
type echoServer struct {
	ln     net.Listener
	mu     sync.Mutex
	greets int
	closed bool
}

func newEchoServer(t *testing.T) *echoServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &echoServer{ln: ln}
	go s.serve()
	t.Cleanup(func() {
		s.mu.Lock()
		s.closed = true
		s.mu.Unlock()
		ln.Close()
	})
	return s
}

func (s *echoServer) addr() string { return s.ln.Addr().String() }

func (s *echoServer) serve() {
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.handle(c)
	}
}

func (s *echoServer) handle(c net.Conn) {
	defer c.Close()
	r := bufio.NewReader(c)
	authed := false
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		cmd := strings.ToUpper(strings.TrimSpace(line))
		switch {
		case cmd == "HELLO":
			s.mu.Lock()
			s.greets++
			s.mu.Unlock()
			authed = true
			fmt.Fprintf(c, "220 ready session %d\r\n", s.greets)
		case cmd == "QUIT":
			fmt.Fprint(c, "221 bye\r\n")
			return
		case authed:
			fmt.Fprint(c, "250 ok\r\n")
		default:
			fmt.Fprint(c, "503 say hello first\r\n")
		}
	}
}

// recorder collects the replies a session produced.
type recorder struct {
	mu      sync.Mutex
	replies []string
	hangups int
}

func (r *recorder) Response(b []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.replies = append(r.replies, string(b))
}

func (r *recorder) Hangup() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.hangups++
}

func (r *recorder) snapshot() ([]string, int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.replies...), r.hangups
}

// session builds an input from a list of messages, as a Repeat node — which is
// what a session is (ADR-0005).
func session(msgs ...string) Input {
	kids := make([]*ir.Node, 0, len(msgs))
	for _, m := range msgs {
		kids = append(kids, ir.Blob("msg", []byte(m)))
	}
	n := ir.Repeat("session", kids...)
	return Input{Node: n, Bytes: ir.Encode(n)}
}

func newTestSession(t *testing.T, addr string, opts SessionOptions) (*Session, *recorder) {
	t.Helper()
	opts.Network, opts.Address = "tcp", addr
	if opts.Framing == FrameIdle && opts.QuietPeriod == 0 {
		opts.QuietPeriod = 20 * time.Millisecond
	}
	e := NewSession("session", plainDialer{}, opts)
	rec := &recorder{}
	e.States = rec
	t.Cleanup(func() { e.Close() })
	return e, rec
}

// The tier's defining behaviour: one execution is a whole session, and each
// message gets its own reply.
func TestSessionDeliversEveryMessageAndReadsEveryReply(t *testing.T) {
	srv := newEchoServer(t)
	e, rec := newTestSession(t, srv.addr(), SessionOptions{Framing: FrameLine})

	if err := e.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	ek, err := e.Run(context.Background(), session("HELLO\r\n", "DATA\r\n", "QUIT\r\n"), nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if ek != feedback.ExitOK {
		t.Errorf("a clean session ended %v", ek)
	}

	replies, _ := rec.snapshot()
	if len(replies) != 3 {
		t.Fatalf("three messages produced %d replies: %q", len(replies), replies)
	}
	// The point of the session: the third reply depends on the first message.
	// A fuzzer that sent these independently would never see 250.
	for i, want := range []string{"220", "250", "221"} {
		if !strings.HasPrefix(replies[i], want) {
			t.Errorf("reply %d = %q, want a %s", i, replies[i], want)
		}
	}
}

// Without the handshake the target answers differently, which is the whole
// reason a session is the unit of work.
func TestSessionOrderDecidesTheReply(t *testing.T) {
	srv := newEchoServer(t)
	e, rec := newTestSession(t, srv.addr(), SessionOptions{Framing: FrameLine})
	if err := e.Start(context.Background()); err != nil {
		t.Fatal(err)
	}

	if _, err := e.Run(context.Background(), session("DATA\r\n"), nil); err != nil {
		t.Fatal(err)
	}
	replies, _ := rec.snapshot()
	if len(replies) != 1 || !strings.HasPrefix(replies[0], "503") {
		t.Fatalf("DATA before HELLO got %q, want a 503", replies)
	}
}

// Reconnect is the default because it is the only policy under which a session
// means the same thing every time it runs.
func TestReconnectGivesEachSessionAFreshConnection(t *testing.T) {
	srv := newEchoServer(t)
	e, rec := newTestSession(t, srv.addr(),
		SessionOptions{Framing: FrameLine, Reset: ResetReconnect})
	if err := e.Start(context.Background()); err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 3; i++ {
		if _, err := e.Run(context.Background(), session("DATA\r\n"), nil); err != nil {
			t.Fatalf("session %d: %v", i, err)
		}
	}
	replies, _ := rec.snapshot()
	for i, r := range replies {
		if !strings.HasPrefix(r, "503") {
			t.Errorf("session %d got %q; a fresh connection has not said HELLO", i, r)
		}
	}
}

// ResetNone carries state across sessions on purpose, and the executor must
// really keep the connection or the policy is a lie.
func TestResetNoneCarriesStateBetweenSessions(t *testing.T) {
	srv := newEchoServer(t)
	e, rec := newTestSession(t, srv.addr(),
		SessionOptions{Framing: FrameLine, Reset: ResetNone})
	if err := e.Start(context.Background()); err != nil {
		t.Fatal(err)
	}

	if _, err := e.Run(context.Background(), session("HELLO\r\n"), nil); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Run(context.Background(), session("DATA\r\n"), nil); err != nil {
		t.Fatal(err)
	}

	replies, _ := rec.snapshot()
	if len(replies) != 2 {
		t.Fatalf("two sessions produced %d replies: %q", len(replies), replies)
	}
	if !strings.HasPrefix(replies[1], "250") {
		t.Errorf("the second session got %q; the handshake from the first did not carry over",
			replies[1])
	}
}

// A target that hangs up is telling the campaign something, and the executor
// has to pass it on rather than reporting a harness failure.
func TestHangupIsRecordedNotReportedAsAnError(t *testing.T) {
	srv := newEchoServer(t)
	e, rec := newTestSession(t, srv.addr(), SessionOptions{Framing: FrameLine})
	if err := e.Start(context.Background()); err != nil {
		t.Fatal(err)
	}

	// QUIT closes the connection; the message after it has nowhere to go.
	ek, err := e.Run(context.Background(), session("QUIT\r\n", "DATA\r\n"), nil)
	if err != nil {
		t.Fatalf("a hangup was reported as a harness error: %v", err)
	}
	if ek != feedback.ExitOK {
		t.Errorf("an unmanaged target's hangup ended %v, want ok", ek)
	}
	if _, hangups := rec.snapshot(); hangups == 0 {
		t.Error("the hangup was not recorded")
	}
}

// Idle framing must work without knowing the protocol, which is why it is the
// default — and it must not merge two replies into one.
func TestIdleFramingSeparatesReplies(t *testing.T) {
	srv := newEchoServer(t)
	e, rec := newTestSession(t, srv.addr(),
		SessionOptions{Framing: FrameIdle, QuietPeriod: 30 * time.Millisecond})
	if err := e.Start(context.Background()); err != nil {
		t.Fatal(err)
	}

	if _, err := e.Run(context.Background(), session("HELLO\r\n", "DATA\r\n"), nil); err != nil {
		t.Fatal(err)
	}
	replies, _ := rec.snapshot()
	if len(replies) != 2 {
		t.Fatalf("idle framing produced %d replies for two messages: %q", len(replies), replies)
	}
	if !strings.HasPrefix(replies[0], "220") || !strings.HasPrefix(replies[1], "250") {
		t.Errorf("replies = %q; idle framing merged or split them", replies)
	}
}

// A session is a Repeat of messages, and each child is delivered whole. Encoding
// the tree and splitting the bytes afterwards would put the message boundary at
// the mercy of the mutation that last ran.
func TestMessagesComeFromTheTreeNotTheBytes(t *testing.T) {
	in := session("AB", "CD", "EF")
	msgs := messagesOf(in)
	if len(msgs) != 3 {
		t.Fatalf("a three-message session split into %d", len(msgs))
	}
	for i, want := range []string{"AB", "CD", "EF"} {
		if string(msgs[i]) != want {
			t.Errorf("message %d = %q, want %q", i, msgs[i], want)
		}
	}

	// And a non-session input is one message, which is how a stateless campaign
	// runs on this tier with nothing switched off.
	one := messagesOf(Input{Node: ir.Blob("m", []byte("solo"))})
	if len(one) != 1 || string(one[0]) != "solo" {
		t.Errorf("a lone node became %q, want one message", one)
	}
	if got := messagesOf(Input{}); got != nil {
		t.Errorf("an empty input became %q, want nothing", got)
	}
}

// The policy ADR-0006 defers has to say so rather than quietly doing something
// weaker, because a campaign that asked for snapshot and got reconnect has
// findings that do not mean what it thinks.
func TestSnapshotResetIsRefusedClearly(t *testing.T) {
	e, _ := newTestSession(t, "127.0.0.1:1", SessionOptions{Reset: ResetSnapshot})
	err := e.Start(context.Background())
	if err == nil {
		t.Fatal("the snapshot policy was accepted")
	}
	if !strings.Contains(err.Error(), "snapshot") {
		t.Errorf("the refusal does not name the policy: %v", err)
	}
}

// A target that never accepts is a configuration error, and the message has to
// name the address rather than being a bare timeout.
func TestStartFailsClearlyWhenNothingListens(t *testing.T) {
	e, _ := newTestSession(t, "127.0.0.1:1",
		SessionOptions{ReadyTimeout: 150 * time.Millisecond, ConnectTimeout: 50 * time.Millisecond})
	err := e.Start(context.Background())
	if err == nil {
		t.Fatal("Start succeeded against a port with nothing on it")
	}
	if !strings.Contains(err.Error(), "127.0.0.1:1") {
		t.Errorf("the error does not name the address: %v", err)
	}
}

func TestSessionCapabilitiesReportTheTier(t *testing.T) {
	e, _ := newTestSession(t, "127.0.0.1:1", SessionOptions{})
	c := e.Capabilities()
	if c.Tier != TierSession {
		t.Errorf("tier = %v, want %v", c.Tier, TierSession)
	}
	// A protocol server has timers and sequence numbers. Claiming determinism
	// would let the engine treat a differing replay as a corrupted corpus.
	if c.Deterministic {
		t.Error("the session tier claims determinism it cannot provide")
	}
	if !c.TimeoutEnforced {
		t.Error("the session tier claims it cannot enforce timeouts, but it can")
	}
}
