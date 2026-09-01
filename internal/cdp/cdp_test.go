package cdp

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// A WebSocket server, in the test only, so the framing is exercised in both
// directions against something that is not itself.
//
// A round trip through the same encoder proves nothing: a client that masks
// wrongly and unmasks wrongly agrees with itself perfectly. This server does the
// handshake the RFC describes, rejects an unmasked client frame the way a real
// one must, and answers with server frames that are deliberately not masked.
type testServer struct {
	ln       net.Listener
	t        *testing.T
	handle   func(*serverConn, []byte)
	onAccept func(*serverConn)

	// pongs receives every pong the client sends. It is filled by the one
	// reader in session, because two goroutines reading the same connection
	// would each take half the frames.
	pongs chan []byte
}

type serverConn struct {
	c   net.Conn
	br  *bufio.Reader
	mu  sync.Mutex
	bad chan string
}

func newTestServer(t *testing.T, handle func(*serverConn, []byte)) *testServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &testServer{ln: ln, t: t, handle: handle, pongs: make(chan []byte, 4)}
	t.Cleanup(func() { ln.Close() })
	go s.serve()
	return s
}

func (s *testServer) endpoint() string { return "ws://" + s.ln.Addr().String() + "/devtools/browser/x" }

func (s *testServer) serve() {
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.session(c)
	}
}

func (s *testServer) session(c net.Conn) {
	defer c.Close()
	br := bufio.NewReader(c)
	var key string
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}
		if name, value, ok := strings.Cut(line, ":"); ok &&
			strings.EqualFold(strings.TrimSpace(name), "Sec-WebSocket-Key") {
			key = strings.TrimSpace(value)
		}
	}
	if key == "" {
		return
	}
	resp := "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n" +
		"Connection: Upgrade\r\nSec-WebSocket-Accept: " + acceptKey(key) + "\r\n\r\n"
	if _, err := io.WriteString(c, resp); err != nil {
		return
	}
	sc := &serverConn{c: c, br: br, bad: make(chan string, 4)}
	if s.onAccept != nil {
		s.onAccept(sc)
	}
	for {
		op, payload, err := sc.read()
		if err != nil {
			return
		}
		switch op {
		case opClose:
			return
		case opPong:
			select {
			case s.pongs <- payload:
			default:
			}
		case opText:
			if s.handle != nil {
				s.handle(sc, payload)
			}
		}
	}
}

// read returns one client frame, requiring it to be masked.
func (sc *serverConn) read() (byte, []byte, error) {
	var h [2]byte
	if _, err := io.ReadFull(sc.br, h[:]); err != nil {
		return 0, nil, err
	}
	op := h[0] & 0x0F
	if h[1]&0x80 == 0 {
		sc.bad <- "a client frame arrived unmasked, which RFC 6455 requires a server to reject"
		return 0, nil, errors.New("unmasked")
	}
	size := uint64(h[1] & 0x7F)
	switch size {
	case 126:
		var b [2]byte
		if _, err := io.ReadFull(sc.br, b[:]); err != nil {
			return 0, nil, err
		}
		size = uint64(binary.BigEndian.Uint16(b[:]))
	case 127:
		var b [8]byte
		if _, err := io.ReadFull(sc.br, b[:]); err != nil {
			return 0, nil, err
		}
		size = binary.BigEndian.Uint64(b[:])
	}
	var mask [4]byte
	if _, err := io.ReadFull(sc.br, mask[:]); err != nil {
		return 0, nil, err
	}
	buf := make([]byte, size)
	if _, err := io.ReadFull(sc.br, buf); err != nil {
		return 0, nil, err
	}
	for i := range buf {
		buf[i] ^= mask[i&3]
	}
	return op, buf, nil
}

// write sends an unmasked server frame, optionally fragmented.
func (sc *serverConn) write(op byte, payload []byte, fin bool) error {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	var hdr [10]byte
	if fin {
		hdr[0] = 0x80 | op
	} else {
		hdr[0] = op
	}
	n := 2
	switch {
	case len(payload) < 126:
		hdr[1] = byte(len(payload))
	case len(payload) <= 0xFFFF:
		hdr[1] = 126
		binary.BigEndian.PutUint16(hdr[2:], uint16(len(payload)))
		n = 4
	default:
		hdr[1] = 127
		binary.BigEndian.PutUint64(hdr[2:], uint64(len(payload)))
		n = 10
	}
	if _, err := sc.c.Write(hdr[:n]); err != nil {
		return err
	}
	_, err := sc.c.Write(payload)
	return err
}

func (sc *serverConn) send(op byte, payload []byte) error { return sc.write(op, payload, true) }

func dialer() DialFunc {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, address)
	}
}

func TestCallGetsItsOwnReply(t *testing.T) {
	// Two commands outstanding at once, answered out of order. The identifier
	// is the only thing that keeps them apart, and a client that assumed
	// replies arrive in order would hand each caller the other's answer —
	// which for a driver means reading the previous page's document.
	s := newTestServer(t, func(sc *serverConn, req []byte) {
		var m message
		if err := json.Unmarshal(req, &m); err != nil {
			t.Error(err)
			return
		}
		go func() {
			if m.Method == "Slow" {
				time.Sleep(60 * time.Millisecond)
			}
			reply, _ := json.Marshal(message{ID: m.ID,
				Result: json.RawMessage(`{"who":"` + m.Method + `"}`)})
			sc.send(opText, reply)
		}()
	})

	ctx := context.Background()
	c, err := Dial(ctx, dialer(), s.endpoint())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	type reply struct {
		Who string `json:"who"`
	}
	var slow, fast reply
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := c.Call(ctx, "", "Slow", nil, &slow); err != nil {
			t.Error(err)
		}
	}()
	time.Sleep(10 * time.Millisecond)
	if err := c.Call(ctx, "", "Fast", nil, &fast); err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	if fast.Who != "Fast" || slow.Who != "Slow" {
		t.Fatalf("replies were crossed: fast=%q slow=%q", fast.Who, slow.Who)
	}
}

func TestProtocolErrorIsReturnedNotSwallowed(t *testing.T) {
	s := newTestServer(t, func(sc *serverConn, req []byte) {
		var m message
		json.Unmarshal(req, &m)
		reply, _ := json.Marshal(message{ID: m.ID,
			Error: &protoError{Code: -32000, Message: "No node with given id found"}})
		sc.send(opText, reply)
	})
	c, err := Dial(context.Background(), dialer(), s.endpoint())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	err = c.Call(context.Background(), "", "DOM.getOuterHTML", nil, nil)
	if err == nil {
		t.Fatal("a refused command reported success")
	}
	if !strings.Contains(err.Error(), "No node with given id") {
		t.Fatalf("the browser's reason was lost: %v", err)
	}
}

func TestEventsReachTheHandler(t *testing.T) {
	s := newTestServer(t, nil)
	// The browser speaks only once the handler is registered. It cannot be
	// registered until Dial returns, and the server's accept hook runs as soon
	// as the handshake is answered — so a server that sent the event there would
	// be racing the test, and on a loaded machine would win: the event arrives
	// with nothing to dispatch it to, is dropped, and the test reports that no
	// event ever came. What is under test is that an event reaches a handler,
	// not that one arriving before any handler exists is kept.
	ready := make(chan struct{})
	s.onAccept = func(sc *serverConn) {
		<-ready
		ev, _ := json.Marshal(message{Method: "Runtime.exceptionThrown",
			SessionID: "S1", Params: json.RawMessage(`{"text":"boom"}`)})
		sc.send(opText, ev)
	}
	c, err := Dial(context.Background(), dialer(), s.endpoint())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	got := make(chan Event, 1)
	c.OnEvent(func(e Event) { got <- e })
	close(ready)
	select {
	case e := <-got:
		if e.Method != "Runtime.exceptionThrown" || e.SessionID != "S1" {
			t.Fatalf("event = %+v", e)
		}
		if !strings.Contains(string(e.Params), "boom") {
			t.Fatalf("the event lost its payload: %s", e.Params)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("no event arrived")
	}
}

func TestAFragmentedMessageIsReassembled(t *testing.T) {
	// The browser fragments a large reply, and a large reply is exactly what a
	// document fingerprint is. A client that treated the first fragment as the
	// whole message would silently truncate every page state.
	s := newTestServer(t, func(sc *serverConn, req []byte) {
		var m message
		json.Unmarshal(req, &m)
		reply, _ := json.Marshal(message{ID: m.ID,
			Result: json.RawMessage(`{"value":"` + strings.Repeat("x", 300) + `"}`)})
		half := len(reply) / 2
		sc.write(opText, reply[:half], false)
		sc.write(opContinuation, reply[half:], true)
	})
	c, err := Dial(context.Background(), dialer(), s.endpoint())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	var res struct {
		Value string `json:"value"`
	}
	if err := c.Call(context.Background(), "", "Runtime.evaluate", nil, &res); err != nil {
		t.Fatal(err)
	}
	if len(res.Value) != 300 {
		t.Fatalf("the reassembled message is %d bytes, want 300", len(res.Value))
	}
}

func TestAPingIsAnswered(t *testing.T) {
	s := newTestServer(t, nil)
	s.onAccept = func(sc *serverConn) { sc.send(opPing, []byte("keepalive")) }
	c, err := Dial(context.Background(), dialer(), s.endpoint())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	select {
	case got := <-s.pongs:
		if string(got) != "keepalive" {
			t.Fatalf("the pong carried %q, not the ping's payload", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the client did not answer a ping, so a browser that keeps the " +
			"connection alive that way would drop it mid-campaign")
	}
}

func TestADeadBrowserFailsEveryWaitingCall(t *testing.T) {
	// The failure that matters most: the browser was killed, and a driver
	// waiting on a command must be told rather than blocked until the whole
	// campaign's timeout.
	s := newTestServer(t, func(sc *serverConn, req []byte) { sc.c.Close() })
	c, err := Dial(context.Background(), dialer(), s.endpoint())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	done := make(chan error, 1)
	go func() { done <- c.Call(context.Background(), "", "Page.navigate", nil, nil) }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a command against a dead connection reported success")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("a command against a dead connection never returned")
	}
}

func TestAWrongHandshakeKeyIsRefused(t *testing.T) {
	// Whatever answered is not the server this asked for. Continuing would read
	// its bytes as WebSocket frames.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		br := bufio.NewReader(c)
		for {
			line, err := br.ReadString('\n')
			if err != nil || strings.TrimRight(line, "\r\n") == "" {
				break
			}
		}
		io.WriteString(c, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"+
			"Connection: Upgrade\r\nSec-WebSocket-Accept: bm90LXRoZS1rZXk=\r\n\r\n")
	}()
	_, err = Dial(context.Background(), dialer(), "ws://"+ln.Addr().String()+"/x")
	if err == nil {
		t.Fatal("a server with the wrong accept key was treated as a DevTools endpoint")
	}
}

func TestClientFramesAreMasked(t *testing.T) {
	// The server rejects an unmasked frame, so this passes only if the client
	// masks. A real endpoint closes the connection on an unmasked frame, which
	// would look like a browser that died for no reason.
	bad := make(chan string, 1)
	s := newTestServer(t, func(sc *serverConn, req []byte) {
		var m message
		json.Unmarshal(req, &m)
		reply, _ := json.Marshal(message{ID: m.ID, Result: json.RawMessage(`{}`)})
		sc.send(opText, reply)
	})
	s.onAccept = func(sc *serverConn) {
		go func() {
			select {
			case msg := <-sc.bad:
				bad <- msg
			case <-time.After(time.Second):
			}
		}()
	}
	c, err := Dial(context.Background(), dialer(), s.endpoint())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.Call(context.Background(), "", "Page.enable", nil, nil); err != nil {
		t.Fatal(err)
	}
	select {
	case msg := <-bad:
		t.Fatal(msg)
	default:
	}
}

func TestAnOversizedFrameEndsTheConnection(t *testing.T) {
	// The browser is being driven into undefined behaviour, so how much of the
	// fuzzer's memory it may claim is not its decision.
	s := newTestServer(t, nil)
	s.onAccept = func(sc *serverConn) {
		var hdr [10]byte
		hdr[0] = 0x80 | opText
		hdr[1] = 127
		binary.BigEndian.PutUint64(hdr[2:], uint64(maxFrame)+1)
		sc.c.Write(hdr[:10])
	}
	c, err := Dial(context.Background(), dialer(), s.endpoint())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	select {
	case <-c.Done():
		if c.Err() == nil {
			t.Fatal("the connection ended with no reason recorded")
		}
		if !strings.Contains(c.Err().Error(), "cap") {
			t.Fatalf("ended for the wrong reason: %v", c.Err())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("an oversized frame was accepted")
	}
}
