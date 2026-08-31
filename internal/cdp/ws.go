package cdp

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"
)

// A WebSocket client, written here rather than taken from the ecosystem.
//
// ADR-0001 makes a runtime dependency on somebody else's fuzzer the thing this
// project does not do, and ADR-0017 keeps the core pure Go; neither forbids a
// library, but a WebSocket client is four hundred lines of framing whose whole
// job is to be exactly right about a wire format, and the alternative is a
// dependency in the fuzzer's own address space that a hostile page's traffic
// reaches. The frames read here come from a browser being driven into undefined
// behaviour by a fuzzer, which is the wrong place to be generous about input.
//
// So it implements RFC 6455 for the one direction that matters: a client that
// dials, upgrades, sends text and reads text, answers a ping and honours a
// close. No extensions, no compression, no subprotocols — the DevTools
// endpoint asks for none of them.

// wsGUID is the constant RFC 6455 appends to the client key before hashing.
const wsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

// maxFrame caps a single incoming message.
//
// A DOM snapshot from a page a fuzzer has been mutating can be large, and a
// page that has been driven into a redraw loop can be enormous. Thirty-two
// mebibytes is well above any state worth fingerprinting and well below what
// would exhaust a worker; a message longer than this ends the connection rather
// than being buffered, because the alternative is that the target chooses how
// much of the fuzzer's memory to use.
const maxFrame = 32 << 20

// WebSocket opcodes.
const (
	opContinuation = 0x0
	opText         = 0x1
	opBinary       = 0x2
	opClose        = 0x8
	opPing         = 0x9
	opPong         = 0xA
)

// DialFunc opens a connection. It is supplied by the caller rather than taken
// from net, because every outbound connection in Xfuzz passes the scope guard
// (ADR-0012) and the architecture lint enforces it from the other side.
type DialFunc func(ctx context.Context, network, address string) (net.Conn, error)

// wsConn is a client WebSocket connection.
type wsConn struct {
	c  net.Conn
	br *bufio.Reader

	wmu sync.Mutex // one writer at a time: a frame must not interleave
}

// wsDial opens a WebSocket connection to a ws:// URL.
func wsDial(ctx context.Context, dial DialFunc, raw string) (*wsConn, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("cdp: %q is not a usable endpoint: %w", raw, err)
	}
	if u.Scheme != "ws" {
		// wss would need TLS, which the DevTools endpoint does not speak: it
		// listens on loopback and relies on that. Refusing the scheme is better
		// than connecting in the clear to something that expected otherwise.
		return nil, fmt.Errorf("cdp: %q is not a ws:// endpoint", raw)
	}
	host := u.Host
	if u.Port() == "" {
		host = net.JoinHostPort(u.Hostname(), "80")
	}

	c, err := dial(ctx, "tcp", host)
	if err != nil {
		return nil, fmt.Errorf("cdp: connecting to %s: %w", host, err)
	}
	if d, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(d)
	}

	key := make([]byte, 16)
	if _, err := rand.Read(key); err != nil {
		c.Close()
		return nil, fmt.Errorf("cdp: generating a handshake key: %w", err)
	}
	k := base64.StdEncoding.EncodeToString(key)

	path := u.RequestURI()
	if path == "" {
		path = "/"
	}
	req := "GET " + path + " HTTP/1.1\r\n" +
		"Host: " + u.Host + "\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Key: " + k + "\r\n" +
		"Sec-WebSocket-Version: 13\r\n\r\n"
	if _, err := io.WriteString(c, req); err != nil {
		c.Close()
		return nil, fmt.Errorf("cdp: sending the upgrade request: %w", err)
	}

	br := bufio.NewReaderSize(c, 64<<10)
	if err := readHandshake(br, k); err != nil {
		c.Close()
		return nil, err
	}
	// The deadline was for the handshake. Leaving it in place would kill an idle
	// connection between two commands, which is most of a driver's life.
	_ = c.SetDeadline(time.Time{})
	return &wsConn{c: c, br: br}, nil
}

// readHandshake consumes the server's 101 response and checks the accept key.
//
// The check is not ceremony. Without it any server that answers 101 — a proxy,
// a captive portal, the wrong process on a reused port — is treated as a
// DevTools endpoint, and the first frame is read as though the bytes were
// WebSocket framing.
func readHandshake(br *bufio.Reader, key string) error {
	status, err := br.ReadString('\n')
	if err != nil {
		return fmt.Errorf("cdp: reading the upgrade response: %w", err)
	}
	if !strings.HasPrefix(status, "HTTP/1.1 101") {
		return fmt.Errorf("cdp: the endpoint refused the upgrade: %s",
			strings.TrimSpace(status))
	}
	want := acceptKey(key)
	var got string
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return fmt.Errorf("cdp: reading the upgrade headers: %w", err)
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(name), "Sec-WebSocket-Accept") {
			got = strings.TrimSpace(value)
		}
	}
	if got != want {
		return errors.New("cdp: the endpoint's handshake key is wrong, so whatever " +
			"answered is not the WebSocket server this asked for")
	}
	return nil
}

// acceptKey computes the value RFC 6455 requires the server to return.
func acceptKey(clientKey string) string {
	h := sha1.Sum([]byte(clientKey + wsGUID))
	return base64.StdEncoding.EncodeToString(h[:])
}

// WriteText sends one text message.
func (w *wsConn) WriteText(b []byte) error {
	w.wmu.Lock()
	defer w.wmu.Unlock()
	return w.writeFrame(opText, b)
}

// writeFrame writes one masked frame. Every client frame is masked; a server
// that receives an unmasked one is required to close the connection.
func (w *wsConn) writeFrame(op byte, payload []byte) error {
	var hdr [14]byte
	hdr[0] = 0x80 | op // FIN set: one frame per message, never fragmented
	n := 2
	switch {
	case len(payload) < 126:
		hdr[1] = 0x80 | byte(len(payload))
	case len(payload) <= 0xFFFF:
		hdr[1] = 0x80 | 126
		binary.BigEndian.PutUint16(hdr[2:], uint16(len(payload)))
		n = 4
	default:
		hdr[1] = 0x80 | 127
		binary.BigEndian.PutUint64(hdr[2:], uint64(len(payload)))
		n = 10
	}
	var mask [4]byte
	if _, err := rand.Read(mask[:]); err != nil {
		return fmt.Errorf("cdp: generating a frame mask: %w", err)
	}
	copy(hdr[n:], mask[:])
	n += 4

	// Masked into a copy: the caller's buffer is the marshalled command and
	// masking it in place would corrupt it for anyone still holding it.
	masked := make([]byte, len(payload))
	for i := range payload {
		masked[i] = payload[i] ^ mask[i&3]
	}
	if _, err := w.c.Write(hdr[:n]); err != nil {
		return fmt.Errorf("cdp: writing a frame header: %w", err)
	}
	if len(masked) > 0 {
		if _, err := w.c.Write(masked); err != nil {
			return fmt.Errorf("cdp: writing a frame: %w", err)
		}
	}
	return nil
}

// ReadMessage returns the next complete text or binary message.
//
// Control frames are handled here rather than reported: a ping is answered, a
// close ends the connection with io.EOF. A caller reading commands should not
// have to know that a protocol-level keepalive exists.
func (w *wsConn) ReadMessage() ([]byte, error) {
	var msg []byte
	for {
		fin, op, payload, err := w.readFrame()
		if err != nil {
			return nil, err
		}
		switch op {
		case opPing:
			w.wmu.Lock()
			err := w.writeFrame(opPong, payload)
			w.wmu.Unlock()
			if err != nil {
				return nil, err
			}
			continue
		case opPong:
			continue
		case opClose:
			return nil, io.EOF
		case opText, opBinary:
			msg = payload
		case opContinuation:
			msg = append(msg, payload...)
		default:
			return nil, fmt.Errorf("cdp: the endpoint sent opcode %#x, which this "+
				"client does not implement", op)
		}
		if fin {
			return msg, nil
		}
		if len(msg) > maxFrame {
			return nil, fmt.Errorf("cdp: a fragmented message exceeded %d bytes", maxFrame)
		}
	}
}

// readFrame reads one frame, unmasking it if the server masked it.
func (w *wsConn) readFrame() (fin bool, op byte, payload []byte, err error) {
	var h [2]byte
	if _, err := io.ReadFull(w.br, h[:]); err != nil {
		return false, 0, nil, err
	}
	fin = h[0]&0x80 != 0
	if h[0]&0x70 != 0 {
		// Reserved bits set means an extension was negotiated. None was, so the
		// frame cannot be interpreted and guessing would desynchronise the
		// stream silently.
		return false, 0, nil, errors.New("cdp: the endpoint used a WebSocket extension " +
			"that was never negotiated")
	}
	op = h[0] & 0x0F
	masked := h[1]&0x80 != 0
	size := uint64(h[1] & 0x7F)
	switch size {
	case 126:
		var b [2]byte
		if _, err := io.ReadFull(w.br, b[:]); err != nil {
			return false, 0, nil, err
		}
		size = uint64(binary.BigEndian.Uint16(b[:]))
	case 127:
		var b [8]byte
		if _, err := io.ReadFull(w.br, b[:]); err != nil {
			return false, 0, nil, err
		}
		size = binary.BigEndian.Uint64(b[:])
	}
	if size > maxFrame {
		return false, 0, nil, fmt.Errorf("cdp: the endpoint announced a %d-byte frame, "+
			"above the %d-byte cap", size, maxFrame)
	}
	var mask [4]byte
	if masked {
		if _, err := io.ReadFull(w.br, mask[:]); err != nil {
			return false, 0, nil, err
		}
	}
	payload = make([]byte, size)
	if _, err := io.ReadFull(w.br, payload); err != nil {
		return false, 0, nil, err
	}
	if masked {
		for i := range payload {
			payload[i] ^= mask[i&3]
		}
	}
	return fin, op, payload, nil
}

// Close sends a close frame and shuts the connection down.
func (w *wsConn) Close() error {
	w.wmu.Lock()
	// Best effort: the endpoint may already be gone, which is the ordinary case
	// when the browser was killed, and reporting it would turn every normal
	// shutdown into an error.
	_ = w.writeFrame(opClose, []byte{0x03, 0xE8}) // 1000, normal closure
	w.wmu.Unlock()
	return w.c.Close()
}
