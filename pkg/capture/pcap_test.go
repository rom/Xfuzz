package capture_test

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/rom/Xfuzz/pkg/capture"
)

// Reassembly is the part of the pcap reader that can be subtly and silently
// wrong: a stream joined across a gap parses as a request the server never saw,
// and a retransmission counted twice doubles a body. So the fixtures here are
// built packet by packet, with the awkward cases — out of order, retransmitted,
// overlapping, missing — constructed on purpose rather than hoped for.

// pcapBuilder writes a classic libpcap file over Ethernet and IPv4.
type pcapBuilder struct {
	buf bytes.Buffer
	ts  uint32
}

func newPcap() *pcapBuilder {
	b := &pcapBuilder{ts: 1_700_000_000}
	var hdr [24]byte
	binary.LittleEndian.PutUint32(hdr[0:], 0xA1B2C3D4) // magic
	binary.LittleEndian.PutUint16(hdr[4:], 2)          // version major
	binary.LittleEndian.PutUint16(hdr[6:], 4)          // version minor
	binary.LittleEndian.PutUint32(hdr[16:], 65535)     // snaplen
	binary.LittleEndian.PutUint32(hdr[20:], 1)         // Ethernet
	b.buf.Write(hdr[:])
	return b
}

// tcp appends one TCP segment from src to dst.
func (b *pcapBuilder) tcp(sport, dport uint16, seq uint32, flags byte, payload []byte) *pcapBuilder {
	tcpHdr := make([]byte, 20)
	binary.BigEndian.PutUint16(tcpHdr[0:], sport)
	binary.BigEndian.PutUint16(tcpHdr[2:], dport)
	binary.BigEndian.PutUint32(tcpHdr[4:], seq)
	tcpHdr[12] = 5 << 4 // data offset: five words
	tcpHdr[13] = flags
	binary.BigEndian.PutUint16(tcpHdr[14:], 65535)

	ip := make([]byte, 20)
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:], uint16(20+len(tcpHdr)+len(payload)))
	ip[8] = 64 // TTL
	ip[9] = 6  // TCP
	// 10.0.0.1 -> 10.0.0.2, with the direction decided by the ports.
	copy(ip[12:16], []byte{10, 0, 0, 1})
	copy(ip[16:20], []byte{10, 0, 0, 2})
	if dport == 45000 {
		copy(ip[12:16], []byte{10, 0, 0, 2})
		copy(ip[16:20], []byte{10, 0, 0, 1})
	}

	eth := make([]byte, 14)
	binary.BigEndian.PutUint16(eth[12:], 0x0800)

	frame := append(append(append(eth, ip...), tcpHdr...), payload...)

	var rec [16]byte
	binary.LittleEndian.PutUint32(rec[0:], b.ts)
	binary.LittleEndian.PutUint32(rec[4:], 0)
	binary.LittleEndian.PutUint32(rec[8:], uint32(len(frame)))
	binary.LittleEndian.PutUint32(rec[12:], uint32(len(frame)))
	b.buf.Write(rec[:])
	b.buf.Write(frame)
	b.ts++
	return b
}

const (
	clientPort = 45000
	serverPort = 80
)

// client and server append a segment in the respective direction.
func (b *pcapBuilder) client(seq uint32, flags byte, s string) *pcapBuilder {
	return b.tcp(clientPort, serverPort, seq, flags, []byte(s))
}

func (b *pcapBuilder) server(seq uint32, flags byte, s string) *pcapBuilder {
	return b.tcp(serverPort, clientPort, seq, flags, []byte(s))
}

func (b *pcapBuilder) reader() *bytes.Reader { return bytes.NewReader(b.buf.Bytes()) }

const (
	getReq  = "GET /items/42 HTTP/1.1\r\nHost: api.example.com\r\n\r\n"
	okResp  = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 15\r\n\r\n{\"id\":42,\"a\":1}"
	postReq = "POST /items HTTP/1.1\r\nHost: api.example.com\r\nContent-Type: application/json\r\nContent-Length: 12\r\n\r\n{\"name\":\"x\"}"
)

func TestPcapReadsARequestAndItsResponse(t *testing.T) {
	p := newPcap().
		client(1000, 0x02, "").     // SYN
		server(2000, 0x12, "").     // SYN-ACK
		client(1001, 0x18, getReq). // PSH+ACK
		server(2001, 0x18, okResp)

	c, err := capture.ReadPcap(p.reader())
	if err != nil {
		t.Fatal(err)
	}
	if c.Len() != 1 {
		t.Fatalf("read %d exchanges, want 1: %v", c.Len(), c.Notes)
	}
	e := c.Exchanges[0]
	if e.Request.Method != "GET" {
		t.Errorf("method %q", e.Request.Method)
	}
	if got := e.Request.Path(); got != "/items/42" {
		t.Errorf("path %q", got)
	}
	if e.Request.Host() != "api.example.com" {
		t.Errorf("host %q, want the value of the Host header", e.Request.Host())
	}
	if e.Response.Status != 200 {
		t.Errorf("status %d", e.Response.Status)
	}
	if string(e.Response.Body) != `{"id":42,"a":1}` {
		t.Errorf("body %q", e.Response.Body)
	}
}

// TestPcapReassemblesOutOfOrderSegments is the case that makes this reassembly
// rather than concatenation. A capture taken on a busy link routinely records
// segments in an order the receiver did not see them in.
func TestPcapReassemblesOutOfOrderSegments(t *testing.T) {
	half := len(getReq) / 2
	p := newPcap().
		client(1000, 0x02, "").
		server(2000, 0x12, "").
		// The second half first.
		client(1001+uint32(half), 0x18, getReq[half:]).
		client(1001, 0x18, getReq[:half]).
		server(2001, 0x18, okResp)

	c, err := capture.ReadPcap(p.reader())
	if err != nil {
		t.Fatal(err)
	}
	if c.Len() != 1 {
		t.Fatalf("read %d exchanges from a request split across two out-of-order "+
			"segments, want 1: %v", c.Len(), c.Notes)
	}
	if got := c.Exchanges[0].Request.Path(); got != "/items/42" {
		t.Errorf("path %q; the halves were joined in the wrong order", got)
	}
}

// TestPcapIgnoresARetransmission checks a duplicate segment does not duplicate
// its bytes, which would corrupt every request after it in the stream.
func TestPcapIgnoresARetransmission(t *testing.T) {
	p := newPcap().
		client(1000, 0x02, "").
		server(2000, 0x12, "").
		client(1001, 0x18, getReq).
		client(1001, 0x18, getReq). // the same segment again
		server(2001, 0x18, okResp)

	c, err := capture.ReadPcap(p.reader())
	if err != nil {
		t.Fatal(err)
	}
	if c.Len() != 1 {
		t.Fatalf("a retransmitted segment produced %d exchanges, want 1", c.Len())
	}
}

// TestPcapStopsAtAGapRatherThanJoiningAcrossIt is the correctness property that
// matters most. Packets the capture missed are not packets that did not exist,
// and joining across the hole produces a byte stream that never travelled.
func TestPcapStopsAtAGapRatherThanJoiningAcrossIt(t *testing.T) {
	p := newPcap().
		client(1000, 0x02, "").
		server(2000, 0x12, "").
		client(1001, 0x18, getReq).
		server(2001, 0x18, okResp).
		// A second request whose first half was never captured.
		client(1001+uint32(len(getReq))+50, 0x18, postReq[20:])

	c, err := capture.ReadPcap(p.reader())
	if err != nil {
		t.Fatal(err)
	}
	if c.Len() != 1 {
		t.Errorf("read %d exchanges; the bytes after the gap must not be joined to the "+
			"bytes before it", c.Len())
	}
}

// TestPcapReadsPipelinedRequests checks several requests on one connection are
// each paired with their own response.
func TestPcapReadsPipelinedRequests(t *testing.T) {
	p := newPcap().
		client(1000, 0x02, "").
		server(2000, 0x12, "").
		client(1001, 0x18, getReq).
		client(1001+uint32(len(getReq)), 0x18, postReq).
		server(2001, 0x18, okResp).
		server(2001+uint32(len(okResp)), 0x18, "HTTP/1.1 201 Created\r\nContent-Length: 0\r\n\r\n")

	c, err := capture.ReadPcap(p.reader())
	if err != nil {
		t.Fatal(err)
	}
	if c.Len() != 2 {
		t.Fatalf("read %d exchanges from two pipelined requests: %v", c.Len(), c.Notes)
	}
	if c.Exchanges[0].Response.Status != 200 || c.Exchanges[1].Response.Status != 201 {
		t.Errorf("responses paired as %d then %d, want 200 then 201",
			c.Exchanges[0].Response.Status, c.Exchanges[1].Response.Status)
	}
	if string(c.Exchanges[1].Request.Body) != `{"name":"x"}` {
		t.Errorf("the second request's body is %q", c.Exchanges[1].Request.Body)
	}
}

// TestPcapSaysWhenTheTrafficWasEncrypted is the difference between a useful
// diagnostic and a mystery. A capture of TLS is a capture of ciphertext, and an
// operator told "no HTTP found" would go looking for the wrong problem.
func TestPcapSaysWhenTheTrafficWasEncrypted(t *testing.T) {
	// A TLS record: content type 22 (handshake), version 3.1, then a length.
	tls := string([]byte{0x16, 0x03, 0x01, 0x00, 0x40}) + strings.Repeat("\x00", 0x40)
	p := newPcap().
		client(1000, 0x02, "").
		server(2000, 0x12, "").
		client(1001, 0x18, tls)

	_, err := capture.ReadPcap(p.reader())
	if err == nil {
		t.Fatal("a capture of TLS produced exchanges")
	}
	if !strings.Contains(err.Error(), "TLS") {
		t.Errorf("the error does not say the traffic was encrypted: %v", err)
	}
}

// TestPcapRefusesWhatItCannotRead covers the two files an operator is most
// likely to hand it by mistake.
func TestPcapRefusesWhatItCannotRead(t *testing.T) {
	t.Run("pcapng", func(t *testing.T) {
		ng := []byte{0x0A, 0x0D, 0x0D, 0x0A, 0, 0, 0, 0}
		_, err := capture.ReadPcap(bytes.NewReader(ng))
		if err == nil {
			t.Fatal("a pcapng file was accepted")
		}
		if !strings.Contains(err.Error(), "pcapng") {
			t.Errorf("the error does not name the format: %v", err)
		}
	})
	t.Run("not a capture", func(t *testing.T) {
		if _, err := capture.ReadPcap(strings.NewReader("hello")); err == nil {
			t.Fatal("an arbitrary file was accepted as a pcap")
		}
	})
}

// TestPcapIsDeterministic guards the property a capture-seeded campaign rests
// on. Go randomises map iteration, and headers arrive from a map.
func TestPcapIsDeterministic(t *testing.T) {
	build := func() *bytes.Reader {
		return newPcap().
			client(1000, 0x02, "").
			server(2000, 0x12, "").
			client(1001, 0x18, "GET /a HTTP/1.1\r\nHost: h\r\nX-A: 1\r\nX-B: 2\r\nX-C: 3\r\n\r\n").
			server(2001, 0x18, okResp).
			reader()
	}
	first, err := capture.ReadPcap(build())
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 8; i++ {
		again, err := capture.ReadPcap(build())
		if err != nil {
			t.Fatal(err)
		}
		if !sameHeaders(first.Exchanges[0].Request.Headers, again.Exchanges[0].Request.Headers) {
			t.Fatalf("reading the same capture twice gave different header orders:\n%v\n%v",
				first.Exchanges[0].Request.Headers, again.Exchanges[0].Request.Headers)
		}
	}
}

func sameHeaders(a, b []capture.Header) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
