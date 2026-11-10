// Package smart holds the protocol-aware payload generators the registry
// wires into Protocol.Smart.
//
// A generator receives one PRNG and returns one payload. The engine calls it
// in a loop, so determinism is a property of the PRNG — the same seed at the
// same iteration produces the same payload, which is what makes a crash
// replayable. Each generator is the shape the parser will begin to accept,
// mutated at one of its structural fields rather than at random bytes.
//
// What makes these "smart" is the frame survives a sanity check: the magic
// matches, the length field is close to right, the type byte names something
// the parser offers. The mutation lives past the acceptance gate — in a
// length that lies, a nested field that overflows, an array whose count the
// payload does not actually contain. That is where parser bugs live.
package smart

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/rand"
	"strings"
)

// --- small helpers shared across the generators -------------------------------

// pickString returns one string from a pool. A smart generator picks a payload
// style from a short, named list so a run through the loop covers all of them
// — "bind as root", "bind as anon", "bind with huge DN" — rather than one
// style with random byte noise on top.
func pickString(rng *rand.Rand, pool []string) string {
	return pool[rng.Intn(len(pool))]
}

// oversizeLength injects an off-by-many length into an existing field.
//
// The field already holds a correct length; this rewrites it with a value
// large enough to pre-allocate against. Big-endian u16/u32 is the honeypot's
// most common framing.
func oversizeLength(buf []byte, off int, width int, rng *rand.Rand) {
	if off+width > len(buf) {
		return
	}
	// Choose from a bank of pathological lengths. A parser that trusts the
	// field over the payload's size allocates this much on the first one.
	ladder := []uint32{0x0000ffff, 0x00010000, 0x0010ffff, 0x7fffffff, 0xffffffff}
	val := ladder[rng.Intn(len(ladder))]
	switch width {
	case 2:
		binary.BigEndian.PutUint16(buf[off:], uint16(val&0xffff))
	case 4:
		binary.BigEndian.PutUint32(buf[off:], val)
	}
}

// --- shell / remote-login -----------------------------------------------------

// SSH builds an SSHv2 handshake with the version string mutated.
//
// The server reads one line, so the shape is a cleartext banner. A server
// that trips on an overlong version — the honeypot does not, but an
// archetype-specific server might — shows it here. The CR-LF, the "SSH-" tag
// and the version digit are the three structural fields the mutator picks
// between.
func SSH(rng *rand.Rand) []byte {
	versions := []string{"2.0", "1.99", "9999.99999", "", "\xff\xff"}
	tags := []string{"SSH-", "SSH-\x00", "SSh-", "SSH-" + strings.Repeat("A", 1<<12)}
	impls := []string{"OpenSSH_9.6p1", "libssh_0.11", "fuzz", strings.Repeat("Z", 1<<10)}
	line := pickString(rng, tags) + pickString(rng, versions) + "-" + pickString(rng, impls)
	// Half the time: no \r\n so the reader keeps waiting past its budget.
	if rng.Intn(2) == 0 {
		return []byte(line + "\r\n")
	}
	return []byte(line)
}

// Telnet builds a stream of IAC options. The handler parses each byte; what
// finds a bug is a subnegotiation whose SE never arrives, or an option code
// the handler's switch does not list.
func Telnet(rng *rand.Rand) []byte {
	var out bytes.Buffer
	for i := 0; i < 8+rng.Intn(64); i++ {
		switch rng.Intn(5) {
		case 0:
			out.Write([]byte{0xff, byte(0xfb + rng.Intn(4)), byte(rng.Intn(0x100))}) // WILL/WONT/DO/DONT
		case 1:
			// SB ... SE with no SE: the parser must bound the read.
			out.Write([]byte{0xff, 0xfa, byte(rng.Intn(0x100))})
			for j := 0; j < rng.Intn(1024); j++ {
				out.WriteByte(byte(rng.Intn(0x100)))
			}
		case 2:
			out.Write([]byte{0xff, 0xff}) // escaped 0xff
		default:
			out.WriteByte(byte(rng.Intn(0x100)))
		}
	}
	return out.Bytes()
}

// --- HTTP ---------------------------------------------------------------------

// HTTP is a request with a structural mutation — oversized header, a method
// nobody recognises, a path that tries directory-climbing, a body whose
// Content-Length lies.
func HTTP(rng *rand.Rand) []byte {
	methods := []string{"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "TRACE", "CONNECT", "PATCH", "WEIRD", strings.Repeat("A", 1<<10)}
	paths := []string{"/", "/..", "/../../../../../etc/passwd", "/" + strings.Repeat("A", 1<<12), "/?" + strings.Repeat("a=b&", 256), "/\x00/evil"}
	versions := []string{"HTTP/1.0", "HTTP/1.1", "HTTP/9.9", "HTTP/0.9", "HTTP/1.1\x00"}
	hosts := []string{"example.com", "a", strings.Repeat("h", 1<<10), "127.0.0.1\r\nX-Injected: yes"}
	var b bytes.Buffer
	fmt.Fprintf(&b, "%s %s %s\r\n", pickString(rng, methods), pickString(rng, paths), pickString(rng, versions))
	fmt.Fprintf(&b, "Host: %s\r\n", pickString(rng, hosts))
	// A sprinkle of extra headers, some of them famously trouble-making.
	extras := []string{
		"Transfer-Encoding: chunked\r\nContent-Length: 10\r\n",
		"Content-Length: -1\r\n",
		"Content-Length: " + strings.Repeat("9", 20) + "\r\n",
		"X-Forwarded-For: " + strings.Repeat("1.1.1.1, ", 1024) + "\r\n",
		"Cookie: " + strings.Repeat("A", 1<<14) + "\r\n",
	}
	for i := 0; i < 1+rng.Intn(3); i++ {
		b.WriteString(pickString(rng, extras))
	}
	b.WriteString("\r\n")
	// Body sometimes; sometimes with the wrong size relative to Content-Length.
	if rng.Intn(3) == 0 {
		body := make([]byte, rng.Intn(8192))
		_, _ = rng.Read(body)
		b.Write(body)
	}
	return b.Bytes()
}

// WebSocket is an HTTP Upgrade with a mutated key / version / extension list.
func WebSocket(rng *rand.Rand) []byte {
	keys := []string{"dGhlIHNhbXBsZSBub25jZQ==", "", strings.Repeat("A", 1<<10), "not-base64!!"}
	vers := []string{"13", "0", "255", strings.Repeat("9", 100)}
	var b bytes.Buffer
	fmt.Fprintf(&b, "GET /ws HTTP/1.1\r\nHost: fuzz\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Version: %s\r\n\r\n",
		pickString(rng, keys), pickString(rng, vers))
	return b.Bytes()
}

// RTSP is an HTTP-shaped protocol, so it reuses most of the HTTP generator's
// shapes with its own method set.
func RTSP(rng *rand.Rand) []byte {
	methods := []string{"OPTIONS", "DESCRIBE", "SETUP", "PLAY", "PAUSE", "TEARDOWN", "ANNOUNCE", "RECORD", "GET_PARAMETER", "SET_PARAMETER", "REDIRECT", strings.Repeat("X", 1<<10)}
	urls := []string{"rtsp://fuzz/stream", "rtsp://" + strings.Repeat("a", 1<<12) + "/x", "rtsp://*", "/relative"}
	var b bytes.Buffer
	fmt.Fprintf(&b, "%s %s RTSP/1.0\r\nCSeq: %d\r\nTransport: RTP/AVP;unicast;client_port=%d-%d\r\n\r\n",
		pickString(rng, methods), pickString(rng, urls), rng.Intn(1<<30), rng.Intn(65535), rng.Intn(65535))
	return b.Bytes()
}

// SIP is HTTP-shaped over a line protocol. Methods and malformed Vias are the
// usual trouble.
func SIP(rng *rand.Rand) []byte {
	methods := []string{"INVITE", "REGISTER", "OPTIONS", "SUBSCRIBE", "PUBLISH", "NOTIFY", "MESSAGE", "INFO", "UPDATE", "REFER", "BYE", "ACK", strings.Repeat("X", 1<<10)}
	var b bytes.Buffer
	fmt.Fprintf(&b, "%s sip:fuzz@example.com SIP/2.0\r\n", pickString(rng, methods))
	// A Via line with no branch, or a very long one.
	via := "SIP/2.0/UDP 127.0.0.1;branch=z9hG4bK." + strings.Repeat("v", rng.Intn(1<<12))
	fmt.Fprintf(&b, "Via: %s\r\nFrom: <sip:a@b>;tag=1\r\nTo: <sip:c@d>\r\nCall-ID: fuzz@local\r\nCSeq: %d %s\r\nContent-Length: %d\r\n\r\n",
		via, rng.Intn(1<<30), pickString(rng, methods), rng.Intn(1<<28))
	return b.Bytes()
}

// --- Mail ---------------------------------------------------------------------

// SMTP picks one of the dangerous commands and corrupts its argument.
func SMTP(rng *rand.Rand) []byte {
	cmds := []string{
		"EHLO " + strings.Repeat("H", 1<<10) + "\r\n",
		"MAIL FROM:<" + strings.Repeat("a", 1<<10) + "@b>\r\n",
		"RCPT TO:<>\r\n",
		"VRFY " + strings.Repeat("x", 1<<10) + "\r\n",
		"AUTH LOGIN " + strings.Repeat("A", 1<<16) + "\r\n",
		"STARTTLS\r\n",
		"DATA\r\n.\r\n",
		strings.Repeat("A", 1<<14) + "\r\n", // overlong command line
	}
	return []byte(pickString(rng, cmds))
}

// POP3 and IMAP are similar: pick one command with an abusive argument.
func POP3(rng *rand.Rand) []byte {
	cmds := []string{"CAPA\r\n", "USER " + strings.Repeat("u", 1<<10) + "\r\n", "PASS " + strings.Repeat("p", 1<<10) + "\r\n", "RETR -1\r\n", "DELE 99999999\r\n", "LIST 0\r\n"}
	return []byte(pickString(rng, cmds))
}
func IMAP(rng *rand.Rand) []byte {
	cmds := []string{"A001 CAPABILITY\r\n", "A002 LOGIN \"" + strings.Repeat("u", 1<<10) + "\" \"p\"\r\n", "A003 SELECT \"" + strings.Repeat("x", 1<<10) + "\"\r\n", "A004 FETCH 1:* ALL\r\n", "A005 LIST \"\" *\r\n"}
	return []byte(pickString(rng, cmds))
}

// --- File transfer ------------------------------------------------------------

// FTP sends a single command with a hostile argument. A classic shape is PORT
// with a line-break injection, which is a credible way to tunnel through.
func FTP(rng *rand.Rand) []byte {
	cmds := []string{
		"USER " + strings.Repeat("u", 1<<10) + "\r\n",
		"PASS " + strings.Repeat("p", 1<<10) + "\r\n",
		"PORT 127,0,0,1,0,80\r\nQUIT\r\n", // injection-shaped
		"CWD ../../../../../\r\n",
		"RNFR a\r\nRNTO " + strings.Repeat("b", 1<<10) + "\r\n",
		"STOR " + strings.Repeat("x", 1<<10) + "\r\n",
	}
	return []byte(pickString(rng, cmds))
}

// --- Windows / AD -------------------------------------------------------------

// SMB sends an SMB2 negotiate with a wildly oversized StructureSize.
func SMB(rng *rand.Rand) []byte {
	payload := []byte{
		0xFE, 'S', 'M', 'B', 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x24, 0x00, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00,
	}
	// Flip StructureSize, DialectCount or security mode.
	switch rng.Intn(3) {
	case 0:
		binary.LittleEndian.PutUint16(payload[64:], uint16(rng.Intn(0xFFFF)))
	case 1:
		binary.LittleEndian.PutUint16(payload[66:], uint16(rng.Intn(0xFFFF)))
	case 2:
		payload[68] = byte(rng.Intn(0x100))
	}
	// Prepend NetBIOS header: 4 bytes with a possibly-wrong length.
	nbt := []byte{0x00, 0x00, 0x00, byte(len(payload))}
	if rng.Intn(4) == 0 {
		// Lie about the length.
		nbt[2] = 0xff
		nbt[3] = 0xff
	}
	return append(nbt, payload...)
}

// RDP is an X.224 Connection Request. The cookie line is where Windows
// servers have historically tripped.
func RDP(rng *rand.Rand) []byte {
	cookies := []string{
		"mstshash=fuzz",
		"mstshash=" + strings.Repeat("A", 1<<10),
		"",
		strings.Repeat("\x00", 128),
	}
	cookie := []byte("Cookie: " + pickString(rng, cookies) + "\r\n")
	body := append(cookie, []byte{0x01, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00}...)
	tpkt := []byte{0x03, 0x00, 0x00, byte(7 + len(body))}
	x224 := []byte{byte(len(body) + 6), 0xE0, 0x00, 0x00, 0x00, 0x00, 0x00}
	return append(append(tpkt, x224...), body...)
}

// DCERPC is a bind with an abuse-shaped interface UUID list.
func DCERPC(rng *rand.Rand) []byte {
	// Build a bind header with a declared context count and only part of the
	// contexts actually present.
	nCtx := byte(rng.Intn(16))
	hdr := []byte{0x05, 0x00, 0x0b, 0x03, 0x10, 0x00, 0x00, 0x00, 0x48, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
		0xb8, 0x10, 0xb8, 0x10, 0x00, 0x00, 0x00, 0x00, nCtx, 0x00, 0x00, 0x00}
	// One actual context.
	ctx := []byte{0x00, 0x00, 0x01, 0x00,
		0x6a, 0x28, 0x19, 0x39, 0x0c, 0xb1, 0xd0, 0x11, 0x9b, 0xa8, 0x00, 0xc0, 0x4f, 0xd9, 0x2e, 0xf5,
		0x00, 0x00, 0x00, 0x00, 0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00,
		0x2b, 0x10, 0x48, 0x60, 0x02, 0x00, 0x00, 0x00}
	return append(hdr, ctx...)
}

// LDAP builds a BER-wrapped bindRequest with a very long DN.
func LDAP(rng *rand.Rand) []byte {
	dn := strings.Repeat("A", 1+rng.Intn(1<<12))
	// SEQUENCE { INTEGER msgid, BindRequest { INTEGER version, OCTET STRING name, [0] password } }
	body := []byte{0x02, 0x01, 0x01} // msgid=1
	// BindRequest tag 0x60, length will be computed.
	bind := []byte{0x02, 0x01, 0x03} // version=3
	// name
	bind = append(bind, 0x04, byte(len(dn)))
	bind = append(bind, []byte(dn)...)
	bind = append(bind, 0x80, 0x00) // [0] auth, empty
	bindLen := byte(len(bind) & 0xff)
	if rng.Intn(4) == 0 {
		// Oversize the length so the parser allocates to the lie.
		bindLen = 0xff
	}
	body = append(body, 0x60, bindLen)
	body = append(body, bind...)
	msgLen := byte(len(body) & 0xff)
	return append([]byte{0x30, msgLen}, body...)
}

// Kerberos is an AS-REQ with ASN.1 structural mutations.
func Kerberos(rng *rand.Rand) []byte {
	// Minimal AS-REQ shape; mutate the pvno and msg-type.
	payload := []byte{0x6a, 0x81, 0x24, 0x30, 0x81, 0x21,
		0xa1, 0x03, 0x02, 0x01, 0x05, // pvno=5
		0xa2, 0x03, 0x02, 0x01, 0x0a, // msg-type=10
		0xa3, 0x12, 0x30, 0x10,
		0x30, 0x0e, 0xa1, 0x03, 0x02, 0x01, 0x12, 0xa2, 0x07, 0x04, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05,
		0xa4, 0x06, 0x30, 0x04, 0xa0, 0x02, 0x04, 0x00}
	switch rng.Intn(3) {
	case 0:
		payload[10] = byte(rng.Intn(0x100)) // pvno
	case 1:
		payload[15] = byte(rng.Intn(0x100)) // msg-type
	case 2:
		payload[2] = 0xff // outer length claim
	}
	return payload
}

// --- Databases ---------------------------------------------------------------

// MySQL: handshake response with a username / auth-plugin that lies about
// its own length.
func MySQL(rng *rand.Rand) []byte {
	user := strings.Repeat("u", rng.Intn(1<<10))
	body := []byte{0x85, 0xa2, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	body = append(body, []byte(user)...)
	body = append(body, 0x00)
	body = append(body, 0x00) // auth-data length
	// MySQL packet header: 3-byte little-endian length + 1-byte sequence.
	hdr := []byte{byte(len(body)), byte(len(body) >> 8), byte(len(body) >> 16), 0x01}
	if rng.Intn(4) == 0 {
		hdr[0], hdr[1], hdr[2] = 0xff, 0xff, 0xff
	}
	return append(hdr, body...)
}

// Postgres startup with a parameter whose value is long or null.
func Postgres(rng *rand.Rand) []byte {
	user := strings.Repeat("u", rng.Intn(1<<10))
	body := bytes.NewBuffer(nil)
	binary.Write(body, binary.BigEndian, int32(0x00030000))
	body.WriteString("user")
	body.WriteByte(0)
	body.WriteString(user)
	body.WriteByte(0)
	body.WriteByte(0)
	out := make([]byte, 4)
	binary.BigEndian.PutUint32(out, uint32(4+body.Len()))
	if rng.Intn(4) == 0 {
		binary.BigEndian.PutUint32(out, 0xffffffff)
	}
	return append(out, body.Bytes()...)
}

// MSSQL TDS pre-login with an oversized option length.
func MSSQL(rng *rand.Rand) []byte {
	body := []byte{0x12, 0x01, 0x00, 0x2f, 0x00, 0x00, 0x01, 0x00,
		0x00, 0x00, 0x1a, 0x00, 0x06, 0x01, 0x00, 0x20, 0x00, 0x01, 0x02, 0x00, 0x21, 0x00, 0x01, 0x03, 0x00, 0x22, 0x00, 0x04, 0xff,
		0x08, 0x00, 0x01, 0x55, 0x00, 0x00, 0x02, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	// Mutate the declared TDS packet length (bytes 2..3, big-endian).
	binary.BigEndian.PutUint16(body[2:], uint16(0x8000+rng.Intn(0x8000)))
	return body
}

// Redis sends a RESP array whose declared count does not match its contents.
func Redis(rng *rand.Rand) []byte {
	declared := rng.Intn(1000)
	var b bytes.Buffer
	fmt.Fprintf(&b, "*%d\r\n", declared)
	actual := rng.Intn(3) + 1
	for i := 0; i < actual; i++ {
		s := strings.Repeat("A", rng.Intn(1024))
		fmt.Fprintf(&b, "$%d\r\n%s\r\n", len(s), s)
	}
	return b.Bytes()
}

// Memcached sends a command whose declared value size differs from the body.
func Memcached(rng *rand.Rand) []byte {
	cmds := []string{
		"set fuzz 0 0 " + fmt.Sprint(rng.Intn(1<<20)) + "\r\nshort\r\n",
		"get " + strings.Repeat("k", 1<<10) + "\r\n",
		"stats cachedump 1 1000000\r\n",
		"version\r\n",
	}
	return []byte(pickString(rng, cmds))
}

// MongoDB OP_MSG with a BSON document whose length header lies.
func MongoDB(rng *rand.Rand) []byte {
	bson := []byte{0x11, 0x00, 0x00, 0x00, 0x08, 'i', 's', 'm', 'a', 's', 't', 'e', 'r', 0x00, 0x01, 0x00}
	if rng.Intn(3) == 0 {
		// Lie about the BSON document length.
		binary.LittleEndian.PutUint32(bson[0:], 0xffffffff)
	}
	hdr := make([]byte, 20)
	binary.LittleEndian.PutUint32(hdr[0:], uint32(20+len(bson)))
	binary.LittleEndian.PutUint32(hdr[4:], 1)
	binary.LittleEndian.PutUint32(hdr[12:], 2013) // OP_MSG
	return append(hdr, bson...)
}

// --- OT / ICS ---------------------------------------------------------------

// Modbus: an MBAP frame with a mutated function or length.
func Modbus(rng *rand.Rand) []byte {
	// MBAP header: tid, protoId, length, unit
	buf := []byte{0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01,
		byte(rng.Intn(0x100)), // function code
		byte(rng.Intn(0x100)), byte(rng.Intn(0x100)),
		byte(rng.Intn(0x100)), byte(rng.Intn(0x100))}
	// Mutate length: valid or lying.
	if rng.Intn(3) == 0 {
		binary.BigEndian.PutUint16(buf[4:], uint16(0x1000+rng.Intn(0xf000)))
	}
	return buf
}

// S7: TPKT + COTP + S7 setup, with a mutated TPDU or function code.
func S7(rng *rand.Rand) []byte {
	// TPKT + COTP CR
	payload := []byte{0x03, 0x00, 0x00, 0x16, 0x11, 0xe0, 0x00, 0x00, 0x00, 0x01, 0x00,
		0xc0, 0x01, byte(rng.Intn(0x100)),
		0xc1, 0x02, 0x01, 0x00,
		0xc2, 0x02, 0x01, byte(rng.Intn(0x100))}
	// Lie about the TPKT length field.
	if rng.Intn(3) == 0 {
		binary.BigEndian.PutUint16(payload[2:], uint16(0x4000+rng.Intn(0x4000)))
	}
	return payload
}

// IEC104 APCI with mutated control-field semantics.
func IEC104(rng *rand.Rand) []byte {
	// Start byte 0x68, length field, 4 control bytes
	hdr := []byte{0x68, byte(rng.Intn(0x100)),
		byte(rng.Intn(0x100)), byte(rng.Intn(0x100)),
		byte(rng.Intn(0x100)), byte(rng.Intn(0x100))}
	// Append a random ASDU of mutated size.
	n := rng.Intn(260)
	asdu := make([]byte, n)
	_, _ = rng.Read(asdu)
	return append(hdr, asdu...)
}

// DNP3: a link-layer frame whose declared length lies.
func DNP3(rng *rand.Rand) []byte {
	hdr := []byte{0x05, 0x64, byte(rng.Intn(0x100)),
		byte(rng.Intn(0x100)), byte(rng.Intn(0x100)), byte(rng.Intn(0x100)),
		byte(rng.Intn(0x100)), byte(rng.Intn(0x100)), 0xe9, 0x21}
	n := rng.Intn(260)
	rest := make([]byte, n)
	_, _ = rng.Read(rest)
	return append(hdr, rest...)
}

// OPCUA HEL/ACK/OPN with mutated size.
func OPCUA(rng *rand.Rand) []byte {
	types := [][]byte{[]byte("HELF"), []byte("ACKF"), []byte("OPNF"), []byte("MSGF"), []byte("CLOF"), []byte("ERRF"), []byte("BADD")}
	hdr := append([]byte(nil), types[rng.Intn(len(types))]...)
	// Length field (4 bytes LE).
	ln := make([]byte, 4)
	binary.LittleEndian.PutUint32(ln, uint32(0x7fffffff))
	if rng.Intn(3) != 0 {
		binary.LittleEndian.PutUint32(ln, uint32(28+rng.Intn(1024)))
	}
	body := make([]byte, 24)
	_, _ = rng.Read(body)
	return append(append(hdr, ln...), body...)
}

// EtherNetIP (ENIP) encapsulation.
func EtherNetIP(rng *rand.Rand) []byte {
	// Command + length + session + status + context + options.
	hdr := make([]byte, 24)
	binary.LittleEndian.PutUint16(hdr[0:], uint16(rng.Intn(0x100)))
	// Length lies about what follows.
	binary.LittleEndian.PutUint16(hdr[2:], uint16(0x1000+rng.Intn(0xf000)))
	data := make([]byte, rng.Intn(256))
	_, _ = rng.Read(data)
	return append(hdr, data...)
}

// --- Messaging ---------------------------------------------------------------

// MQTT: a CONNECT with a variable-length remaining length that lies.
func MQTT(rng *rand.Rand) []byte {
	// Fixed header: CONNECT (0x10), remaining length (variable byte integer).
	remaining := encodeVarint(rng.Intn(1 << 28))
	variable := []byte{0x00, 0x04, 'M', 'Q', 'T', 'T', 0x04, 0x02, 0x00, 0x3c}
	clientID := strings.Repeat("c", rng.Intn(1<<10))
	payload := append([]byte{0x00, byte(len(clientID) >> 8), byte(len(clientID))}, []byte(clientID)...)
	body := append(variable, payload...)
	return append(append([]byte{0x10}, remaining...), body...)
}

// encodeVarint is MQTT's remaining-length encoding: 1 to 4 bytes, each with a
// continuation bit. Used alone and in the dumb mutator's oversized-length
// shape where the smart generator happens to need it.
func encodeVarint(v int) []byte {
	var out []byte
	for i := 0; i < 4; i++ {
		b := byte(v & 0x7f)
		v >>= 7
		if v > 0 {
			b |= 0x80
		}
		out = append(out, b)
		if v == 0 {
			break
		}
	}
	return out
}

// AMQP header plus a Start-Ok method frame with a bad class/method id.
func AMQP(rng *rand.Rand) []byte {
	// Protocol header
	hdr := []byte{'A', 'M', 'Q', 'P', 0, 0, 9, 1}
	// Method frame: type(1) channel(2) size(4) class(2) method(2) ...
	size := make([]byte, 4)
	// Lie about the size.
	binary.BigEndian.PutUint32(size, uint32(0x01000000+rng.Intn(0x00ffffff)))
	frame := append([]byte{0x01, 0x00, 0x00}, size...)
	// class + method
	frame = append(frame, byte(rng.Intn(0x100)), byte(rng.Intn(0x100)), byte(rng.Intn(0x100)), byte(rng.Intn(0x100)))
	// Payload bytes.
	body := make([]byte, rng.Intn(1024))
	_, _ = rng.Read(body)
	frame = append(frame, body...)
	frame = append(frame, 0xCE) // frame-end
	return append(hdr, frame...)
}

// --- UDP ----------------------------------------------------------------------

// DNS crafts a query whose name has unusual labels (overlong, compressed to
// itself, trailing bytes).
func DNS(rng *rand.Rand) []byte {
	hdr := []byte{byte(rng.Intn(0x100)), byte(rng.Intn(0x100)), 0x01, 0x20, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	// Build a name: labels of varying length, some at the 63-byte boundary.
	var name []byte
	labels := 1 + rng.Intn(8)
	for i := 0; i < labels; i++ {
		ln := 1 + rng.Intn(63)
		if rng.Intn(16) == 0 {
			ln = 64 + rng.Intn(192) // over the per-label limit
		}
		name = append(name, byte(ln))
		for j := 0; j < ln && j < 255; j++ {
			name = append(name, byte('a'+rng.Intn(26)))
		}
	}
	// Sometimes end with a compression pointer that loops to itself.
	if rng.Intn(4) == 0 {
		name = append(name, 0xc0, byte(len(hdr)))
	} else {
		name = append(name, 0x00)
	}
	q := append(name, 0x00, byte(rng.Intn(0x40)), 0x00, 0x01)
	return append(hdr, q...)
}

// DNSTCP is the same frame with a two-byte big-endian length. The length
// sometimes lies, which is where the parser's bounds check lives.
func DNSTCP(rng *rand.Rand) []byte {
	body := DNS(rng)
	ln := make([]byte, 2)
	binary.BigEndian.PutUint16(ln, uint16(len(body)))
	if rng.Intn(4) == 0 {
		binary.BigEndian.PutUint16(ln, 0xffff)
	}
	return append(ln, body...)
}

// MDNS / LLMNR / NBNS are DNS-shaped; reuse DNS and swap the opcode.
func MDNS(rng *rand.Rand) []byte  { b := DNS(rng); b[2] = 0x00; return b }
func LLMNR(rng *rand.Rand) []byte { return DNS(rng) }
func NBNS(rng *rand.Rand) []byte {
	// NetBIOS names are 32 bytes, "first-level encoded": every half-byte is
	// mapped to a letter. Build one with occasional out-of-range characters.
	name := make([]byte, 34)
	name[0] = 0x20
	for i := 1; i < 33; i++ {
		name[i] = byte('A' + rng.Intn(16))
		if rng.Intn(64) == 0 {
			name[i] = byte(rng.Intn(0x100))
		}
	}
	hdr := []byte{byte(rng.Intn(0x100)), byte(rng.Intn(0x100)), 0x01, 0x10, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	return append(append(hdr, name...), 0x00, 0x20, 0x00, 0x01)
}

// SSDP is HTTP-shaped over UDP; reuse HTTP with M-SEARCH.
func SSDP(rng *rand.Rand) []byte {
	hdrs := []string{
		"ssdp:all",
		"ssdp:discover",
		strings.Repeat("X", 1<<12),
		"",
	}
	return []byte(fmt.Sprintf("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"%s\"\r\nMX: %d\r\nST: %s\r\n\r\n",
		pickString(rng, hdrs), rng.Intn(100), pickString(rng, hdrs)))
}

// SNMP: a GET-REQUEST ASN.1 shape with a community string of mutating length.
func SNMP(rng *rand.Rand) []byte {
	community := strings.Repeat("c", 1+rng.Intn(1<<10))
	// Community length may be oversized.
	clen := byte(len(community))
	if rng.Intn(4) == 0 {
		clen = 0xff
	}
	var b bytes.Buffer
	b.Write([]byte{0x30, 0x40, 0x02, 0x01, byte(rng.Intn(0x05)), 0x04, clen})
	b.WriteString(community)
	// PDU
	b.Write([]byte{0xa0, 0x0e, 0x02, 0x04, 0x11, 0x22, 0x33, 0x44, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x00})
	return b.Bytes()
}

// NTP: an NTPv4 client header with some fields pushed to extremes.
func NTP(rng *rand.Rand) []byte {
	// 48-byte header.
	b := make([]byte, 48)
	// First byte: LI (2b) + VN (3b) + mode (3b). Mode 6 and 7 are the
	// amplifier modes the honeypot's reply policy guards; mode 3 is a client.
	b[0] = byte(rng.Intn(0x100))
	b[1] = byte(rng.Intn(0x100))
	b[2] = byte(rng.Intn(0x100))
	b[3] = byte(rng.Intn(0x100))
	// Reference timestamp.
	for i := 24; i < 48; i++ {
		b[i] = byte(rng.Intn(0x100))
	}
	return b
}

// TFTP: a RRQ or WRQ with an abusive filename.
func TFTP(rng *rand.Rand) []byte {
	op := []byte{0x00, 0x01}
	if rng.Intn(2) == 0 {
		op = []byte{0x00, 0x02}
	}
	name := strings.Repeat("A", 1+rng.Intn(1<<10))
	modes := []string{"octet", "netascii", "mail", strings.Repeat("M", 1<<10)}
	mode := pickString(rng, modes)
	return append(append(op, []byte(name)...), append([]byte{0}, append([]byte(mode), 0)...)...)
}

// RADIUS: an Access-Request with a mutated length field and a long attribute.
func RADIUS(rng *rand.Rand) []byte {
	hdr := []byte{0x01, byte(rng.Intn(0x100)), 0x00, 0x00}
	// Authenticator.
	auth := make([]byte, 16)
	_, _ = rng.Read(auth)
	// One attribute: User-Name
	name := strings.Repeat("u", 1+rng.Intn(0xff))
	attr := append([]byte{0x01, byte(2 + len(name))}, []byte(name)...)
	body := append(append(hdr, auth...), attr...)
	// Fill in the length (big-endian u16 at offset 2).
	binary.BigEndian.PutUint16(body[2:], uint16(len(body)))
	if rng.Intn(4) == 0 {
		binary.BigEndian.PutUint16(body[2:], 0xffff)
	}
	return body
}

// IPMI RMCP presence ping, with mutated class/sequence.
func IPMI(rng *rand.Rand) []byte {
	return []byte{0x06, 0x00, byte(rng.Intn(0x100)), byte(rng.Intn(0x100)),
		0x00, 0x00, 0x11, 0xbe,
		0x80, 0x00, 0x00, 0x00}
}

// BACnet APDU with a varying function.
func BACnet(rng *rand.Rand) []byte {
	// BVLC header (0x81 version, function, length)
	fn := byte(rng.Intn(0x0d))
	bvlc := []byte{0x81, fn, 0x00, 0x00}
	// NPDU + APDU
	rest := make([]byte, rng.Intn(128))
	_, _ = rng.Read(rest)
	body := append(bvlc, rest...)
	binary.BigEndian.PutUint16(body[2:], uint16(len(body)))
	if rng.Intn(4) == 0 {
		binary.BigEndian.PutUint16(body[2:], 0xffff)
	}
	return body
}

// DHCP Discover with mutated options.
func DHCP(rng *rand.Rand) []byte {
	buf := make([]byte, 240)
	buf[0] = 0x01 // BOOTREQUEST
	buf[1] = 0x01 // Ethernet
	buf[2] = 0x06
	// Transaction ID
	binary.BigEndian.PutUint32(buf[4:], rng.Uint32())
	// Client MAC: random
	for i := 28; i < 34; i++ {
		buf[i] = byte(rng.Intn(0x100))
	}
	// Magic cookie
	buf[236], buf[237], buf[238], buf[239] = 0x63, 0x82, 0x53, 0x63
	// Options: random types, random lengths (occasionally overflowing).
	var opts []byte
	opts = append(opts, 53, 1, byte(rng.Intn(9)+1)) // DHCP message type
	for i := 0; i < 1+rng.Intn(16); i++ {
		code := byte(rng.Intn(0xff))
		if code == 0 || code == 0xff {
			continue
		}
		ln := byte(rng.Intn(0xff))
		data := make([]byte, int(ln))
		_, _ = rng.Read(data)
		opts = append(opts, code, ln)
		opts = append(opts, data...)
	}
	opts = append(opts, 0xff)
	return append(buf, opts...)
}

// DHCPv6 Solicit with random options.
func DHCPv6(rng *rand.Rand) []byte {
	msg := []byte{0x01} // Solicit
	txid := make([]byte, 3)
	_, _ = rng.Read(txid)
	msg = append(msg, txid...)
	// Add an Option Request Option.
	oro := []byte{0x00, 0x08, 0x00, 0x02, 0x00, 0x00}
	// Add a bunch of random options.
	for i := 0; i < rng.Intn(8); i++ {
		code := make([]byte, 2)
		ln := make([]byte, 2)
		binary.BigEndian.PutUint16(code, uint16(rng.Intn(0xffff)))
		binary.BigEndian.PutUint16(ln, uint16(rng.Intn(0x100)))
		data := make([]byte, rng.Intn(0x100))
		_, _ = rng.Read(data)
		oro = append(oro, code...)
		oro = append(oro, ln...)
		oro = append(oro, data...)
	}
	return append(msg, oro...)
}

// CoAP with a token / option list / payload marker test.
func CoAP(rng *rand.Rand) []byte {
	// Version 1, type (2b), token length 0..8.
	tkl := rng.Intn(9)
	ver := byte(0x40 | byte(rng.Intn(4))<<4 | byte(tkl))
	code := byte(rng.Intn(0x100))
	mid := []byte{byte(rng.Intn(0x100)), byte(rng.Intn(0x100))}
	token := make([]byte, tkl)
	_, _ = rng.Read(token)
	// A few options: Uri-Path (number 11, delta-encoded).
	var opts []byte
	for i := 0; i < rng.Intn(5); i++ {
		d := rng.Intn(16)
		ln := rng.Intn(16)
		opts = append(opts, byte((d<<4)|ln))
		data := make([]byte, ln)
		_, _ = rng.Read(data)
		opts = append(opts, data...)
	}
	// Payload marker + body.
	body := make([]byte, rng.Intn(128))
	_, _ = rng.Read(body)
	out := append([]byte{ver, code}, mid...)
	out = append(out, token...)
	out = append(out, opts...)
	if len(body) > 0 {
		out = append(out, 0xff)
		out = append(out, body...)
	}
	return out
}

// KNX/IP
func KNX(rng *rand.Rand) []byte {
	// 6-byte header: 0x06, protoVer, service, length
	svc := []byte{0x02, 0x03}
	if rng.Intn(2) == 0 {
		binary.BigEndian.PutUint16(svc, uint16(rng.Intn(0xffff)))
	}
	body := make([]byte, rng.Intn(64))
	_, _ = rng.Read(body)
	hdr := []byte{0x06, 0x10, svc[0], svc[1], 0x00, byte(6 + len(body))}
	return append(hdr, body...)
}

// STUN binding request with mutated transaction id.
func STUN(rng *rand.Rand) []byte {
	msg := make([]byte, 20)
	binary.BigEndian.PutUint16(msg[0:], 0x0001)
	binary.BigEndian.PutUint16(msg[2:], uint16(rng.Intn(0xffff)))
	binary.BigEndian.PutUint32(msg[4:], 0x2112a442)
	for i := 8; i < 20; i++ {
		msg[i] = byte(rng.Intn(0x100))
	}
	return msg
}

// VNC: the client's protocol-version string.
func VNC(rng *rand.Rand) []byte {
	versions := []string{"RFB 003.008\n", "RFB 003.003\n", "RFB 999.999\n", "RFB 00!!.!!!\n", strings.Repeat("A", 100)}
	return []byte(pickString(rng, versions))
}
