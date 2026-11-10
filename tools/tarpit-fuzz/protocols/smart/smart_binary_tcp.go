package smart

import (
	"encoding/binary"
	"math/rand"
	"strings"
)

// Smart generators for binary length-prefixed TCP protocols. Each one builds
// a short, structurally valid header, then pushes one field — the length,
// the type, the payload-count — to a value the parser was not written for.
// A good generator keeps the magic bytes correct so the parser is still
// dispatching into the right code path; what finds the bug is the field just
// past the magic.

// shortRandom returns a short random byte slice.
func shortRandom(rng *rand.Rand, max int) []byte {
	n := rng.Intn(max)
	b := make([]byte, n)
	_, _ = rng.Read(b)
	return b
}

// lengthFrame prepends a mutated big-endian length prefix of the given width
// to a payload. The length sometimes lies (0xff... for u16, 0xffff... for
// u32), which is the shape memory-corruption bugs live in.
func lengthFrame(width int, payload []byte, rng *rand.Rand) []byte {
	ln := uint64(len(payload))
	if rng.Intn(4) == 0 {
		ln = (1<<uint(8*width) - 1)
	}
	out := make([]byte, width, width+len(payload))
	for i := 0; i < width; i++ {
		out[i] = byte(ln >> uint(8*(width-1-i)))
	}
	return append(out, payload...)
}

// --- Enterprise / Java / DB ---------------------------------------------

// Cassandra: a native protocol frame — version, flags, stream, opcode,
// length(4), body. Mutating opcode and length finds the dispatch table.
func Cassandra(rng *rand.Rand) []byte {
	version := byte(0x04 | rng.Intn(2))
	flags := byte(rng.Intn(0x100))
	stream := []byte{byte(rng.Intn(0x100)), byte(rng.Intn(0x100))}
	opcode := byte(rng.Intn(0x10))
	body := shortRandom(rng, 256)
	ln := uint32(len(body))
	if rng.Intn(4) == 0 {
		ln = 0x7fffffff
	}
	hdr := []byte{version, flags, stream[0], stream[1], opcode,
		byte(ln >> 24), byte(ln >> 16), byte(ln >> 8), byte(ln)}
	return append(hdr, body...)
}

// Kafka: a request with ApiKey + ApiVersion + CorrelationId + ClientId. The
// shape every request shares; the body differs per ApiKey, which the parser
// dispatches on.
func Kafka(rng *rand.Rand) []byte {
	apiKey := uint16(rng.Intn(80)) // currently 0..70-ish
	apiVer := uint16(rng.Intn(20))
	corrID := rng.Uint32()
	clientID := strings.Repeat("c", 1+rng.Intn(1<<10))
	body := make([]byte, 8)
	binary.BigEndian.PutUint16(body[0:], apiKey)
	binary.BigEndian.PutUint16(body[2:], apiVer)
	binary.BigEndian.PutUint32(body[4:], corrID)
	body = append(body, byte(len(clientID)>>8), byte(len(clientID)))
	body = append(body, []byte(clientID)...)
	body = append(body, shortRandom(rng, 128)...)
	return lengthFrame(4, body, rng)
}

// Zookeeper: 4-byte length then a ConnectRequest (long ver, long sessionId,
// int timeout, byte[] passwd). Mutating the length and the passwd blob is
// the pattern the handler checks.
func Zookeeper(rng *rand.Rand) []byte {
	body := make([]byte, 44)
	binary.BigEndian.PutUint32(body[0:], uint32(rng.Intn(0x10000))) // ver
	binary.BigEndian.PutUint64(body[4:], rng.Uint64())              // zxid
	binary.BigEndian.PutUint32(body[12:], uint32(rng.Intn(60000)))  // timeout
	binary.BigEndian.PutUint64(body[16:], rng.Uint64())             // sessionId
	binary.BigEndian.PutUint32(body[24:], uint32(1+rng.Intn(1<<16)))
	for i := 28; i < 44; i++ {
		body[i] = byte(rng.Intn(0x100))
	}
	return lengthFrame(4, body, rng)
}

// MongoDB wire: already in smart.go as MongoDB. Unused here.

// Neo4j: Bolt protocol — 16-byte magic (0x60 0x60 B0 17) then four 4-byte
// versions. The handler reads the magic and picks a version.
func Neo4j(rng *rand.Rand) []byte {
	out := []byte{0x60, 0x60, 0xb0, 0x17}
	for i := 0; i < 4; i++ {
		v := rng.Uint32()
		out = append(out, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
	}
	return out
}

// RethinkDB: 4-byte version then an auth JSON.
func RethinkDB(rng *rand.Rand) []byte {
	versions := []uint32{0xaf61ba35, 0xc3bdc234, 0x5f75e83e, 0xffffffff}
	v := versions[rng.Intn(len(versions))]
	out := []byte{byte(v), byte(v >> 8), byte(v >> 16), byte(v >> 24)}
	auth := shortRandom(rng, 128)
	return append(out, auth...)
}

// IBM MQ: TSH (Transmission Segment Header) structured header.
func IBMMQ(rng *rand.Rand) []byte {
	// 4-byte "TSH ", 4-byte length BE, then 3-byte seg/req, 1-byte cflag,
	// 1-byte encoding, 1-byte ccsid, 2-byte ...
	body := []byte{'T', 'S', 'H', ' '}
	ln := uint32(32 + rng.Intn(1<<10))
	body = append(body, byte(ln>>24), byte(ln>>16), byte(ln>>8), byte(ln))
	rest := shortRandom(rng, int(ln))
	return append(body, rest...)
}

// RMI: JRMI protocol: magic 0x4a524d49 + version + protocol.
func RMI(rng *rand.Rand) []byte {
	return []byte{'J', 'R', 'M', 'I', 0x00, byte(rng.Intn(0x100)), byte(rng.Intn(0x100))}
}

// WebSphere/IBM MQ share the TSH shape with IBM MQ.
func WebSphereMQ(rng *rand.Rand) []byte { return IBMMQ(rng) }

// ADB: Android Debug Bridge messages — CNXN, AUTH, OPEN, OKAY, CLSE, WRTE.
func ADB(rng *rand.Rand) []byte {
	cmds := [][]byte{[]byte("CNXN"), []byte("AUTH"), []byte("OPEN"), []byte("OKAY"), []byte("CLSE"), []byte("WRTE"), []byte("SYNC"), []byte("FAIL")}
	cmd := cmds[rng.Intn(len(cmds))]
	arg0 := rng.Uint32()
	arg1 := rng.Uint32()
	payload := shortRandom(rng, 256)
	ln := uint32(len(payload))
	if rng.Intn(4) == 0 {
		ln = 0xffffffff
	}
	// Magic is NOT XOR of cmd, which is wrong on purpose.
	hdr := append([]byte(nil), cmd...)
	hdr = append(hdr, byte(arg0), byte(arg0>>8), byte(arg0>>16), byte(arg0>>24))
	hdr = append(hdr, byte(arg1), byte(arg1>>8), byte(arg1>>16), byte(arg1>>24))
	hdr = append(hdr, byte(ln), byte(ln>>8), byte(ln>>16), byte(ln>>24))
	hdr = append(hdr, 0, 0, 0, 0) // checksum (ignored, mutated)
	hdr = append(hdr, 0xff^cmd[0], 0xff^cmd[1], 0xff^cmd[2], 0xff^cmd[3])
	return append(hdr, payload...)
}

// AJP13: a Tomcat connector packet. Magic 0x1234, length BE, type byte, then
// dispatch body.
func AJP13(rng *rand.Rand) []byte {
	magic := []byte{0x12, 0x34}
	ln := uint16(1 + rng.Intn(1<<14))
	if rng.Intn(4) == 0 {
		ln = 0xffff
	}
	types := []byte{0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09}
	t := types[rng.Intn(len(types))]
	body := shortRandom(rng, 256)
	hdr := append(magic, byte(ln>>8), byte(ln), t)
	return append(hdr, body...)
}

// PPTP: control-message-type packet.
func PPTP(rng *rand.Rand) []byte {
	ln := uint16(16 + rng.Intn(256))
	if rng.Intn(4) == 0 {
		ln = 0xffff
	}
	out := []byte{byte(ln >> 8), byte(ln), 0x00, 0x01, // length, type=control
		0x1a, 0x2b, 0x3c, 0x4d, // cookie
		0x00, byte(1 + rng.Intn(16)), 0x00, 0x00, // msg type
	}
	return append(out, shortRandom(rng, int(ln))...)
}

// NFS/RPCBIND share ONC RPC framing: 4-byte record marker then an RPC body.
func RPCBind(rng *rand.Rand) []byte {
	// Record marker: last fragment bit + length.
	body := []byte{
		0x00, 0x00, 0x00, 0x01, // xid
		0x00, 0x00, 0x00, 0x00, // call
		0x00, 0x00, 0x00, 0x02, // rpcvers=2
		0x00, 0x01, byte(rng.Intn(0x100)), byte(rng.Intn(0x100)), // prog
		0x00, 0x00, 0x00, 0x04, // vers
		0x00, 0x00, 0x00, byte(rng.Intn(16)), // proc
	}
	body = append(body, shortRandom(rng, 128)...)
	marker := uint32(len(body)) | 0x80000000
	if rng.Intn(4) == 0 {
		marker = 0xffffffff
	}
	hdr := []byte{byte(marker >> 24), byte(marker >> 16), byte(marker >> 8), byte(marker)}
	return append(hdr, body...)
}
func NFS(rng *rand.Rand) []byte { return RPCBind(rng) }

// TACACS+: 12-byte header plus encrypted body.
func TACACS(rng *rand.Rand) []byte {
	hdr := []byte{
		0xc0,                  // version
		byte(rng.Intn(4) + 1), // type (AUTHEN/AUTHOR/ACCT)
		byte(rng.Intn(0x100)), // seq
		0x00,                  // flags
		byte(rng.Intn(0x100)), // session id
		byte(rng.Intn(0x100)),
		byte(rng.Intn(0x100)),
		byte(rng.Intn(0x100)),
		0x00, 0x00, 0x00, 0x08, // length
	}
	body := shortRandom(rng, 256)
	ln := uint32(len(body))
	if rng.Intn(4) == 0 {
		ln = 0xffffffff
	}
	binary.BigEndian.PutUint32(hdr[8:], ln)
	return append(hdr, body...)
}

// X11: byte-order byte + protocol version + auth data lengths.
func X11(rng *rand.Rand) []byte {
	order := []byte{0x42, 0x6c}
	o := order[rng.Intn(len(order))]
	major := uint16(11)
	minor := uint16(0)
	authNameLen := uint16(rng.Intn(1 << 10))
	authDataLen := uint16(rng.Intn(1 << 10))
	hdr := []byte{o, 0x00,
		byte(major >> 8), byte(major), byte(minor >> 8), byte(minor),
		byte(authNameLen >> 8), byte(authNameLen),
		byte(authDataLen >> 8), byte(authDataLen),
		0x00, 0x00}
	body := shortRandom(rng, 64)
	return append(hdr, body...)
}

// H.323 Q.931: TPKT + Q.931 header (same shape as RDP's X.224 path).
func H323(rng *rand.Rand) []byte {
	// TPKT header: version(3), reserved(0), length BE.
	body := shortRandom(rng, 128)
	ln := uint16(4 + len(body))
	if rng.Intn(4) == 0 {
		ln = 0xffff
	}
	out := []byte{0x03, 0x00, byte(ln >> 8), byte(ln)}
	return append(out, body...)
}

// SCCP (Skinny): 8-byte header length + reserved + msg id, body.
func SCCP(rng *rand.Rand) []byte {
	ln := uint32(rng.Intn(1 << 10))
	if rng.Intn(4) == 0 {
		ln = 0xffffffff
	}
	msgID := uint32(rng.Intn(0x200))
	body := shortRandom(rng, int(min(ln, 128)))
	out := []byte{
		byte(ln), byte(ln >> 8), byte(ln >> 16), byte(ln >> 24),
		0, 0, 0, 0,
		byte(msgID), byte(msgID >> 8), byte(msgID >> 16), byte(msgID >> 24),
	}
	return append(out, body...)
}

// OpenVPN: UDP/TCP shape — opcode byte + session id (8) + ack len + ...
func OpenVPN(rng *rand.Rand) []byte {
	op := byte(rng.Intn(0x100))
	sid := make([]byte, 8)
	_, _ = rng.Read(sid)
	// For TCP OpenVPN: 2-byte length prefix.
	body := append([]byte{op}, sid...)
	body = append(body, shortRandom(rng, 64)...)
	ln := uint16(len(body))
	if rng.Intn(4) == 0 {
		ln = 0xffff
	}
	return append([]byte{byte(ln >> 8), byte(ln)}, body...)
}

// Osdp: SCBK-shaped open supervised device protocol.
func OSDP(rng *rand.Rand) []byte {
	// Start-of-message, address, length(2 LE), control, command, data, checksum.
	addr := byte(rng.Intn(0x80))
	ln := uint16(8 + rng.Intn(256))
	ctrl := byte(rng.Intn(0x100))
	cmd := byte(rng.Intn(0x100))
	data := shortRandom(rng, int(ln)-8)
	out := []byte{0x53, addr, byte(ln), byte(ln >> 8), ctrl, cmd}
	out = append(out, data...)
	out = append(out, 0x00, 0x00) // checksum
	return out
}

// Codesys / Fox / ROC Plus / ADS / Melsec / FINS-TCP / SECS-GEM / PCOM /
// PCWorx / Proconos / GE-SRTP / HART-IP / Focas / C37.118 / ICCP (secure)
// and CRIMSON all share "a short magic + a length field + a body". Each has
// its own magic. The pattern is identical; a small table-driven generator
// is enough.

// icsLengthMag builds an ICS-style frame: fixed magic bytes + big-endian
// length + random body.
func icsLengthMag(magic []byte, lenAt, lenWidth int, rng *rand.Rand) []byte {
	payload := shortRandom(rng, 256)
	body := append(append([]byte(nil), magic...), payload...)
	ln := uint64(len(payload))
	if rng.Intn(4) == 0 {
		ln = (1<<uint(8*lenWidth) - 1)
	}
	// Write the length where the magic ends.
	if lenAt+lenWidth <= len(body) {
		for i := 0; i < lenWidth; i++ {
			body[lenAt+i] = byte(ln >> uint(8*(lenWidth-1-i)))
		}
	}
	return body
}

func Codesys(rng *rand.Rand) []byte { return icsLengthMag([]byte{0xbb, 0xaa, 0x00, 0x00}, 2, 2, rng) }
func C37118(rng *rand.Rand) []byte  { return icsLengthMag([]byte{0xaa, 0x41, 0x00, 0x00}, 2, 2, rng) }
func ROCPlus(rng *rand.Rand) []byte {
	return icsLengthMag([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00}, 6, 2, rng)
}
func PCWorx(rng *rand.Rand) []byte { return icsLengthMag([]byte{0x01, 0x01, 0x00, 0x00}, 2, 2, rng) }
func GESRTP(rng *rand.Rand) []byte {
	return icsLengthMag([]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, 4, 4, rng)
}
func Focas(rng *rand.Rand) []byte {
	return icsLengthMag([]byte{0xa0, 0xa0, 0xa0, 0xa0, 0x00, 0x00}, 4, 2, rng)
}
func HARTIP(rng *rand.Rand) []byte {
	return icsLengthMag([]byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, 6, 2, rng)
}
func Melsec(rng *rand.Rand) []byte {
	return icsLengthMag([]byte{0x50, 0x00, 0x00, 0xff, 0xff, 0x03, 0x00, 0x00, 0x00}, 7, 2, rng)
}
func ADS(rng *rand.Rand) []byte {
	return icsLengthMag([]byte{0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00}, 2, 4, rng)
}
func FINSTCP(rng *rand.Rand) []byte {
	return icsLengthMag([]byte{'F', 'I', 'N', 'S', 0x00, 0x00, 0x00, 0x00}, 4, 4, rng)
}
func SECSGEM(rng *rand.Rand) []byte {
	return icsLengthMag([]byte{0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00}, 0, 4, rng)
}
func PCOM(rng *rand.Rand) []byte {
	return icsLengthMag([]byte{0x2f, 0x5f, 0x4f, 0x50, 0x4c, 0x43, 0x00, 0x00}, 6, 2, rng)
}
func Proconos(rng *rand.Rand) []byte   { return icsLengthMag([]byte{0x80, 0x80, 0x00, 0x00}, 2, 2, rng) }
func MMS(rng *rand.Rand) []byte        { return S7(rng) } // MMS over the same TPKT+COTP as S7
func ICCPSecure(rng *rand.Rand) []byte { return S7(rng) }
func Crimson(rng *rand.Rand) []byte    { return icsLengthMag([]byte{0x00, 0x00, 0x00, 0x00}, 0, 4, rng) }

// BACnetSC: WebSocket-framed BACnet over TLS. The initial frame is the
// BACnet/SC BVLC message; WebSocket handshake is the HTTP front.
func BACnetSC(rng *rand.Rand) []byte {
	if rng.Intn(3) == 0 {
		return WebSocket(rng)
	}
	// BVLC/SC: 1-byte version, 1-byte function, 2-byte flags, 4-byte msgId.
	body := []byte{0x00, byte(rng.Intn(0x10)), byte(rng.Intn(0x100)), byte(rng.Intn(0x100)),
		byte(rng.Intn(0x100)), byte(rng.Intn(0x100)), byte(rng.Intn(0x100)), byte(rng.Intn(0x100))}
	body = append(body, shortRandom(rng, 128)...)
	return body
}

// LPD: 1-byte opcode + queue + LF.
func LPD(rng *rand.Rand) []byte {
	ops := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
	op := ops[rng.Intn(len(ops))]
	q := pickString(rng, textArgs)
	return append([]byte{op}, append([]byte(q), 0x0a)...)
}

// PJL: HP's Printer Job Language — text with ESC-% prefix.
func PJL(rng *rand.Rand) []byte {
	cmds := []string{
		"\x1b%-12345X@PJL INFO STATUS\r\n\x1b%-12345X",
		"\x1b%-12345X@PJL FSUPLOAD NAME=\"" + strings.Repeat("x", 1<<10) + "\"\r\n",
		"\x1b%-12345X@PJL ENTER LANGUAGE=PCL\r\n",
		"\x1b%-12345X@PJL RDYMSG DISPLAY=\"" + pickString(rng, textArgs) + "\"\r\n\x1b%-12345X",
		strings.Repeat("\x1b%-12345X", 32),
	}
	return []byte(pickString(rng, cmds))
}

// IPP: 2-byte version + 2-byte op + 4-byte id + attributes + end tag.
func IPP(rng *rand.Rand) []byte {
	op := uint16(rng.Intn(0x40))
	id := rng.Uint32()
	hdr := []byte{
		byte(rng.Intn(3) + 1), 0x01, // version
		byte(op >> 8), byte(op),
		byte(id >> 24), byte(id >> 16), byte(id >> 8), byte(id),
	}
	hdr = append(hdr, 0x01, 0x47, 0x00, 0x12)
	hdr = append(hdr, []byte("attributes-charset")...)
	hdr = append(hdr, 0x00, 0x05, 'u', 't', 'f', '-', '8')
	hdr = append(hdr, 0x03) // end-of-attributes
	hdr = append(hdr, shortRandom(rng, 128)...)
	return hdr
}

// AFP: Apple Filing Protocol — DSI header.
func AFP(rng *rand.Rand) []byte {
	// 16-byte DSI header + body.
	flags := byte(rng.Intn(0x100))
	cmd := byte(rng.Intn(0x100))
	req := rng.Uint32()
	writeOff := rng.Uint32()
	ln := uint32(rng.Intn(1 << 16))
	if rng.Intn(4) == 0 {
		ln = 0xffffffff
	}
	hdr := []byte{flags, cmd,
		byte(req >> 24), byte(req >> 16), byte(req >> 8), byte(req),
		byte(writeOff >> 24), byte(writeOff >> 16), byte(writeOff >> 8), byte(writeOff),
		byte(ln >> 24), byte(ln >> 16), byte(ln >> 8), byte(ln),
		0, 0, 0, 0,
	}
	return append(hdr, shortRandom(rng, 128)...)
}

// NBD: Network Block Device — oldstyle (NBDMAGIC) and newstyle (IHAVEOPT).
func NBD(rng *rand.Rand) []byte {
	if rng.Intn(2) == 0 {
		return []byte{'N', 'B', 'D', 'M', 'A', 'G', 'I', 'C',
			0x00, 0x00, 0x42, 0x02, 0x81, 0x86, 0x12, 0x53,
			byte(rng.Intn(0x100)), byte(rng.Intn(0x100)), 0, 0, 0, 0, 0, 0,
			byte(rng.Intn(0x100)), byte(rng.Intn(0x100)), 0, 0}
	}
	return []byte{'N', 'B', 'D', 'M', 'A', 'G', 'I', 'C',
		'I', 'H', 'A', 'V', 'E', 'O', 'P', 'T',
		byte(rng.Intn(0x100)), 0x00}
}

// ASTM: STX/ETX framed line protocol.
func ASTM(rng *rand.Rand) []byte {
	// STX + frame-number + text + CR + ETX
	frames := []string{
		"\x02" + "1H|\\^&||" + pickString(rng, textArgs) + "|LAB|||" + "\r\x03",
		"\x05",
		"\x04",
		"\x02" + strings.Repeat("X", 1+rng.Intn(1<<14)) + "\x03",
	}
	return []byte(pickString(rng, frames))
}

// POCT1: HL7-shaped but with its own version strings.
func POCT1(rng *rand.Rand) []byte {
	body := "\x0bMSH|^~\\&|POCT1||||20250101000000||OUL^R22|1|P|2.3\r" +
		"OBX|1|ST|GLUC||" + pickString(rng, textArgs) + "||N|||F\r" + "\x1c\r"
	return []byte(body)
}

// DICOM / DICOM over TLS: P-DATA-TF PDUs with PDU type + reserved + length.
func DICOM(rng *rand.Rand) []byte {
	pduType := byte(rng.Intn(8) + 1)
	ln := uint32(rng.Intn(1 << 16))
	if rng.Intn(4) == 0 {
		ln = 0xffffffff
	}
	hdr := []byte{pduType, 0x00,
		byte(ln >> 24), byte(ln >> 16), byte(ln >> 8), byte(ln),
	}
	return append(hdr, shortRandom(rng, 128)...)
}

// NTS (TLS-wrapped NTS-KE): present an ALPN-"ntske/1" negotiation shape.
func NTS(rng *rand.Rand) []byte {
	// NTS-KE records: 2-byte type (with critical bit) + 2-byte length + body.
	rec := func(t uint16, body []byte) []byte {
		out := []byte{byte(t >> 8), byte(t), byte(len(body) >> 8), byte(len(body))}
		return append(out, body...)
	}
	records := []byte{}
	records = append(records, rec(0x8001, []byte{0x00, 0x00})...)  // next-protocol: 0 (ntp)
	records = append(records, rec(0x8004, shortRandom(rng, 8))...) // aead algorithms
	records = append(records, rec(0x8000, nil)...)                 // end-of-message
	// Mutate: a never-terminating record (no end-of-message) or oversized length.
	if rng.Intn(3) == 0 {
		records = rec(0x0001, shortRandom(rng, 1<<10))
	}
	return records
}

// SSRFCanary: a URL-eating HTTP endpoint. Reuse HTTP() with CRLF injection.
func SSRFCanary(rng *rand.Rand) []byte { return HTTP(rng) }

// FTPS / IMAPS / POP3S / LDAPS / MQTTS / SMTPS: plaintext handler behind
// TLS. The engine's TLS wrapping takes care of the handshake; after that
// the plaintext generator is what applies.
func FTPS(rng *rand.Rand) []byte  { return FTP(rng) }
func IMAPS(rng *rand.Rand) []byte { return IMAP(rng) }
func POP3S(rng *rand.Rand) []byte { return POP3(rng) }
func LDAPS(rng *rand.Rand) []byte { return LDAP(rng) }

// gRPC: HTTP/2 + protobuf. The engine's smart gRPC sends an HTTP/2 preface
// then one HEADERS frame. mutations: oversize frame length, pseudo-headers
// out of order, flags with reserved bits set.
func GRPC(rng *rand.Rand) []byte {
	preface := []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
	// SETTINGS frame (type=4) with mutated settings.
	settings := make([]byte, rng.Intn(48))
	_, _ = rng.Read(settings)
	ln := uint32(len(settings))
	if rng.Intn(4) == 0 {
		ln = 0xffffff
	}
	hdr := []byte{
		byte(ln >> 16), byte(ln >> 8), byte(ln),
		0x04, // SETTINGS
		byte(rng.Intn(0x100)),
		0, 0, 0, 0,
	}
	return append(append(preface, hdr...), settings...)
}

// Osisoft PI / Proficy Historian / Canary Historian / Aspen IP.21 — all
// proprietary binary protocols the honeypot answers with a terse banner.
// Generic length-prefixed mutator suffices.
func GenericLengthTCP(rng *rand.Rand) []byte {
	return lengthFrame(4, shortRandom(rng, 256), rng)
}

// Oracle TNS: packet length(2) + checksum(2) + type(1) + flags(1) + hdr(2)
// then type-specific body. Already in main smart.go (seeded). Mutate:
func OracleTNS(rng *rand.Rand) []byte {
	body := make([]byte, 50+rng.Intn(128))
	_, _ = rng.Read(body)
	ln := uint16(len(body))
	if rng.Intn(4) == 0 {
		ln = 0xffff
	}
	body[0] = byte(ln >> 8)
	body[1] = byte(ln)
	body[4] = byte(rng.Intn(0x20)) // packet type
	return body
}

// Spice: 16-byte magic ("REDQ") + binary.
func Spice(rng *rand.Rand) []byte {
	hdr := []byte{'R', 'E', 'D', 'Q', 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		byte(rng.Intn(0x100)), 0, 0, 0}
	return append(hdr, shortRandom(rng, 64)...)
}

// PCAnywhere: binary opening frame.
func PCAnywhere(rng *rand.Rand) []byte {
	return shortRandom(rng, 32)
}

// Radmin: 8-byte header + opcode + body.
func Radmin(rng *rand.Rand) []byte {
	hdr := []byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, byte(rng.Intn(0x10)), 0x00}
	return append(hdr, shortRandom(rng, 64)...)
}

// Teamviewer: TV-specific binary opening.
func TeamViewer(rng *rand.Rand) []byte { return shortRandom(rng, 64) }

// AnyDesk: similar.
func AnyDesk(rng *rand.Rand) []byte { return shortRandom(rng, 64) }

// NX (NoMachine): "NXSSH-1.5" ASCII greeting + binary.
func NX(rng *rand.Rand) []byte {
	versions := []string{"NXSSH-1.5-NoMachine_Login\r\n", "NXSSH-99.9\r\n", "NXSSH-" + strings.Repeat("X", 1<<10) + "\r\n"}
	return []byte(pickString(rng, versions))
}

// PCoIP / ARD / Dameware: opaque binary protocols. Shape mutation is "a
// plausible first-byte followed by garbage".
func PCoIP(rng *rand.Rand) []byte    { return shortRandom(rng, 128) }
func ARD(rng *rand.Rand) []byte      { return shortRandom(rng, 32) }
func Dameware(rng *rand.Rand) []byte { return shortRandom(rng, 32) }

// CitrixICA: fixed signature + framed.
func CitrixICA(rng *rand.Rand) []byte {
	hdr := []byte{0x1a, 0x7d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	return append(hdr, shortRandom(rng, 64)...)
}

// Classic small services: echo/discard/daytime/qotd/chargen/time.
// For echo/discard sending random bytes is already as "smart" as it gets.
// For time (RFC 868) the server answers 4 bytes; the client sends nothing.
// For daytime/qotd/chargen the client sends nothing either. A smart
// generator for these just drops a line a fuzzer would — and the oracle is
// the liveness check anyway.
func EchoSmall(rng *rand.Rand) []byte    { return shortRandom(rng, 64) }
func DiscardSmall(rng *rand.Rand) []byte { return shortRandom(rng, 64) }
func DaytimeSmall(rng *rand.Rand) []byte { return []byte{} }
func QotdSmall(rng *rand.Rand) []byte    { return []byte{} }
func ChargenSmall(rng *rand.Rand) []byte { return []byte{} }
func TimeSmall(rng *rand.Rand) []byte    { return []byte{} }

// Fall-throughs: raw / auto / scripted / lua.
func RawFallthrough(rng *rand.Rand) []byte { return shortRandom(rng, 256) }

// min is a local helper so we do not depend on go 1.21's builtin from a
// package that may be compiled against an older toolchain.
func min(a, b uint32) uint32 {
	if a < b {
		return a
	}
	return b
}

// SyslogTCP: an octet-counted or newline-framed syslog message.
func SyslogTCP(rng *rand.Rand) []byte {
	msg := "<" + "14" + ">Nov 10 10:00:00 host fuzz: " + pickString(rng, textArgs)
	if rng.Intn(2) == 0 {
		return []byte(msg + "\n")
	}
	// Octet-counted framing
	ln := len(msg)
	if rng.Intn(4) == 0 {
		ln = 1 << 24
	}
	return []byte(strings.Join([]string{string(rune('0' + ln%10)), msg}, " ")) // close enough to drive the parser
}

// DLMS: COSEM over TCP wrapper — 4-byte wrapper header + length + APDU.
func DLMS(rng *rand.Rand) []byte {
	// Wrapper: version(2) src(2) dst(2) length(2)
	src := uint16(1 + rng.Intn(0xffff))
	dst := uint16(1 + rng.Intn(0xffff))
	body := []byte{0x60} // AARQ tag
	body = append(body, shortRandom(rng, 128)...)
	ln := uint16(len(body))
	if rng.Intn(4) == 0 {
		ln = 0xffff
	}
	hdr := []byte{0x00, 0x01,
		byte(src >> 8), byte(src), byte(dst >> 8), byte(dst),
		byte(ln >> 8), byte(ln)}
	return append(hdr, body...)
}
