package smart

import (
	"fmt"
	"math/rand"
	"strings"
)

// Smart generators for the UDP handlers. UDP is a single datagram per send,
// so every generator here returns one packet and the engine writes it
// as-is. Shapes mirror the protocols' first-contact packets: discovery
// probes, routing hellos, NAT-traversal beacons, device-vendor magic.

// --- Small / classic -------------------------------------------------------

// NetBIOSDgram: NetBIOS Datagram Service at 138.
func NetBIOSDgram(rng *rand.Rand) []byte {
	// Message type 0x10 (direct unique) + flags + dgm id + source IP/port.
	hdr := []byte{0x10, byte(rng.Intn(0x20)),
		byte(rng.Intn(0x100)), byte(rng.Intn(0x100)),
		byte(rng.Intn(0x100)), byte(rng.Intn(0x100)), byte(rng.Intn(0x100)), byte(rng.Intn(0x100)),
		byte(rng.Intn(0x100)), byte(rng.Intn(0x100))}
	return append(hdr, NBNS(rng)...)
}

// Chronyd: command-mode packets.
func Chronyd(rng *rand.Rand) []byte {
	// Version 6, pkt-type 1 (request), command, attempt, seq, etc.
	hdr := []byte{0x06, 0x01, byte(rng.Intn(0x80)), byte(rng.Intn(0x10)),
		byte(rng.Intn(0x100)), byte(rng.Intn(0x100)), byte(rng.Intn(0x100)), byte(rng.Intn(0x100))}
	body := shortRandom(rng, 400)
	return append(hdr, body...)
}

// SyslogUDP: RFC 3164 / 5424 line.
func SyslogUDP(rng *rand.Rand) []byte {
	pri := rng.Intn(192)
	texts := []string{
		pickString(rng, textArgs),
		strings.Repeat("A", 1<<12),
		"<" + strings.Repeat("9", 20) + ">normal",
		"BOM" + strings.Repeat("\xef\xbb\xbf", 4),
	}
	return []byte("<" + fmt.Sprint(pri) + ">" + pickString(rng, texts))
}

// Chargen: anything sent elicits a stream reply, so random bytes trigger it.
func ChargenUDP(rng *rand.Rand) []byte { return shortRandom(rng, 1) }
func EchoUDP(rng *rand.Rand) []byte    { return shortRandom(rng, 128) }
func DiscardUDP(rng *rand.Rand) []byte { return shortRandom(rng, 128) }
func DaytimeUDP(rng *rand.Rand) []byte { return []byte{} }
func QotdUDP(rng *rand.Rand) []byte    { return []byte{} }
func TimeUDP(rng *rand.Rand) []byte    { return []byte{} }

// --- Databases / discovery / IoT ------------------------------------------

// MSSQLBrowser: 1-byte opcode + optional instance name.
func MSSQLBrowser(rng *rand.Rand) []byte {
	ops := []byte{0x01, 0x02, 0x03, 0x04, 0x0a, 0x0b, 0x0c}
	op := ops[rng.Intn(len(ops))]
	if rng.Intn(2) == 0 {
		return []byte{op}
	}
	name := []byte(pickString(rng, textArgs))
	return append([]byte{op}, name...)
}

// DB2 discovery: broadcast with simple structured header.
func DB2Disc(rng *rand.Rand) []byte {
	return shortRandom(rng, 64)
}

// DropboxLSP: JSON broadcast at port 17500.
func DropboxLSP(rng *rand.Rand) []byte {
	return []byte(`{"host_int":` + fmt.Sprint(rng.Intn(1<<30)) + `,"version":[2,0],"ns":[],"blob":"` + strings.Repeat("A", rng.Intn(1<<12)) + `"}`)
}

// BTDHT: KRPC bencoded DHT query.
func BTDHT(rng *rand.Rand) []byte {
	qs := []string{
		"d1:ad2:id20:abcdefghij0123456789e1:q4:ping1:t2:aa1:y1:qe",
		"d1:ad2:id20:" + strings.Repeat("A", 20) + "6:target20:" + strings.Repeat("B", 20) + "e1:q9:find_node1:t2:bb1:y1:qe",
		"d" + strings.Repeat("1:a", 256) + "0:e",
	}
	return []byte(pickString(rng, qs))
}

// GameSpy: query header 0xfe 0xfd + type + session id.
func GameSpyUDP(rng *rand.Rand) []byte {
	return []byte{0xfe, 0xfd, byte(rng.Intn(0x10)),
		byte(rng.Intn(0x100)), byte(rng.Intn(0x100)), byte(rng.Intn(0x100)), byte(rng.Intn(0x100)),
		byte(rng.Intn(0x100))}
}

// Steam query (Source Engine).
func Steam(rng *rand.Rand) []byte {
	msgs := [][]byte{
		append([]byte{0xff, 0xff, 0xff, 0xff, 0x54}, append([]byte("Source Engine Query"), 0x00)...),
		{0xff, 0xff, 0xff, 0xff, 0x55, 0x00, 0x00, 0x00, 0x00},
		{0xff, 0xff, 0xff, 0xff, 0x56, 0x00, 0x00, 0x00, 0x00},
	}
	return msgs[rng.Intn(len(msgs))]
}

// Natpmp / Teredo / LantronixDisc / PCAnywhereStat / DahuaDisc /
// HikvisionSADP / TPLinkKasa / Tuya / MiIO / WiZ / Yeelight / Ubiquiti /
// Matter / Loxone / AMXNetlinx / Vantage / ArtNet / sACN / Crestron /
// PJLink / CBus / Saia SBUS / PowerLink / SLMP / Siprotec-EN100 / FF-HSE —
// device-discovery and controller probes. Each has a magic prefix and a
// short body; a generic magic-prefixed random suffices.
func discProbe(magic []byte, maxBody int) func(*rand.Rand) []byte {
	return func(rng *rand.Rand) []byte {
		return append(append([]byte(nil), magic...), shortRandom(rng, maxBody)...)
	}
}

var (
	NATPMP         = discProbe([]byte{0x00, 0x00}, 16)
	Teredo         = discProbe([]byte{0x00, 0x01}, 64)
	LantronixDisc  = discProbe([]byte{0x00, 0x00, 0x00, 0xf6}, 32)
	PCAnywhereStat = discProbe([]byte{0x03, 0x14, 0x00, 0x00}, 32)
	DahuaDisc      = discProbe([]byte{0xa3, 0x00, 0x00, 0x00}, 128)
	TPLinkKasa     = discProbe([]byte{0xd0, 0xf2, 0x81, 0xf8}, 128)
	Tuya           = discProbe([]byte{0x00, 0x00, 0x55, 0xaa, 0x00, 0x00, 0x00, 0x00}, 256)
	MiIO           = discProbe([]byte{0x21, 0x31}, 64)
	WiZ            = discProbe([]byte("{\"method\":\""), 128)
	Yeelight       = discProbe([]byte("M-SEARCH * HTTP/1.1\r\n"), 256)
	Ubiquiti       = discProbe([]byte{0x01, 0x00, 0x00, 0x00}, 64)
	Matter         = discProbe([]byte{0x00, 0x01, 0x00, 0x00}, 128)
	Loxone         = discProbe([]byte{0x00, 0x00, 0x00, 0x00}, 64)
	AMXNetlinx     = discProbe([]byte{0x02, 0x00}, 64)
	Vantage        = discProbe([]byte{0x00, 0x00}, 64)
	ArtNet         = discProbe([]byte("Art-Net\x00"), 64)
	SACN           = discProbe([]byte{0x00, 0x10, 0x00, 0x00, 'A', 'S', 'C', '-', 'E', '1', '.', '1', '7', 0x00, 0x00, 0x00}, 128)
	Crestron       = discProbe([]byte{0x15, 0x00, 0x00}, 32)
	PJLink         = discProbe([]byte("%1POWR ?\r"), 32)
	CBus           = discProbe([]byte{0x05, 0x38, 0x00, 0x01, 0x00, 0x00}, 32)
	SaiaSBus       = discProbe([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, 64)
	Powerlink      = discProbe([]byte{0x00, 0x00, 0x00, 0x00}, 64)
	SLMP           = discProbe([]byte{0x50, 0x00, 0x00, 0xff, 0xff, 0x03, 0x00}, 128)
	SiprotecEN100  = discProbe([]byte{0x68, 0x00}, 64)
	FFHSE          = discProbe([]byte{0x00, 0x00}, 64)
	CIPIO          = discProbe([]byte{0x00, 0x02, 0x00, 0x00}, 64)
	ADSDiscovery   = discProbe([]byte{0x00, 0x00, 0x00, 0x00}, 64)
	ADSUDP         = discProbe([]byte{0x00, 0x00, 0x20, 0x00}, 64)
	GEEgD          = discProbe([]byte{0x00, 0x01}, 128)
	BSAP           = discProbe([]byte{0x00, 0x00}, 64)
	Lontalk        = discProbe([]byte{0x00, 0x00}, 128)
	MNDP           = discProbe([]byte{0x00, 0x01}, 64)
	ArubaPAPI      = discProbe([]byte{0x00, 0x00}, 128)
	Synchrophasor  = discProbe([]byte{0xaa, 0x41}, 64)
	ChinaHiks      = discProbe([]byte{0x00, 0x00}, 64)
	HikvisionSADP  = discProbe([]byte("<?xml version=\"1.0\""), 256)
	Tristation     = discProbe([]byte{0x01, 0x00}, 64)
	PCOMUDP        = discProbe([]byte{0x2f, 0x5f, 0x4f, 0x50}, 128)
	DNP3UDP        = discProbe([]byte{0x05, 0x64}, 64)
	HARTIPUDP      = discProbe([]byte{0x01, 0x00, 0x00, 0x00}, 64)
	OPCUAPubSub    = discProbe([]byte{0xf0}, 128)
	DDSRtps        = discProbe([]byte{'R', 'T', 'P', 'S', 0x02, 0x01, 0x01, 0x0f}, 128)
	EnipUDP        = discProbe([]byte{0x63, 0x00, 0x04, 0x00}, 64)
	ModbusUDPDup   = discProbe([]byte{0x00, 0x01, 0x00, 0x00, 0x00, 0x06}, 64)
	MQTTSN         = discProbe([]byte{0x02, 0x01}, 128)
	Ethercat       = discProbe([]byte{0x01, 0x00}, 128)
	Powrlink       = discProbe([]byte{0x00, 0x00}, 64)
)

// LightweightM2M: CoAP-shaped already.
func LWM2M(rng *rand.Rand) []byte { return CoAP(rng) }

// ChinaMoxi: same.
func Fins(rng *rand.Rand) []byte {
	return []byte{'F', 'I', 'N', 'S', 0x00, 0x00, 0x00, 0x0c,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
}

// Isakmp / IKE NAT-T: already have seed for ISAKMP; here as smart.
func ISAKMP(rng *rand.Rand) []byte {
	cookieI := make([]byte, 8)
	cookieR := make([]byte, 8)
	_, _ = rng.Read(cookieI)
	_, _ = rng.Read(cookieR)
	hdr := append(cookieI, cookieR...)
	hdr = append(hdr, byte(rng.Intn(0x100))) // next payload
	hdr = append(hdr, 0x10)                  // version
	hdr = append(hdr, byte(rng.Intn(0x40)))  // exchange type
	hdr = append(hdr, byte(rng.Intn(0x100))) // flags
	hdr = append(hdr, 0, 0, 0, 0)            // msg id
	ln := uint32(28 + rng.Intn(1<<10))
	if rng.Intn(4) == 0 {
		ln = 0xffffffff
	}
	hdr = append(hdr, byte(ln>>24), byte(ln>>16), byte(ln>>8), byte(ln))
	return append(hdr, shortRandom(rng, 128)...)
}
func IKENATT(rng *rand.Rand) []byte {
	// NAT-T prepends four 0x00 bytes to disambiguate from ESP.
	return append([]byte{0, 0, 0, 0}, ISAKMP(rng)...)
}

// KerberosUDP: reuse the Kerberos smart generator.
func KerberosUDP(rng *rand.Rand) []byte { return Kerberos(rng) }

// OpenVPN UDP: same opcode structure as the TCP variant.
func OpenVPNUDP(rng *rand.Rand) []byte {
	op := byte(rng.Intn(0x100))
	sid := make([]byte, 8)
	_, _ = rng.Read(sid)
	body := append([]byte{op}, sid...)
	return append(body, shortRandom(rng, 128)...)
}

// WireGuard: 4-byte type + handshake blob.
func WireGuard(rng *rand.Rand) []byte {
	t := byte(1 + rng.Intn(4))
	return append([]byte{t, 0, 0, 0}, shortRandom(rng, 128)...)
}

// L2TP: control message with flags/version + length + tunnel/session.
func L2TP(rng *rand.Rand) []byte {
	flags := []byte{0xc8, byte(rng.Intn(0x100))}
	ln := uint16(20 + rng.Intn(256))
	if rng.Intn(4) == 0 {
		ln = 0xffff
	}
	hdr := append(flags, byte(ln>>8), byte(ln))
	tun := make([]byte, 8)
	_, _ = rng.Read(tun)
	hdr = append(hdr, tun...)
	return append(hdr, shortRandom(rng, 128)...)
}

// RIP / RIPng / Babel / BFD / LDP / WCCP — routing-protocol packets.
func RIPSmart(rng *rand.Rand) []byte {
	cmd := byte(1 + rng.Intn(4))
	return append([]byte{cmd, 0x02, 0x00, 0x00}, shortRandom(rng, 128)...)
}
func RIPngSmart(rng *rand.Rand) []byte {
	cmd := byte(1 + rng.Intn(2))
	return append([]byte{cmd, 0x01, 0x00, 0x00}, shortRandom(rng, 128)...)
}
func BabelSmart(rng *rand.Rand) []byte {
	return append([]byte{0x2a, byte(rng.Intn(0x08)), byte(rng.Intn(0x100)), byte(rng.Intn(0x100))}, shortRandom(rng, 128)...)
}
func BFDSmart(rng *rand.Rand) []byte {
	return append([]byte{0x20, byte(rng.Intn(0x100)), byte(rng.Intn(0x40)), byte(rng.Intn(0x40))}, shortRandom(rng, 20)...)
}
func LDPSmart(rng *rand.Rand) []byte {
	return append([]byte{0x00, 0x01, 0x00, 0x1a}, shortRandom(rng, 128)...)
}
func WCCPSmart(rng *rand.Rand) []byte {
	return append([]byte{0x00, 0x00, 0x00, byte(rng.Intn(0x20))}, shortRandom(rng, 128)...)
}

// NetFlow v5 / sFlow: monitoring protocols with structured samples.
func NetFlowSmart(rng *rand.Rand) []byte {
	ver := []byte{0x00, byte([]byte{5, 9, 10}[rng.Intn(3)])}
	nrec := uint16(rng.Intn(0x100))
	if rng.Intn(4) == 0 {
		nrec = 0xffff
	}
	hdr := append(ver, byte(nrec>>8), byte(nrec))
	hdr = append(hdr, shortRandom(rng, 20)...)
	return append(hdr, shortRandom(rng, int(min(uint32(nrec)*48, 1<<10)))...)
}
func SflowSmart(rng *rand.Rand) []byte {
	return append([]byte{0x00, 0x00, 0x00, 0x05}, shortRandom(rng, 128)...)
}

// StatsD / CollectD.
func StatsDSmart(rng *rand.Rand) []byte {
	kinds := []string{"c", "g", "h", "ms", "s", "unknown"}
	return []byte(pickString(rng, textArgs) + ":" + fmt.Sprint(rng.Intn(1<<30)) + "|" + pickString(rng, kinds) + "\n")
}
func CollectdSmart(rng *rand.Rand) []byte {
	// Part type 0x0000 (host) + length(2) + data.
	hdr := []byte{0x00, 0x00, 0x00, 14}
	host := []byte("fuzzhost\x00")
	return append(append(hdr, host...), shortRandom(rng, 128)...)
}

// GTP-C / GTP-U / VXLAN / Geneve — tunnelling headers.
func GTPCSmart(rng *rand.Rand) []byte {
	ver := byte(0x32 | rng.Intn(0x10))
	ln := uint16(rng.Intn(1 << 12))
	if rng.Intn(4) == 0 {
		ln = 0xffff
	}
	hdr := []byte{ver, byte(1 + rng.Intn(0xff)), byte(ln >> 8), byte(ln)}
	hdr = append(hdr, shortRandom(rng, 128)...)
	return hdr
}
func GTPUSmart(rng *rand.Rand) []byte {
	return append([]byte{0x30, byte(0xff - rng.Intn(0xf0)), 0x00, byte(rng.Intn(0x100))}, shortRandom(rng, 128)...)
}
func VXLANSmart(rng *rand.Rand) []byte {
	return append([]byte{0x08, 0x00, 0x00, 0x00, byte(rng.Intn(0x100)), byte(rng.Intn(0x100)), byte(rng.Intn(0x100)), 0x00}, shortRandom(rng, 128)...)
}
func GeneveSmart(rng *rand.Rand) []byte {
	return append([]byte{0x00, 0x00, 0x65, 0x58, byte(rng.Intn(0x100)), byte(rng.Intn(0x100)), byte(rng.Intn(0x100)), 0x00}, shortRandom(rng, 128)...)
}

// CLDAP: identical envelope to LDAP but UDP.
func CLDAP(rng *rand.Rand) []byte { return LDAP(rng) }

// SLP: Service Location Protocol packets.
func SLPSmart(rng *rand.Rand) []byte {
	return append([]byte{0x02, byte(rng.Intn(0x10) + 1), 0x00, 0x00, 0x16}, shortRandom(rng, 128)...)
}

// XDMCP: X Display Manager protocol.
func XDMCPSmart(rng *rand.Rand) []byte {
	return append([]byte{0x00, 0x01, 0x00, byte(1 + rng.Intn(7))}, shortRandom(rng, 32)...)
}

// MQTT-SN variant.
func MQTTSNSmart(rng *rand.Rand) []byte {
	ln := byte(2 + rng.Intn(0xfd))
	types := []byte{0x00, 0x04, 0x05, 0x06, 0x0c, 0x0d, 0x18, 0x19}
	return append([]byte{ln, types[rng.Intn(len(types))]}, shortRandom(rng, int(ln)-2)...)
}

// IAX2 / MGCP / H.323 / Siprotec share an SIP-like or binary mix. Use SIP
// for IAX2's call setup where applicable.
func IAX2(rng *rand.Rand) []byte {
	// 12-byte full frame header.
	hdr := []byte{0x80 | byte(rng.Intn(0x80)), byte(rng.Intn(0x100)),
		byte(rng.Intn(0x100)), byte(rng.Intn(0x100)),
		byte(rng.Intn(0x100)), byte(rng.Intn(0x100)), byte(rng.Intn(0x100)), byte(rng.Intn(0x100)),
		byte(rng.Intn(0x100)), byte(rng.Intn(0x100)),
		byte(rng.Intn(0x100)), byte(rng.Intn(0x100))}
	return append(hdr, shortRandom(rng, 128)...)
}
func MGCPSmart(rng *rand.Rand) []byte {
	verbs := []string{"RQNT", "NTFY", "CRCX", "MDCX", "DLCX", "RSIP", "AUEP"}
	return []byte(pickString(rng, verbs) + " " + fmt.Sprint(rng.Intn(1<<30)) + " aaln/1@fuzz MGCP 1.0\r\nX: " + fmt.Sprint(rng.Intn(1<<30)) + "\r\nR: " + pickString(rng, textArgs) + "\r\n")
}

// DTLS: ClientHello with mutated fields.
func DTLSSmart(rng *rand.Rand) []byte {
	// Record layer: type=22 handshake, version, epoch, seq, length, then
	// handshake ClientHello.
	rec := []byte{0x16, 0xfe, 0xfd, 0x00, 0x00,
		0, 0, 0, 0, 0, 0, 0, byte(rng.Intn(0x100))}
	// ClientHello
	hs := []byte{0x01,
		0, 0, byte(rng.Intn(0x100)),
		0, 0,
		0, 0, 0, 0, 0, 0,
		0xfe, 0xfd,
	}
	// random 32
	hs = append(hs, shortRandom(rng, 32)...)
	hs = append(hs, 0)                     // session id len
	hs = append(hs, byte(rng.Intn(0x100))) // cookie len
	hs = append(hs, shortRandom(rng, 32)...)
	hs = append(hs, 0, 0x02, 0xc0, 0x2f) // one cipher
	hs = append(hs, 0x01, 0x00)          // compression methods
	// length into record
	ln := uint16(len(hs))
	if rng.Intn(4) == 0 {
		ln = 0xffff
	}
	rec[11] = byte(ln >> 8)
	rec[12] = byte(ln)
	return append(rec, hs...)
}

// QUIC: Initial packet with mutated version and length.
func QUICSmart(rng *rand.Rand) []byte {
	ver := []byte{0, 0, 0, 1}
	if rng.Intn(3) == 0 {
		ver = []byte{byte(rng.Intn(0x100)), byte(rng.Intn(0x100)), byte(rng.Intn(0x100)), byte(rng.Intn(0x100))}
	}
	hdr := append([]byte{0xc0}, ver...)
	dcidLen := byte(rng.Intn(21))
	hdr = append(hdr, dcidLen)
	hdr = append(hdr, shortRandom(rng, int(dcidLen))...)
	scidLen := byte(rng.Intn(21))
	hdr = append(hdr, scidLen)
	hdr = append(hdr, shortRandom(rng, int(scidLen))...)
	return append(hdr, shortRandom(rng, 256)...)
}

// RDPUDP: UDP transport for RDP.
func RDPUDPSmart(rng *rand.Rand) []byte {
	return append([]byte{0x30, byte(rng.Intn(0x100)), 0, 0, 0, 0, 0, 0, 0}, shortRandom(rng, 128)...)
}

// Memcached UDP: 8-byte header before the ASCII request.
func MemcachedUDPSmart(rng *rand.Rand) []byte {
	hdr := []byte{byte(rng.Intn(0x100)), byte(rng.Intn(0x100)), // request id
		0, 0, // sequence
		0, 1, // total datagrams
		0, 0} // reserved
	return append(hdr, Memcached(rng)...)
}

// C1222: metering over UDP: tiny ASN.1 shape.
func C1222(rng *rand.Rand) []byte {
	return append([]byte{0x60, 0x08, 0x02, 0x01, 0x00, 0x80, byte(rng.Intn(0x100)), 0x00, 0x00, 0x00}, shortRandom(rng, 128)...)
}

// WDBRPC (VxWorks): Sun RPC with program 0x55555555.
func WDBRPC(rng *rand.Rand) []byte {
	// Reuse RPCBIND's shape but set program to WDB.
	body := []byte{
		0x00, 0x00, 0x00, 0x01, // xid
		0x00, 0x00, 0x00, 0x00, // call
		0x00, 0x00, 0x00, 0x02, // rpcvers
		0x55, 0x55, 0x55, 0x55, // program
		0x00, 0x00, 0x00, 0x01, // vers
		0x00, 0x00, 0x00, byte(rng.Intn(0x100)),
	}
	body = append(body, shortRandom(rng, 128)...)
	return body
}

// WsDiscovery: SOAP over UDP.
func WSDiscoverySmart(rng *rand.Rand) []byte {
	msg := `<?xml version="1.0"?><e:Envelope xmlns:e="http://www.w3.org/2003/05/soap-envelope" xmlns:w="http://schemas.xmlsoap.org/ws/2005/04/discovery"><e:Header><w:MessageID>uuid:` + strings.Repeat("A", rng.Intn(1<<10)) + `</w:MessageID><w:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To></e:Header><e:Body/></e:Envelope>`
	return []byte(msg)
}

// SentinelHASP, Profinet: vendor-specific binary.
func SentinelHASP(rng *rand.Rand) []byte { return shortRandom(rng, 128) }
func ProfinetSmart(rng *rand.Rand) []byte {
	return append([]byte{0xfe, 0xfd, byte(rng.Intn(0x10)), byte(rng.Intn(0x10))}, shortRandom(rng, 256)...)
}

// PlexGDM: same wire as SSDP.
func PlexGDM(rng *rand.Rand) []byte { return SSDP(rng) }

// STUN already in main smart.go. UDP tacacs alias to TCP shape.
func TacacsUDP(rng *rand.Rand) []byte { return TACACS(rng) }
