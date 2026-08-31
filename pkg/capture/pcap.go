package capture

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"time"
)

// Reading a packet capture.
//
// A pcap is not a list of requests. It is a list of frames, and getting from one
// to the other means three layers of work that HAR does for free: decode the
// link, network and transport headers; reassemble each TCP connection's byte
// stream from segments that may arrive out of order, overlap, or be missing
// entirely; and only then parse HTTP out of the two directions.
//
// That is worth doing because a pcap is what exists when nobody thought to
// record a HAR — a tcpdump from a production incident, a capture taken by
// someone else, a trace from an embedded device with no browser involved. It is
// also the only source that shows traffic a proxy would not see.
//
// What this does not do is decrypt. A capture of TLS is a capture of ciphertext,
// and the honest thing is to say so and count it rather than to produce an empty
// result that looks like a capture with no traffic in it.

// pcap file magic, in both byte orders, plus the nanosecond-resolution variant.
const (
	pcapMagicLE   = 0xA1B2C3D4
	pcapMagicNano = 0xA1B23C4D
	pcapNGMagic   = 0x0A0D0D0A
)

// Link-layer types this reader understands.
const (
	linkEthernet = 1
	linkRaw      = 101 // raw IP, no link header
	linkLoopback = 0   // BSD loopback
	linkLinuxSLL = 113 // Linux "cooked" capture, from tcpdump -i any
)

// MaxStreams bounds how many concurrent connections are tracked, and
// MaxStreamBytes how much of one is buffered. A capture is a file someone else
// produced, so both are bounds on what a hostile or merely enormous one can
// cost.
const (
	MaxStreams     = 4096
	MaxStreamBytes = 8 << 20
)

// ReadPcap reads a libpcap capture, reassembles its TCP streams, and returns the
// HTTP exchanges it found.
func ReadPcap(r io.Reader) (*Capture, error) {
	br := bufio.NewReaderSize(r, 1<<16)

	var magicBytes [4]byte
	if _, err := io.ReadFull(br, magicBytes[:]); err != nil {
		return nil, fmt.Errorf("capture: reading the pcap header: %w", err)
	}
	if binary.BigEndian.Uint32(magicBytes[:]) == pcapNGMagic {
		return nil, fmt.Errorf("capture: this is a pcapng file, and this reader takes " +
			"classic pcap; convert it with `editcap -F pcap in.pcapng out.pcap`")
	}

	var order binary.ByteOrder = binary.LittleEndian
	magic := binary.LittleEndian.Uint32(magicBytes[:])
	if magic != pcapMagicLE && magic != pcapMagicNano {
		order = binary.BigEndian
		magic = binary.BigEndian.Uint32(magicBytes[:])
		if magic != pcapMagicLE && magic != pcapMagicNano {
			return nil, fmt.Errorf("capture: this is not a pcap file")
		}
	}
	nano := magic == pcapMagicNano

	var hdr [20]byte
	if _, err := io.ReadFull(br, hdr[:]); err != nil {
		return nil, fmt.Errorf("capture: reading the pcap header: %w", err)
	}
	link := order.Uint32(hdr[16:20])

	asm := newAssembler()
	var read int64
	var frames, nonTCP, encrypted int

	for {
		var rec [16]byte
		if _, err := io.ReadFull(br, rec[:]); err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				break
			}
			return nil, fmt.Errorf("capture: reading a packet header: %w", err)
		}
		secs := order.Uint32(rec[0:4])
		frac := order.Uint32(rec[4:8])
		caplen := order.Uint32(rec[8:12])
		if caplen > 1<<20 {
			return nil, fmt.Errorf("capture: a packet claims %d bytes", caplen)
		}
		read += int64(caplen)
		if read > MaxCaptureBytes {
			return nil, fmt.Errorf("capture: the pcap holds more than %d bytes of packets",
				MaxCaptureBytes)
		}

		buf := make([]byte, caplen)
		if _, err := io.ReadFull(br, buf); err != nil {
			break // a truncated final packet; what came before is still usable
		}
		frames++

		at := time.Unix(int64(secs), 0)
		if nano {
			at = at.Add(time.Duration(frac))
		} else {
			at = at.Add(time.Duration(frac) * time.Microsecond)
		}

		seg, ok := parseFrame(uint32(link), buf)
		if !ok {
			nonTCP++
			continue
		}
		if seg.encrypted {
			encrypted++
			continue
		}
		asm.add(seg, at)
	}

	c := asm.exchanges()
	if frames == 0 {
		return nil, fmt.Errorf("capture: the pcap holds no packets")
	}
	if nonTCP > 0 {
		c.Notes = append(c.Notes, fmt.Sprintf("%d frame(s) were not TCP", nonTCP))
	}
	if encrypted > 0 {
		c.Notes = append(c.Notes,
			fmt.Sprintf("%d segment(s) were TLS and could not be read; capture the traffic "+
				"before it is encrypted, or record it with the proxy instead", encrypted))
	}
	if len(c.Exchanges) == 0 {
		return c, fmt.Errorf("capture: %d frames held no readable HTTP; %s",
			frames, strings.Join(c.Notes, "; "))
	}
	c.Sort()
	return c, nil
}

// segment is one TCP payload with enough addressing to place it in a stream.
type segment struct {
	src, dst  netip.AddrPort
	seq       uint32
	payload   []byte
	syn, fin  bool
	encrypted bool
}

// parseFrame peels the link, network and transport headers off one frame.
func parseFrame(link uint32, b []byte) (segment, bool) {
	var seg segment

	switch link {
	case linkEthernet:
		if len(b) < 14 {
			return seg, false
		}
		etype := binary.BigEndian.Uint16(b[12:14])
		b = b[14:]
		// VLAN tags, which a capture from a switched network routinely carries.
		for etype == 0x8100 || etype == 0x88A8 {
			if len(b) < 4 {
				return seg, false
			}
			etype = binary.BigEndian.Uint16(b[2:4])
			b = b[4:]
		}
		switch etype {
		case 0x0800, 0x86DD:
		default:
			return seg, false
		}
	case linkLinuxSLL:
		if len(b) < 16 {
			return seg, false
		}
		if p := binary.BigEndian.Uint16(b[14:16]); p != 0x0800 && p != 0x86DD {
			return seg, false
		}
		b = b[16:]
	case linkLoopback:
		if len(b) < 4 {
			return seg, false
		}
		b = b[4:]
	case linkRaw:
	default:
		return seg, false
	}

	if len(b) < 1 {
		return seg, false
	}
	var proto byte
	var src, dst netip.Addr
	switch b[0] >> 4 {
	case 4:
		if len(b) < 20 {
			return seg, false
		}
		ihl := int(b[0]&0x0F) * 4
		if ihl < 20 || len(b) < ihl {
			return seg, false
		}
		// A fragmented datagram carries only part of the transport header, and
		// reassembling IP fragments as well as TCP streams is more than this
		// needs to do. Dropped, and counted as not-TCP.
		if binary.BigEndian.Uint16(b[6:8])&0x1FFF != 0 {
			return seg, false
		}
		proto = b[9]
		src, _ = netip.AddrFromSlice(b[12:16])
		dst, _ = netip.AddrFromSlice(b[16:20])
		total := int(binary.BigEndian.Uint16(b[2:4]))
		if total > 0 && total <= len(b) {
			b = b[:total]
		}
		b = b[ihl:]
	case 6:
		if len(b) < 40 {
			return seg, false
		}
		proto = b[6]
		src, _ = netip.AddrFromSlice(b[8:24])
		dst, _ = netip.AddrFromSlice(b[24:40])
		b = b[40:]
	default:
		return seg, false
	}
	if proto != 6 { // TCP
		return seg, false
	}
	if len(b) < 20 {
		return seg, false
	}

	sport := binary.BigEndian.Uint16(b[0:2])
	dport := binary.BigEndian.Uint16(b[2:4])
	seq := binary.BigEndian.Uint32(b[4:8])
	off := int(b[12]>>4) * 4
	if off < 20 || len(b) < off {
		return seg, false
	}
	flags := b[13]
	payload := b[off:]

	seg = segment{
		src:     netip.AddrPortFrom(src, sport),
		dst:     netip.AddrPortFrom(dst, dport),
		seq:     seq,
		payload: payload,
		syn:     flags&0x02 != 0,
		fin:     flags&0x01 != 0,
	}
	// A TLS record begins with a content type of 20-23 followed by a version of
	// 0x03xx. Recognised so the reader can say "this was encrypted" rather than
	// "this was not HTTP", which are different problems with different answers.
	if len(payload) >= 3 && payload[0] >= 20 && payload[0] <= 23 && payload[1] == 3 {
		seg.encrypted = true
	}
	return seg, true
}

// stream is one direction of one TCP connection, reassembled.
type stream struct {
	key      streamKey
	base     uint32
	haveBase bool
	chunks   map[uint32][]byte
	bytes    int
	first    time.Time
	last     time.Time
}

type streamKey struct {
	src, dst netip.AddrPort
}

type assembler struct {
	streams map[streamKey]*stream
	order   []streamKey
}

func newAssembler() *assembler {
	return &assembler{streams: map[streamKey]*stream{}}
}

func (a *assembler) add(seg segment, at time.Time) {
	if len(seg.payload) == 0 && !seg.syn {
		return
	}
	k := streamKey{src: seg.src, dst: seg.dst}
	s := a.streams[k]
	if s == nil {
		if len(a.streams) >= MaxStreams {
			return
		}
		s = &stream{key: k, chunks: map[uint32][]byte{}, first: at}
		a.streams[k] = s
		a.order = append(a.order, k)
	}
	s.last = at

	if seg.syn {
		// The sequence number in a SYN is the initial one, and the first byte of
		// data is the one after it. Anchoring here is what lets the stream be
		// ordered without assuming the capture began at the connection's start.
		s.base, s.haveBase = seg.seq+1, true
		return
	}
	if len(seg.payload) == 0 {
		return
	}
	if !s.haveBase {
		s.base, s.haveBase = seg.seq, true
	}
	if s.bytes+len(seg.payload) > MaxStreamBytes {
		return
	}
	// Keyed by offset so a retransmission overwrites rather than duplicating,
	// which is what makes this reassembly rather than concatenation.
	off := seg.seq - s.base
	if _, seen := s.chunks[off]; !seen {
		s.bytes += len(seg.payload)
	}
	s.chunks[off] = seg.payload
}

// bytes returns the stream's payload in sequence order, stopping at the first
// gap.
//
// Stopping rather than skipping: a gap means packets the capture did not record,
// and joining across one produces a byte stream that never existed. An HTTP
// parser fed that would report a malformed request that the server never saw.
func (s *stream) reassemble() []byte {
	if len(s.chunks) == 0 {
		return nil
	}
	offs := make([]uint32, 0, len(s.chunks))
	for off := range s.chunks {
		offs = append(offs, off)
	}
	sort.Slice(offs, func(i, j int) bool { return offs[i] < offs[j] })

	var out []byte
	var next uint32
	for _, off := range offs {
		switch {
		case off == next:
		case off < next:
			// Overlapping retransmission: keep what is already there and take
			// only the part past it.
			skip := next - off
			if int(skip) >= len(s.chunks[off]) {
				continue
			}
			out = append(out, s.chunks[off][skip:]...)
			next = off + uint32(len(s.chunks[off]))
			continue
		default:
			return out // a gap
		}
		out = append(out, s.chunks[off]...)
		next = off + uint32(len(s.chunks[off]))
	}
	return out
}

// exchanges pairs each request stream with its reply stream and parses HTTP.
func (a *assembler) exchanges() *Capture {
	c := &Capture{}
	var unpaired int

	for _, k := range a.order {
		s := a.streams[k]
		data := s.reassemble()
		if len(data) == 0 {
			continue
		}
		reqs := parseRequests(data)
		if len(reqs) == 0 {
			continue
		}

		// The reply travels the other way on the same pair of endpoints.
		var resps []Response
		if back := a.streams[streamKey{src: k.dst, dst: k.src}]; back != nil {
			resps = parseResponses(back.reassemble())
		}
		for i, req := range reqs {
			ex := Exchange{Request: req, At: s.first, Source: "pcap"}
			if i < len(resps) {
				ex.Response = resps[i]
			} else {
				unpaired++
			}
			c.Exchanges = append(c.Exchanges, ex)
		}
	}
	if unpaired > 0 {
		c.Notes = append(c.Notes,
			fmt.Sprintf("%d request(s) had no response in the capture", unpaired))
	}
	return c
}

// parseRequests reads pipelined HTTP requests out of one direction's bytes.
func parseRequests(data []byte) []Request {
	var out []Request
	br := bufio.NewReader(bytes.NewReader(data))
	for {
		r, err := http.ReadRequest(br)
		if err != nil {
			return out
		}
		body, _ := io.ReadAll(io.LimitReader(r.Body, MaxStreamBytes))
		r.Body.Close()

		req := Request{
			Method: r.Method,
			Proto:  r.Proto,
			Body:   body,
		}
		// http.ReadRequest gives a server-side request: the URL is a path and
		// the authority is in the Host header. The capture wants the absolute
		// URL, because that is what identifies the endpoint.
		host := r.Host
		if host == "" {
			host = r.URL.Host
		}
		req.URL = "http://" + host + r.URL.RequestURI()
		for name, vals := range r.Header {
			for _, v := range vals {
				req.Headers = append(req.Headers, Header{Name: name, Value: v})
			}
		}
		SortHeaders(req.Headers)
		if host != "" {
			req.Set("Host", host)
		}
		out = append(out, req)
	}
}

// parseResponses reads pipelined HTTP responses out of the reply direction.
func parseResponses(data []byte) []Response {
	var out []Response
	br := bufio.NewReader(bytes.NewReader(data))
	for {
		r, err := http.ReadResponse(br, nil)
		if err != nil {
			return out
		}
		body, _ := io.ReadAll(io.LimitReader(r.Body, MaxStreamBytes))
		r.Body.Close()

		resp := Response{Status: r.StatusCode, Proto: r.Proto, Body: body}
		for name, vals := range r.Header {
			for _, v := range vals {
				resp.Headers = append(resp.Headers, Header{Name: name, Value: v})
			}
		}
		SortHeaders(resp.Headers)
		out = append(out, resp)
	}
}

// SortHeaders puts headers in a stable order.
//
// Go's header map has no order and ranging it is deliberately randomised, so
// without this the same capture read twice would produce different requests —
// and a campaign seeded from it would not reproduce (ASR-0008). Exported because
// every source that builds headers from an http.Header needs it, and the proxy
// is one of them.
func SortHeaders(h []Header) {
	sort.SliceStable(h, func(i, j int) bool {
		if h[i].Name != h[j].Name {
			return h[i].Name < h[j].Name
		}
		return h[i].Value < h[j].Value
	})
}
