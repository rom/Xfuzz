package engine

import (
	"encoding/binary"
	"math/rand"
)

// generator produces one fuzzer's stream of payloads.
//
// Two kinds share the type: dumb picks a seed and corrupts it with byte-level
// operators, smart calls the protocol's own structural generator. A protocol
// with no smart generator falls through to dumb — a "smart" column that is
// empty is a protocol's own admission that nothing beyond byte mutation is
// known to be useful against it yet, and leaving the slot open invites a
// later contribution to fill it.
type generator struct {
	p    Protocol
	rng  *rand.Rand
	kind Kind
}

func newGenerator(kind Kind, p Protocol, rng *rand.Rand) *generator {
	return &generator{p: p, rng: rng, kind: kind}
}

// next returns the next payload.
func (g *generator) next() []byte {
	switch g.kind {
	case KindSmart:
		if g.p.Smart != nil {
			return g.p.Smart(g.rng)
		}
		fallthrough
	default:
		return g.dumb()
	}
}

// dumb builds a protocol-unaware payload.
//
// Six operators, chosen with equal probability; a run through a full campaign
// visits each. Named rather than numbered so a finding's reproducer can say
// which one found it.
func (g *generator) dumb() []byte {
	// A quarter of the time there is no seed to start from — that is a
	// protocol the harness has not been taught the shape of — so pure random
	// is the only option. On the protocols with a seed, pick one.
	op := g.rng.Intn(6)
	switch op {
	case 0:
		return g.random()
	case 1:
		return g.seedPlusFlips()
	case 2:
		return g.seedTruncated()
	case 3:
		return g.seedExtended()
	case 4:
		return g.magicValues()
	default:
		return g.oversizedLength()
	}
}

// random is bytes from /dev/urandom-shaped noise: a length distribution that
// fits both inside a TCP MSS and well beyond a common UDP MTU, so framing
// paths that split on either boundary both see mutation.
func (g *generator) random() []byte {
	n := g.rng.Intn(2048)
	if g.rng.Intn(8) == 0 {
		n = g.rng.Intn(16384)
	}
	b := make([]byte, n)
	_, _ = g.rng.Read(b)
	return b
}

// seedPlusFlips is a seed with a handful of random bits inverted. Shallow,
// but what finds a parser whose check is "does this byte equal 0x03" when the
// byte could be seven other values the author did not list.
func (g *generator) seedPlusFlips() []byte {
	b := g.seedCopy()
	if len(b) == 0 {
		return g.random()
	}
	for i := 0; i < 1+g.rng.Intn(8); i++ {
		b[g.rng.Intn(len(b))] ^= byte(1 << uint(g.rng.Intn(8)))
	}
	return b
}

// seedTruncated is a seed cut short. What finds a parser that trusts a length
// field over the bytes actually present.
func (g *generator) seedTruncated() []byte {
	b := g.seedCopy()
	if len(b) < 2 {
		return b
	}
	return b[:g.rng.Intn(len(b))]
}

// seedExtended is a seed with garbage appended. What finds a parser that
// keeps reading past the length it declared, or one that trips on data it did
// not expect to see.
func (g *generator) seedExtended() []byte {
	b := g.seedCopy()
	ext := make([]byte, g.rng.Intn(1024))
	_, _ = g.rng.Read(ext)
	return append(b, ext...)
}

// magicValues drops a seed with one value replaced by a boundary number — 0,
// -1, INT_MAX, a common off-by-one bound, an overflow nudge. One-byte parsers
// trip on the first few; multi-byte ones on the last.
func (g *generator) magicValues() []byte {
	b := g.seedCopy()
	if len(b) < 4 {
		return g.random()
	}
	magics8 := []byte{0x00, 0xff, 0x01, 0x7f, 0x80, 0x20, 0x0a, 0x0d}
	magics16 := []uint16{0x0000, 0xffff, 0x0001, 0x7fff, 0x8000, 0x8001, 0xfffe}
	magics32 := []uint32{0, 0xffffffff, 1, 0x7fffffff, 0x80000000, 0x100000, 0x7f000001}
	switch g.rng.Intn(3) {
	case 0:
		b[g.rng.Intn(len(b))] = magics8[g.rng.Intn(len(magics8))]
	case 1:
		if len(b) >= 2 {
			off := g.rng.Intn(len(b) - 1)
			binary.BigEndian.PutUint16(b[off:], magics16[g.rng.Intn(len(magics16))])
		}
	default:
		if len(b) >= 4 {
			off := g.rng.Intn(len(b) - 3)
			binary.BigEndian.PutUint32(b[off:], magics32[g.rng.Intn(len(magics32))])
		}
	}
	return b
}

// oversizedLength is the industry's favourite memory-corruption shape: a
// length-prefixed message whose length field claims more than the payload
// holds. The seed may already be length-prefixed; if it is not, the operator
// still prepends one and sees what the parser does with it.
func (g *generator) oversizedLength() []byte {
	payload := g.seedCopy()
	if len(payload) == 0 {
		payload = []byte{0x41, 0x41, 0x41, 0x41}
	}
	// Overstate by anywhere from a few bytes to 100 MB. A parser that
	// pre-allocates on a length field is the bug this catches.
	claim := uint32(len(payload)) + 1 + uint32(g.rng.Intn(1<<27))
	var hdr [4]byte
	switch g.rng.Intn(3) {
	case 0:
		binary.BigEndian.PutUint32(hdr[:], claim)
	case 1:
		binary.LittleEndian.PutUint32(hdr[:], claim)
	default:
		binary.BigEndian.PutUint16(hdr[:2], uint16(claim&0xffff))
		return append(hdr[:2], payload...)
	}
	return append(hdr[:], payload...)
}

// seedCopy returns one of the protocol's seeds, copied so the operators may
// mutate it freely, or an empty slice when the protocol has no seed at all.
func (g *generator) seedCopy() []byte {
	if len(g.p.Seeds) == 0 {
		return nil
	}
	seed := g.p.Seeds[g.rng.Intn(len(g.p.Seeds))]
	return append([]byte(nil), seed...)
}
