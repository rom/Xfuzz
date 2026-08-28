package ir

import (
	"fmt"
	"hash/adler32"
	"hash/crc32"
	"sort"
	"strconv"
	"sync"
)

// DeriveKind is the class of a derived value.
//
// The classes split on what they depend on, which is what makes the fixup pass
// tractable. Length, Count, and Offset depend only on the *sizes* of other
// nodes, and every derived node's size is fixed by its width — so they can
// never form a genuine cycle. Checksum depends on the *values* of other nodes,
// so checksums can nest and must be ordered.
type DeriveKind uint8

// The derivation classes.
const (
	DeriveLength   DeriveKind = iota // encoded byte length of a range
	DeriveCount                      // number of children of the target
	DeriveOffset                     // byte offset of the target from the root
	DeriveChecksum                   // checksum over the encoded bytes of a range
	numDeriveKinds
)

var deriveNames = [...]string{
	DeriveLength:   "length",
	DeriveCount:    "count",
	DeriveOffset:   "offset",
	DeriveChecksum: "checksum",
}

func (d DeriveKind) String() string {
	if int(d) < len(deriveNames) && deriveNames[d] != "" {
		return deriveNames[d]
	}
	return "DeriveKind(" + strconv.Itoa(int(d)) + ")"
}

// ValueDependent reports whether the class depends on other nodes' values
// rather than only their sizes.
func (d DeriveKind) ValueDependent() bool { return d == DeriveChecksum }

// Derivation describes how a derived node computes its value.
type Derivation struct {
	Kind DeriveKind

	// From is the target, or the start of the range for Length and Checksum.
	From Ref
	// To ends an inclusive range. Leave zero to cover From alone.
	To Ref

	// Algo names a registered checksum function. Required for DeriveChecksum.
	Algo string

	// SelfZero zeroes this field's own bytes before checksumming.
	//
	// A checksum covering the field that holds it is circular, and several real
	// formats resolve it exactly this way — the IPv4 header checksum among them.
	// Without this flag such a derivation is an error rather than a surprise.
	SelfZero bool

	// Addend is added to the computed value, for fields defined as "length
	// including the header" and similar.
	Addend int64
}

func (d *Derivation) equal(o *Derivation) bool {
	if d == nil || o == nil {
		return d == o
	}
	return d.Kind == o.Kind && d.From.equal(&o.From) && d.To.equal(&o.To) &&
		d.Algo == o.Algo && d.SelfZero == o.SelfZero && d.Addend == o.Addend
}

func (d *Derivation) String() string {
	if d == nil {
		return "<nil derivation>"
	}
	s := d.Kind.String() + "(" + d.From.String()
	if !d.To.IsZero() {
		s += ".." + d.To.String()
	}
	if d.Kind == DeriveChecksum {
		s += ", " + d.Algo
		if d.SelfZero {
			s += ", self-zero"
		}
	}
	if d.Addend != 0 {
		s += fmt.Sprintf(", %+d", d.Addend)
	}
	return s + ")"
}

// ChecksumFunc computes a checksum over a byte range.
type ChecksumFunc func([]byte) uint64

var (
	checksumMu sync.RWMutex
	checksums  = map[string]ChecksumFunc{
		"crc32":      func(b []byte) uint64 { return uint64(crc32.ChecksumIEEE(b)) },
		"crc32c":     func(b []byte) uint64 { return uint64(crc32.Checksum(b, crc32.MakeTable(crc32.Castagnoli))) },
		"adler32":    func(b []byte) uint64 { return uint64(adler32.Checksum(b)) },
		"sum8":       func(b []byte) uint64 { return uint64(sumBytes(b) & 0xff) },
		"sum16":      func(b []byte) uint64 { return uint64(sumBytes(b) & 0xffff) },
		"sum32":      func(b []byte) uint64 { return uint64(sumBytes(b) & 0xffffffff) },
		"xor8":       func(b []byte) uint64 { return uint64(xorBytes(b)) },
		"len":        func(b []byte) uint64 { return uint64(len(b)) },
		"zero":       func([]byte) uint64 { return 0 },
		"internet":   func(b []byte) uint64 { return uint64(internetChecksum(b)) },
		"crc16ccitt": func(b []byte) uint64 { return uint64(crc16CCITT(b)) },
	}
)

// RegisterChecksum makes a checksum algorithm available to derivations. It
// panics on a duplicate name, since silently shadowing a checksum would corrupt
// every corpus built with the original.
func RegisterChecksum(name string, fn ChecksumFunc) {
	checksumMu.Lock()
	defer checksumMu.Unlock()
	if _, dup := checksums[name]; dup {
		panic("ir: checksum algorithm already registered: " + name)
	}
	checksums[name] = fn
}

// Checksum returns a registered algorithm.
func Checksum(name string) (ChecksumFunc, bool) {
	checksumMu.RLock()
	defer checksumMu.RUnlock()
	fn, ok := checksums[name]
	return fn, ok
}

// ChecksumNames lists the registered algorithms, sorted.
func ChecksumNames() []string {
	checksumMu.RLock()
	defer checksumMu.RUnlock()
	names := make([]string, 0, len(checksums))
	for n := range checksums {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

func sumBytes(b []byte) uint64 {
	var s uint64
	for _, c := range b {
		s += uint64(c)
	}
	return s
}

func xorBytes(b []byte) byte {
	var x byte
	for _, c := range b {
		x ^= c
	}
	return x
}

// internetChecksum is the one's-complement sum of 16-bit words used by IPv4,
// ICMP, TCP, and UDP.
func internetChecksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func crc16CCITT(b []byte) uint16 {
	crc := uint16(0xffff)
	for _, c := range b {
		crc ^= uint16(c) << 8
		for i := 0; i < 8; i++ {
			if crc&0x8000 != 0 {
				crc = crc<<1 ^ 0x1021
			} else {
				crc <<= 1
			}
		}
	}
	return crc
}

// Suppress selects derivations to leave alone during a fixup.
//
// This is not an optimisation. A fuzzer that always writes a correct checksum
// can never reach a target's checksum-validation code, so deliberately
// inconsistent inputs are a requirement, not a side effect (ASR-0014). The
// campaign file turns per-class probabilities into a concrete Suppress for each
// execution.
type Suppress struct {
	Length   bool
	Count    bool
	Offset   bool
	Checksum bool

	// Node suppresses individual derived nodes. Nil suppresses none.
	Node func(*Node) bool
}

// SuppressAll leaves every derivation untouched.
func SuppressAll() Suppress {
	return Suppress{Length: true, Count: true, Offset: true, Checksum: true}
}

// suppresses reports whether a derived node should be left alone.
func (s Suppress) suppresses(n *Node) bool {
	if s.Node != nil && s.Node(n) {
		return true
	}
	switch n.Derive.Kind {
	case DeriveLength:
		return s.Length
	case DeriveCount:
		return s.Count
	case DeriveOffset:
		return s.Offset
	case DeriveChecksum:
		return s.Checksum
	}
	return false
}

// Any reports whether the set suppresses at least one class.
func (s Suppress) Any() bool {
	return s.Length || s.Count || s.Offset || s.Checksum || s.Node != nil
}
