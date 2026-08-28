package codec

import (
	"fmt"
	"sort"
	"sync"

	"github.com/rom/Xfuzz/pkg/ir"
)

// OpaqueName marks a node holding bytes the codec did not understand.
//
// Partial parsing is a requirement, not a fallback. Real corpora are full of
// truncated, extended, and subtly malformed files, and those are frequently the
// most valuable seeds — a strict parser would reject exactly the inputs worth
// having (ASR-0014).
const OpaqueName = "@opaque"

// Codec lifts bytes into the IR and is the only format-specific part of the
// pipeline. Encoding is generic (ir.AppendEncode): a codec has to know how to
// parse a format, not how to write one.
type Codec interface {
	// Name is the identifier used in campaign files.
	Name() string

	// Extensions lists the usual file extensions, for corpus import.
	Extensions() []string

	// Decode lifts src into a tree.
	//
	// Decode is best-effort and total: malformed input yields a partial tree
	// with the unrecognised bytes preserved in opaque nodes, not an error. An
	// error means the codec could not run at all.
	//
	// The returned tree references src rather than copying it. Clone it into an
	// arena before mutating.
	//
	// For every input, re-encoding the result must reproduce src byte for byte.
	// Values read from the file are preserved even when they are wrong — a
	// corrupt length or checksum survives decoding and is repaired only when a
	// fixup is explicitly run. Decode preserves; fixup repairs.
	Decode(a *ir.Arena, src []byte) (*ir.Node, error)
}

var (
	mu       sync.RWMutex
	registry = map[string]Codec{}
)

// Register makes a codec available by name. It panics on a duplicate, since
// silently shadowing a codec would change how every corpus entry is parsed.
func Register(c Codec) {
	mu.Lock()
	defer mu.Unlock()
	name := c.Name()
	if _, dup := registry[name]; dup {
		panic("codec: already registered: " + name)
	}
	registry[name] = c
}

// Get returns a codec by name.
func Get(name string) (Codec, error) {
	mu.RLock()
	defer mu.RUnlock()
	c, ok := registry[name]
	if !ok {
		return nil, fmt.Errorf("codec: unknown codec %q (have %v)", name, namesLocked())
	}
	return c, nil
}

// Names lists the registered codecs, sorted.
func Names() []string {
	mu.RLock()
	defer mu.RUnlock()
	return namesLocked()
}

func namesLocked() []string {
	out := make([]string, 0, len(registry))
	for n := range registry {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// ForExtension returns the codec claiming a file extension, which may include
// the leading dot.
func ForExtension(ext string) (Codec, bool) {
	if len(ext) > 0 && ext[0] == '.' {
		ext = ext[1:]
	}
	mu.RLock()
	defer mu.RUnlock()
	for _, name := range namesLocked() { // deterministic order
		for _, e := range registry[name].Extensions() {
			if e == ext {
				return registry[name], true
			}
		}
	}
	return nil, false
}

// Opaque builds a node holding bytes that were not understood.
func Opaque(a *ir.Arena, raw []byte) *ir.Node {
	n := a.Alloc(ir.KindBytes, OpaqueName)
	n.Raw = raw
	return n
}

// IsOpaque reports whether a node holds unparsed bytes.
func IsOpaque(n *ir.Node) bool { return n != nil && n.Name == OpaqueName }

// UnparsedBytes returns how many bytes of a tree remain unstructured.
//
// This is a corpus health metric, not a correctness one: a seed that is 100%
// opaque parses as a byte blob and will be fuzzed as one, which is a signal the
// schema does not match the corpus.
func UnparsedBytes(n *ir.Node) int {
	total := 0
	ir.Walk(n, func(x *ir.Node) bool {
		if IsOpaque(x) {
			total += ir.EncodedLen(x)
			return false
		}
		return true
	})
	return total
}

// StructuredFraction returns the share of a tree's bytes that a codec
// understood, between 0 and 1. An empty input counts as fully structured.
func StructuredFraction(n *ir.Node) float64 {
	total := ir.EncodedLen(n)
	if total == 0 {
		return 1
	}
	return float64(total-UnparsedBytes(n)) / float64(total)
}
