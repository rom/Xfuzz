package state

import (
	"encoding/binary"
	"hash/fnv"
	"strconv"
	"strings"
)

// StateFn maps a target's response to a state label.
//
// Pluggable, because this is the one piece of stateful fuzzing that is genuinely
// protocol-specific (ADR-0010). Everything else — the model, the feedback, the
// scheduler — works on labels and does not care where they came from, which is
// what lets one engine fuzz a text protocol, a binary one, and a GUI where a
// state is a screen.
type StateFn interface {
	// Name identifies the function in configuration and reports.
	Name() string

	// Label classifies one response. An empty label means "cannot tell", which
	// the trace records as Unknown rather than guessing.
	Label(resp []byte) Label
}

// StatusFn labels a response by its leading status token.
//
// The highest-signal default for text protocols, and it covers most of them:
// SMTP, FTP, POP3, IRC, Redis and HTTP all put a short, stable status at the
// front of a reply, and it is exactly the field that says which state the
// exchange is now in. "250" after MAIL FROM and "250" after RCPT TO are the same
// label, which is correct — the target is in the same place, and it is the
// transition that distinguishes them.
type StatusFn struct {
	// Prefix, when set, is skipped before the status is read. HTTP needs it:
	// the status follows "HTTP/1.1 ", not the start of the line.
	Prefix string
}

// NewStatusFn returns a status-code state function.
func NewStatusFn() *StatusFn { return &StatusFn{} }

func (f *StatusFn) Name() string { return "status" }

// Label implements StateFn.
func (f *StatusFn) Label(resp []byte) Label {
	line := firstLine(resp)
	if line == "" {
		return ""
	}
	if f.Prefix != "" {
		rest, ok := strings.CutPrefix(line, f.Prefix)
		if !ok {
			return ""
		}
		line = strings.TrimLeft(rest, " ")
	}
	tok := leadingToken(line)
	if tok == "" {
		return ""
	}
	// Numeric or a short word. A whole sentence is not a status, and taking one
	// as a label is how every distinct error message becomes its own state.
	if _, err := strconv.Atoi(tok); err != nil && len(tok) > maxWordStatus {
		return ""
	}
	return Label(tok)
}

// maxWordStatus bounds a non-numeric status token. Redis replies "+OK" and IRC
// "PING"; a longer first word is prose, and prose makes a state per message.
const maxWordStatus = 12

// FingerprintFn labels a response by its shape, with the variable parts removed.
//
// The default for binary and for text protocols with no status field. What makes
// it work — or fail — is the normalisation: a fingerprint over raw bytes gives
// every nonce, session id and timestamp its own state, which is the failure
// ADR-0006 warns about, and a fingerprint over nothing but the length merges
// states that differ. So the normalisation is a named, ordered pipeline that a
// campaign can tune, and the model keeps one exemplar response per label so that
// a bad clustering can be seen rather than guessed at.
type FingerprintFn struct {
	// Normalisers run in order before hashing.
	Normalisers []Normaliser

	// LengthBuckets makes the response's length part of the fingerprint, in
	// powers of two. Off by default: a length that varies with a nonce splits
	// one state into many, and where length *is* the signal the campaign can
	// say so.
	LengthBuckets bool
}

// NewFingerprintFn returns a fingerprint state function with the default
// normalisation: digits and quoted strings collapsed, which between them cover
// session ids, nonces, timestamps and counters.
func NewFingerprintFn() *FingerprintFn {
	return &FingerprintFn{Normalisers: DefaultNormalisers()}
}

func (f *FingerprintFn) Name() string { return "fingerprint" }

// Label implements StateFn.
func (f *FingerprintFn) Label(resp []byte) Label {
	if len(resp) == 0 {
		return ""
	}
	b := resp
	for _, n := range f.Normalisers {
		b = n.Normalise(b)
	}
	h := fnv.New64a()
	_, _ = h.Write(b)
	if f.LengthBuckets {
		var buf [8]byte
		binary.LittleEndian.PutUint64(buf[:], uint64(bucketOf(len(resp))))
		_, _ = h.Write(buf[:])
	}
	// Short and hex: it appears in state graphs and finding reports, where a
	// full 64-bit number is noise.
	return Label("f" + strconv.FormatUint(h.Sum64()&0xffffff, 16))
}

// bucketOf rounds a length down to a power of two.
func bucketOf(n int) int {
	b := 1
	for b <= n/2 {
		b *= 2
	}
	return b
}

// ConstantFn gives every response the same label.
//
// The degenerate configuration ADR-0006 keeps deliberately available: with no
// state model a session is just a structured input guided by code coverage,
// which is the right answer for a protocol whose replies carry no state and a
// useful baseline to measure state guidance against.
type ConstantFn struct{ L Label }

// NewConstantFn returns a state function that labels everything alike.
func NewConstantFn() *ConstantFn { return &ConstantFn{L: "any"} }

func (f *ConstantFn) Name() string { return "constant" }

// Label implements StateFn.
func (f *ConstantFn) Label([]byte) Label { return f.L }

// FnNamed returns the state function a campaign file asked for.
//
// An unknown name gives the fingerprint function rather than an error: the
// campaign file's own validation is where a bad name is refused, and a second
// refusal here would mean a campaign that validated could still fail to start on
// the same field.
func FnNamed(name string) StateFn {
	switch name {
	case "status":
		return NewStatusFn()
	case "http":
		return &StatusFn{Prefix: "HTTP/1.1"}
	case "constant", "none":
		return NewConstantFn()
	default:
		return NewFingerprintFn()
	}
}

// firstLine returns the first line of a response, without its terminator.
func firstLine(b []byte) string {
	for i, c := range b {
		if c == '\n' || c == '\r' {
			return string(b[:i])
		}
	}
	return string(b)
}

// leadingToken returns the first whitespace-delimited token of a line.
func leadingToken(s string) string {
	s = strings.TrimLeft(s, " \t")
	if i := strings.IndexAny(s, " \t"); i >= 0 {
		return s[:i]
	}
	return s
}
