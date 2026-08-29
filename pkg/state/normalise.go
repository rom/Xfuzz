package state

import "unicode"

// Normaliser removes a class of variable content from a response before it is
// fingerprinted.
//
// This is the whole difficulty of black-box state inference, in one interface.
// A response carries two kinds of content: the part that says which state the
// target is in, and the part that varies for reasons that have nothing to do
// with state — a session id, a nonce, a timestamp, a byte count. Fingerprint the
// first and the clustering works; fingerprint the second and every reply is a
// new state, the state graph fills with thousands of leaves, and the scheduler
// chases noise (ADR-0006).
//
// Named steps rather than one clever function, because which parts vary is a
// property of the protocol and the campaign has to be able to say so.
type Normaliser interface {
	Name() string
	Normalise(b []byte) []byte
}

// DefaultNormalisers is the pipeline used when a campaign does not choose one.
//
// Digits and quoted strings, in that order. Between them they cover the
// overwhelming majority of what actually varies in a protocol reply — counters,
// lengths, ids, timestamps, ports, and every name or token a server echoes back
// — and neither removes anything that distinguishes one state from another in
// the protocols this was calibrated against.
func DefaultNormalisers() []Normaliser {
	return []Normaliser{CollapseDigits{}, CollapseQuoted{}, CollapseSpace{}}
}

// CollapseDigits replaces every run of digits with a single marker.
//
// The single highest-value step, because almost everything that varies without
// meaning is a number: sequence numbers, byte counts, session ids, ports,
// timestamps. A status code is a number too, which is why this belongs to the
// fingerprint function and not to StatusFn.
type CollapseDigits struct{}

func (CollapseDigits) Name() string { return "digits" }

// Normalise implements Normaliser.
func (CollapseDigits) Normalise(b []byte) []byte {
	out := make([]byte, 0, len(b))
	inRun := false
	for _, c := range b {
		if c >= '0' && c <= '9' {
			if !inRun {
				out = append(out, '#')
				inRun = true
			}
			continue
		}
		inRun = false
		out = append(out, c)
	}
	return out
}

// CollapseQuoted replaces the contents of quoted strings with a marker.
//
// A server that echoes a name, a path or a token back inside quotes is
// reporting the client's own input, not its own state; leaving it in makes the
// state a function of what was sent, which is exactly backwards.
type CollapseQuoted struct{}

func (CollapseQuoted) Name() string { return "quoted" }

// Normalise implements Normaliser.
func (CollapseQuoted) Normalise(b []byte) []byte {
	out := make([]byte, 0, len(b))
	var quote byte
	for _, c := range b {
		switch {
		case quote == 0 && (c == '"' || c == '\''):
			quote = c
			out = append(out, c, '$')
		case quote != 0 && c == quote:
			quote = 0
			out = append(out, c)
		case quote != 0:
			// Inside a quoted run: dropped, the marker above stands for it.
		default:
			out = append(out, c)
		}
	}
	return out
}

// CollapseSpace reduces every run of whitespace to one space and trims the ends.
//
// Alignment padding and line-ending differences are not state.
type CollapseSpace struct{}

func (CollapseSpace) Name() string { return "space" }

// Normalise implements Normaliser.
func (CollapseSpace) Normalise(b []byte) []byte {
	out := make([]byte, 0, len(b))
	inRun := false
	for _, c := range b {
		if unicode.IsSpace(rune(c)) {
			inRun = true
			continue
		}
		if inRun && len(out) > 0 {
			out = append(out, ' ')
		}
		inRun = false
		out = append(out, c)
	}
	return out
}

// TruncateAfter keeps only the first n bytes.
//
// For protocols whose reply begins with a fixed header and continues with a
// body: the header is the state, the body is the payload, and a fingerprint over
// both makes every payload a state. Which n is right is protocol-specific, so
// it is configured rather than guessed.
type TruncateAfter struct{ N int }

func (TruncateAfter) Name() string { return "truncate" }

// Normalise implements Normaliser.
func (t TruncateAfter) Normalise(b []byte) []byte {
	if t.N <= 0 || len(b) <= t.N {
		return b
	}
	return b[:t.N]
}

// NormaliserNamed returns the normalisation step a campaign file asked for.
// An unknown name returns nil, which the caller reports against the field.
func NormaliserNamed(name string) Normaliser {
	switch name {
	case "digits":
		return CollapseDigits{}
	case "quoted":
		return CollapseQuoted{}
	case "space":
		return CollapseSpace{}
	default:
		return nil
	}
}
