package codec

import (
	"bytes"

	"github.com/rom/Xfuzz/pkg/ir"
)

func init() { Register(Session{}) }

// Session splits an input into a sequence of messages.
//
// The codec that makes a seed file a *conversation*. A session is a Repeat node
// whose children are messages (ADR-0005), and this is what produces one: a
// captured exchange, one message per line, decodes into the tree the sequence
// operators and the state scheduler both expect.
//
// Without it a stateful campaign starts from single-message sessions and has to
// discover the handshake by insertion alone — which it can, eventually, and
// which wastes the one thing a person can most easily supply: an example of the
// protocol being spoken correctly.
type Session struct {
	// Delimiter ends a message. Empty means "\n", which is what a line protocol
	// wants and what a captured text session looks like on disk.
	Delimiter []byte
}

// Name implements Codec.
func (Session) Name() string { return "session" }

// Extensions implements Codec.
func (Session) Extensions() []string { return []string{"session", "txt"} }

func (s Session) delim() []byte {
	if len(s.Delimiter) == 0 {
		return []byte("\n")
	}
	return s.Delimiter
}

// Decode implements Codec.
//
// The delimiter stays on the message it ends, so re-encoding is concatenation
// and reproduces the input byte for byte — including a final message with no
// terminator, which is what a truncated capture looks like and which the codec
// must not silently repair. Decode preserves; fixup repairs.
func (s Session) Decode(a *ir.Arena, src []byte) (*ir.Node, error) {
	root := a.Alloc(ir.KindRepeat, "session")
	if len(src) == 0 {
		return root, nil
	}

	d := s.delim()
	rest := src
	for len(rest) > 0 {
		i := bytes.Index(rest, d)
		var msg []byte
		if i < 0 {
			msg, rest = rest, nil
		} else {
			msg, rest = rest[:i+len(d)], rest[i+len(d):]
		}
		n := a.Alloc(ir.KindBytes, "message")
		n.Raw = msg
		root.Children = append(root.Children, n)
	}
	return root, nil
}
