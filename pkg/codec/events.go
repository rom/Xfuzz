package codec

import (
	"bytes"

	"github.com/rom/Xfuzz/pkg/ir"
)

func init() { Register(Events{}) }

// Events is the codec for a sequence of interaction events, which is what the
// T7 driver tier takes as an input (ADR-0013).
//
// One line, one event, one child of a Repeat. That is the whole of it, and the
// reason it exists is the same reason the session codec does: without a codec
// the input is one opaque blob, and the sequence operators — insert, delete,
// reorder, duplicate — apply to a Repeat. A mutator working on the bytes
// reorders *characters*, and a sequence of interactions cut in half mid-word is
// not an interaction at all.
//
// The event grammar itself lives in pkg/executor, which is where the events are
// delivered; a line this codec does not understand is still a line, and the
// driver reads it as literal text. Splitting is deliberately dumber than
// parsing, because the codec's contract is that re-encoding reproduces the
// source byte for byte, and a parser that normalised "key  enter" to "key enter"
// would break it.
type Events struct{}

// Name implements Codec.
func (Events) Name() string { return "events" }

// Extensions implements Codec.
//
// .events for a file somebody wrote by hand, and .txt because a sequence of
// keystrokes saved out of a terminal is a text file and nothing else.
func (Events) Extensions() []string { return []string{".events", ".txt"} }

// MaxEventLines bounds how many lines are lifted into the tree.
//
// A corpus entry is a sequence of interactions and the tier will not deliver
// more than a few hundred of them, so a file with a hundred thousand lines is
// not a longer sequence — it is a text file that landed in the corpus, and
// building a hundred thousand nodes for it costs more than reading it.
const MaxEventLines = 4096

// Decode implements Codec.
func (Events) Decode(a *ir.Arena, src []byte) (*ir.Node, error) {
	root := a.Alloc(ir.KindRepeat, "events")
	if len(src) == 0 {
		return root, nil
	}

	rest := src
	for len(rest) > 0 && len(root.Children) < MaxEventLines {
		line := rest
		if i := bytes.IndexByte(rest, '\n'); i >= 0 {
			// The newline travels with the line it terminates, so removing an
			// event removes its separator too and the rest of the sequence
			// still reads as one event per line.
			line, rest = rest[:i+1], rest[i+1:]
		} else {
			rest = nil
		}
		n := a.Alloc(ir.KindBytes, "event")
		n.Raw = line
		root.Children = append(root.Children, n)
	}
	if len(rest) > 0 {
		// Everything past the limit in one node, so the encoding still
		// reproduces the source exactly.
		n := a.Alloc(ir.KindBytes, OpaqueName)
		n.Raw = rest
		root.Children = append(root.Children, n)
	}
	return root, nil
}
