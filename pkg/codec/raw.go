package codec

import "github.com/rom/Xfuzz/pkg/ir"

func init() { Register(Raw{}) }

// Raw is the degenerate codec: the whole input is one Bytes node.
//
// It exists so that unstructured targets need no special handling anywhere else
// in the engine. Byte-level fuzzing is structured fuzzing with a one-node tree,
// not a separate path through the corpus, the mutators, or the scheduler.
type Raw struct{}

// Name implements Codec.
func (Raw) Name() string { return "raw" }

// Extensions implements Codec.
func (Raw) Extensions() []string { return []string{"bin", "dat"} }

// Decode implements Codec. It never fails and never leaves anything unparsed:
// the input is exactly one opaque-free byte node.
func (Raw) Decode(a *ir.Arena, src []byte) (*ir.Node, error) {
	n := a.Alloc(ir.KindBytes, "data")
	n.Raw = src
	return n, nil
}
