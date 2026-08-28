package generate

import (
	"fmt"

	"github.com/rom/Xfuzz/pkg/ir"
	"github.com/rom/Xfuzz/pkg/rng"
	"github.com/rom/Xfuzz/pkg/schema"
)

// Generation builds an input from a format description rather than from an
// existing one.
//
// It complements mutation rather than replacing it. Mutation needs a corpus and
// inherits its blind spots: whatever the seeds never contained, mutation is
// unlikely to invent. Generation reaches those regions directly — a chunk type
// no seed used, a nesting depth no seed reached — at the cost of producing
// inputs with none of a real file's accumulated realism. Campaigns run both,
// over the same IR, and the corpus keeps whatever proves interesting.

// Generator produces inputs from a schema.
type Generator struct {
	Schema *schema.Schema

	// MaxDepth bounds recursion. A schema may legitimately recurse through a
	// repeat or an opt, and without a depth bound a lucky sequence of draws
	// produces an input too large to execute.
	MaxDepth int

	// MaxBytes bounds a single generated payload.
	MaxBytes int

	// DefaultRepeatMax is the element count used for a sequence the schema
	// leaves unbounded.
	DefaultRepeatMax int

	// OptionalChance is how often an optional subtree is generated.
	OptionalChance float64

	// Fix recomputes derived values after generation. Leave it on unless the
	// campaign wants deliberately inconsistent inputs.
	Fix bool

	fixer *ir.Fixer
}

// New returns a generator with defaults suited to producing inputs a target
// will actually accept.
func New(s *schema.Schema) *Generator {
	return &Generator{
		Schema:           s,
		MaxDepth:         12,
		MaxBytes:         1 << 16,
		DefaultRepeatMax: 8,
		OptionalChance:   0.5,
		Fix:              true,
		fixer:            ir.NewFixer(),
	}
}

// Generate produces one input.
//
// Nodes come from the arena, so a generator in a fuzz loop allocates nothing in
// steady state once the arena has grown.
func (g *Generator) Generate(a *ir.Arena, r *rng.Rand) (*ir.Node, error) {
	root, ok := g.Schema.Lookup(g.Schema.Root)
	if !ok {
		return nil, fmt.Errorf("generate: schema has no root type %q", g.Schema.Root)
	}
	n, err := g.build(a, r, root, g.Schema.Root, 0)
	if err != nil {
		return nil, err
	}
	if g.Fix {
		if g.fixer == nil {
			g.fixer = ir.NewFixer()
		}
		if _, err := g.fixer.Fix(n, ir.Suppress{}); err != nil {
			return nil, fmt.Errorf("generate: %w", err)
		}
	}
	return n, nil
}

// build produces a node for one schema type.
func (g *Generator) build(a *ir.Arena, r *rng.Rand, t *schema.Type, name string, depth int) (*ir.Node, error) {
	switch t.Kind {
	case schema.KindInt:
		n := a.Alloc(ir.KindInt, name)
		n.Width, n.Endian = t.Width, t.Endian
		n.SetSigned(t.Signed)
		if t.HasLiteral {
			n.Val = t.LiteralInt
		} else {
			n.Val = randomInt(r, t.Width)
		}
		return n, nil

	case schema.KindBytes, schema.KindStr:
		kind := ir.KindBytes
		if t.Kind == schema.KindStr {
			kind = ir.KindStr
		}
		n := a.Alloc(kind, name)
		n.MinLen, n.MaxLen = int32(t.Min), int32(t.Max)
		n.SetImmutable(t.Immutable)
		if t.HasLiteral {
			n.Raw = a.CopyBytes(t.Literal)
			return n, nil
		}
		n.Raw = g.randomPayload(a, r, t)
		return n, nil

	case schema.KindStruct:
		n := a.Alloc(ir.KindStruct, name)
		n.Children = a.AllocKids(len(t.Fields))
		for _, f := range t.Fields {
			kid, err := g.buildField(a, r, f, depth+1)
			if err != nil {
				return nil, err
			}
			n.Children = append(n.Children, kid)
		}
		return n, nil

	case schema.KindRepeat:
		elem, ok := g.Schema.Lookup(t.Elem)
		if !ok {
			return nil, fmt.Errorf("%s: unknown element type %q", t.Pos, t.Elem)
		}
		n := a.Alloc(ir.KindRepeat, name)
		n.MinLen, n.MaxLen = int32(t.Min), int32(t.Max)
		count := g.repeatCount(r, t, depth)
		n.Children = a.AllocKids(count)
		for i := 0; i < count; i++ {
			kid, err := g.build(a, r, elem, t.Elem, depth+1)
			if err != nil {
				return nil, err
			}
			n.Children = append(n.Children, kid)
		}
		return n, nil

	case schema.KindChoice:
		n := a.Alloc(ir.KindChoice, name)
		n.Children = a.AllocKids(len(t.Fields))
		for _, f := range t.Fields {
			kid, err := g.buildField(a, r, f, depth+1)
			if err != nil {
				return nil, err
			}
			n.Children = append(n.Children, kid)
		}
		n.Sel = int32(r.Intn(len(t.Fields)))
		return n, nil

	case schema.KindOpt:
		elem, ok := g.Schema.Lookup(t.Elem)
		if !ok {
			return nil, fmt.Errorf("%s: unknown element type %q", t.Pos, t.Elem)
		}
		n := a.Alloc(ir.KindOpt, name)
		n.Children = a.AllocKids(1)
		kid, err := g.build(a, r, elem, t.Elem, depth+1)
		if err != nil {
			return nil, err
		}
		n.Children = append(n.Children, kid)
		n.SetPresent(depth < g.MaxDepth && r.Chance(g.OptionalChance))
		return n, nil

	case schema.KindRef:
		target, ok := g.Schema.Lookup(t.Target)
		if !ok {
			return nil, fmt.Errorf("%s: unknown type %q", t.Pos, t.Target)
		}
		return g.build(a, r, target, name, depth)
	}
	return nil, fmt.Errorf("%s: cannot generate a %s", t.Pos, t.Kind)
}

// buildField produces a node for a struct member, turning a field with a
// derivation into a derived node.
func (g *Generator) buildField(a *ir.Arena, r *rng.Rand, f schema.Field, depth int) (*ir.Node, error) {
	if f.Derive == nil {
		return g.build(a, r, f.Type, f.Name, depth)
	}
	if f.Type.Kind != schema.KindInt {
		return nil, fmt.Errorf("%s: %q has a derivation but is not an integer field", f.Pos, f.Name)
	}
	n := a.Alloc(ir.KindDerived, f.Name)
	n.Width, n.Endian = f.Type.Width, f.Type.Endian
	n.Derive = f.Derive
	// The value is a placeholder; the fixup pass computes the real one. It is
	// set here so an unfixed tree still encodes to the right width.
	n.Val = 0
	return n, nil
}

// repeatCount chooses how many elements a sequence gets.
func (g *Generator) repeatCount(r *rng.Rand, t *schema.Type, depth int) int {
	lo, hi := t.Min, t.Max
	if hi <= 0 {
		hi = lo + g.DefaultRepeatMax
	}
	if depth >= g.MaxDepth {
		return lo // stop growing, but honour the schema's minimum
	}
	if hi < lo {
		hi = lo
	}
	return r.IntRange(lo, hi)
}

// randomPayload produces bytes for an unconstrained field.
func (g *Generator) randomPayload(a *ir.Arena, r *rng.Rand, t *schema.Type) []byte {
	lo, hi := t.Min, t.Max
	if hi <= 0 {
		hi = lo + 32
	}
	if g.MaxBytes > 0 && hi > g.MaxBytes {
		hi = g.MaxBytes
	}
	if hi < lo {
		hi = lo
	}
	n := r.IntRange(lo, hi)
	if n == 0 {
		return nil
	}
	buf := a.Buf(n)
	if t.Kind == schema.KindStr {
		// Printable ASCII, since a str field is text and random bytes would make
		// most of it invalid before the target ever looks at it.
		for i := range buf {
			buf[i] = byte(r.IntRange(0x20, 0x7e))
		}
		return buf
	}
	r.Fill(buf)
	return buf
}

func randomInt(r *rng.Rand, width uint8) int64 {
	v := int64(r.Uint64())
	if width < 8 {
		v &= int64(1)<<(8*uint(width)) - 1
	}
	return v
}
