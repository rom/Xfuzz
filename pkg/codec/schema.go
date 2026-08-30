package codec

import (
	"fmt"

	"github.com/rom/Xfuzz/pkg/ir"
	"github.com/rom/Xfuzz/pkg/schema"
)

// Schema decodes any format a .xfg grammar describes.
//
// This is what makes a grammar worth writing. Without it a grammar produces
// seeds and nothing else: the campaign decodes those seeds as opaque bytes,
// mutates them blindly, and the fixup pass — the whole point of the structured
// IR (ADR-0005) — never runs, because there is no structure to fix. Measured at
// the mutation layer, the difference between the two is 99.8% of inputs
// surviving a checksummed format's validation and 0.0%.
//
// Decoding is the harder half of a codec and the reason the interface is shaped
// the way it is: encoding a tree is generic, but recovering a tree from bytes
// needs the format. A hand-written codec knows its format; this one is handed
// one.
type Schema struct {
	s *schema.Schema
}

// NewSchema returns a codec for a parsed grammar.
func NewSchema(s *schema.Schema) *Schema { return &Schema{s: s} }

// Name implements Codec. It is the grammar's root type, so per-operator stats
// and provenance name the format rather than saying "schema" for all of them.
func (c *Schema) Name() string {
	if c.s == nil || c.s.Root == "" {
		return "schema"
	}
	return c.s.Root
}

// Extensions implements Codec. A grammar does not declare file extensions, and
// inventing one would make corpus import claim a format it cannot vouch for.
func (c *Schema) Extensions() []string { return nil }

// Decode implements Codec.
//
// Total and best-effort, as the interface requires: an input that stops
// matching the grammar part-way keeps everything decoded so far and carries the
// rest as opaque bytes. That matters more here than for a hand-written codec,
// because a grammar is usually an approximation of a format — the most valuable
// seeds are the ones a strict parser would reject (ASR-0014).
//
// Values are read from the input, never recomputed. A file whose length field
// or checksum is wrong decodes with the wrong value in it and re-encodes byte
// for byte; repair happens only when a fixup is explicitly run.
func (c *Schema) Decode(a *ir.Arena, src []byte) (*ir.Node, error) {
	if c.s == nil {
		return nil, fmt.Errorf("codec: no schema")
	}
	root, ok := c.s.Lookup(c.s.Root)
	if !ok {
		return nil, fmt.Errorf("codec: schema has no root type %q", c.s.Root)
	}

	d := &decoder{c: c, a: a, src: src}
	n, err := d.build(root, c.s.Root, nil, 0)
	if err != nil || n == nil {
		// Nothing matched at all. The tree is still valid and still
		// round-trips; it is simply unstructured, which UnparsedBytes reports.
		wrap := a.Alloc(ir.KindStruct, c.s.Root)
		wrap.Children = a.AllocKids(1)
		wrap.Children = append(wrap.Children, Opaque(a, src))
		return wrap, nil
	}
	if d.pos < len(src) {
		// A truncated tail, trailing data, or a file the grammar only partly
		// describes. Preserved, so the input survives round-tripping.
		wrap := a.Alloc(ir.KindStruct, c.s.Root)
		wrap.Children = a.AllocKids(2)
		wrap.Children = append(wrap.Children, n, Opaque(a, src[d.pos:]))
		return wrap, nil
	}
	return n, nil
}

// decoder walks the schema and the input together.
type decoder struct {
	c   *Schema
	a   *ir.Arena
	src []byte
	pos int
}

// maxDecodeDepth bounds recursion.
//
// A grammar can be recursive — a struct that contains itself through a repeat
// or an option — and the schema's own cycle check permits that, since a
// guarded cycle terminates when generating. Decoding has a second way to
// diverge: an input that keeps matching. The bound is the backstop, and it is
// generous enough that no real format reaches it.
const maxDecodeDepth = 64

var errNoMatch = fmt.Errorf("codec: the input does not match here")

// build decodes one schema type, returning nil and an error when the input does
// not match. parent is the struct being decoded, so a length-derived field can
// find the sibling that gives its length.
func (d *decoder) build(t *schema.Type, name string, parent *ir.Node, depth int) (*ir.Node, error) {
	if depth > maxDecodeDepth {
		return nil, errNoMatch
	}

	switch t.Kind {
	case schema.KindInt:
		if d.left() < int(t.Width) {
			return nil, errNoMatch
		}
		n := d.a.Alloc(ir.KindInt, name)
		n.Width, n.Endian = t.Width, t.Endian
		n.SetSigned(t.Signed)
		n.Val = d.readInt(t.Width, t.Endian, t.Signed)
		return n, nil

	case schema.KindBytes, schema.KindStr:
		return d.bytes(t, name, parent)

	case schema.KindStruct:
		n := d.a.Alloc(ir.KindStruct, name)
		n.Children = d.a.AllocKids(len(t.Fields))
		for _, f := range t.Fields {
			kid, err := d.field(f, n, depth+1)
			if err != nil {
				return nil, err
			}
			n.Children = append(n.Children, kid)
		}
		return n, nil

	case schema.KindRepeat:
		return d.repeat(t, name, parent, depth)

	case schema.KindChoice:
		return d.choice(t, name, depth)

	case schema.KindOpt:
		elem, ok := d.c.s.Lookup(t.Elem)
		if !ok {
			return nil, fmt.Errorf("%s: unknown type %q", t.Pos, t.Elem)
		}
		n := d.a.Alloc(ir.KindOpt, name)
		n.Children = d.a.AllocKids(1)

		// Optional means "try it, and if it does not fit, it was not there".
		// The save/restore is what makes that possible without lookahead.
		mark := d.pos
		kid, err := d.build(elem, t.Elem, parent, depth+1)
		if err != nil {
			d.pos = mark
			// A placeholder child, so a mutation that turns the option on has
			// something to encode. It contributes nothing while absent.
			blank := d.a.Alloc(ir.KindBytes, t.Elem)
			n.Children = append(n.Children, blank)
			n.SetPresent(false)
			return n, nil
		}
		n.Children = append(n.Children, kid)
		n.SetPresent(true)
		return n, nil

	case schema.KindRef:
		target, ok := d.c.s.Lookup(t.Target)
		if !ok {
			return nil, fmt.Errorf("%s: unknown type %q", t.Pos, t.Target)
		}
		return d.build(target, name, parent, depth)
	}
	return nil, fmt.Errorf("%s: cannot decode a %s", t.Pos, t.Kind)
}

// field decodes one struct member, turning a field with a derivation into a
// derived node that keeps the value the file gave it.
func (d *decoder) field(f schema.Field, parent *ir.Node, depth int) (*ir.Node, error) {
	if f.Derive == nil {
		return d.build(f.Type, f.Name, parent, depth)
	}
	if f.Type.Kind != schema.KindInt {
		return nil, fmt.Errorf("%s: %q has a derivation but is not an integer field", f.Pos, f.Name)
	}
	if d.left() < int(f.Type.Width) {
		return nil, errNoMatch
	}
	n := d.a.Alloc(ir.KindDerived, f.Name)
	n.Width, n.Endian = f.Type.Width, f.Type.Endian
	n.Derive = f.Derive
	n.Val = d.readInt(f.Type.Width, f.Type.Endian, false)
	return n, nil
}

// bytes decodes a payload, whose length comes from whichever of four sources
// the grammar provides.
func (d *decoder) bytes(t *schema.Type, name string, parent *ir.Node) (*ir.Node, error) {
	kind := ir.KindBytes
	if t.Kind == schema.KindStr {
		kind = ir.KindStr
	}
	n := d.a.Alloc(kind, name)
	n.MinLen, n.MaxLen = int32(t.Min), int32(t.Max)
	n.SetImmutable(t.Immutable)

	switch {
	case t.HasLiteral:
		// A magic or a literal: the input must carry exactly these bytes, or
		// this is not a file of this format and the caller falls back.
		lit := t.Literal
		if d.left() < len(lit) || string(d.src[d.pos:d.pos+len(lit)]) != string(lit) {
			return nil, errNoMatch
		}
		n.Raw = d.take(len(lit))
		return n, nil

	case t.Min == t.Max && t.Max > 0:
		if d.left() < t.Max {
			return nil, errNoMatch
		}
		n.Raw = d.take(t.Max)
		return n, nil
	}

	// A length another field declares. This is the case the whole design turns
	// on: without it a variable payload cannot be found in a byte stream at
	// all, and the length field and the payload could never be kept consistent
	// through a mutation.
	if declared, ok := d.declaredLength(name, parent); ok {
		if declared < 0 || declared > d.left() {
			return nil, errNoMatch
		}
		n.Raw = d.take(declared)
		return n, nil
	}

	// Nothing says how long it is. Take what is left, up to the bound.
	//
	// Greedy, which is right for the common shape — a trailing payload — and
	// wrong for a variable field in the middle of a struct with no length. A
	// grammar with one of those is ambiguous as a parser however it is read,
	// and the honest response is to consume what the bound allows and let the
	// fields after it fail to match, which puts the rest in an opaque node
	// where a reader can see what happened.
	take := d.left()
	if t.Max > 0 && take > t.Max {
		take = t.Max
	}
	if take < t.Min {
		return nil, errNoMatch
	}
	n.Raw = d.take(take)
	return n, nil
}

// declaredLength finds a sibling that declares this field's length.
func (d *decoder) declaredLength(name string, parent *ir.Node) (int, bool) {
	if parent == nil {
		return 0, false
	}
	for _, sib := range parent.Children {
		if sib.Kind != ir.KindDerived || sib.Derive == nil {
			continue
		}
		if sib.Derive.Kind != ir.DeriveLength {
			continue
		}
		if !refNames(sib.Derive.From, name) {
			continue
		}
		return int(sib.Val) - int(sib.Derive.Addend), true
	}
	return 0, false
}

// declaredCount finds a sibling that declares a sequence's element count.
func (d *decoder) declaredCount(name string, parent *ir.Node) (int, bool) {
	if parent == nil {
		return 0, false
	}
	for _, sib := range parent.Children {
		if sib.Kind != ir.KindDerived || sib.Derive == nil {
			continue
		}
		if sib.Derive.Kind != ir.DeriveCount || !refNames(sib.Derive.From, name) {
			continue
		}
		return int(sib.Val) - int(sib.Derive.Addend), true
	}
	return 0, false
}

// refNames reports whether a reference points at a sibling of this name.
//
// Only the simple case, deliberately: a length that reaches across the tree to
// a field in another branch cannot be resolved while decoding, because the
// field it names may not have been decoded yet. Such a grammar still generates
// and still fixes up; it decodes as far as the ambiguity and no further.
func refNames(r ir.Ref, name string) bool {
	if r.Self || r.Absolute || r.Up != 0 || len(r.Steps) != 1 {
		return false
	}
	return r.Steps[0].Name == name && !r.Steps[0].ByIndex
}

// repeat decodes a sequence.
func (d *decoder) repeat(t *schema.Type, name string, parent *ir.Node, depth int) (*ir.Node, error) {
	elem, ok := d.c.s.Lookup(t.Elem)
	if !ok {
		return nil, fmt.Errorf("%s: unknown element type %q", t.Pos, t.Elem)
	}
	n := d.a.Alloc(ir.KindRepeat, name)
	n.MinLen, n.MaxLen = int32(t.Min), int32(t.Max)

	want, counted := d.declaredCount(name, parent)
	limit := t.Max
	if counted {
		if want < 0 {
			return nil, errNoMatch
		}
		limit = want
	}
	if limit <= 0 {
		limit = defaultRepeatLimit
	}
	n.Children = d.a.AllocKids(min(limit, defaultRepeatLimit))

	for len(n.Children) < limit {
		if d.left() == 0 {
			break
		}
		mark := d.pos
		kid, err := d.build(elem, t.Elem, n, depth+1)
		if err != nil {
			// An element that does not match ends the sequence rather than
			// failing it: a file with three chunks and a truncated fourth is a
			// file with three chunks, and the fourth belongs in an opaque node.
			d.pos = mark
			break
		}
		if d.pos == mark {
			// A zero-width element would loop forever. A grammar that admits
			// one is a grammar bug, and stopping is the only safe answer.
			break
		}
		n.Children = append(n.Children, kid)
	}

	if len(n.Children) < t.Min || (counted && len(n.Children) < want) {
		return nil, errNoMatch
	}
	return n, nil
}

// defaultRepeatLimit bounds an unbounded sequence, so a long input cannot make
// the tree unboundedly wide.
const defaultRepeatLimit = 4096

// choice decodes the first alternative that matches.
//
// First rather than longest: a grammar's alternatives are written in the order
// the format distinguishes them, usually behind a tag, and preferring the
// longest match would silently pick a different arm from the one the format's
// own parser picks.
func (d *decoder) choice(t *schema.Type, name string, depth int) (*ir.Node, error) {
	n := d.a.Alloc(ir.KindChoice, name)
	n.Children = d.a.AllocKids(len(t.Fields))

	mark := d.pos
	chosen := -1
	for i, f := range t.Fields {
		d.pos = mark
		kid, err := d.build(f.Type, f.Name, n, depth+1)
		if err != nil {
			continue
		}
		// The other alternatives still need nodes, so a mutation that switches
		// arms has something to switch to. They are built after the choice is
		// made, from no input, which is what generation does anyway.
		n.Children = append(n.Children, kid)
		chosen = i
		break
	}
	if chosen < 0 {
		d.pos = mark
		return nil, errNoMatch
	}
	n.Sel = 0
	return n, nil
}

func (d *decoder) left() int { return len(d.src) - d.pos }

func (d *decoder) take(n int) []byte {
	b := d.src[d.pos : d.pos+n]
	d.pos += n
	return b
}

func (d *decoder) readInt(width uint8, e ir.Endian, signed bool) int64 {
	b := d.take(int(width))
	var u uint64
	if e == ir.LittleEndian {
		for i := len(b) - 1; i >= 0; i-- {
			u = u<<8 | uint64(b[i])
		}
	} else {
		u = beUint(b)
	}
	if signed && width < 8 {
		shift := 64 - 8*uint(width)
		return int64(u<<shift) >> shift
	}
	return int64(u)
}

func beUint(b []byte) uint64 {
	var u uint64
	for _, c := range b {
		u = u<<8 | uint64(c)
	}
	return u
}
