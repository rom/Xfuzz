package schema

import (
	"fmt"

	"github.com/rom/Xfuzz/pkg/ir"
)

// intTypes maps the scalar type names to their shape. Names are explicit about
// width and byte order because a format's fields are, and leaving either
// implicit is how a schema silently describes the wrong layout.
var intTypes = map[string]struct {
	width  uint8
	endian ir.Endian
	signed bool
}{
	"u8":    {1, ir.BigEndian, false},
	"i8":    {1, ir.BigEndian, true},
	"u16be": {2, ir.BigEndian, false},
	"u16le": {2, ir.LittleEndian, false},
	"i16be": {2, ir.BigEndian, true},
	"i16le": {2, ir.LittleEndian, true},
	"u32be": {4, ir.BigEndian, false},
	"u32le": {4, ir.LittleEndian, false},
	"i32be": {4, ir.BigEndian, true},
	"i32le": {4, ir.LittleEndian, true},
	"u64be": {8, ir.BigEndian, false},
	"u64le": {8, ir.LittleEndian, false},
	"i64be": {8, ir.BigEndian, true},
	"i64le": {8, ir.LittleEndian, true},
}

// IntTypeNames lists the scalar type names the language accepts.
func IntTypeNames() []string {
	out := make([]string, 0, len(intTypes))
	for n := range intTypes {
		out = append(out, n)
	}
	return out
}

func fits(v, minimum, maximum int) bool {
	if v < minimum {
		return false
	}
	return maximum <= 0 || v <= maximum
}

// typeExpr parses a field's type.
func (p *parser) typeExpr() (*Type, error) {
	pos := p.tok.pos
	if p.tok.kind != tokIdent {
		return nil, fmt.Errorf("%s: expected a type, got %s", pos, p.tok)
	}
	word := p.tok.text

	if spec, ok := intTypes[word]; ok {
		if err := p.advance(); err != nil {
			return nil, err
		}
		return &Type{
			Kind: KindInt, Width: spec.width, Endian: spec.endian,
			Signed: spec.signed, Pos: pos,
		}, nil
	}

	switch word {
	case "bytes", "str":
		if err := p.advance(); err != nil {
			return nil, err
		}
		kind := KindBytes
		if word == "str" {
			kind = KindStr
		}
		t := &Type{Kind: kind, Pos: pos}
		var err error
		if t.Min, t.Max, err = p.sizeSuffix(); err != nil {
			return nil, err
		}
		return t, nil

	case "magic":
		if err := p.advance(); err != nil {
			return nil, err
		}
		if p.tok.kind != tokString {
			return nil, fmt.Errorf("%s: magic needs a string literal, got %s", p.tok.pos, p.tok)
		}
		lit := p.tok.str
		if err := p.advance(); err != nil {
			return nil, err
		}
		// Fixed length and off-limits to mutation: a signature a target compares
		// byte for byte is not worth spending executions on.
		return &Type{
			Kind: KindBytes, Pos: pos, Literal: lit, HasLiteral: true,
			Min: len(lit), Max: len(lit), Immutable: true,
		}, nil

	case "repeat":
		if err := p.advance(); err != nil {
			return nil, err
		}
		t := &Type{Kind: KindRepeat, Pos: pos}
		var err error
		if t.Min, t.Max, err = p.sizeSuffix(); err != nil {
			return nil, err
		}
		if t.Elem, err = p.ident(); err != nil {
			return nil, err
		}
		return t, nil

	case "opt":
		if err := p.advance(); err != nil {
			return nil, err
		}
		elem, err := p.ident()
		if err != nil {
			return nil, err
		}
		return &Type{Kind: KindOpt, Elem: elem, Pos: pos}, nil

	case "choice":
		if err := p.advance(); err != nil {
			return nil, err
		}
		if err := p.expect("{"); err != nil {
			return nil, err
		}
		t := &Type{Kind: KindChoice, Pos: pos}
		for !p.at("}") {
			if p.tok.kind == tokEOF {
				return nil, fmt.Errorf("%s: unterminated choice", pos)
			}
			fpos := p.tok.pos
			name, err := p.ident()
			if err != nil {
				return nil, err
			}
			if err := p.expect(":"); err != nil {
				return nil, err
			}
			at, err := p.typeExpr()
			if err != nil {
				return nil, err
			}
			t.Fields = append(t.Fields, Field{Name: name, Type: at, Pos: fpos})
			if p.at(",") {
				if err := p.advance(); err != nil {
					return nil, err
				}
			}
		}
		if len(t.Fields) == 0 {
			return nil, fmt.Errorf("%s: a choice needs at least one alternative", pos)
		}
		return t, p.expect("}")
	}

	// Anything else names a declared type.
	name, err := p.ident()
	if err != nil {
		return nil, err
	}
	return &Type{Kind: KindRef, Target: name, Pos: pos}, nil
}

// sizeSuffix parses an optional [N] or <min..max> after a type.
func (p *parser) sizeSuffix() (minimum, maximum int, err error) {
	switch {
	case p.at("["):
		if err = p.advance(); err != nil {
			return
		}
		if p.tok.kind != tokNumber {
			return 0, 0, fmt.Errorf("%s: expected a size, got %s", p.tok.pos, p.tok)
		}
		n := int(p.tok.num)
		if n < 0 {
			return 0, 0, fmt.Errorf("%s: size cannot be negative", p.tok.pos)
		}
		if err = p.advance(); err != nil {
			return
		}
		return n, n, p.expect("]")

	case p.at("<"):
		if err = p.advance(); err != nil {
			return
		}
		if p.tok.kind != tokNumber {
			return 0, 0, fmt.Errorf("%s: expected a lower bound, got %s", p.tok.pos, p.tok)
		}
		lo := int(p.tok.num)
		if err = p.advance(); err != nil {
			return
		}
		if err = p.expect(".."); err != nil {
			return
		}
		if p.tok.kind != tokNumber {
			return 0, 0, fmt.Errorf("%s: expected an upper bound, got %s", p.tok.pos, p.tok)
		}
		hi := int(p.tok.num)
		if err = p.advance(); err != nil {
			return
		}
		if hi < lo {
			return 0, 0, fmt.Errorf("%s: upper bound %d is below lower bound %d", p.tok.pos, hi, lo)
		}
		return lo, hi, p.expect(">")
	}
	return 0, 0, nil
}
