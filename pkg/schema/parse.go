package schema

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"unicode"

	"github.com/rom/Xfuzz/pkg/ir"
)

// The .xfg grammar language.
//
// A format description has to be writable by someone who knows the format and
// not the fuzzer. That rules out expressing schemas as Go code — which needs a
// rebuild — and it rules out a general-purpose configuration language, where
// "this field is the CRC of those two" becomes three levels of nesting. So the
// syntax says the things formats actually say:
//
//	format png {
//	  signature: magic "\x89PNG\r\n\x1a\n"
//	  chunks:    repeat<1..1024> chunk
//	}
//
//	struct chunk {
//	  length: u32be = len(^data)
//	  type:   bytes[4] = "IDAT"
//	  data:   bytes<0..65536>
//	  crc:    u32be = crc32(^type..^data)
//	}

type tokenKind uint8

const (
	tokEOF tokenKind = iota
	tokIdent
	tokNumber
	tokString
	tokPunct
)

type token struct {
	kind tokenKind
	text string
	num  int64
	str  []byte
	pos  Position
}

func (t token) String() string {
	switch t.kind {
	case tokEOF:
		return "end of file"
	case tokString:
		return "string " + quote(t.str)
	case tokNumber:
		return "number " + strconv.FormatInt(t.num, 10)
	}
	return strconv.Quote(t.text)
}

type lexer struct {
	src  []byte
	file string
	pos  int
	line int
	col  int
}

func newLexer(src []byte, file string) *lexer {
	return &lexer{src: src, file: file, line: 1, col: 1}
}

func (l *lexer) here() Position { return Position{File: l.file, Line: l.line, Col: l.col} }

func (l *lexer) advance() byte {
	c := l.src[l.pos]
	l.pos++
	if c == '\n' {
		l.line++
		l.col = 1
	} else {
		l.col++
	}
	return c
}

func (l *lexer) next() (token, error) {
	for l.pos < len(l.src) {
		c := l.src[l.pos]
		switch {
		case c == ' ' || c == '\t' || c == '\r' || c == '\n':
			l.advance()
		case c == '#':
			for l.pos < len(l.src) && l.src[l.pos] != '\n' {
				l.advance()
			}
		case c == '/' && l.pos+1 < len(l.src) && l.src[l.pos+1] == '/':
			for l.pos < len(l.src) && l.src[l.pos] != '\n' {
				l.advance()
			}
		default:
			goto scan
		}
	}
	return token{kind: tokEOF, pos: l.here()}, nil

scan:
	pos := l.here()
	c := l.src[l.pos]

	switch {
	case isIdentStart(c):
		start := l.pos
		for l.pos < len(l.src) && isIdentPart(l.src[l.pos]) {
			l.advance()
		}
		return token{kind: tokIdent, text: string(l.src[start:l.pos]), pos: pos}, nil

	case c >= '0' && c <= '9':
		start := l.pos
		for l.pos < len(l.src) && isNumberPart(l.src[l.pos]) {
			l.advance()
		}
		text := string(l.src[start:l.pos])
		v, err := strconv.ParseInt(text, 0, 64)
		if err != nil {
			// Try unsigned, so 0xFFFFFFFF is usable in a u32 field.
			u, uerr := strconv.ParseUint(text, 0, 64)
			if uerr != nil {
				return token{}, fmt.Errorf("%s: %q is not a number", pos, text)
			}
			v = int64(u)
		}
		return token{kind: tokNumber, text: text, num: v, pos: pos}, nil

	case c == '"':
		l.advance()
		var out []byte
		for {
			if l.pos >= len(l.src) {
				return token{}, fmt.Errorf("%s: unterminated string", pos)
			}
			ch := l.advance()
			if ch == '"' {
				break
			}
			if ch != '\\' {
				out = append(out, ch)
				continue
			}
			if l.pos >= len(l.src) {
				return token{}, fmt.Errorf("%s: string ends with a backslash", pos)
			}
			esc := l.advance()
			switch esc {
			case 'n':
				out = append(out, '\n')
			case 'r':
				out = append(out, '\r')
			case 't':
				out = append(out, '\t')
			case '0':
				out = append(out, 0)
			case '\\':
				out = append(out, '\\')
			case '"':
				out = append(out, '"')
			case 'x':
				if l.pos+1 >= len(l.src) {
					return token{}, fmt.Errorf(`%s: \x needs two hex digits`, pos)
				}
				hi, lo := l.advance(), l.advance()
				v, err := strconv.ParseUint(string([]byte{hi, lo}), 16, 8)
				if err != nil {
					return token{}, fmt.Errorf(`%s: bad \x escape "%c%c"`, pos, hi, lo)
				}
				out = append(out, byte(v))
			default:
				return token{}, fmt.Errorf("%s: unknown escape \\%c", pos, esc)
			}
		}
		return token{kind: tokString, str: out, pos: pos}, nil
	}

	// Punctuation, longest match first so ".." beats ".".
	for _, p := range []string{"..", "{", "}", "[", "]", "<", ">", "(", ")", ":", "=", ",", ".", "^", "/", "+", "-"} {
		if strings.HasPrefix(string(l.src[l.pos:]), p) {
			for range p {
				l.advance()
			}
			return token{kind: tokPunct, text: p, pos: pos}, nil
		}
	}
	return token{}, fmt.Errorf("%s: unexpected character %q", pos, string(c))
}

func isIdentStart(c byte) bool {
	return c == '_' || unicode.IsLetter(rune(c))
}

func isIdentPart(c byte) bool {
	return isIdentStart(c) || (c >= '0' && c <= '9')
}

func isNumberPart(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F' ||
		c == 'x' || c == 'X'
}

type parser struct {
	lex  *lexer
	tok  token
	peek token
	file string
}

// Parse reads a .xfg source file.
func Parse(src []byte, file string) (*Schema, error) {
	p := &parser{lex: newLexer(src, file), file: file}
	if err := p.fill(); err != nil {
		return nil, err
	}
	s := &Schema{Types: map[string]*Type{}, File: file}

	for p.tok.kind != tokEOF {
		keyword := p.tok.text
		if p.tok.kind != tokIdent || (keyword != "format" && keyword != "struct") {
			return nil, fmt.Errorf("%s: expected 'format' or 'struct', got %s", p.tok.pos, p.tok)
		}
		pos := p.tok.pos
		if err := p.advance(); err != nil {
			return nil, err
		}
		name, err := p.ident()
		if err != nil {
			return nil, err
		}
		if _, dup := s.Types[name]; dup {
			return nil, fmt.Errorf("%s: %q is declared more than once", pos, name)
		}
		t, err := p.structBody(pos)
		if err != nil {
			return nil, err
		}
		s.Types[name] = t

		if keyword == "format" {
			if s.Root != "" {
				return nil, fmt.Errorf("%s: a second format declaration (%q); there must be exactly one", pos, name)
			}
			s.Root = name
		}
	}

	if err := s.Validate(); err != nil {
		return nil, err
	}
	return s, nil
}

// ParseFile reads a .xfg file from disk.
func ParseFile(path string) (*Schema, error) {
	src, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("schema: %w", err)
	}
	return Parse(src, path)
}

func (p *parser) fill() error {
	t, err := p.lex.next()
	if err != nil {
		return err
	}
	p.tok = t
	t, err = p.lex.next()
	if err != nil {
		return err
	}
	p.peek = t
	return nil
}

func (p *parser) advance() error {
	p.tok = p.peek
	t, err := p.lex.next()
	if err != nil {
		return err
	}
	p.peek = t
	return nil
}

func (p *parser) ident() (string, error) {
	if p.tok.kind != tokIdent {
		return "", fmt.Errorf("%s: expected a name, got %s", p.tok.pos, p.tok)
	}
	name := p.tok.text
	return name, p.advance()
}

func (p *parser) expect(punct string) error {
	if p.tok.kind != tokPunct || p.tok.text != punct {
		return fmt.Errorf("%s: expected %q, got %s", p.tok.pos, punct, p.tok)
	}
	return p.advance()
}

func (p *parser) at(punct string) bool {
	return p.tok.kind == tokPunct && p.tok.text == punct
}

func (p *parser) atIdent(word string) bool {
	return p.tok.kind == tokIdent && p.tok.text == word
}

func (p *parser) structBody(pos Position) (*Type, error) {
	if err := p.expect("{"); err != nil {
		return nil, err
	}
	t := &Type{Kind: KindStruct, Pos: pos}
	for !p.at("}") {
		if p.tok.kind == tokEOF {
			return nil, fmt.Errorf("%s: unterminated declaration", pos)
		}
		f, err := p.field()
		if err != nil {
			return nil, err
		}
		t.Fields = append(t.Fields, f)
	}
	return t, p.expect("}")
}

func (p *parser) field() (Field, error) {
	pos := p.tok.pos
	name, err := p.ident()
	if err != nil {
		return Field{}, err
	}
	if err := p.expect(":"); err != nil {
		return Field{}, err
	}
	ft, err := p.typeExpr()
	if err != nil {
		return Field{}, err
	}
	f := Field{Name: name, Type: ft, Pos: pos}

	if p.at("=") {
		if err := p.advance(); err != nil {
			return Field{}, err
		}
		if err := p.assignment(&f); err != nil {
			return Field{}, err
		}
	}
	return f, nil
}

// assignment parses what follows '=': either a literal value or a derivation.
func (p *parser) assignment(f *Field) error {
	switch {
	case p.tok.kind == tokString:
		f.Type.Literal = p.tok.str
		f.Type.HasLiteral = true
		if f.Type.Kind == KindBytes || f.Type.Kind == KindStr {
			if f.Type.Max == 0 && f.Type.Min == 0 {
				f.Type.Min, f.Type.Max = len(p.tok.str), len(p.tok.str)
			}
			if !fits(len(p.tok.str), f.Type.Min, f.Type.Max) {
				return fmt.Errorf("%s: literal is %d bytes, outside the declared bounds",
					p.tok.pos, len(p.tok.str))
			}
		}
		return p.advance()

	case p.tok.kind == tokNumber:
		f.Type.LiteralInt = p.tok.num
		f.Type.HasLiteral = true
		return p.advance()

	case p.tok.kind == tokIdent:
		return p.derivation(f)
	}
	return fmt.Errorf("%s: expected a literal or a derivation, got %s", p.tok.pos, p.tok)
}

// derivation parses len(...), count(...), offset(...), or a checksum call.
func (p *parser) derivation(f *Field) error {
	pos := p.tok.pos
	name, err := p.ident()
	if err != nil {
		return err
	}
	d := &ir.Derivation{}
	switch name {
	case "len":
		d.Kind = ir.DeriveLength
	case "count":
		d.Kind = ir.DeriveCount
	case "offset":
		d.Kind = ir.DeriveOffset
	default:
		if _, ok := ir.Checksum(name); !ok {
			return fmt.Errorf("%s: unknown derivation %q; expected len, count, offset, or a checksum algorithm (%s)",
				pos, name, strings.Join(ir.ChecksumNames(), ", "))
		}
		d.Kind = ir.DeriveChecksum
		d.Algo = name
	}

	if err := p.expect("("); err != nil {
		return err
	}
	from, err := p.ref()
	if err != nil {
		return err
	}
	d.From = from
	if p.at("..") {
		if err := p.advance(); err != nil {
			return err
		}
		to, err := p.ref()
		if err != nil {
			return err
		}
		d.To = to
	}
	if err := p.expect(")"); err != nil {
		return err
	}

	// An optional addend, for fields defined as "length including the header".
	if p.at("+") || p.at("-") {
		neg := p.at("-")
		if err := p.advance(); err != nil {
			return err
		}
		if p.tok.kind != tokNumber {
			return fmt.Errorf("%s: expected a number after the sign, got %s", p.tok.pos, p.tok)
		}
		d.Addend = p.tok.num
		if neg {
			d.Addend = -d.Addend
		}
		if err := p.advance(); err != nil {
			return err
		}
	}

	if p.atIdent("selfzero") {
		d.SelfZero = true
		if err := p.advance(); err != nil {
			return err
		}
	}

	f.Derive = d
	return nil
}

// ref parses a reference: ^sibling, ^^grandparent.field, /absolute[0].path
func (p *parser) ref() (ir.Ref, error) {
	pos := p.tok.pos
	var r ir.Ref
	switch {
	case p.at("^"):
		up := 0
		for p.at("^") {
			if err := p.advance(); err != nil {
				return r, err
			}
			up++
		}
		r.Up = up - 1
	case p.at("/"):
		r.Absolute = true
		if err := p.advance(); err != nil {
			return r, err
		}
	case p.at("."):
		if err := p.advance(); err != nil {
			return r, err
		}
		return ir.Ref{Self: true}, nil
	default:
		return r, fmt.Errorf("%s: a reference must start with '^', '/' or '.', got %s", pos, p.tok)
	}

	for {
		switch {
		case p.tok.kind == tokIdent:
			r.Steps = append(r.Steps, ir.Named(p.tok.text))
			if err := p.advance(); err != nil {
				return r, err
			}
		case p.at("["):
			if err := p.advance(); err != nil {
				return r, err
			}
			if p.tok.kind != tokNumber {
				return r, fmt.Errorf("%s: expected an index, got %s", p.tok.pos, p.tok)
			}
			r.Steps = append(r.Steps, ir.At(int(p.tok.num)))
			if err := p.advance(); err != nil {
				return r, err
			}
			if err := p.expect("]"); err != nil {
				return r, err
			}
		case p.at("."):
			if err := p.advance(); err != nil {
				return r, err
			}
			continue
		default:
			if len(r.Steps) == 0 && !r.Absolute && r.Up >= 0 {
				return r, nil // '^' alone means the parent
			}
			return r, nil
		}
		if !p.at(".") && !p.at("[") {
			return r, nil
		}
	}
}
