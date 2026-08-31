package schemaio

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/rom/Xfuzz/pkg/ir"
	"github.com/rom/Xfuzz/pkg/schema"
)

// ASN1 imports an ASN.1 module as a grammar for its DER encoding.
//
// DER, because that is what a fuzzer sends: certificates, LDAP messages, SNMP
// packets and Kerberos tickets are all ASN.1 on the page and tag-length-value on
// the wire, and the wire is where the parsers with the interesting bugs are.
//
// The shape is uniform, which makes the translation uniform: every value is a
// tag byte, a length, and a content whose form depends on the type. A tag is a
// constant, so it is an exact immutable literal. A SEQUENCE's content is its
// members concatenated; a SEQUENCE OF's is its element repeated; a CHOICE has no
// tag of its own and is one of its alternatives.
//
// The length is the one approximation, and it is the same one protobuf has for
// the same reason: DER's short form is a single byte holding a length below 128,
// and the long form is a count byte followed by that many length bytes — a
// variable-width integer, which this schema language does not have. So contents
// are bounded to stay inside the short form and the report says so. A campaign
// that needs to fuzz the long form is fuzzing the length encoding itself, which
// is what mutating the length byte already does.
//
// What does not survive at all is the constraint language. "INTEGER (1..255)"
// and "SIZE(1..64)" are predicates, and the size ones translate because this
// language has size bounds; the value ones do not, and are reported.
type ASN1 struct{}

// Name implements Importer.
func (ASN1) Name() string { return "asn1" }

// Extensions implements Importer.
func (ASN1) Extensions() []string { return []string{".asn1", ".asn"} }

// DER universal tags. Constructed types carry bit 6.
const (
	tagBoolean     = 0x01
	tagInteger     = 0x02
	tagBitString   = 0x03
	tagOctetString = 0x04
	tagNull        = 0x05
	tagOID         = 0x06
	tagEnumerated  = 0x0a
	tagUTF8String  = 0x0c
	tagSequence    = 0x30 // constructed
	tagSet         = 0x31 // constructed
	tagPrintable   = 0x13
	tagIA5String   = 0x16
	tagUTCTime     = 0x17
	tagGenTime     = 0x18
)

// asn1LeafMax bounds a leaf's content so the one-byte short-form length is
// exact. Chosen so a SEQUENCE of a few members also stays inside it.
const asn1LeafMax = 24

// Import implements Importer.
func (ASN1) Import(src []byte, filename string) (*schema.Schema, *Report, error) {
	p := &asnParser{lex: newAsnLexer(string(src))}
	assignments, err := p.parseModule()
	if err != nil {
		return nil, nil, fmt.Errorf("asn1: %s: %w", filename, err)
	}
	if len(assignments) == 0 {
		return nil, nil, fmt.Errorf("asn1: %s declares no type assignments", filename)
	}

	e := &asnEmit{b: newBuilder("asn1", filename), decl: map[string]*asnType{}}
	for _, a := range assignments {
		e.decl[a.name] = a.body
		e.order = append(e.order, a.name)
		e.b.nameFor(a.name)
	}
	for _, name := range e.order {
		e.b.s.Types[e.b.nameFor(name)] = wrap(e.typeFor(e.decl[name], name, name))
	}
	return e.b.finish(e.b.nameFor(e.order[0]))
}

// --- the model --------------------------------------------------------------

type asnAssignment struct {
	name string
	body *asnType
}

// asnType is a parsed type expression.
type asnType struct {
	// base is the keyword: SEQUENCE, INTEGER, CHOICE, or a referenced name.
	base string

	// members are the components of a SEQUENCE, SET or CHOICE.
	members []asnMember

	// elem is the element type of a SEQUENCE OF or SET OF.
	elem *asnType

	// tag replaces the universal one, for [0], [APPLICATION 1] and the rest.
	tag     int
	hasTag  bool
	tagKind string // "", "IMPLICIT", "EXPLICIT"

	// size is a SIZE constraint, which is one of the few this language can use.
	sizeMin, sizeMax int
	hasSize          bool

	// constrained records that a value constraint was dropped.
	constraint string
}

type asnMember struct {
	name     string
	typ      *asnType
	optional bool
}

// --- emission ---------------------------------------------------------------

type asnEmit struct {
	b     *builder
	decl  map[string]*asnType
	order []string
	depth int
}

const maxASN1Depth = 24

// typeFor renders a type as its DER encoding: tag, length, content.
func (e *asnEmit) typeFor(t *asnType, hint, where string) *schema.Type {
	if t == nil {
		return bytesOf(0, asn1LeafMax)
	}
	e.depth++
	defer func() { e.depth-- }()
	if e.depth > maxASN1Depth {
		e.b.rep.Add(where, "recursive type",
			"nested past the depth limit; generated as free bytes")
		return bytesOf(0, asn1LeafMax)
	}
	if t.constraint != "" {
		e.b.rep.Add(where, "value constraint",
			t.constraint+" restricts which values are legal, and this language "+
				"bounds sizes rather than values; the field is generated unconstrained")
	}

	switch strings.ToUpper(t.base) {
	case "SEQUENCE", "SET":
		if t.elem != nil {
			return e.sequenceOf(t, hint, where)
		}
		return e.constructed(t, hint, where, e.tagOr(t, tagSequence))
	case "CHOICE":
		// A CHOICE has no encoding of its own: what appears on the wire is
		// whichever alternative was selected, tag and all.
		alts := make([]schema.Field, 0, len(t.members))
		for _, m := range t.members {
			alts = append(alts, field(m.name, e.member(m, hint+"_"+ident(m.name), where)))
		}
		if len(alts) == 0 {
			return bytesOf(0, asn1LeafMax)
		}
		return choiceOf(uniqueFields(alts)...)
	case "NULL":
		return magic(string([]byte{byte(e.tagOr(t, tagNull)), 0}))
	case "BOOLEAN":
		return e.primitive(t, tagBoolean, 1, 1, hint)
	case "INTEGER":
		return e.primitive(t, tagInteger, 1, 4, hint)
	case "ENUMERATED":
		return e.primitive(t, tagEnumerated, 1, 1, hint)
	case "OCTET":
		return e.primitive(t, tagOctetString, 0, asn1LeafMax, hint)
	case "BIT":
		// A BIT STRING's content begins with a count of unused trailing bits.
		return e.bitString(t, hint)
	case "OBJECT":
		return e.primitive(t, tagOID, 1, 12, hint)
	case "UTF8STRING":
		return e.primitive(t, tagUTF8String, 0, asn1LeafMax, hint)
	case "PRINTABLESTRING", "NUMERICSTRING", "VISIBLESTRING":
		return e.primitive(t, tagPrintable, 0, asn1LeafMax, hint)
	case "IA5STRING":
		return e.primitive(t, tagIA5String, 0, asn1LeafMax, hint)
	case "UTCTIME":
		return e.primitive(t, tagUTCTime, 13, 13, hint)
	case "GENERALIZEDTIME":
		return e.primitive(t, tagGenTime, 15, 15, hint)
	case "ANY":
		e.b.rep.Add(where, "ANY",
			"the type is decided by a field elsewhere in the message; generated as "+
				"one free tag-length-value")
		return bytesOf(2, asn1LeafMax)
	}

	// A reference to another assignment.
	if _, ok := e.decl[t.base]; ok {
		if t.hasTag {
			return e.taggedRef(t, hint, where)
		}
		return refTo(e.b.nameFor(t.base))
	}
	e.b.rep.Add(where, "unknown type "+t.base,
		"not assigned in this module; generated as one free tag-length-value")
	return bytesOf(2, asn1LeafMax)
}

// tagOr returns the tag a type carries, which is the universal one unless the
// module gave it another.
//
// A context tag replaces the universal one under IMPLICIT tagging and wraps it
// under EXPLICIT. Getting that backwards produces a message every decoder
// rejects, which is why the two are handled separately rather than treated as
// the same annotation.
func (e *asnEmit) tagOr(t *asnType, universal int) int {
	if !t.hasTag {
		return universal
	}
	// Context class, the constructed bit of the type it replaces, and the
	// number. Keeping the constructed bit is what makes [0] IMPLICIT on a
	// SEQUENCE still a constructed tag and on an INTEGER still a primitive one;
	// forcing either produces a message no decoder reads.
	constructed := universal & 0x20
	return 0x80 | constructed | (t.tag & 0x1f)
}

// primitive renders a tag, a length and a content of bounded size.
func (e *asnEmit) primitive(t *asnType, universal, minimum, maximum int, hint string) *schema.Type {
	if t.hasSize {
		minimum, maximum = t.sizeMin, t.sizeMax
	}
	if maximum <= 0 || maximum > asn1LeafMax {
		maximum = asn1LeafMax
	}
	if minimum > maximum {
		minimum = maximum
	}
	content := e.b.nameFor(hint + "_v")
	e.b.s.Types[content] = wrap(bytesOf(minimum, maximum))
	return structOf(
		field("tag", magic(string([]byte{byte(e.tagOr(t, universal))}))),
		lengthField("len", 1, ir.BigEndian, "v"),
		field("v", refTo(content)),
	)
}

// bitString is an OCTET STRING with a leading count of unused bits, which is
// the one primitive whose content is not simply its value.
func (e *asnEmit) bitString(t *asnType, hint string) *schema.Type {
	body := e.b.nameFor(hint + "_bits")
	e.b.s.Types[body] = structOf(
		field("unused", magic("\x00")),
		field("bits", bytesOf(0, asn1LeafMax-1)),
	)
	return structOf(
		field("tag", magic(string([]byte{byte(e.tagOr(t, tagBitString))}))),
		lengthField("len", 1, ir.BigEndian, "v"),
		field("v", refTo(body)),
	)
}

// constructed renders a SEQUENCE or SET: a tag, a length, and the members.
func (e *asnEmit) constructed(t *asnType, hint, where string, tag int) *schema.Type {
	fields := make([]schema.Field, 0, len(t.members))
	for _, m := range t.members {
		fields = append(fields, field(m.name, e.member(m, hint+"_"+ident(m.name), where)))
	}
	body := e.b.nameFor(hint + "_body")
	e.b.s.Types[body] = structOf(uniqueFields(fields)...)
	return structOf(
		field("tag", magic(string([]byte{byte(tag)}))),
		lengthField("len", 1, ir.BigEndian, "v"),
		field("v", refTo(body)),
	)
}

// sequenceOf renders a SEQUENCE OF: a tag, a length, and the element repeated.
func (e *asnEmit) sequenceOf(t *asnType, hint, where string) *schema.Type {
	elem := e.b.nameFor(hint + "_elem")
	e.b.s.Types[elem] = wrap(e.typeFor(t.elem, hint+"_elem", where))
	minimum, maximum := 0, 2
	if t.hasSize {
		minimum, maximum = t.sizeMin, t.sizeMax
		if maximum <= 0 || maximum > 4 {
			maximum = 4
		}
		if minimum > maximum {
			minimum = maximum
		}
	}
	body := e.b.nameFor(hint + "_items")
	e.b.s.Types[body] = structOf(field("items", repeatOf(elem, minimum, maximum)))
	return structOf(
		field("tag", magic(string([]byte{byte(e.tagOr(t, tagSequence))}))),
		lengthField("len", 1, ir.BigEndian, "v"),
		field("v", refTo(body)),
	)
}

// taggedRef wraps a referenced type in an explicit context tag.
func (e *asnEmit) taggedRef(t *asnType, hint, where string) *schema.Type {
	_ = where
	inner := e.b.nameFor(hint + "_inner")
	e.b.s.Types[inner] = wrap(refTo(e.b.nameFor(t.base)))
	return structOf(
		field("tag", magic(string([]byte{byte(0xa0 | (t.tag & 0x1f))}))),
		lengthField("len", 1, ir.BigEndian, "v"),
		field("v", refTo(inner)),
	)
}

// member renders one component, optional or not.
func (e *asnEmit) member(m asnMember, hint, where string) *schema.Type {
	t := e.typeFor(m.typ, hint, where+"."+m.name)
	if !m.optional {
		return t
	}
	// OPTIONAL is exactly an opt, which is the one place this translation is
	// perfect rather than merely close.
	name := e.b.nameFor(hint + "_opt")
	e.b.s.Types[name] = wrap(t)
	return optOf(name)
}

// --- the module parser ------------------------------------------------------

type asnLexer struct {
	src string
	pos int
}

func newAsnLexer(s string) *asnLexer { return &asnLexer{src: s} }

func (l *asnLexer) next() string {
	for l.pos < len(l.src) {
		c := l.src[l.pos]
		switch {
		case c == ' ' || c == '\t' || c == '\r' || c == '\n':
			l.pos++
		case c == '-' && l.pos+1 < len(l.src) && l.src[l.pos+1] == '-':
			l.skipComment()
		default:
			goto token
		}
	}
	return ""
token:
	c := l.src[l.pos]
	if isAsnIdent(c) {
		start := l.pos
		for l.pos < len(l.src) && isAsnIdent(l.src[l.pos]) {
			l.pos++
		}
		return l.src[start:l.pos]
	}
	if c == ':' && strings.HasPrefix(l.src[l.pos:], "::=") {
		l.pos += 3
		return "::="
	}
	if c == '.' && strings.HasPrefix(l.src[l.pos:], "..") {
		l.pos += 2
		return ".."
	}
	l.pos++
	return string(c)
}

func (l *asnLexer) peek() string {
	save := l.pos
	t := l.next()
	l.pos = save
	return t
}

// skipComment consumes an ASN.1 comment, which ends at a newline or at the next
// pair of hyphens — a rule that makes "-- a -- b" two tokens of comment and one
// of b, and a reader that stopped at the newline would swallow the b.
func (l *asnLexer) skipComment() {
	l.pos += 2
	for l.pos < len(l.src) && l.src[l.pos] != '\n' {
		if l.src[l.pos] == '-' && l.pos+1 < len(l.src) && l.src[l.pos+1] == '-' {
			l.pos += 2
			return
		}
		l.pos++
	}
}

func isAsnIdent(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_'
}

type asnParser struct {
	lex *asnLexer
}

// parseModule reads the type assignments between BEGIN and END.
func (p *asnParser) parseModule() ([]asnAssignment, error) {
	// Skip the module header, if there is one. A bare list of assignments is
	// also common in documentation and is accepted.
	if i := strings.Index(p.lex.src, "BEGIN"); i >= 0 {
		p.lex.pos = i + len("BEGIN")
	}
	var out []asnAssignment
	for {
		tok := p.lex.next()
		switch tok {
		case "", "END":
			return out, nil
		case "IMPORTS", "EXPORTS":
			p.skipToSemicolon()
			continue
		}
		if p.lex.peek() != "::=" {
			continue
		}
		p.lex.next() // ::=
		body, err := p.parseType()
		if err != nil {
			return nil, fmt.Errorf("%s: %w", tok, err)
		}
		if body == nil {
			continue
		}
		out = append(out, asnAssignment{name: tok, body: body})
	}
}

func (p *asnParser) skipToSemicolon() {
	for {
		switch p.lex.next() {
		case "", ";":
			return
		}
	}
}

// parseType reads a type expression.
func (p *asnParser) parseType() (*asnType, error) {
	t := &asnType{}

	if p.lex.peek() == "[" {
		p.lex.next()
		var parts []string
		for {
			tok := p.lex.next()
			if tok == "]" || tok == "" {
				break
			}
			parts = append(parts, tok)
		}
		if len(parts) > 0 {
			if n, err := strconv.Atoi(parts[len(parts)-1]); err == nil {
				t.tag, t.hasTag = n, true
			}
		}
		switch p.lex.peek() {
		case "IMPLICIT", "EXPLICIT":
			t.tagKind = p.lex.next()
		}
	}

	base := p.lex.next()
	if base == "" {
		return nil, fmt.Errorf("expected a type")
	}
	t.base = base

	switch strings.ToUpper(base) {
	case "OCTET", "BIT":
		if s := p.lex.peek(); strings.EqualFold(s, "STRING") {
			p.lex.next()
		}
	case "OBJECT":
		if s := p.lex.peek(); strings.EqualFold(s, "IDENTIFIER") {
			p.lex.next()
		}
	case "SEQUENCE", "SET":
		// SIZE may come between the keyword and OF.
		p.readSize(t)
		if strings.EqualFold(p.lex.peek(), "OF") {
			p.lex.next()
			elem, err := p.parseType()
			if err != nil {
				return nil, err
			}
			t.elem = elem
			return t, nil
		}
		if p.lex.peek() == "{" {
			members, err := p.parseMembers()
			if err != nil {
				return nil, err
			}
			t.members = members
			return t, nil
		}
		return t, nil
	case "CHOICE":
		if p.lex.peek() == "{" {
			members, err := p.parseMembers()
			if err != nil {
				return nil, err
			}
			t.members = members
		}
		return t, nil
	case "INTEGER", "ENUMERATED":
		// A named-number list is documentation for a value this language does
		// not constrain, so it is consumed and dropped.
		if p.lex.peek() == "{" {
			p.skipBraces()
		}
	}

	p.readConstraint(t)
	return t, nil
}

// parseMembers reads a { name Type, ... } component list.
func (p *asnParser) parseMembers() ([]asnMember, error) {
	if p.lex.next() != "{" {
		return nil, fmt.Errorf("expected {")
	}
	var out []asnMember
	for {
		tok := p.lex.peek()
		switch tok {
		case "":
			return nil, fmt.Errorf("unclosed component list")
		case "}":
			p.lex.next()
			return out, nil
		case ",":
			p.lex.next()
			continue
		case "...":
			p.lex.next()
			continue
		}
		name := p.lex.next()
		if name == "." {
			// An extension marker, written as three separate dots by the lexer.
			continue
		}
		typ, err := p.parseType()
		if err != nil {
			return nil, err
		}
		m := asnMember{name: name, typ: typ}
		for {
			switch strings.ToUpper(p.lex.peek()) {
			case "OPTIONAL":
				p.lex.next()
				m.optional = true
				continue
			case "DEFAULT":
				p.lex.next()
				p.lex.next() // the default value
				m.optional = true
				continue
			}
			break
		}
		out = append(out, m)
	}
}

// readSize reads a SIZE(a..b) constraint, which is one this language can use.
func (p *asnParser) readSize(t *asnType) {
	if p.lex.peek() != "(" {
		return
	}
	save := p.lex.pos
	p.lex.next()
	if !strings.EqualFold(p.lex.peek(), "SIZE") {
		p.lex.pos = save
		return
	}
	p.lex.next()
	if p.lex.next() != "(" {
		p.lex.pos = save
		return
	}
	lo, err := strconv.Atoi(p.lex.next())
	if err != nil {
		p.lex.pos = save
		return
	}
	hi := lo
	if p.lex.peek() == ".." {
		p.lex.next()
		tok := p.lex.next()
		if n, err := strconv.Atoi(tok); err == nil {
			hi = n
		} else {
			hi = asn1LeafMax // MAX
		}
	}
	t.sizeMin, t.sizeMax, t.hasSize = lo, hi, true
	// Consume the closing parentheses.
	for p.lex.peek() == ")" {
		p.lex.next()
	}
}

// readConstraint consumes a parenthesised constraint and records it, so the
// report can say which one was dropped.
func (p *asnParser) readConstraint(t *asnType) {
	if p.lex.peek() != "(" {
		return
	}
	save := p.lex.pos
	p.lex.next()
	if strings.EqualFold(p.lex.peek(), "SIZE") {
		p.lex.pos = save
		p.readSize(t)
		return
	}
	depth, text := 1, ""
	for depth > 0 {
		tok := p.lex.next()
		switch tok {
		case "":
			return
		case "(":
			depth++
		case ")":
			depth--
			if depth == 0 {
				t.constraint = "(" + strings.TrimSpace(text) + ")"
				return
			}
		}
		text += tok + " "
	}
}

func (p *asnParser) skipBraces() {
	if p.lex.next() != "{" {
		return
	}
	depth := 1
	for depth > 0 {
		switch p.lex.next() {
		case "":
			return
		case "{":
			depth++
		case "}":
			depth--
		}
	}
}
