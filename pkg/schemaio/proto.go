package schemaio

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/rom/Xfuzz/pkg/ir"
	"github.com/rom/Xfuzz/pkg/schema"
)

// Proto imports a Protocol Buffers definition as a grammar for the wire format.
//
// The wire format, not the text one: a .proto describes messages a service
// exchanges as bytes, and the bytes are what a fuzzer sends. So a field becomes
// a key and a payload, where the key is the tag number and wire type packed into
// a varint — a constant, and therefore an exact immutable literal — and the
// payload's shape follows the wire type.
//
// The gap is the varint, and it is worth being precise about because it is the
// only thing in this file that is approximate. Protobuf encodes a scalar and a
// length as an integer whose width depends on its value; this schema language
// has only fixed-width integers. A one-byte varint holds every value below 128,
// which covers a length-delimited field shorter than 128 bytes and a scalar
// below 128 — most of what a real message carries and none of what it can carry.
// So the importer generates the one-byte form, and the report says so rather
// than emitting a two-byte field that would be a malformed varint every time.
//
// Keys are exact at any field number: a key is a constant, so its varint is
// computed once and written as a literal however many bytes it takes.
type Proto struct{}

// Name implements Importer.
func (Proto) Name() string { return "proto" }

// Extensions implements Importer.
func (Proto) Extensions() []string { return []string{".proto"} }

// Import implements Importer.
func (Proto) Import(src []byte, filename string) (*schema.Schema, *Report, error) {
	p := &protoParser{lex: newProtoLexer(string(src))}
	file, err := p.parseFile()
	if err != nil {
		return nil, nil, fmt.Errorf("proto: %s: %w", filename, err)
	}
	if len(file.messages) == 0 {
		return nil, nil, fmt.Errorf("proto: %s declares no messages", filename)
	}

	e := &protoEmit{
		b:      newBuilder("proto", filename),
		byName: map[string]*protoMessage{},
		enums:  map[string]bool{},
	}
	for name := range file.enums {
		e.enums[name] = true
	}
	for _, imp := range file.imports {
		e.b.rep.Add("import", "imported definition",
			imp+" is a separate file; the messages it declares are generated as free "+
				"bytes unless you paste them in")
	}
	for _, s := range file.services {
		e.b.rep.Add("service "+s, "service definition",
			"a service names the messages an RPC carries; it is not itself a wire "+
				"format and nothing is generated for it")
	}
	e.index(file.messages, "")
	for _, m := range e.order {
		e.b.nameFor(m.qualified)
	}
	for _, m := range e.order {
		e.emit(m)
	}
	return e.b.finish(e.b.nameFor(file.messages[0].qualified))
}

// --- the model --------------------------------------------------------------

type protoFile struct {
	imports  []string
	services []string
	enums    map[string]bool
	messages []*protoMessage
}

type protoMessage struct {
	name      string
	qualified string
	fields    []protoField
	nested    []*protoMessage
	enums     map[string]bool
	oneofs    map[string][]protoField
	oneofName []string
}

type protoField struct {
	name     string
	typeName string
	number   int
	repeated bool
	optional bool
	mapKey   string
	mapValue string
	oneof    string
}

// --- emission ---------------------------------------------------------------

type protoEmit struct {
	b      *builder
	byName map[string]*protoMessage
	order  []*protoMessage
	enums  map[string]bool
}

func (e *protoEmit) index(msgs []*protoMessage, prefix string) {
	for _, m := range msgs {
		m.qualified = prefix + m.name
		e.byName[m.qualified] = m
		e.byName[m.name] = m
		e.order = append(e.order, m)
		for name := range m.enums {
			e.enums[name] = true
			e.enums[m.qualified+"."+name] = true
		}
		e.index(m.nested, m.qualified+".")
	}
}

func (e *protoEmit) emit(m *protoMessage) {
	var fields []schema.Field
	seenOneof := map[string]bool{}

	for _, f := range m.fields {
		if f.oneof != "" {
			if seenOneof[f.oneof] {
				continue
			}
			seenOneof[f.oneof] = true
			fields = append(fields, field(f.oneof, e.oneofType(m, f.oneof)))
			continue
		}
		fields = append(fields, e.fieldOf(m, f)...)
	}
	e.b.s.Types[e.b.nameFor(m.qualified)] = structOf(uniqueFields(fields)...)
}

// oneofType turns a oneof into a choice, which is what it is.
func (e *protoEmit) oneofType(m *protoMessage, name string) *schema.Type {
	members := m.oneofs[name]
	alts := make([]schema.Field, 0, len(members))
	for _, f := range members {
		inner := e.fieldOf(m, f)
		t := inner[0].Type
		if len(inner) > 1 {
			// A key and a payload: they travel together, so the alternative is
			// the pair rather than either half.
			t = structOf(uniqueFields(inner)...)
		}
		alts = append(alts, field(f.name, t))
	}
	return choiceOf(uniqueFields(alts)...)
}

// fieldOf renders one field as the sequence of parts it occupies on the wire.
func (e *protoEmit) fieldOf(m *protoMessage, f protoField) []schema.Field {
	where := m.qualified + "." + f.name

	if f.mapKey != "" {
		// A map entry is a message with key 1 and value 2, repeated. The
		// specification says so, which makes this an exact translation rather
		// than an approximation.
		entry := e.mapEntry(m, f, where)
		return []schema.Field{field(f.name, repeatOf(entry, 0, protoRepeatMax))}
	}

	wire := protoWireType(f.typeName, e.isMessage(f.typeName), e.isEnum(f.typeName))
	key := magic(string(protoVarint(uint64(f.number)<<3 | uint64(wire))))

	var parts []schema.Field
	switch wire {
	case 0:
		parts = []schema.Field{
			field(f.name+"_key", key),
			field(f.name, e.varintValue(f, where)),
		}
	case 1:
		parts = []schema.Field{field(f.name+"_key", key), field(f.name, bytesOf(8, 8))}
	case 5:
		parts = []schema.Field{field(f.name+"_key", key), field(f.name, bytesOf(4, 4))}
	default: // 2, length-delimited
		payload := e.payloadType(f, where)
		lf := lengthField(f.name+"_len", 1, ir.BigEndian, f.name)
		e.b.rep.Add(where, "varint length",
			fmt.Sprintf("a length above 127 needs a multi-byte varint, which is not a "+
				"fixed-width integer; the field carries a one-byte length, and leaf "+
				"payloads are capped at %d bytes so that a nested message stays inside "+
				"it", protoLeafMax))
		parts = []schema.Field{
			field(f.name+"_key", key),
			lf,
			field(f.name, payload),
		}
	}

	if f.repeated {
		// A repeated field is the whole key-and-payload group repeated, not the
		// payload: each occurrence carries its own key.
		group := e.b.nameFor(where + "_item")
		e.b.s.Types[group] = structOf(uniqueFields(parts)...)
		return []schema.Field{field(f.name, repeatOf(group, 0, protoRepeatMax))}
	}
	if f.optional {
		group := e.b.nameFor(where + "_opt")
		e.b.s.Types[group] = structOf(uniqueFields(parts)...)
		return []schema.Field{field(f.name, optOf(group))}
	}
	return parts
}

// varintValue is a scalar encoded as a varint.
func (e *protoEmit) varintValue(f protoField, where string) *schema.Type {
	if e.isEnum(f.typeName) {
		e.b.rep.Add(where, "enum "+f.typeName,
			"an enumeration constrains a field's value and this language constrains "+
				"lengths; generated as a one-byte varint, which covers the first 128 "+
				"members")
		return varintByte()
	}
	if f.typeName == "bool" {
		return choiceOf(field("f", magic("\x00")), field("t", magic("\x01")))
	}
	e.b.rep.Add(where, "varint scalar",
		"a value above 127 needs a multi-byte varint, which is not a fixed-width "+
			"integer; generated as the one-byte form")
	return varintByte()
}

// protoLeafMax bounds a string or bytes payload.
//
// Not a taste judgement: a length-delimited field carries a one-byte length,
// which is exact below 128, and a message used as a payload has to encode to
// less than that including its own fields' keys and lengths. Capping the leaves
// is what keeps a nested message inside the form this importer can write.
const protoLeafMax = 24

// protoRepeatMax bounds a repeated field, for the same reason: each element
// carries its own key and payload inside the enclosing message's length.
const protoRepeatMax = 2

// varintByte is a one-byte varint: mutable, so a campaign explores the value,
// and starting at zero, so what the grammar *generates* is always a varint that
// terminates. A random byte here would have its continuation bit set half the
// time, and a varint that continues into the next field's key desynchronises
// every byte after it.
func varintByte() *schema.Type {
	return &schema.Type{
		Kind: schema.KindBytes, Min: 1, Max: 1,
		Literal: []byte{0}, HasLiteral: true,
	}
}

// payloadType is the content of a length-delimited field.
func (e *protoEmit) payloadType(f protoField, where string) *schema.Type {
	if e.isMessage(f.typeName) {
		if m, ok := e.byName[f.typeName]; ok {
			return refTo(e.b.nameFor(m.qualified))
		}
	}
	switch f.typeName {
	case "string":
		return &schema.Type{Kind: schema.KindStr, Min: 0, Max: protoLeafMax}
	case "bytes":
		return bytesOf(0, protoLeafMax)
	}
	e.b.rep.Add(where, "unknown type "+f.typeName,
		"not declared in this file; generated as free bytes")
	return bytesOf(0, protoLeafMax)
}

// mapEntry declares the synthetic message a map field is made of.
func (e *protoEmit) mapEntry(m *protoMessage, f protoField, where string) string {
	name := e.b.nameFor(m.qualified + "." + f.name + "_entry")
	key := protoField{name: "key", typeName: f.mapKey, number: 1}
	val := protoField{name: "value", typeName: f.mapValue, number: 2}
	inner := append(e.fieldOf(m, key), e.fieldOf(m, val)...)
	entry := structOf(uniqueFields(inner)...)

	// The entry itself is a length-delimited field of the outer message.
	outerKey := magic(string(protoVarint(uint64(f.number)<<3 | 2)))
	body := e.b.nameFor(where + "_body")
	e.b.s.Types[body] = entry
	e.b.s.Types[name] = structOf(
		field("key", outerKey),
		lengthField("len", 1, ir.BigEndian, "body"),
		field("body", refTo(body)),
	)
	return name
}

func (e *protoEmit) isMessage(name string) bool {
	_, ok := e.byName[name]
	return ok
}

func (e *protoEmit) isEnum(name string) bool { return e.enums[name] }

// protoWireType returns the wire type a declared type is encoded with.
func protoWireType(name string, isMessage, isEnum bool) int {
	switch name {
	case "double", "fixed64", "sfixed64":
		return 1
	case "float", "fixed32", "sfixed32":
		return 5
	case "string", "bytes":
		return 2
	case "int32", "int64", "uint32", "uint64", "sint32", "sint64", "bool":
		return 0
	}
	if isEnum {
		return 0
	}
	if isMessage {
		return 2
	}
	// An unresolved name is a message from an imported file more often than
	// anything else, and a length-delimited guess at least keeps the frame
	// parseable up to it.
	return 2
}

// protoVarint encodes a value in protobuf's base-128 form.
//
// Exact, and used only where the value is a constant: a field's key is fixed by
// the declaration, so its varint is computed here once and written as a literal
// however many bytes it needs. It is the values that vary that this importer
// cannot encode.
func protoVarint(v uint64) []byte {
	var out []byte
	for v >= 0x80 {
		out = append(out, byte(v)|0x80)
		v >>= 7
	}
	return append(out, byte(v))
}

// --- the .proto parser ------------------------------------------------------

type protoLexer struct {
	src string
	pos int
}

func newProtoLexer(s string) *protoLexer { return &protoLexer{src: s} }

// next returns the next token: an identifier, a number, a quoted string, or one
// punctuation character. Comments and whitespace are skipped.
func (l *protoLexer) next() string {
	for l.pos < len(l.src) {
		c := l.src[l.pos]
		switch {
		case c == ' ' || c == '\t' || c == '\r' || c == '\n':
			l.pos++
		case c == '/' && l.pos+1 < len(l.src) && l.src[l.pos+1] == '/':
			for l.pos < len(l.src) && l.src[l.pos] != '\n' {
				l.pos++
			}
		case c == '/' && l.pos+1 < len(l.src) && l.src[l.pos+1] == '*':
			if i := strings.Index(l.src[l.pos+2:], "*/"); i >= 0 {
				l.pos += i + 4
				continue
			}
			l.pos = len(l.src)
		default:
			goto token
		}
	}
	return ""
token:
	c := l.src[l.pos]
	switch {
	case c == '"' || c == '\'':
		start := l.pos
		l.pos++
		for l.pos < len(l.src) && l.src[l.pos] != c {
			// A backslash escapes the next byte — unless there is no next byte,
			// which is what a truncated file ends with and what walks the
			// position past the end of the source.
			if l.src[l.pos] == '\\' && l.pos+1 < len(l.src) {
				l.pos++
			}
			l.pos++
		}
		if l.pos < len(l.src) {
			l.pos++
		}
		return l.src[start:min(l.pos, len(l.src))]
	case isProtoIdent(c):
		start := l.pos
		for l.pos < len(l.src) && (isProtoIdent(l.src[l.pos]) || l.src[l.pos] == '.') {
			l.pos++
		}
		return l.src[start:l.pos]
	}
	l.pos++
	return string(c)
}

func (l *protoLexer) peek() string {
	save := l.pos
	t := l.next()
	l.pos = save
	return t
}

func isProtoIdent(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
		c == '_' || c == '-'
}

type protoParser struct {
	lex *protoLexer
}

func (p *protoParser) parseFile() (*protoFile, error) {
	f := &protoFile{enums: map[string]bool{}}
	for {
		tok := p.lex.next()
		switch tok {
		case "":
			return f, nil
		case "syntax", "package", "option", "edition":
			p.skipToSemicolon()
		case "import":
			path := p.lex.next()
			if strings.HasPrefix(path, "public") || strings.HasPrefix(path, "weak") {
				path = p.lex.next()
			}
			f.imports = append(f.imports, strings.Trim(path, `"'`))
			p.skipToSemicolon()
		case "message":
			m, err := p.parseMessage()
			if err != nil {
				return nil, err
			}
			f.messages = append(f.messages, m)
		case "enum":
			// A top-level enum is a type other messages use, and it is not a
			// message: recording it as one would make it the file's first
			// declaration and therefore the grammar's root, which is a type
			// nothing sends.
			f.enums[p.lex.next()] = true
			p.skipBlock()
		case "service":
			f.services = append(f.services, p.lex.next())
			p.skipBlock()
		case "extend":
			p.lex.next()
			p.skipBlock()
		case ";":
		default:
			// Anything else at the top level is a construct this subset does not
			// know. Skipping to the next statement keeps one unknown keyword
			// from losing the rest of the file.
			p.skipToSemicolon()
		}
	}
}

func (p *protoParser) parseMessage() (*protoMessage, error) {
	m := &protoMessage{
		name:   p.lex.next(),
		enums:  map[string]bool{},
		oneofs: map[string][]protoField{},
	}
	if m.name == "" {
		return nil, fmt.Errorf("a message with no name")
	}
	if tok := p.lex.next(); tok != "{" {
		return nil, fmt.Errorf("message %s: expected {, got %q", m.name, tok)
	}
	for {
		tok := p.lex.next()
		switch tok {
		case "":
			return nil, fmt.Errorf("message %s: unclosed", m.name)
		case "}":
			return m, nil
		case ";":
		case "reserved", "option", "extensions":
			p.skipToSemicolon()
		case "message":
			nested, err := p.parseMessage()
			if err != nil {
				return nil, err
			}
			m.nested = append(m.nested, nested)
		case "enum":
			m.enums[p.lex.next()] = true
			p.skipBlock()
		case "oneof":
			name := p.lex.next()
			m.oneofName = append(m.oneofName, name)
			if err := p.parseOneof(m, name); err != nil {
				return nil, err
			}
		default:
			f, err := p.parseField(tok)
			if err != nil {
				return nil, err
			}
			if f != nil {
				m.fields = append(m.fields, *f)
			}
		}
	}
}

func (p *protoParser) parseOneof(m *protoMessage, name string) error {
	if tok := p.lex.next(); tok != "{" {
		return fmt.Errorf("oneof %s: expected {, got %q", name, tok)
	}
	for {
		tok := p.lex.next()
		switch tok {
		case "":
			return fmt.Errorf("oneof %s: unclosed", name)
		case "}":
			return nil
		case ";":
		case "option":
			p.skipToSemicolon()
		default:
			f, err := p.parseField(tok)
			if err != nil {
				return err
			}
			if f != nil {
				f.oneof = name
				m.fields = append(m.fields, *f)
				m.oneofs[name] = append(m.oneofs[name], *f)
			}
		}
	}
}

// parseField reads one field declaration, whose first token has been consumed.
func (p *protoParser) parseField(first string) (*protoField, error) {
	f := &protoField{}
	tok := first
	switch tok {
	case "repeated":
		f.repeated = true
		tok = p.lex.next()
	case "optional":
		f.optional = true
		tok = p.lex.next()
	case "required":
		tok = p.lex.next()
	}

	if tok == "map" {
		if p.lex.next() != "<" {
			return nil, fmt.Errorf("map: expected <")
		}
		f.mapKey = p.lex.next()
		if p.lex.next() != "," {
			return nil, fmt.Errorf("map: expected ,")
		}
		f.mapValue = p.lex.next()
		if p.lex.next() != ">" {
			return nil, fmt.Errorf("map: expected >")
		}
	} else {
		f.typeName = strings.TrimPrefix(tok, ".")
	}

	f.name = p.lex.next()
	if p.lex.next() != "=" {
		p.skipToSemicolon()
		return nil, nil
	}
	n, err := strconv.Atoi(p.lex.next())
	if err != nil || n <= 0 {
		p.skipToSemicolon()
		return nil, nil
	}
	f.number = n
	p.skipToSemicolon()
	return f, nil
}

func (p *protoParser) skipToSemicolon() {
	for {
		switch p.lex.next() {
		case "", ";":
			return
		case "{":
			p.skipRest()
		}
	}
}

// skipBlock consumes a { ... } that has not been opened yet.
func (p *protoParser) skipBlock() {
	for {
		tok := p.lex.next()
		if tok == "" {
			return
		}
		if tok == "{" {
			p.skipRest()
			return
		}
		if tok == ";" {
			return
		}
	}
}

// skipRest consumes to the closing brace of a block already opened.
func (p *protoParser) skipRest() {
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
