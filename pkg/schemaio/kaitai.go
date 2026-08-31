package schemaio

import (
	"fmt"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/rom/Xfuzz/pkg/ir"
	"github.com/rom/Xfuzz/pkg/schema"
)

// Kaitai imports a Kaitai Struct definition.
//
// The closest correspondence of the six after ABNF, and the richest source: the
// Kaitai gallery carries descriptions of a few hundred binary formats that
// people wrote for hex editors and parser generators, and every one of them is
// a grammar somebody else has already debugged against real files.
//
// A sequence is a struct, a nested type is a type, a repeat is a repeat, a
// contents is a magic, a switch-on is a choice. The one translation worth
// pointing at is the length: Kaitai writes `size: len_field` on the *payload*,
// naming the field that holds its length, and Xfuzz writes `= len(payload)` on
// the *length field*. Inverting that is what makes a generated file have
// correct lengths rather than plausible ones, and it is why this importer looks
// backwards through a sequence rather than translating attribute by attribute.
//
// What does not survive is expressions. Kaitai's `if:`, `repeat-until:` and
// `instances:` are a small language over already-parsed values, and evaluating
// it would be writing an interpreter for a second grammar language inside this
// one. A conditional field becomes an optional one — which is what it is,
// structurally, minus the condition — and the report says so.
type Kaitai struct{}

// Name implements Importer.
func (Kaitai) Name() string { return "kaitai" }

// Extensions implements Importer.
func (Kaitai) Extensions() []string { return []string{".ksy"} }

// Import implements Importer.
func (Kaitai) Import(src []byte, filename string) (*schema.Schema, *Report, error) {
	var doc ksy
	if err := yaml.Unmarshal(src, &doc); err != nil {
		return nil, nil, fmt.Errorf("kaitai: %s: %w", filename, err)
	}
	if doc.Meta.ID == "" {
		return nil, nil, fmt.Errorf("kaitai: %s: no meta.id, so the format has no name", filename)
	}

	k := &ksyImport{
		b:      newBuilder("kaitai", filename),
		endian: endianOf(doc.Meta.Endian),
	}
	for _, imp := range doc.Meta.Imports {
		k.b.rep.Add("meta.imports", "imported definition",
			imp+" is a separate .ksy file; import it and paste the types in, or the "+
				"fields that use them are generated as free bytes")
	}
	// Every type gets its identifier before any body is built, so a forward
	// reference resolves to the same name its declaration will use.
	k.collect(doc.Meta.ID, doc.Types)
	k.emit(doc.Meta.ID, doc.Seq, doc.Types, doc.Instances, doc.Enums)
	return k.b.finish(k.b.nameFor(doc.Meta.ID))
}

// sniff implements sniffer, for a .ksy written with a .yaml suffix.
func (Kaitai) sniff(head string) bool {
	return strings.Contains(head, "meta:") &&
		(strings.Contains(head, "seq:") || strings.Contains(head, "\nid:") ||
			strings.Contains(head, "  id:"))
}

type ksy struct {
	Meta      ksyMeta                   `yaml:"meta"`
	Seq       []ksyAttr                 `yaml:"seq"`
	Types     map[string]*ksyType       `yaml:"types"`
	Enums     map[string]map[string]any `yaml:"enums"`
	Instances map[string]yaml.Node      `yaml:"instances"`
}

type ksyMeta struct {
	ID       string   `yaml:"id"`
	Endian   string   `yaml:"endian"`
	Encoding string   `yaml:"encoding"`
	Imports  []string `yaml:"imports"`
}

type ksyType struct {
	Seq       []ksyAttr                 `yaml:"seq"`
	Types     map[string]*ksyType       `yaml:"types"`
	Enums     map[string]map[string]any `yaml:"enums"`
	Instances map[string]yaml.Node      `yaml:"instances"`
}

type ksyAttr struct {
	ID          string    `yaml:"id"`
	Type        yaml.Node `yaml:"type"`
	Size        yaml.Node `yaml:"size"`
	SizeEOS     bool      `yaml:"size-eos"`
	Contents    yaml.Node `yaml:"contents"`
	Repeat      string    `yaml:"repeat"`
	RepeatExpr  yaml.Node `yaml:"repeat-expr"`
	RepeatUntil yaml.Node `yaml:"repeat-until"`
	If          yaml.Node `yaml:"if"`
	Encoding    string    `yaml:"encoding"`
	Enum        string    `yaml:"enum"`
	Terminator  *int      `yaml:"terminator"`
	Process     string    `yaml:"process"`
	Doc         string    `yaml:"doc"`
}

type ksyImport struct {
	b      *builder
	endian ir.Endian
}

func endianOf(s string) ir.Endian {
	if strings.EqualFold(s, "le") {
		return ir.LittleEndian
	}
	return ir.BigEndian
}

// collect assigns identifiers to every declared type, nested ones included, so
// that a reference resolves whichever order the document lists them in.
func (k *ksyImport) collect(root string, types map[string]*ksyType) {
	k.b.nameFor(root)
	var walk func(m map[string]*ksyType)
	walk = func(m map[string]*ksyType) {
		for _, name := range sortedKeys(m) {
			k.b.nameFor(name)
			if m[name] != nil {
				walk(m[name].Types)
			}
		}
	}
	walk(types)
}

func (k *ksyImport) emit(name string, seq []ksyAttr, types map[string]*ksyType,
	instances map[string]yaml.Node, enums map[string]map[string]any) {

	k.b.s.Types[k.b.nameFor(name)] = k.structFor(name, seq)
	for _, key := range sortedKeys(instances) {
		k.b.rep.Add(name+".instances."+key, "instance",
			"a value computed from parsed fields; it is not in the byte stream and "+
				"nothing needs to be generated for it")
	}
	_ = enums // enums constrain values; the note is attached where a field uses one
	for _, typeName := range sortedKeys(types) {
		t := types[typeName]
		if t == nil {
			continue
		}
		k.emit(typeName, t.Seq, t.Types, t.Instances, t.Enums)
	}
}

// structFor builds a type from a sequence of attributes.
func (k *ksyImport) structFor(owner string, seq []ksyAttr) *schema.Type {
	fields := make([]schema.Field, 0, len(seq))
	// byName remembers where each attribute landed, so that a later `size:` or
	// `repeat-expr:` naming an earlier field can turn it into a derivation.
	byName := map[string]int{}

	for i, a := range seq {
		id := a.ID
		if id == "" {
			id = fmt.Sprintf("f%d", i+1)
		}
		where := owner + "." + id
		f := field(id, k.typeFor(a, where))
		byName[a.ID] = len(fields)
		fields = append(fields, f)

		// Now the inversion: Kaitai names the length field from the payload,
		// and this language derives the length field from the payload. The
		// reference only makes sense backwards, so it is applied here rather
		// than when the length field was built.
		k.deriveFrom(fields, byName, a, where, ir.DeriveLength, a.Size)
		k.deriveFrom(fields, byName, a, where, ir.DeriveCount, a.RepeatExpr)
	}
	return structOf(uniqueFields(fields)...)
}

// deriveFrom attaches a derivation to the earlier field an expression names.
func (k *ksyImport) deriveFrom(fields []schema.Field, byName map[string]int,
	a ksyAttr, where string, kind ir.DeriveKind, expr yaml.Node) {

	if expr.Kind == 0 || expr.Value == "" {
		return
	}
	if _, err := strconv.Atoi(expr.Value); err == nil {
		return // a literal, already applied as a bound
	}
	src, ok := byName[expr.Value]
	if !ok {
		k.b.rep.Add(where, "expression",
			expr.Value+" is not a plain field name of the same sequence; the "+
				"derived value cannot be computed and the field is generated free")
		return
	}
	target := fields[len(fields)-1].Name
	if fields[src].Type.Kind != schema.KindInt {
		k.b.rep.Add(where, "expression",
			expr.Value+" is not an integer field, so it cannot carry the derived value")
		return
	}
	fields[src].Derive = &ir.Derivation{Kind: kind, From: ir.Sibling(target)}
}

// typeFor turns one attribute into a type, wrapping it in a repeat or an opt as
// the attribute asks.
func (k *ksyImport) typeFor(a ksyAttr, where string) *schema.Type {
	base := k.baseType(a, where)

	if a.Repeat != "" || a.RepeatExpr.Kind != 0 {
		elem := k.declare(where+"_elem", base)
		minimum, maximum := 0, UnboundedRepeatMax
		if n, err := strconv.Atoi(a.RepeatExpr.Value); err == nil && n > 0 {
			minimum, maximum = n, n
		}
		if a.Repeat == "until" {
			k.b.rep.Add(where, "repeat-until",
				"the terminating condition is an expression over parsed values; the "+
					"repetition is generated with a bound instead")
		}
		base = repeatOf(elem, minimum, maximum)
	}
	if a.If.Kind != 0 && a.If.Value != "" {
		k.b.rep.Add(where, "conditional field",
			"if: "+a.If.Value+" is an expression over parsed values; the field is "+
				"generated as optional, which is its shape without the condition")
		base = optOf(k.declare(where+"_opt", base))
	}
	return base
}

// declare gives an anonymous type a name, because repeat and opt refer to their
// element by one.
func (k *ksyImport) declare(hint string, t *schema.Type) string {
	if t.Kind == schema.KindRef {
		return t.Target
	}
	name := k.b.nameFor(hint)
	k.b.s.Types[name] = wrap(t)
	return name
}

// baseType is the attribute's type before repetition and conditions.
func (k *ksyImport) baseType(a ksyAttr, where string) *schema.Type {
	if a.Process != "" {
		k.b.rep.Add(where, "process",
			a.Process+" transforms the bytes after reading; generating the field means "+
				"applying the inverse, which this importer does not")
	}
	if lit, ok := k.contents(a.Contents, where); ok {
		return magic(lit)
	}
	if a.Type.Kind == yaml.MappingNode {
		return k.switchType(a, where)
	}

	name := a.Type.Value
	if t, ok := k.scalar(name, a, where); ok {
		return t
	}
	if name != "" {
		// A user-defined type, whose identifier was reserved by collect.
		if _, known := k.b.taken[name]; known {
			return refTo(k.b.nameFor(name))
		}
		k.b.rep.Add(where, "unknown type "+name,
			"not declared in this file; it is probably in an imported one, and the "+
				"field is generated as free bytes")
		return k.sizedBytes(a, where)
	}
	// No type at all is Kaitai for "a run of bytes", sized by size or size-eos.
	return k.sizedBytes(a, where)
}

// scalar handles the built-in types.
func (k *ksyImport) scalar(name string, a ksyAttr, where string) (*schema.Type, bool) {
	if name == "" {
		return nil, false
	}
	switch {
	case name == "str" || name == "strz":
		t := k.sizedBytes(a, where)
		t.Kind = schema.KindStr
		if name == "strz" {
			k.b.rep.Add(where, "strz",
				"a NUL-terminated string; the terminator is not part of the schema's "+
					"length model, so the field is generated without one")
		}
		return t, true

	case name == "f4" || name == "f8":
		width := 4
		if name == "f8" {
			width = 8
		}
		k.b.rep.Add(where, "floating-point field",
			"the grammar language has no float; generated as "+strconv.Itoa(width)+
				" free bytes, which is every bit pattern including the signalling NaNs")
		return bytesOf(width, width), true

	case strings.HasPrefix(name, "b") && isDigits(name[1:]):
		bits, _ := strconv.Atoi(name[1:])
		k.b.rep.Add(where, "bit field",
			fmt.Sprintf("%d bits; the grammar language addresses whole bytes, so a "+
				"sub-byte field cannot be expressed", bits))
		return bytesOf((bits+7)/8, (bits+7)/8), true
	}

	if t, ok := k.integer(name, a, where); ok {
		return t, true
	}
	return nil, false
}

// integer parses u1, s4le, u8be and the rest.
func (k *ksyImport) integer(name string, a ksyAttr, where string) (*schema.Type, bool) {
	if len(name) < 2 || (name[0] != 'u' && name[0] != 's') {
		return nil, false
	}
	rest := name[1:]
	e := k.endian
	switch {
	case strings.HasSuffix(rest, "le"):
		e, rest = ir.LittleEndian, rest[:len(rest)-2]
	case strings.HasSuffix(rest, "be"):
		e, rest = ir.BigEndian, rest[:len(rest)-2]
	}
	width, err := strconv.Atoi(rest)
	if err != nil {
		return nil, false
	}
	switch width {
	case 1, 2, 4, 8:
	default:
		return nil, false
	}
	if a.Enum != "" {
		k.b.rep.Add(where, "enum "+a.Enum,
			"an enumeration constrains a field's value, and the grammar language "+
				"constrains lengths; the field is generated as an unconstrained integer")
	}
	return intOf(uint8(width), e, name[0] == 's'), true
}

// sizedBytes builds a byte run from size, size-eos or neither.
func (k *ksyImport) sizedBytes(a ksyAttr, where string) *schema.Type {
	if n, err := strconv.Atoi(a.Size.Value); err == nil && n >= 0 {
		return bytesOf(n, n)
	}
	if a.Size.Kind != 0 && a.Size.Value != "" {
		// A named size becomes a derivation on the field it names, applied by
		// the caller; here it only sets a generous bound.
		return bytesOf(0, 255)
	}
	if a.SizeEOS {
		return bytesOf(0, 1024)
	}
	if a.Terminator != nil {
		k.b.rep.Add(where, "terminator",
			"the field ends at a byte value rather than a length; the schema has no "+
				"terminator model and the field is generated with a bound instead")
		return bytesOf(0, 64)
	}
	return bytesOf(0, 32)
}

// switchType turns a switch-on into a choice.
func (k *ksyImport) switchType(a ksyAttr, where string) *schema.Type {
	var sw struct {
		On    string            `yaml:"switch-on"`
		Cases map[string]string `yaml:"cases"`
	}
	if err := a.Type.Decode(&sw); err != nil || len(sw.Cases) == 0 {
		k.b.rep.Add(where, "switch-on", "could not be read; the field is generated as free bytes")
		return bytesOf(0, 32)
	}
	fields := make([]schema.Field, 0, len(sw.Cases))
	for _, key := range sortedKeys(sw.Cases) {
		target := sw.Cases[key]
		var t *schema.Type
		if _, known := k.b.taken[target]; known {
			t = refTo(k.b.nameFor(target))
		} else if inner, ok := k.scalar(target, ksyAttr{}, where); ok {
			t = inner
		} else {
			t = bytesOf(0, 32)
		}
		fields = append(fields, field("case_"+key, t))
	}
	// The tag that selects the case is a value, and this language selects an
	// alternative structurally. The choice is right; which arm a given tag
	// implies is what is lost.
	k.b.rep.Add(where, "switch-on "+sw.On,
		"the alternatives are kept but the tag that selects between them is not "+
			"tied to them; a generated file may pair a tag with the wrong arm")
	return choiceOf(uniqueFields(fields)...)
}

// contents reads a `contents:` literal, which may be a string, a list of byte
// values, or a mixture of the two.
func (k *ksyImport) contents(n yaml.Node, where string) (string, bool) {
	switch n.Kind {
	case 0:
		return "", false
	case yaml.ScalarNode:
		return n.Value, true
	case yaml.SequenceNode:
		var out []byte
		for _, item := range n.Content {
			if v, err := strconv.ParseInt(item.Value, 0, 16); err == nil {
				out = append(out, byte(v))
				continue
			}
			out = append(out, item.Value...)
		}
		return string(out), true
	}
	k.b.rep.Add(where, "contents", "not a string or a list of bytes")
	return "", false
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}
