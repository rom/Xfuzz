package schema

import (
	"fmt"
	"sort"
	"strings"

	"github.com/rom/Xfuzz/pkg/ir"
)

// Kind is the class of a schema type.
type Kind uint8

// The schema type kinds. They map one-to-one onto ir node kinds; a schema is a
// description of trees, not a second representation of them.
const (
	KindInvalid Kind = iota
	KindInt
	KindBytes
	KindStr
	KindStruct
	KindRepeat
	KindChoice
	KindOpt
	KindRef
)

var kindNames = [...]string{
	KindInt: "int", KindBytes: "bytes", KindStr: "str", KindStruct: "struct",
	KindRepeat: "repeat", KindChoice: "choice", KindOpt: "opt", KindRef: "ref",
}

func (k Kind) String() string {
	if int(k) < len(kindNames) && kindNames[k] != "" {
		return kindNames[k]
	}
	return "invalid"
}

// Type describes one node of a format.
type Type struct {
	Kind Kind

	// Integers.
	Width  uint8
	Endian ir.Endian
	Signed bool

	// Payload and sequence bounds. Max of zero means unbounded.
	Min, Max int

	// Literal is fixed initial content for a bytes or str field, or the value of
	// an int field.
	Literal    []byte
	LiteralInt int64
	HasLiteral bool

	// Immutable marks a field mutators must leave alone, for magic numbers.
	Immutable bool

	// Elem names the element type of a repeat or opt.
	Elem string

	// Fields are the members of a struct or the alternatives of a choice.
	Fields []Field

	// Target names the type a ref points at.
	Target string

	// Pos is where the type was declared, for error messages.
	Pos Position
}

// Field is a named member of a struct or an alternative of a choice.
type Field struct {
	Name   string
	Type   *Type
	Derive *ir.Derivation
	Pos    Position
}

// Position locates a declaration in its source file.
type Position struct {
	File string
	Line int
	Col  int
}

func (p Position) String() string {
	if p.File == "" {
		return fmt.Sprintf("%d:%d", p.Line, p.Col)
	}
	return fmt.Sprintf("%s:%d:%d", p.File, p.Line, p.Col)
}

// Schema is a parsed and resolved format description.
//
// It is the authored counterpart to a codec: a codec knows how to *parse* an
// existing file, while a schema describes the shape well enough to *generate*
// one. Both produce the same IR, so a campaign can seed from a corpus, from a
// grammar, or from both at once (ADR-0005).
type Schema struct {
	// Root is the name of the format declaration.
	Root string

	// Types holds every declared type by name.
	Types map[string]*Type

	// File is the source path, for error messages.
	File string
}

// Lookup returns a declared type.
func (s *Schema) Lookup(name string) (*Type, bool) {
	t, ok := s.Types[name]
	return t, ok
}

// TypeNames lists the declared types, sorted.
func (s *Schema) TypeNames() []string {
	out := make([]string, 0, len(s.Types))
	for n := range s.Types {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// Validate checks that every reference resolves and that the schema is not
// unconditionally recursive.
//
// An unguarded cycle — a struct containing itself, directly or through other
// types — cannot be generated: every attempt to build one recurses forever. A
// cycle behind a repeat or an opt is fine, because those can stop.
func (s *Schema) Validate() error {
	if s.Root == "" {
		return fmt.Errorf("schema: no format declaration")
	}
	if _, ok := s.Types[s.Root]; !ok {
		return fmt.Errorf("schema: format %q is not declared", s.Root)
	}
	for _, name := range s.TypeNames() {
		if err := s.checkRefs(s.Types[name]); err != nil {
			return err
		}
	}
	return s.checkCycles()
}

func (s *Schema) checkRefs(t *Type) error {
	switch t.Kind {
	case KindRef:
		if _, ok := s.Types[t.Target]; !ok {
			return fmt.Errorf("%s: unknown type %q", t.Pos, t.Target)
		}
	case KindRepeat, KindOpt:
		if _, ok := s.Types[t.Elem]; !ok {
			return fmt.Errorf("%s: unknown element type %q", t.Pos, t.Elem)
		}
	}
	for _, f := range t.Fields {
		if err := s.checkRefs(f.Type); err != nil {
			return err
		}
	}
	return nil
}

// checkCycles reports a recursion that generation could not terminate.
func (s *Schema) checkCycles() error {
	const (
		white = 0
		grey  = 1
		black = 2
	)
	state := make(map[string]int, len(s.Types))
	var stack []string

	var visit func(name string) error
	visit = func(name string) error {
		switch state[name] {
		case grey:
			return fmt.Errorf("schema: unguarded recursion %s -> %s; put the recursive "+
				"field behind a repeat or an opt so generation can stop",
				strings.Join(stack, " -> "), name)
		case black:
			return nil
		}
		state[name] = grey
		stack = append(stack, name)
		defer func() {
			stack = stack[:len(stack)-1]
			state[name] = black
		}()

		t, ok := s.Types[name]
		if !ok {
			return nil
		}
		return s.walkUnguarded(t, visit)
	}

	for _, name := range s.TypeNames() {
		if state[name] == white {
			if err := visit(name); err != nil {
				return err
			}
		}
	}
	return nil
}

// walkUnguarded follows only the references generation must always expand.
// Repeat and opt can produce nothing, so recursion through them terminates.
func (s *Schema) walkUnguarded(t *Type, visit func(string) error) error {
	switch t.Kind {
	case KindRef:
		return visit(t.Target)
	case KindRepeat, KindOpt:
		return nil
	}
	for _, f := range t.Fields {
		if err := s.walkUnguarded(f.Type, visit); err != nil {
			return err
		}
	}
	return nil
}

// String renders the schema back to its source form, which makes a parsed
// schema reviewable and gives the tests a round-trip to check.
func (s *Schema) String() string {
	var b strings.Builder
	for _, name := range s.TypeNames() {
		t := s.Types[name]
		keyword := "struct"
		if name == s.Root {
			keyword = "format"
		}
		fmt.Fprintf(&b, "%s %s {\n", keyword, name)
		for _, f := range t.Fields {
			fmt.Fprintf(&b, "  %s: %s", f.Name, f.Type)
			switch {
			case f.Derive != nil:
				fmt.Fprintf(&b, " = %s", renderDerivation(f.Derive))
			case f.Type.HasLiteral && !f.Type.Immutable:
				// A magic field carries its literal in the type itself, so
				// re-emitting it would produce `magic = "..."`, which is not
				// syntax the language accepts.
				fmt.Fprintf(&b, " = %s", renderLiteral(f.Type))
			}
			b.WriteString("\n")
		}
		b.WriteString("}\n\n")
	}
	return strings.TrimRight(b.String(), "\n") + "\n"
}

func (t *Type) String() string {
	switch t.Kind {
	case KindInt:
		sign := "u"
		if t.Signed {
			sign = "i"
		}
		s := fmt.Sprintf("%s%d", sign, t.Width*8)
		if t.Width > 1 {
			if t.Endian == ir.LittleEndian {
				s += "le"
			} else {
				s += "be"
			}
		}
		return s
	case KindBytes, KindStr:
		base := "bytes"
		if t.Kind == KindStr {
			base = "str"
		}
		if t.Immutable {
			return "magic " + quote(t.Literal)
		}
		switch {
		case t.Min == t.Max && t.Max > 0:
			return fmt.Sprintf("%s[%d]", base, t.Max)
		case t.Max > 0 || t.Min > 0:
			return fmt.Sprintf("%s<%d..%d>", base, t.Min, t.Max)
		}
		return base
	case KindRepeat:
		if t.Max > 0 || t.Min > 0 {
			return fmt.Sprintf("repeat<%d..%d> %s", t.Min, t.Max, t.Elem)
		}
		return "repeat " + t.Elem
	case KindOpt:
		return "opt " + t.Elem
	case KindChoice:
		parts := make([]string, 0, len(t.Fields))
		for _, f := range t.Fields {
			parts = append(parts, f.Name+": "+f.Type.String())
		}
		return "choice { " + strings.Join(parts, ", ") + " }"
	case KindRef:
		return t.Target
	}
	return t.Kind.String()
}

func renderLiteral(t *Type) string {
	if t.Kind == KindInt {
		return fmt.Sprintf("%d", t.LiteralInt)
	}
	return quote(t.Literal)
}

func quote(b []byte) string {
	var s strings.Builder
	s.WriteByte('"')
	for _, c := range b {
		switch {
		case c == '"':
			s.WriteString(`\"`)
		case c == '\\':
			s.WriteString(`\\`)
		case c == '\n':
			s.WriteString(`\n`)
		case c == '\r':
			s.WriteString(`\r`)
		case c == '\t':
			s.WriteString(`\t`)
		case c < 0x20 || c > 0x7e:
			fmt.Fprintf(&s, `\x%02x`, c)
		default:
			s.WriteByte(c)
		}
	}
	s.WriteByte('"')
	return s.String()
}

// deriveKeywords maps a derivation class to the word the language uses for it.
// The ir names are not reused directly: ir calls the class "length" while the
// grammar spells it "len", and rendering the wrong one produces a schema that
// looks right and does not re-parse.
var deriveKeywords = map[ir.DeriveKind]string{
	ir.DeriveLength: "len",
	ir.DeriveCount:  "count",
	ir.DeriveOffset: "offset",
}

func renderDerivation(d *ir.Derivation) string {
	name := d.Algo
	if d.Kind != ir.DeriveChecksum {
		name = deriveKeywords[d.Kind]
	}
	s := name + "(" + d.From.String()
	if !d.To.IsZero() {
		s += ".." + d.To.String()
	}
	s += ")"
	if d.Addend != 0 {
		s += fmt.Sprintf(" %+d", d.Addend)
	}
	if d.SelfZero {
		s += " selfzero"
	}
	return s
}
