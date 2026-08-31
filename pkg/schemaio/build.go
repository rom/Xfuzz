package schemaio

import (
	"fmt"
	"sort"
	"strings"

	"github.com/rom/Xfuzz/pkg/ir"
	"github.com/rom/Xfuzz/pkg/schema"
)

// builder accumulates a schema, keeping its type names valid and unique.
//
// Every importer needs the same three things and gets them wrong differently
// without this: a name from a foreign language may not be an identifier here, a
// name may collide with one the schema language already means, and two
// declarations in the source may translate to the same name. A schema with a
// type called "bytes" parses and refers to something else entirely.
type builder struct {
	s     *schema.Schema
	used  map[string]bool
	taken map[string]string // source name -> assigned name
	rep   *Report
}

func newBuilder(source, file string) *builder {
	return &builder{
		s:     &schema.Schema{Types: map[string]*schema.Type{}, File: file},
		used:  map[string]bool{},
		taken: map[string]string{},
		rep:   &Report{Source: source, File: file},
	}
}

// reserved are the words the grammar already means. A type with one of these
// names is unreachable: the parser resolves the keyword first, so a field
// declared as that type gets the built-in and the declaration is silently dead.
var reserved = func() map[string]bool {
	m := map[string]bool{
		"format": true, "struct": true, "bytes": true, "str": true,
		"repeat": true, "opt": true, "choice": true, "magic": true,
		"len": true, "count": true, "offset": true, "crc32": true,
	}
	for _, n := range schema.IntTypeNames() {
		m[n] = true
	}
	return m
}()

// ident turns a name from the source language into an identifier.
func ident(raw string) string {
	var b strings.Builder
	for i, r := range raw {
		switch {
		case r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r == '_':
			b.WriteRune(r)
		case r >= '0' && r <= '9' && i > 0:
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	s := strings.Trim(b.String(), "_")
	if s == "" {
		return "x"
	}
	if c := s[0]; c >= '0' && c <= '9' {
		s = "x" + s
	}
	return s
}

// nameFor returns the identifier a source name maps to, allocating one on first
// use so that two references to the same source name agree.
func (b *builder) nameFor(raw string) string {
	if n, ok := b.taken[raw]; ok {
		return n
	}
	n := ident(raw)
	if reserved[n] {
		n = "t_" + n
	}
	base := n
	for i := 2; b.used[n]; i++ {
		n = fmt.Sprintf("%s_%d", base, i)
	}
	b.used[n] = true
	b.taken[raw] = n
	return n
}

// declare adds a type under the identifier for a source name and returns it.
func (b *builder) declare(raw string, t *schema.Type) string {
	n := b.nameFor(raw)
	b.s.Types[n] = t
	return n
}

// finish resolves the root, counts what was produced and validates.
func (b *builder) finish(root string) (*schema.Schema, *Report, error) {
	if root == "" || b.s.Types[root] == nil {
		return nil, nil, fmt.Errorf("schemaio: the import produced no root type")
	}
	b.s.Root = root
	b.flattenInline()
	b.noteUnreachable()
	b.rep.Types = len(b.s.Types)
	for _, t := range b.s.Types {
		b.rep.Fields += len(t.Fields)
	}
	if err := b.s.Validate(); err != nil {
		return nil, b.rep, fmt.Errorf("schemaio: the imported schema is not usable: %w", err)
	}
	return b.s, b.rep, nil
}

// flattenInline gives every anonymous struct a name.
//
// The grammar language has no inline struct: a field's type may be a scalar, a
// bytes run, a choice, a repeat, an opt or a named type, and a struct only ever
// appears as a declaration. So a translation that nested one — a JSON object
// inside a JSON object, an ABNF concatenation inside an alternation — produces a
// schema that is correct in memory and renders as the word "struct", which is
// not a type the parser knows.
//
// Done once, here, rather than at each of the twenty places an importer builds
// a field: this is the kind of rule that is remembered in five of them.
func (b *builder) flattenInline() {
	// To a fixpoint, because an extracted struct may itself hold one.
	for pass := 0; pass < 64; pass++ {
		changed := false
		for _, owner := range sortedKeys(b.s.Types) {
			t := b.s.Types[owner]
			if b.extractFrom(owner, t) {
				changed = true
			}
		}
		if !changed {
			return
		}
	}
}

// extractFrom replaces every struct-typed field of t with a reference to a
// newly declared type, and reports whether it changed anything.
//
// It descends through the types that stay inline — a choice's alternatives are
// written inside it — because a struct nested two levels down is just as
// unwritable as one nested at the top, and a oneof of message fields is exactly
// that shape.
func (b *builder) extractFrom(owner string, t *schema.Type) bool {
	if t == nil || len(t.Fields) == 0 {
		return false
	}
	changed := false
	for i := range t.Fields {
		ft := t.Fields[i].Type
		if ft == nil {
			continue
		}
		if ft.Kind == schema.KindStruct {
			name := b.nameFor(owner + "_" + t.Fields[i].Name)
			b.s.Types[name] = ft
			t.Fields[i].Type = refTo(name)
			changed = true
			continue
		}
		if ft.Kind == schema.KindChoice {
			if b.extractFrom(owner+"_"+t.Fields[i].Name, ft) {
				changed = true
			}
		}
	}
	return changed
}

// noteUnreachable reports the declared types the root cannot reach.
//
// Not an error and not removed. A description usually has several entry points
// — an RFC states a grammar for a request and another for a response, a .proto
// declares every message a service exchanges — and only one of them can be the
// root of a schema. Dropping the rest would throw away most of the file; leaving
// them silently would let somebody run a campaign against the wrong entry point
// and never know. So they stay, and the report says which, and Reroot changes
// the choice.
func (b *builder) noteUnreachable() {
	live := b.reachable()
	for _, name := range sortedKeys(b.s.Types) {
		if live[name] {
			continue
		}
		b.rep.Add(name, "not reachable from the root",
			"the description has more than one entry point; this one is generated from "+
				b.s.Root+", and xfuzz grammar import --root selects another")
	}
}

// reachable returns the set of types the root can reach.
func (b *builder) reachable() map[string]bool {
	live := map[string]bool{}
	var walk func(name string)
	walk = func(name string) {
		if live[name] {
			return
		}
		t, ok := b.s.Types[name]
		if !ok {
			return
		}
		live[name] = true
		var visit func(*schema.Type)
		visit = func(t *schema.Type) {
			if t == nil {
				return
			}
			if t.Target != "" {
				walk(t.Target)
			}
			if t.Elem != "" {
				walk(t.Elem)
			}
			for _, f := range t.Fields {
				visit(f.Type)
			}
		}
		visit(t)
	}
	walk(b.s.Root)
	return live
}

// Reroot changes which type a schema generates from.
//
// The counterpart to the unreachable-type note: an importer picks a root by a
// convention its source language cannot state, and this is how somebody
// overrides it without editing the grammar by hand.
func Reroot(s *schema.Schema, name string) error {
	if _, ok := s.Lookup(name); !ok {
		return fmt.Errorf("schemaio: %q is not a type in this grammar; it declares %s",
			name, strings.Join(s.TypeNames(), ", "))
	}
	s.Root = name
	return s.Validate()
}

// --- type constructors ------------------------------------------------------

// magic returns a fixed, immutable literal: a tag, a delimiter, a keyword.
//
// Immutable rather than merely initialised. A magic number a mutator may edit
// is a magic number the target rejects on the first byte, and every execution
// after that is wasted (ADR-0005).
func magic(lit string) *schema.Type {
	return &schema.Type{
		Kind: schema.KindBytes, Literal: []byte(lit), HasLiteral: true,
		Immutable: true, Min: len(lit), Max: len(lit),
	}
}

// text returns an editable string field with a starting value.
func text(lit string, minimum, maximum int) *schema.Type {
	t := &schema.Type{Kind: schema.KindStr, Min: minimum, Max: maximum}
	if lit != "" {
		t.Literal, t.HasLiteral = []byte(lit), true
	}
	return t
}

func bytesOf(minimum, maximum int) *schema.Type {
	return &schema.Type{Kind: schema.KindBytes, Min: minimum, Max: maximum}
}

func intOf(width uint8, e ir.Endian, signed bool) *schema.Type {
	return &schema.Type{Kind: schema.KindInt, Width: width, Endian: e, Signed: signed}
}

func structOf(fields ...schema.Field) *schema.Type {
	return &schema.Type{Kind: schema.KindStruct, Fields: fields}
}

func choiceOf(fields ...schema.Field) *schema.Type {
	return &schema.Type{Kind: schema.KindChoice, Fields: fields}
}

// UnboundedRepeatMax is the upper bound given to a repetition whose source has
// none.
//
// The grammar language requires both bounds where either is written, so "one or
// more" has to become "one to something". Sixty-four is well past what any
// parser distinguishes structurally and small enough that a generated input
// stays a plausible one; a campaign that needs longer edits the grammar, which
// is why every import reports how many repetitions this affected.
const UnboundedRepeatMax = 64

func repeatOf(elem string, minimum, maximum int) *schema.Type {
	return &schema.Type{Kind: schema.KindRepeat, Elem: elem, Min: minimum, Max: maximum}
}

// wrap makes a type declarable at the top level.
//
// Only a struct can be a named declaration in the grammar language, so a rule
// whose whole body is a choice, a repetition or a literal needs a struct around
// it. Without this the renderer writes the alternatives of a choice as the
// fields of a struct, which parses, means concatenation, and is silently a
// different grammar.
func wrap(t *schema.Type) *schema.Type {
	if t == nil {
		return structOf()
	}
	if t.Kind == schema.KindStruct {
		return t
	}
	return structOf(field("value", t))
}

func optOf(elem string) *schema.Type {
	return &schema.Type{Kind: schema.KindOpt, Elem: elem}
}

func refTo(target string) *schema.Type {
	return &schema.Type{Kind: schema.KindRef, Target: target}
}

func field(name string, t *schema.Type) schema.Field {
	return schema.Field{Name: ident(name), Type: t}
}

// lengthField returns an integer field derived from the length of another.
func lengthField(name string, width uint8, e ir.Endian, of string) schema.Field {
	f := field(name, intOf(width, e, false))
	f.Derive = &ir.Derivation{Kind: ir.DeriveLength, From: ir.Sibling(ident(of))}
	return f
}

// countField returns an integer field derived from the element count of a
// repeat.
func countField(name string, width uint8, e ir.Endian, of string) schema.Field {
	f := field(name, intOf(width, e, false))
	f.Derive = &ir.Derivation{Kind: ir.DeriveCount, From: ir.Sibling(ident(of))}
	return f
}

// uniqueFields renames duplicates, which a foreign language may permit and this
// one may not.
func uniqueFields(fields []schema.Field) []schema.Field {
	seen := map[string]int{}
	for i := range fields {
		n := fields[i].Name
		if n == "" {
			n = "f"
		}
		if k := seen[n]; k > 0 {
			fields[i].Name = fmt.Sprintf("%s_%d", n, k+1)
		} else {
			fields[i].Name = n
		}
		seen[n]++
	}
	return fields
}

// sortedKeys is for every importer that reads a map, so that two runs over the
// same document produce the same schema (ASR-0008).
func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
