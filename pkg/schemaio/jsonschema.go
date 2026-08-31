package schemaio

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/rom/Xfuzz/pkg/schema"
)

// JSONSchema imports a JSON Schema document.
//
// The output is a grammar for JSON *text*, which is the part worth saying out
// loud: JSON Schema describes a value tree, and a fuzzer sends bytes. So a
// property becomes a struct of a quoted name, a colon, and the value's own
// type, with the punctuation as immutable literals — which is what keeps a
// generated document parseable while its values are mutated freely, and is
// exactly the split a JSON parser's bugs live on either side of.
//
// It is a validation language, and validation and generation are not the same
// direction. "minimum: 100" is a predicate a generator would have to solve; a
// pattern is a regular expression a generator would have to invert. Those are
// reported. What translates is everything structural: type, properties,
// required, items, enum, const, $ref, oneOf and anyOf, and the length and count
// bounds, which are the same bounds this language has.
type JSONSchema struct{}

// Name implements Importer.
func (JSONSchema) Name() string { return "jsonschema" }

// Extensions implements Importer.
func (JSONSchema) Extensions() []string { return []string{".json", ".jsonschema"} }

// sniff implements sniffer, for the .json suffix three importers claim.
func (JSONSchema) sniff(head string) bool {
	return strings.Contains(head, `"$schema"`) || strings.Contains(head, `"$defs"`) ||
		strings.Contains(head, `"properties"`) || strings.Contains(head, `"definitions"`)
}

// Import implements Importer.
func (JSONSchema) Import(src []byte, filename string) (*schema.Schema, *Report, error) {
	var doc map[string]any
	if err := json.Unmarshal(src, &doc); err != nil {
		return nil, nil, fmt.Errorf("jsonschema: %s: %w", filename, err)
	}
	j := newJSONImport(newBuilder("jsonschema", filename), doc)
	root := j.declare("root", doc, "#")
	return j.b.finish(root)
}

type jsonImport struct {
	b    *builder
	root map[string]any

	// depth guards against a schema that refers to itself, which is legal and
	// common — a tree node whose children are tree nodes — and which would
	// otherwise recurse until the stack ran out.
	depth int

	// building tracks the $refs currently being expanded, so a cycle resolves to
	// the type already under construction instead of a second copy of it.
	building map[string]string
}

// newJSONImport returns a translator over a document.
//
// Shared with the OpenAPI importer, which needs exactly this over its own
// document: an operation's request body is a JSON Schema, and its $refs resolve
// against the whole description rather than against the fragment.
func newJSONImport(b *builder, root map[string]any) *jsonImport {
	return &jsonImport{b: b, root: root, building: map[string]string{}}
}

// maxJSONDepth bounds nesting. A document deeper than this is describing a
// recursive structure, and the schema language expresses recursion through a
// repeat or an opt, which the cycle handling below produces.
const maxJSONDepth = 24

// declare builds a named type from a JSON Schema object.
func (j *jsonImport) declare(name string, node map[string]any, where string) string {
	n := j.b.nameFor(name)
	j.b.s.Types[n] = wrap(j.typeFor(node, where, name))
	return n
}

func (j *jsonImport) typeFor(node map[string]any, where, hint string) *schema.Type {
	if node == nil {
		return j.anyValue(where)
	}
	j.depth++
	defer func() { j.depth-- }()
	if j.depth > maxJSONDepth {
		j.b.rep.Add(where, "nesting past the depth limit",
			fmt.Sprintf("deeper than %d levels; generated as a free JSON value", maxJSONDepth))
		return j.anyValue(where)
	}

	if ref, ok := node["$ref"].(string); ok {
		return j.resolveRef(ref, where, hint)
	}
	j.noteValidationOnly(node, where)

	if c, ok := node["const"]; ok {
		return magic(jsonLiteral(c))
	}
	if e, ok := node["enum"].([]any); ok && len(e) > 0 {
		fields := make([]schema.Field, 0, len(e))
		for i, v := range e {
			fields = append(fields, field(fmt.Sprintf("v%d", i+1), magic(jsonLiteral(v))))
		}
		return choiceOf(uniqueFields(fields)...)
	}
	for _, key := range []string{"oneOf", "anyOf"} {
		alts, ok := node[key].([]any)
		if !ok || len(alts) == 0 {
			continue
		}
		fields := make([]schema.Field, 0, len(alts))
		for i, a := range alts {
			m, _ := a.(map[string]any)
			fields = append(fields, field(fmt.Sprintf("alt%d", i+1),
				j.typeFor(m, fmt.Sprintf("%s/%s/%d", where, key, i), fmt.Sprintf("%s_alt%d", hint, i+1))))
		}
		return choiceOf(uniqueFields(fields)...)
	}
	if _, ok := node["allOf"]; ok {
		j.b.rep.Add(where, "allOf",
			"a value satisfying several schemas at once; the generator builds one "+
				"shape at a time, so only the first is used")
		if alts, ok := node["allOf"].([]any); ok && len(alts) > 0 {
			m, _ := alts[0].(map[string]any)
			return j.typeFor(m, where+"/allOf/0", hint)
		}
	}

	switch jsonTypeOf(node) {
	case "object":
		return j.objectType(node, where, hint)
	case "array":
		return j.arrayType(node, where, hint)
	case "string":
		return j.stringType(node, where)
	case "integer", "number":
		return j.numberType(node, where)
	case "boolean":
		return choiceOf(
			field("t", magic("true")),
			field("f", magic("false")),
		)
	case "null":
		return magic("null")
	}
	return j.anyValue(where)
}

// jsonTypeOf reads the type keyword, which may be a string or a list.
func jsonTypeOf(node map[string]any) string {
	switch t := node["type"].(type) {
	case string:
		return t
	case []any:
		if len(t) > 0 {
			if s, ok := t[0].(string); ok {
				return s
			}
		}
	}
	// A schema with properties and no type is an object, which is how most
	// hand-written documents are written.
	if _, ok := node["properties"]; ok {
		return "object"
	}
	if _, ok := node["items"]; ok {
		return "array"
	}
	return ""
}

// objectType builds the JSON text of an object.
//
// The braces, the quotes, the colons and the commas are immutable literals: a
// generated document whose punctuation a mutator may edit is a document the
// parser rejects at the first byte it reaches, and every execution after that
// is spent on the same rejection.
func (j *jsonImport) objectType(node map[string]any, where, hint string) *schema.Type {
	props, _ := node["properties"].(map[string]any)
	required := map[string]bool{}
	if req, ok := node["required"].([]any); ok {
		for _, r := range req {
			if s, ok := r.(string); ok {
				required[s] = true
			}
		}
	}

	// Required members first, then optional ones. The order is not arbitrary and
	// it is the only thing that makes the punctuation work: JSON puts a comma
	// *between* members, and "between" is not a shape a grammar can express when
	// either neighbour may be absent. Putting the comma at the front of every
	// member after the first, and guaranteeing that the first is always present,
	// turns a conditional separator into an unconditional one.
	names := sortedKeys(props)
	var must, may []string
	for _, key := range names {
		if required[key] {
			must = append(must, key)
			continue
		}
		may = append(may, key)
	}
	if len(must) == 0 && len(may) > 0 {
		// An object with no required properties still needs a first member, or
		// every optional one would carry a comma with nothing before it.
		j.b.rep.Add(where, "object with no required property",
			"the first property is generated unconditionally, because a leading "+
				"comma cannot be made conditional")
		must, may = may[:1], may[1:]
	}

	fields := []schema.Field{field("open", magic("{"))}
	member := func(key string, first bool) *schema.Type {
		m, _ := props[key].(map[string]any)
		parts := []schema.Field{
			field("name", magic(strconv.Quote(key)+":")),
			field("value", j.typeFor(m, where+"/properties/"+key, hint+"_"+key)),
		}
		if !first {
			parts = append([]schema.Field{field("comma", magic(","))}, parts...)
		}
		return structOf(uniqueFields(parts)...)
	}
	for i, key := range must {
		fields = append(fields, field(key, member(key, i == 0)))
	}
	for _, key := range may {
		elem := j.b.nameFor(hint + "_" + key + "_member")
		j.b.s.Types[elem] = member(key, false)
		fields = append(fields, field(key, optOf(elem)))
	}
	if len(names) == 0 {
		if _, ok := node["additionalProperties"]; ok {
			j.b.rep.Add(where, "additionalProperties with no properties",
				"the document constrains members it does not name; generated as an "+
					"empty object")
		}
	}
	fields = append(fields, field("close", magic("}")))
	return structOf(uniqueFields(fields)...)
}

func (j *jsonImport) arrayType(node map[string]any, where, hint string) *schema.Type {
	items, _ := node["items"].(map[string]any)
	elemType := j.typeFor(items, where+"/items", hint+"_item")

	// A JSON array's separator belongs between the elements, and a repeat has no
	// separator. Putting the comma before each element and the first element
	// outside the repeat is the shape that produces valid text.
	first := j.b.nameFor(hint + "_first")
	j.b.s.Types[first] = wrap(elemType)
	rest := j.b.nameFor(hint + "_rest")
	j.b.s.Types[rest] = structOf(field("comma", magic(",")), field("value", refTo(first)))

	minimum, maximum := 0, 4
	if v, ok := jsonInt(node["minItems"]); ok && v > 0 {
		minimum = v - 1 // the first element is outside the repeat
	}
	if v, ok := jsonInt(node["maxItems"]); ok && v > 0 {
		maximum = v - 1
	}
	if maximum < minimum {
		maximum = minimum
	}
	return structOf(
		field("open", magic("[")),
		field("first", refTo(first)),
		field("rest", repeatOf(rest, minimum, maximum)),
		field("close", magic("]")),
	)
}

func (j *jsonImport) stringType(node map[string]any, where string) *schema.Type {
	minimum, maximum := 0, 32
	if v, ok := jsonInt(node["minLength"]); ok {
		minimum = v
	}
	if v, ok := jsonInt(node["maxLength"]); ok && v > 0 {
		maximum = v
	}
	if maximum < minimum {
		maximum = minimum
	}
	if p, ok := node["pattern"].(string); ok {
		j.b.rep.Add(where, "pattern",
			"/"+trimTo(p, 40)+"/ is a regular expression; generating a string that "+
				"matches means inverting it, which this importer does not")
	}
	if f, ok := node["format"].(string); ok {
		j.b.rep.Add(where, "format "+f,
			"a named value constraint; the field is generated as a free string of "+
				"the right length")
	}
	// The quotes are literals so the value stays a string however it is
	// mutated. What a mutator may then produce inside them is an unescaped quote
	// or a lone backslash, which is a JSON parser's most productive input — and
	// the filler is there so that the *generated* document is valid before any
	// mutation, which is the baseline a campaign measures its findings against.
	return structOf(
		field("open", magic(`"`)),
		field("text", text(strings.Repeat("x", max(minimum, 1)), minimum, maximum)),
		field("close", magic(`"`)),
	)
}

func (j *jsonImport) numberType(node map[string]any, where string) *schema.Type {
	for _, k := range []string{"minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum", "multipleOf"} {
		if _, ok := node[k]; ok {
			j.b.rep.Add(where, k,
				"a value constraint; this language bounds lengths, so the number is "+
					"generated unconstrained")
		}
	}
	// Decimal text, not a binary integer: the document is JSON.
	return text("0", 1, 8)
}

// anyValue is a free JSON value, for the places a document says nothing.
func (j *jsonImport) anyValue(where string) *schema.Type {
	_ = where
	return structOf(
		field("open", magic(`"`)),
		field("text", text("x", 0, 16)),
		field("close", magic(`"`)),
	)
}

// resolveRef follows a local $ref.
func (j *jsonImport) resolveRef(ref, where, hint string) *schema.Type {
	if !strings.HasPrefix(ref, "#/") {
		j.b.rep.Add(where, "external $ref",
			ref+" points outside this document; the field is generated as a free value")
		return j.anyValue(where)
	}
	if name, ok := j.building[ref]; ok {
		// A cycle: the type is already being built, so pointing at it is both
		// correct and the only thing that terminates.
		return refTo(name)
	}
	node := j.follow(ref)
	if node == nil {
		j.b.rep.Add(where, "unresolved $ref",
			ref+" does not resolve inside this document")
		return j.anyValue(where)
	}
	base := ref[strings.LastIndexByte(ref, '/')+1:]
	name := j.b.nameFor(base)
	j.building[ref] = name
	j.b.s.Types[name] = wrap(j.typeFor(node, ref, base))
	delete(j.building, ref)
	return refTo(name)
}

// follow walks a JSON pointer from the document root.
func (j *jsonImport) follow(ref string) map[string]any {
	cur := any(j.root)
	for _, part := range strings.Split(strings.TrimPrefix(ref, "#/"), "/") {
		part = strings.ReplaceAll(strings.ReplaceAll(part, "~1", "/"), "~0", "~")
		m, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur, ok = m[part]
		if !ok {
			return nil
		}
	}
	out, _ := cur.(map[string]any)
	return out
}

// noteValidationOnly reports the keywords that constrain a value rather than
// describe its shape.
//
// The distinction is the whole difference between the two languages: JSON Schema
// says what a document must satisfy and this one says how to build one, and a
// predicate is not a construction. A generator honouring "minimum: 100" would be
// a constraint solver.
func (j *jsonImport) noteValidationOnly(node map[string]any, where string) {
	for _, k := range []string{"not", "if", "then", "else", "dependentSchemas",
		"propertyNames", "patternProperties", "uniqueItems", "contains"} {
		if _, ok := node[k]; ok {
			j.b.rep.Add(where, k,
				"a validation keyword with no construction; a generator honouring it "+
					"would be a constraint solver")
		}
	}
}

func jsonInt(v any) (int, bool) {
	switch n := v.(type) {
	case float64:
		return int(n), true
	case int:
		return n, true
	case json.Number:
		i, err := n.Int64()
		return int(i), err == nil
	}
	return 0, false
}

// jsonLiteral renders a value as the JSON text of it.
func jsonLiteral(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return "null"
	}
	return string(b)
}
