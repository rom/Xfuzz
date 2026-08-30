package campaign

import (
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"
)

// SchemaID is the published identifier of the campaign file schema.
const SchemaID = "https://xfuzz.dev/schema/campaign/v1.json"

// JSONSchema generates the campaign file's JSON Schema from the Go types.
//
// Generated rather than maintained, because the schema, the parser, and the
// documentation must agree and only one of them can be the source. A schema
// written by hand beside the structs drifts the first time a field is added,
// and a schema that says a field exists when the parser rejects it is worse than
// no schema: an editor will offer the field, and the campaign will fail to load.
//
// The generated document is checked in and a test asserts it matches, so drift
// is a build failure rather than a surprise (the same pattern as the licence
// inventory and the traceability matrix).
func JSONSchema() ([]byte, error) {
	s := schemaOf(reflect.TypeOf(File{}), map[string]bool{})
	s["$schema"] = "https://json-schema.org/draft/2020-12/schema"
	s["$id"] = SchemaID
	s["title"] = "Xfuzz campaign"
	s["description"] = "A campaign file is the only interface for defining what a campaign does (ADR-0016). " +
		"Every field is optional in the schema; what is actually required is reported by `xfuzz validate`, " +
		"which can say things a schema cannot — that a target path is executable, that a scope is present " +
		"when the campaign leaves the host, that a grammar exists."

	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// schemaOf builds the schema for one type.
//
// seen guards against the recursion File → Profiles → File, which is not a
// mistake: a profile is an overlay with exactly the shape of the file, so that
// it can adjust anything the file can set and nothing else.
func schemaOf(t reflect.Type, seen map[string]bool) map[string]any {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}

	// Checked before the kind switch: Duration is an int64 underneath but is
	// written and parsed as a string, and a schema that called it a number
	// would have editors offering integers for a field the parser refuses to
	// read as one.
	if t == reflect.TypeOf(Size(0)) {
		return map[string]any{
			"type":        []any{"string", "integer"},
			"description": "A byte count, plain or with a unit: 4096, 512KB, 64MB, 2GB.",
		}
	}
	if t == reflect.TypeOf(Duration(0)) {
		return map[string]any{
			"type":        "string",
			"pattern":     `^[0-9]+(\.[0-9]+)?(ns|us|ms|s|m|h|d)$`,
			"description": "A duration with a unit, such as 30s, 10m, 2h, or 7d.",
		}
	}

	switch t.Kind() {
	case reflect.Struct:
		name := t.Name()
		if seen[name] {
			// Self-reference. Emitted as a bare object rather than a $ref
			// because the only recursive case is Profiles, whose depth is one
			// in practice, and a $ref here would make the document harder to
			// read for no gain.
			return map[string]any{"type": "object"}
		}
		seen[name] = true
		defer delete(seen, name)

		props := map[string]any{}
		var required []string
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			if !f.IsExported() {
				continue
			}
			jsonName, omitempty := jsonFieldName(f)
			if jsonName == "" || jsonName == "-" {
				continue
			}
			sub := schemaOf(f.Type, seen)
			if doc := f.Tag.Get("doc"); doc != "" {
				sub["description"] = doc
			}
			props[jsonName] = sub
			if !omitempty {
				required = append(required, jsonName)
			}
		}
		out := map[string]any{
			"type":                 "object",
			"properties":           props,
			"additionalProperties": false,
		}
		if len(required) > 0 {
			sort.Strings(required)
			out["required"] = required
		}
		return out

	case reflect.Slice:
		return map[string]any{"type": "array", "items": schemaOf(t.Elem(), seen)}

	case reflect.Map:
		return map[string]any{
			"type":                 "object",
			"additionalProperties": schemaOf(t.Elem(), seen),
		}

	case reflect.String:
		return map[string]any{"type": "string"}

	case reflect.Bool:
		return map[string]any{"type": "boolean"}

	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return map[string]any{"type": "integer"}

	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return map[string]any{"type": "integer", "minimum": 0}

	case reflect.Float32, reflect.Float64:
		return map[string]any{"type": "number"}

	default:
		panic(fmt.Sprintf("campaign: no JSON Schema mapping for %s", t.Kind()))
	}
}

func jsonFieldName(f reflect.StructField) (name string, omitempty bool) {
	tag := f.Tag.Get("json")
	if tag == "" {
		return strings.ToLower(f.Name), true
	}
	name, opts, _ := strings.Cut(tag, ",")
	if name == "" {
		name = strings.ToLower(f.Name)
	}
	return name, strings.Contains(opts, "omitempty")
}
