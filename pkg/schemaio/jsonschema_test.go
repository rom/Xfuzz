package schemaio_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/rom/Xfuzz/pkg/schemaio"
)

// A JSON Schema of the shape an API repository is full of: an object with
// required and optional members, a nested object behind a $ref, an array, an
// enum, and a handful of validation keywords that describe values rather than
// shapes.
const orderSchema = `{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "required": ["id", "items"],
  "properties": {
    "id":     {"type": "string", "minLength": 8, "maxLength": 36, "pattern": "^[a-f0-9-]+$"},
    "status": {"enum": ["new", "paid", "shipped"]},
    "total":  {"type": "number", "minimum": 0},
    "paid":   {"type": "boolean"},
    "items":  {"type": "array", "minItems": 1, "maxItems": 8, "items": {"$ref": "#/$defs/item"}},
    "note":   {"type": "string"}
  },
  "$defs": {
    "item": {
      "type": "object",
      "required": ["sku"],
      "properties": {
        "sku": {"type": "string"},
        "qty": {"type": "integer"}
      }
    }
  }
}`

func TestJSONSchemaGeneratesParseableJSON(t *testing.T) {
	s, rep := mustImport(t, schemaio.JSONSchema{}, orderSchema, "order.json")
	t.Logf("%s", rep)

	out := generates(t, s)
	t.Logf("generated: %s", out)
	// The claim the whole design rests on: the punctuation is immutable, so
	// what comes out of the grammar is a document a parser will read, and the
	// mutation happens inside the values.
	var v any
	if err := json.Unmarshal(out, &v); err != nil {
		t.Fatalf("the grammar generated text that is not JSON: %v\n%s", err, out)
	}
	obj, ok := v.(map[string]any)
	if !ok {
		t.Fatalf("the root generated a %T, want an object", v)
	}
	for _, required := range []string{"id", "items"} {
		if _, ok := obj[required]; !ok {
			t.Errorf("the required property %q is missing from %s", required, out)
		}
	}
	if _, ok := obj["items"].([]any); !ok {
		t.Errorf("items generated a %T, want an array", obj["items"])
	}
}

func TestJSONSchemaEnumBecomesAChoiceOfLiterals(t *testing.T) {
	s, _ := mustImport(t, schemaio.JSONSchema{},
		`{"type":"object","required":["status"],"properties":{"status":{"enum":["new","paid"]}}}`,
		"e.json")
	text := s.String()
	for _, want := range []string{`\"new\"`, `\"paid\"`} {
		if !strings.Contains(text, want) {
			t.Errorf("the enum literal %s is not in the grammar:\n%s", want, text)
		}
	}
}

// TestJSONSchemaReportsValidationKeywords is the distinction that matters
// between the two languages: JSON Schema says what a document must satisfy and
// this one says how to build one, and a predicate is not a construction.
func TestJSONSchemaReportsValidationKeywords(t *testing.T) {
	_, rep := mustImport(t, schemaio.JSONSchema{}, orderSchema, "order.json")
	joined := strings.Join(rep.Summarise(), "\n")
	for _, want := range []string{"pattern", "minimum"} {
		if !strings.Contains(joined, want) {
			t.Errorf("%q was not reported:\n%s", want, joined)
		}
	}
	if !strings.Contains(joined, "constraint solver") && !strings.Contains(joined, "inverting") {
		t.Errorf("the notes do not say why the keyword could not be used:\n%s", joined)
	}
}

// TestJSONSchemaRecursiveRefTerminates. A tree node whose children are tree
// nodes is legal, common, and the shape that makes a naive expander recurse
// until the stack runs out.
func TestJSONSchemaRecursiveRefTerminates(t *testing.T) {
	src := `{
	  "type": "object",
	  "properties": {
	    "name":     {"type": "string"},
	    "children": {"type": "array", "items": {"$ref": "#"}}
	  }
	}`
	s, _, err := schemaio.JSONSchema{}.Import([]byte(src), "tree.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Validate(); err != nil {
		t.Fatalf("a recursive document produced a schema that does not validate: %v", err)
	}
	generates(t, s)
}

func TestJSONSchemaOptionalPropertiesCanBeAbsent(t *testing.T) {
	s, _ := mustImport(t, schemaio.JSONSchema{}, orderSchema, "order.json")
	root, _ := s.Lookup(s.Root)
	var optional, required int
	for _, f := range root.Fields {
		switch f.Name {
		case "id", "items":
			required++
		case "status", "total", "paid", "note":
			optional++
			if f.Type.Kind.String() != "opt" {
				t.Errorf("the optional property %s became %s", f.Name, f.Type.Kind)
			}
		}
	}
	if required != 2 || optional != 4 {
		t.Errorf("found %d required and %d optional properties", required, optional)
	}
}

// TestJSONSchemaOptionalPropertyLeavesValidText is the reason the comma travels
// inside the member rather than between them: an absent property must not leave
// a dangling separator.
func TestJSONSchemaOptionalPropertyLeavesValidText(t *testing.T) {
	s, _ := mustImport(t, schemaio.JSONSchema{}, orderSchema, "order.json")
	for i := 0; i < 16; i++ {
		out := generates(t, s)
		var v any
		if err := json.Unmarshal(out, &v); err != nil {
			t.Fatalf("sample %d is not JSON: %v\n%s", i, err, out)
		}
	}
}

func TestJSONSchemaRefusesSomethingThatIsNotJSON(t *testing.T) {
	if _, _, err := (schemaio.JSONSchema{}).Import([]byte("not json"), "x.json"); err == nil {
		t.Error("a file that is not JSON imported successfully")
	}
}

func TestJSONSchemaIsDeterministic(t *testing.T) {
	first, _, err := schemaio.JSONSchema{}.Import([]byte(orderSchema), "o.json")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 8; i++ {
		got, _, err := schemaio.JSONSchema{}.Import([]byte(orderSchema), "o.json")
		if err != nil {
			t.Fatal(err)
		}
		if got.String() != first.String() {
			t.Fatalf("import %d differed:\n%s\n---\n%s", i+1, first, got)
		}
	}
}
