package schemaio_test

import (
	"strings"
	"testing"

	"github.com/rom/Xfuzz/pkg/codec"
	"github.com/rom/Xfuzz/pkg/ir"
	"github.com/rom/Xfuzz/pkg/schemaio"
)

// An OpenAPI document of the shape a service repository carries: a couple of
// operations, a path template, a query parameter, a header, a JSON request body
// behind a component reference, and one operation whose body is not JSON.
const ordersOpenAPI = `
openapi: 3.0.3
info:
  title: orders
  version: "1.0"
servers:
  - url: https://api.example.com/v1
paths:
  /items:
    get:
      operationId: listItems
      parameters:
        - name: limit
          in: query
          schema: {type: integer}
        - name: cursor
          in: query
          required: true
          schema: {type: string, example: "abc"}
    post:
      operationId: createItem
      parameters:
        - name: X-Request-Id
          in: header
          required: true
          schema: {type: string, example: "r-1"}
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/Item'
  /items/{itemId}:
    parameters:
      - name: itemId
        in: path
        required: true
        schema: {type: string, minLength: 4, example: "abcd"}
    get:
      operationId: getItem
    delete:
      operationId: deleteItem
  /upload:
    post:
      operationId: upload
      requestBody:
        content:
          application/octet-stream:
            schema: {type: string, format: binary}
components:
  schemas:
    Item:
      type: object
      required: [sku]
      properties:
        sku: {type: string, minLength: 3}
        qty: {type: integer}
`

func TestOpenAPIGeneratesRequestsTheCodecCanRead(t *testing.T) {
	s, rep := mustImport(t, schemaio.OpenAPI{}, ordersOpenAPI, "orders.yaml")
	t.Logf("%s", rep)

	// Sixteen samples through the HTTP codec, which is what the API tier uses:
	// a grammar that produces text the tier cannot split into requests is a
	// grammar that sends one malformed message and stops.
	for i := 0; i < 16; i++ {
		out := generates(t, s)
		if i == 0 {
			t.Logf("generated:\n%s", out)
		}
		a := ir.NewArena()
		tree, err := codec.HTTP{}.Decode(a, out)
		if err != nil {
			t.Fatalf("sample %d is not an HTTP request the codec can read: %v\n%s", i, err, out)
		}
		if len(tree.Children) != 1 {
			t.Errorf("sample %d parsed as %d requests:\n%s", i, len(tree.Children), out)
		}
		if !strings.HasSuffix(string(out), "\r\n") && !strings.Contains(string(out), "\r\n\r\n") {
			t.Errorf("sample %d has no header terminator:\n%s", i, out)
		}
	}
}

func TestOpenAPICoversEveryOperation(t *testing.T) {
	s, _ := mustImport(t, schemaio.OpenAPI{}, ordersOpenAPI, "orders.yaml")
	for _, op := range []string{"listItems", "createItem", "getItem", "deleteItem", "upload"} {
		if _, ok := s.Lookup(op); !ok {
			t.Errorf("the operation %s is not in the grammar", op)
		}
	}
	// One grammar covering the whole API, so a mutation that switches the
	// alternative sends a different endpoint with the corpus's accumulated body
	// shapes behind it.
	root, _ := s.Lookup(s.Root)
	choice := root.Fields[0].Type
	if choice.Kind.String() != "choice" || len(choice.Fields) != 5 {
		t.Errorf("the root is %s over %d operations, want a choice over 5",
			choice.Kind, len(choice.Fields))
	}
}

// TestOpenAPIPathParameterIsAValueNotALiteral. /items/{id} is where the
// identifier-shaped bugs are, and a grammar that froze the template's example
// would never send a different one.
func TestOpenAPIPathParameterIsAValueNotALiteral(t *testing.T) {
	s, _ := mustImport(t, schemaio.OpenAPI{}, ordersOpenAPI, "orders.yaml")
	get, ok := s.Lookup("getItem")
	if !ok {
		t.Fatal("getItem is missing")
	}
	var found bool
	for _, f := range get.Fields {
		if f.Name != "itemId" {
			continue
		}
		found = true
		if f.Type.Immutable {
			t.Error("the path parameter is immutable, so no campaign will ever change it")
		}
		if f.Type.Min != 4 {
			t.Errorf("minLength: 4 became min %d", f.Type.Min)
		}
	}
	if !found {
		t.Errorf("the path template's parameter is not a field:\n%s", get)
	}
}

func TestOpenAPIRequiredAndOptionalQueryParameters(t *testing.T) {
	s, _ := mustImport(t, schemaio.OpenAPI{}, ordersOpenAPI, "orders.yaml")
	list, _ := s.Lookup("listItems")
	var hasQuery bool
	for _, f := range list.Fields {
		if f.Name == "query" {
			hasQuery = true
		}
	}
	if !hasQuery {
		t.Errorf("listItems has no query string:\n%s", s)
	}
	// Whichever the generator chooses to include, the request has to remain
	// routable: no dangling ampersand and no question mark with nothing after it.
	for i := 0; i < 16; i++ {
		out := string(generates(t, s))
		for _, bad := range []string{"?&", "&&", "& ", "? "} {
			if strings.Contains(out, bad) {
				t.Fatalf("a query string with %q survived:\n%s", bad, out)
			}
		}
	}
}

// TestOpenAPIReportsTheLengthItCannotDerive is the honest half of the HTTP
// envelope: a decimal Content-Length is not a fixed-width integer, so the
// grammar cannot compute it, and the tier's own option is what does.
func TestOpenAPIReportsTheLengthItCannotDerive(t *testing.T) {
	_, rep := mustImport(t, schemaio.OpenAPI{}, ordersOpenAPI, "orders.yaml")
	joined := strings.Join(rep.Summarise(), "\n")
	if !strings.Contains(joined, "Content-Length") {
		t.Errorf("the length was not reported:\n%s", joined)
	}
	if !strings.Contains(joined, "fix-length") {
		t.Errorf("the note does not say what to do about it:\n%s", joined)
	}
	if !strings.Contains(joined, "octet-stream") {
		t.Errorf("the non-JSON request body was not reported:\n%s", joined)
	}
}

func TestOpenAPIRefusesADocumentWithNoPaths(t *testing.T) {
	if _, _, err := (schemaio.OpenAPI{}).Import(
		[]byte("openapi: 3.0.0\ninfo:\n  title: x\n"), "x.yaml"); err == nil {
		t.Error("a document with no paths imported successfully")
	}
}

func TestOpenAPIDetection(t *testing.T) {
	imp, ok := schemaio.Detect("api.yaml", []byte(ordersOpenAPI))
	if !ok || imp.Name() != "openapi" {
		t.Errorf("an OpenAPI document went to %v", imp)
	}
	// The extension three importers claim resolves by content.
	imp, ok = schemaio.Detect("api.json", []byte(`{"openapi":"3.0.0","paths":{}}`))
	if !ok || imp.Name() != "openapi" {
		t.Errorf("an OpenAPI document in .json went to %v", imp)
	}
	imp, ok = schemaio.Detect("thing.json", []byte(`{"$schema":"x","type":"object"}`))
	if !ok || imp.Name() != "jsonschema" {
		t.Errorf("a JSON Schema in .json went to %v", imp)
	}
}

func TestOpenAPIIsDeterministic(t *testing.T) {
	first, _, err := schemaio.OpenAPI{}.Import([]byte(ordersOpenAPI), "o.yaml")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 8; i++ {
		got, _, err := schemaio.OpenAPI{}.Import([]byte(ordersOpenAPI), "o.yaml")
		if err != nil {
			t.Fatal(err)
		}
		if got.String() != first.String() {
			t.Fatalf("import %d differed:\n%s\n---\n%s", i+1, first, got)
		}
	}
}
