package campaign

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const schemaPath = "schema/campaign.v1.json"

// TestPublishedSchemaIsCurrent is the drift guard.
//
// A schema nobody regenerates is a schema that lies, and it lies in the worst
// direction: an editor offers a field the parser rejects, and the campaign fails
// to load with an error about the thing the tool told the user to write.
func TestPublishedSchemaIsCurrent(t *testing.T) {
	want, err := JSONSchema()
	if err != nil {
		t.Fatalf("generating the schema: %v", err)
	}
	got, err := os.ReadFile(schemaPath)
	if err != nil {
		t.Fatalf("reading the published schema: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("%s is out of date; regenerate it with\n\n\tgo run ./pkg/campaign/gen_schema.go\n", schemaPath)
	}
}

// TestSchemaCoversEveryField asserts the generated schema describes the same
// fields the parser accepts. The two are generated from one set of structs, so
// this is really a check that nothing has been excluded by a tag.
func TestSchemaCoversEveryField(t *testing.T) {
	b, err := JSONSchema()
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	props, ok := doc["properties"].(map[string]any)
	if !ok {
		t.Fatal("the schema has no properties")
	}
	for _, want := range []string{
		"name", "description", "include", "profiles", "target", "seeds", "format",
		"mutation", "feedback", "workers", "safety", "storage", "triage", "stop",
	} {
		if _, ok := props[want]; !ok {
			t.Errorf("the schema omits the top-level field %q", want)
		}
	}

	target, ok := props["target"].(map[string]any)
	if !ok {
		t.Fatal("target is not an object")
	}
	if target["additionalProperties"] != false {
		t.Error("the schema permits unknown keys under target, but the parser rejects them")
	}
	tp, _ := target["properties"].(map[string]any)
	path, _ := tp["path"].(map[string]any)
	if path["description"] == nil {
		t.Error("target.path has no description; the doc tags are not reaching the schema")
	}
}

// TestSchemaDescribesDurationsAsStrings — a duration is written "30s", and a
// schema that called it a number would have editors offering integers for a
// field the parser refuses to read as one.
func TestSchemaDescribesDurationsAsStrings(t *testing.T) {
	b, err := JSONSchema()
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	props := doc["properties"].(map[string]any)
	target := props["target"].(map[string]any)["properties"].(map[string]any)
	timeout := target["timeout"].(map[string]any)
	if timeout["type"] != "string" {
		t.Fatalf("target.timeout is described as %v, not a string", timeout["type"])
	}
	if !strings.Contains(timeout["pattern"].(string), "d)") {
		t.Errorf("the duration pattern does not admit the day unit: %v", timeout["pattern"])
	}
}

// TestExampleCampaignIsValid keeps the documented example honest. An example
// that does not load is worse than none: it is the first thing a new user
// copies.
func TestExampleCampaignIsValid(t *testing.T) {
	dir := t.TempDir()
	target(t, dir)
	if err := os.MkdirAll(filepath.Join(dir, "seeds"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "seeds", "a"), []byte("seed"), 0o644); err != nil {
		t.Fatal(err)
	}

	src, err := os.ReadFile("testdata/example.yaml")
	if err != nil {
		t.Fatalf("reading the example: %v", err)
	}
	path := filepath.Join(dir, "example.yaml")
	if err := os.WriteFile(path, src, 0o644); err != nil {
		t.Fatal(err)
	}

	r, err := Load(path)
	if err != nil {
		t.Fatalf("the documented example does not load:\n%v", err)
	}
	if r.Name == "" || r.Target.Path == "" {
		t.Fatal("the example resolved to something empty")
	}

	// And each of its profiles.
	var f File
	if err := yamlUnmarshal(src, &f); err != nil {
		t.Fatal(err)
	}
	for name := range f.Profiles {
		if _, err := Load(path, name); err != nil {
			t.Errorf("the example's %q profile does not resolve: %v", name, err)
		}
	}
}
