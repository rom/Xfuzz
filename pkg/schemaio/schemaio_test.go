package schemaio_test

import (
	"strings"
	"testing"

	"github.com/rom/Xfuzz/pkg/generate"
	"github.com/rom/Xfuzz/pkg/ir"
	"github.com/rom/Xfuzz/pkg/rng"
	"github.com/rom/Xfuzz/pkg/schema"
	"github.com/rom/Xfuzz/pkg/schemaio"
)

// Every import has to satisfy the same three things, and they are the three that
// make a grammar worth having. It has to be a valid schema, or nothing
// downstream will load it. It has to survive being written out and read back,
// or `xfuzz grammar import` produces a file the tool itself cannot open. And it
// has to generate something, or the campaign is running a grammar that emits
// nothing and calling it structured fuzzing.

// mustImport runs an importer and checks the three properties.
func mustImport(t *testing.T, imp schemaio.Importer, src, filename string) (*schema.Schema, *schemaio.Report) {
	t.Helper()
	s, rep, err := imp.Import([]byte(src), filename)
	if err != nil {
		t.Fatalf("%s: %v", imp.Name(), err)
	}
	if err := s.Validate(); err != nil {
		t.Fatalf("%s produced a schema that does not validate: %v", imp.Name(), err)
	}

	// Written out and read back. A grammar the tool cannot re-open is not a
	// grammar; this is also the only check that the renderer and the emitter
	// agree about what each construct means.
	text := s.String()
	back, err := schema.Parse([]byte(text), filename+".xfg")
	if err != nil {
		t.Fatalf("%s: the imported grammar does not re-parse: %v\n%s", imp.Name(), err, text)
	}
	if back.Root != s.Root {
		t.Errorf("%s: the root changed from %q to %q", imp.Name(), s.Root, back.Root)
	}
	if len(back.Types) != len(s.Types) {
		t.Errorf("%s: %d types became %d on re-parse", imp.Name(), len(s.Types), len(back.Types))
	}
	if got := back.String(); got != text {
		t.Errorf("%s: rendering is not stable across a round trip:\n%s\n---\n%s",
			imp.Name(), text, got)
	}
	return s, rep
}

// generates checks that the grammar produces something, the way the engine
// does: build a tree from the schema, run the fixup that computes the derived
// fields, encode it.
//
// A grammar that validates and generates nothing is the failure mode an
// importer has: every construct translated to something legal, and the result
// emits an empty file or refuses to build at all. Only running the generator
// catches it.
func generates(t *testing.T, s *schema.Schema) []byte {
	t.Helper()
	gen := generate.New(s)
	a := ir.NewArena()
	r := rng.New(1)
	tree, err := gen.Generate(a, r)
	if err != nil {
		t.Fatalf("the grammar does not generate: %v", err)
	}
	// The fixup is what makes a length field a length rather than a number: it
	// is the difference between a generated file a parser accepts and one it
	// rejects at the first field.
	if err := ir.Fixup(tree, ir.Suppress{}); err != nil {
		t.Fatalf("the generated tree could not be fixed up: %v", err)
	}
	out := ir.AppendEncode(nil, tree)
	if len(out) == 0 {
		t.Error("the grammar generated an empty input")
	}
	return out
}

func TestImporterRegistry(t *testing.T) {
	if len(schemaio.Importers()) == 0 {
		t.Fatal("no importers are registered")
	}
	for _, imp := range schemaio.Importers() {
		if imp.Name() == "" {
			t.Error("an importer has no name")
		}
		if len(imp.Extensions()) == 0 {
			t.Errorf("%s claims no file extensions, so Detect can never pick it", imp.Name())
		}
		for _, ext := range imp.Extensions() {
			if !strings.HasPrefix(ext, ".") {
				t.Errorf("%s claims extension %q, which is not one", imp.Name(), ext)
			}
		}
		if got, ok := schemaio.For(imp.Name()); !ok || got.Name() != imp.Name() {
			t.Errorf("For(%q) did not return it", imp.Name())
		}
	}
}

func TestReportSummarisesRatherThanLists(t *testing.T) {
	r := &schemaio.Report{Source: "test"}
	for i := 0; i < 40; i++ {
		r.Add("somewhere", "prose-val", "English is not a grammar")
	}
	r.Add("elsewhere", "oneof", "no discriminated union")
	if r.Complete() {
		t.Error("a report with notes claims the import was complete")
	}
	lines := r.Summarise()
	if len(lines) != 2 {
		t.Fatalf("41 notes summarised to %d lines: %v", len(lines), lines)
	}
	if !strings.Contains(strings.Join(lines, "\n"), "(40)") {
		t.Errorf("the summary does not count the repeats: %v", lines)
	}
}

func TestDetect(t *testing.T) {
	for _, tc := range []struct{ file, want string }{
		{"http.abnf", "abnf"},
	} {
		imp, ok := schemaio.Detect(tc.file, nil)
		if !ok {
			t.Errorf("nothing claims %s", tc.file)
			continue
		}
		if imp.Name() != tc.want {
			t.Errorf("%s went to %s, want %s", tc.file, imp.Name(), tc.want)
		}
	}
	if _, ok := schemaio.Detect("notes.txt", nil); ok {
		t.Error("something claimed a .txt file")
	}
}
