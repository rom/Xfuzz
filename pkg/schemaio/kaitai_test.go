package schemaio_test

import (
	"strings"
	"testing"

	"github.com/rom/Xfuzz/pkg/ir"
	"github.com/rom/Xfuzz/pkg/schema"
	"github.com/rom/Xfuzz/pkg/schemaio"
)

// A .ksy of the shape the Kaitai gallery is full of: a magic, a fixed header, a
// length-prefixed payload, a counted sequence of records, a nested type and a
// tagged union.
const gifKSY = `
meta:
  id: tiny_gif
  endian: le
seq:
  - id: magic
    contents: 'GIF'
  - id: version
    size: 3
  - id: width
    type: u2
  - id: height
    type: u2
  - id: flags
    type: u1
  - id: comment_len
    type: u1
  - id: comment
    size: comment_len
  - id: block_count
    type: u1
  - id: blocks
    type: block
    repeat: expr
    repeat-expr: block_count
types:
  block:
    seq:
      - id: kind
        type: u1
      - id: body
        type:
          switch-on: kind
          cases:
            1: image
            2: extension
  image:
    seq:
      - id: left
        type: u2
      - id: top
        type: u2
  extension:
    seq:
      - id: label
        type: u1
      - id: data
        size: 4
`

func TestKaitaiImportsABinaryFormat(t *testing.T) {
	s, rep := mustImport(t, schemaio.Kaitai{}, gifKSY, "tiny_gif.ksy")
	t.Logf("%s", rep)
	t.Logf("%s", s)

	if s.Root != "tiny_gif" {
		t.Errorf("the root is %q, want the meta.id", s.Root)
	}
	root, _ := s.Lookup("tiny_gif")

	byName := map[string]schema.Field{}
	for _, f := range root.Fields {
		byName[f.Name] = f
	}
	if got := byName["magic"].Type; !got.Immutable || string(got.Literal) != "GIF" {
		t.Errorf("the magic became %s", got)
	}
	if got := byName["width"].Type; got.Kind != schema.KindInt || got.Width != 2 ||
		got.Endian != ir.LittleEndian {
		t.Errorf("u2 under meta.endian: le became %s", got)
	}
	if got := byName["version"].Type; got.Min != 3 || got.Max != 3 {
		t.Errorf("size: 3 became %s", got)
	}
	generates(t, s)
}

// TestKaitaiInvertsTheLengthReference is the translation that decides whether a
// generated file has correct lengths or plausible ones. Kaitai writes the length
// on the *payload*, naming the field that holds it; this language writes it on
// the *length field*, naming the payload.
func TestKaitaiInvertsTheLengthReference(t *testing.T) {
	s, _ := mustImport(t, schemaio.Kaitai{}, gifKSY, "tiny_gif.ksy")
	root, _ := s.Lookup("tiny_gif")

	var lenField, countField *schema.Field
	for i := range root.Fields {
		switch root.Fields[i].Name {
		case "comment_len":
			lenField = &root.Fields[i]
		case "block_count":
			countField = &root.Fields[i]
		}
	}
	if lenField == nil || lenField.Derive == nil {
		t.Fatalf("size: comment_len did not become a length derivation on comment_len")
	}
	if lenField.Derive.Kind != ir.DeriveLength {
		t.Errorf("comment_len derives %s", lenField.Derive.Kind)
	}
	if got := lenField.Derive.From.String(); !strings.Contains(got, "comment") {
		t.Errorf("comment_len derives from %q, want the comment field", got)
	}
	if countField == nil || countField.Derive == nil ||
		countField.Derive.Kind != ir.DeriveCount {
		t.Fatal("repeat-expr: block_count did not become a count derivation")
	}
}

// TestKaitaiGeneratesCorrectLengths is the same claim measured rather than
// inspected: a file built from the grammar has a length field that agrees with
// the field it describes.
func TestKaitaiGeneratesCorrectLengths(t *testing.T) {
	s, _ := mustImport(t, schemaio.Kaitai{}, gifKSY, "tiny_gif.ksy")
	out := generates(t, s)
	if len(out) < 12 {
		t.Fatalf("the grammar generated %d bytes", len(out))
	}
	// GIF(3) version(3) width(2) height(2) flags(1) comment_len(1) comment(n)
	commentLen := int(out[11])
	if got := len(out); got < 12+commentLen {
		t.Fatalf("the declared comment length %d does not fit in %d bytes", commentLen, got)
	}
	if string(out[:3]) != "GIF" {
		t.Errorf("the magic is %q", out[:3])
	}
}

func TestKaitaiSwitchOnBecomesAChoice(t *testing.T) {
	s, rep := mustImport(t, schemaio.Kaitai{}, gifKSY, "tiny_gif.ksy")
	block, ok := s.Lookup("block")
	if !ok {
		t.Fatal("the nested type block was not declared")
	}
	var body *schema.Type
	for _, f := range block.Fields {
		if f.Name == "body" {
			body = f.Type
		}
	}
	if body == nil || body.Kind != schema.KindChoice {
		t.Fatalf("switch-on became %v", body)
	}
	if len(body.Fields) != 2 {
		t.Errorf("the choice has %d alternatives, want 2", len(body.Fields))
	}
	// The tag that selects between them is exactly what does not survive, and
	// the report has to say so rather than leave somebody to find out from a
	// campaign that never gets past the first block.
	if !strings.Contains(strings.Join(rep.Summarise(), "\n"), "switch-on") {
		t.Errorf("the untied tag was not reported:\n%s", rep)
	}
}

func TestKaitaiReportsWhatItCannotTranslate(t *testing.T) {
	src := `
meta:
  id: awkward
  endian: be
seq:
  - id: flags
    type: b4
  - id: ratio
    type: f4
  - id: name
    type: strz
  - id: body
    size-eos: true
    if: flags > 0
  - id: items
    type: u1
    repeat: until
    repeat-until: _ == 0
instances:
  total:
    value: 'flags + ratio'
`
	s, rep := mustImport(t, schemaio.Kaitai{}, src, "awkward.ksy")
	joined := strings.Join(rep.Summarise(), "\n")
	for _, want := range []string{"bit field", "floating-point", "strz", "conditional", "repeat-until", "instance"} {
		if !strings.Contains(joined, want) {
			t.Errorf("%q was not reported:\n%s", want, joined)
		}
	}
	// And it still produced a usable grammar rather than giving up.
	generates(t, s)
}

func TestKaitaiConditionalBecomesOptional(t *testing.T) {
	src := "meta:\n  id: c\nseq:\n  - id: a\n    type: u1\n  - id: b\n    type: u1\n    if: a > 0\n"
	s, _ := mustImport(t, schemaio.Kaitai{}, src, "c.ksy")
	root, _ := s.Lookup("c")
	if got := root.Fields[1].Type; got.Kind != schema.KindOpt {
		t.Errorf("a conditional field became %s, want an opt", got.Kind)
	}
}

func TestKaitaiContentsAcceptsAByteList(t *testing.T) {
	src := "meta:\n  id: c\nseq:\n  - id: m\n    contents: [0x89, 'PNG', 0x0d, 0x0a]\n"
	s, _ := mustImport(t, schemaio.Kaitai{}, src, "c.ksy")
	root, _ := s.Lookup("c")
	if got := string(root.Fields[0].Type.Literal); got != "\x89PNG\r\n" {
		t.Errorf("the contents list became %q", got)
	}
}

func TestKaitaiEndianSuffixOverridesTheDefault(t *testing.T) {
	src := "meta:\n  id: c\n  endian: le\nseq:\n  - id: a\n    type: u4\n  - id: b\n    type: u4be\n"
	s, _ := mustImport(t, schemaio.Kaitai{}, src, "c.ksy")
	root, _ := s.Lookup("c")
	if root.Fields[0].Type.Endian != ir.LittleEndian {
		t.Error("u4 did not take meta.endian")
	}
	if root.Fields[1].Type.Endian != ir.BigEndian {
		t.Error("u4be did not override meta.endian")
	}
}

func TestKaitaiRefusesADefinitionWithNoID(t *testing.T) {
	if _, _, err := (schemaio.Kaitai{}).Import([]byte("seq:\n  - id: a\n"), "x.ksy"); err == nil {
		t.Error("a definition with no meta.id imported successfully")
	}
}

func TestKaitaiIsDeterministic(t *testing.T) {
	first, _, err := schemaio.Kaitai{}.Import([]byte(gifKSY), "g.ksy")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 8; i++ {
		got, _, err := schemaio.Kaitai{}.Import([]byte(gifKSY), "g.ksy")
		if err != nil {
			t.Fatal(err)
		}
		if got.String() != first.String() {
			t.Fatalf("import %d differed:\n%s\n---\n%s", i+1, first, got)
		}
	}
}
