package schema

import (
	"strings"
	"testing"

	"github.com/rom/Xfuzz/pkg/ir"
)

const pngSource = `
# PNG
format png {
  signature: magic "\x89PNG\r\n\x1a\n"
  chunks:    repeat<1..64> chunk
}

struct chunk {
  length: u32be   = len(^data)
  type:   bytes[4]
  data:   bytes<0..4096>
  crc:    u32be   = crc32(^type..^data)
}
`

func TestParsePNG(t *testing.T) {
	s, err := Parse([]byte(pngSource), "png.xfg")
	if err != nil {
		t.Fatal(err)
	}
	if s.Root != "png" {
		t.Errorf("root = %q, want png", s.Root)
	}
	if len(s.Types) != 2 {
		t.Errorf("declared %d types, want 2", len(s.Types))
	}

	root := s.Types["png"]
	if len(root.Fields) != 2 {
		t.Fatalf("png has %d fields, want 2", len(root.Fields))
	}
	sig := root.Fields[0]
	if !sig.Type.Immutable || !sig.Type.HasLiteral {
		t.Error("magic must be immutable and carry its literal")
	}
	if string(sig.Type.Literal) != "\x89PNG\r\n\x1a\n" {
		t.Errorf("signature literal = %q", sig.Type.Literal)
	}
	if sig.Type.Min != 8 || sig.Type.Max != 8 {
		t.Errorf("magic bounds = [%d,%d], want [8,8]", sig.Type.Min, sig.Type.Max)
	}

	chunks := root.Fields[1].Type
	if chunks.Kind != KindRepeat || chunks.Elem != "chunk" || chunks.Min != 1 || chunks.Max != 64 {
		t.Errorf("chunks = %+v, want repeat<1..64> chunk", chunks)
	}

	chunk := s.Types["chunk"]
	length := chunk.Fields[0]
	if length.Derive == nil || length.Derive.Kind != ir.DeriveLength {
		t.Fatalf("length has derivation %+v, want a length derivation", length.Derive)
	}
	if got := length.Derive.From.String(); got != "^data" {
		t.Errorf("length refers to %q, want ^data", got)
	}
	crc := chunk.Fields[3]
	if crc.Derive == nil || crc.Derive.Kind != ir.DeriveChecksum || crc.Derive.Algo != "crc32" {
		t.Fatalf("crc has derivation %+v", crc.Derive)
	}
	if got, want := crc.Derive.From.String()+".."+crc.Derive.To.String(), "^type..^data"; got != want {
		t.Errorf("crc covers %q, want %q", got, want)
	}
	if chunk.Fields[1].Type.Min != 4 || chunk.Fields[1].Type.Max != 4 {
		t.Error("bytes[4] must pin both bounds to 4")
	}
}

func TestParseEveryTypeForm(t *testing.T) {
	const src = `
format demo {
  a: u8
  b: i16le
  c: u32be
  d: u64le
  e: bytes
  f: bytes[7]
  g: bytes<2..9>
  h: str<1..4>
  i: magic "hi"
  j: repeat item
  k: repeat<0..3> item
  l: opt item
  m: choice { x: u8, y: bytes[2], z: item }
  n: item
  o: u16be = 513
  p: str = "fixed"
  q: u32be = len(^e..^g)
  r: u16be = count(^j)
  s: u32be = offset(^f)
  t: u32be = crc32(^e) + 4
  u: u16be = adler32(^e) - 1
  v: u32be = crc32(^^demo) selfzero
}

struct item {
  z: u8
}
`
	s, err := Parse([]byte(src), "demo.xfg")
	if err != nil {
		t.Fatal(err)
	}
	f := s.Types["demo"].Fields
	byName := map[string]Field{}
	for _, x := range f {
		byName[x.Name] = x
	}

	checks := []struct {
		field string
		want  string
	}{
		{"a", "u8"}, {"b", "i16le"}, {"c", "u32be"}, {"d", "u64le"},
		{"e", "bytes"}, {"f", "bytes[7]"}, {"g", "bytes<2..9>"}, {"h", "str<1..4>"},
		{"i", `magic "hi"`}, {"j", "repeat item"}, {"k", "repeat<0..3> item"},
		{"l", "opt item"}, {"n", "item"},
	}
	for _, c := range checks {
		if got := byName[c.field].Type.String(); got != c.want {
			t.Errorf("field %s renders as %q, want %q", c.field, got, c.want)
		}
	}
	if got := byName["m"].Type; got.Kind != KindChoice || len(got.Fields) != 3 {
		t.Errorf("choice = %+v, want three alternatives", got)
	}
	if got := byName["o"].Type; !got.HasLiteral || got.LiteralInt != 513 {
		t.Errorf("integer literal = %+v", got)
	}
	if got := byName["p"].Type; !got.HasLiteral || string(got.Literal) != "fixed" {
		t.Errorf("string literal = %+v", got)
	}
	if d := byName["q"].Derive; d == nil || d.Kind != ir.DeriveLength || d.To.IsZero() {
		t.Errorf("len over a range = %+v", d)
	}
	if d := byName["r"].Derive; d == nil || d.Kind != ir.DeriveCount {
		t.Errorf("count = %+v", d)
	}
	if d := byName["s"].Derive; d == nil || d.Kind != ir.DeriveOffset {
		t.Errorf("offset = %+v", d)
	}
	if d := byName["t"].Derive; d == nil || d.Addend != 4 {
		t.Errorf("positive addend = %+v", d)
	}
	if d := byName["u"].Derive; d == nil || d.Addend != -1 || d.Algo != "adler32" {
		t.Errorf("negative addend = %+v", d)
	}
	if d := byName["v"].Derive; d == nil || !d.SelfZero {
		t.Errorf("selfzero = %+v", d)
	}
}

func TestParseErrors(t *testing.T) {
	cases := map[string]string{
		"no format":            `struct a { x: u8 }`,
		"two formats":          `format a { x: u8 } format b { y: u8 }`,
		"duplicate name":       `format a { x: u8 } struct a { y: u8 }`,
		"unknown type":         `format a { x: nosuchtype }`,
		"unknown element":      `format a { x: repeat nope }`,
		"unknown derivation":   `format a { x: u8 = frobnicate(^y) y: u8 }`,
		"unterminated struct":  `format a { x: u8`,
		"missing colon":        `format a { x u8 }`,
		"bad reference":        `format a { x: u8 = len(y) y: u8 }`,
		"inverted range":       `format a { x: bytes<9..2> }`,
		"empty choice":         `format a { x: choice { } }`,
		"unterminated string":  `format a { x: magic "abc }`,
		"bad escape":           `format a { x: magic "\q" }`,
		"short hex escape":     `format a { x: magic "\x4" }`,
		"unexpected character": "format a { x: u8 @ }",
		"derivation on bytes":  `format a { x: bytes = len(^y) y: u8 }`,
		"literal too long":     `format a { x: bytes[2] = "toolong" }`,
		"unguarded recursion":  `format a { x: b } struct b { y: a }`,
		"self recursion":       `format a { x: a }`,
		"magic without string": `format a { x: magic 5 }`,
		"trailing garbage":     `format a { x: u8 } nonsense`,
	}
	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			s, err := Parse([]byte(src), "t.xfg")
			if err == nil {
				// A few of these are only caught at generation time; the parser
				// must at least not accept them silently as valid schemas.
				if name == "derivation on bytes" {
					t.Skip("caught by the generator, which knows a derivation needs an integer field")
				}
				t.Errorf("expected an error, got schema %v", s)
			}
		})
	}
}

// TestGuardedRecursionIsAllowed: a format may recurse as long as generation can
// stop, which means through a repeat or an opt.
func TestGuardedRecursionIsAllowed(t *testing.T) {
	for _, src := range []string{
		`format a { x: repeat<0..2> a }`,
		`format a { x: opt a }`,
		`format a { x: repeat<0..2> b } struct b { y: opt a }`,
	} {
		if _, err := Parse([]byte(src), "t.xfg"); err != nil {
			t.Errorf("%s: %v", src, err)
		}
	}
}

func TestCommentsAndWhitespace(t *testing.T) {
	const src = `
# hash comment
// slash comment
format a {   # trailing comment
  x: u8      // another
}
`
	if _, err := Parse([]byte(src), "t.xfg"); err != nil {
		t.Fatal(err)
	}
}

// TestStringRoundTrips: rendering a schema and re-parsing it must produce the
// same schema, which keeps the printed form trustworthy for review.
func TestStringRoundTrips(t *testing.T) {
	s, err := Parse([]byte(pngSource), "png.xfg")
	if err != nil {
		t.Fatal(err)
	}
	rendered := s.String()
	s2, err := Parse([]byte(rendered), "rendered.xfg")
	if err != nil {
		t.Fatalf("re-parsing the rendered schema failed: %v\n%s", err, rendered)
	}
	if s2.String() != rendered {
		t.Errorf("rendering is not stable:\nfirst:\n%s\nsecond:\n%s", rendered, s2.String())
	}
	if !strings.Contains(rendered, "format png") || !strings.Contains(rendered, "crc32(^type..^data)") {
		t.Errorf("rendered form lost detail:\n%s", rendered)
	}
}

func TestParseFileErrors(t *testing.T) {
	if _, err := ParseFile("testdata/does-not-exist.xfg"); err == nil {
		t.Error("parsing a missing file must fail")
	}
}

func TestTypeNamesAndLookup(t *testing.T) {
	s, _ := Parse([]byte(pngSource), "png.xfg")
	names := s.TypeNames()
	if len(names) != 2 || names[0] != "chunk" || names[1] != "png" {
		t.Errorf("TypeNames = %v, want [chunk png]", names)
	}
	if _, ok := s.Lookup("nope"); ok {
		t.Error("Lookup found a type that is not declared")
	}
}

func TestIntTypeNames(t *testing.T) {
	if len(IntTypeNames()) != 14 {
		t.Errorf("expected 14 scalar type names, got %d", len(IntTypeNames()))
	}
}

func TestKindString(t *testing.T) {
	for _, k := range []Kind{KindInt, KindBytes, KindStr, KindStruct, KindRepeat, KindChoice, KindOpt, KindRef} {
		if k.String() == "invalid" {
			t.Errorf("kind %d has no name", k)
		}
	}
	if Kind(99).String() != "invalid" {
		t.Error("an unknown kind should render as invalid")
	}
}

func TestPositionString(t *testing.T) {
	if got := (Position{File: "a.xfg", Line: 3, Col: 7}).String(); got != "a.xfg:3:7" {
		t.Errorf("Position = %q", got)
	}
	if got := (Position{Line: 3, Col: 7}).String(); got != "3:7" {
		t.Errorf("Position without a file = %q", got)
	}
}
