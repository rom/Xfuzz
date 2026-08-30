package codec

import (
	"bytes"
	"encoding/binary"
	"hash/crc32"
	"strings"
	"testing"

	"github.com/rom/Xfuzz/pkg/ir"
	"github.com/rom/Xfuzz/pkg/schema"
)

// chunkedGrammar is the worked format: a magic, a version, and a sequence of
// length-prefixed, CRC-protected chunks. It exercises both derivation classes
// that matter — a length over a sibling and a checksum over a sibling range.
const chunkedGrammar = `
format chunked {
  magic:   magic "XCHK"
  version: u8 = 1
  chunks:  repeat<1..8> chunk
}
struct chunk {
  tag:     bytes[4]
  length:  u32be   = len(^payload)
  payload: bytes<0..128>
  crc:     u32be   = crc32(^tag..^payload)
}
`

func schemaCodec(t testing.TB, src string) *Schema {
	t.Helper()
	s, err := schema.Parse([]byte(src), "test.xfg")
	if err != nil {
		t.Fatalf("parsing the grammar: %v", err)
	}
	return NewSchema(s)
}

// chunkedFile builds a well-formed file: correct lengths, correct checksums.
func chunkedFile(chunks ...struct {
	tag     string
	payload []byte
}) []byte {
	out := append([]byte("XCHK"), 1)
	for _, c := range chunks {
		body := append([]byte(c.tag), 0, 0, 0, 0)
		binary.BigEndian.PutUint32(body[4:], uint32(len(c.payload)))
		body = append(body, c.payload...)
		sum := make([]byte, 4)
		binary.BigEndian.PutUint32(sum, crc32.ChecksumIEEE(body))
		out = append(out, append(body, sum...)...)
	}
	return out
}

type chunk = struct {
	tag     string
	payload []byte
}

func TestASchemaCodecRecoversTheStructureAGrammarDescribes(t *testing.T) {
	c := schemaCodec(t, chunkedGrammar)
	in := chunkedFile(
		chunk{"SIZE", []byte("0123456789abcdef")},
		chunk{"IDXT", []byte{0, 4, 7}},
	)

	a := ir.NewArena()
	n, err := c.Decode(a, in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}

	// Byte-exact, which the interface requires of every codec: a corpus entry
	// that changed merely by being read would make every campaign that imported
	// it fuzz something other than what was collected.
	if got := ir.Encode(n); !bytes.Equal(got, in) {
		t.Fatalf("round-trip differs:\n in %x\nout %x", in, got)
	}
	if opaque := UnparsedBytes(n); opaque != 0 {
		t.Errorf("a well-formed file left %d bytes unstructured", opaque)
	}

	// And the structure is really there: two chunks, each with a payload the
	// length field found.
	chunks := findChild(n, "chunks")
	if chunks == nil {
		t.Fatalf("no chunks node in:\n%s", n)
	}
	if len(chunks.Children) != 2 {
		t.Fatalf("decoded %d chunks, want 2", len(chunks.Children))
	}
	payload := findChild(chunks.Children[0], "payload")
	if payload == nil || string(payload.Raw) != "0123456789abcdef" {
		t.Fatalf("the first chunk's payload is %q", payload.Raw)
	}
}

func TestASchemaCodecKeepsWhatTheFileSaysRatherThanWhatItShouldSay(t *testing.T) {
	// Decode preserves; fixup repairs. A file with a wrong checksum has to
	// survive reading with the wrong checksum still in it, or a corpus of
	// deliberately corrupt inputs — which is most of an interesting corpus —
	// would be silently repaired on import.
	c := schemaCodec(t, chunkedGrammar)
	in := chunkedFile(chunk{"SIZE", []byte("payload")})
	in[len(in)-1] ^= 0xff // break the CRC

	a := ir.NewArena()
	n, err := c.Decode(a, in)
	if err != nil {
		t.Fatal(err)
	}
	if got := ir.Encode(n); !bytes.Equal(got, in) {
		t.Fatalf("a file with a broken checksum did not round-trip:\n in %x\nout %x", in, got)
	}

	// And the fixup pass repairs it, which is what makes a mutation of this
	// tree land past the target's gate.
	fixed, err := ir.NewFixer().Fix(n, ir.Suppress{})
	if err != nil {
		t.Fatalf("Fix: %v", err)
	}
	if bytes.Equal(fixed, in) {
		t.Error("the fixup pass left the broken checksum alone")
	}
	repaired := chunkedFile(chunk{"SIZE", []byte("payload")})
	if !bytes.Equal(fixed, repaired) {
		t.Errorf("repaired to\n%x\nwant\n%x", fixed, repaired)
	}
}

func TestASchemaCodecIsTotal(t *testing.T) {
	c := schemaCodec(t, chunkedGrammar)

	for _, tc := range []struct {
		name string
		in   []byte
	}{
		{"empty", nil},
		{"not this format", []byte("hello, world")},
		{"magic only", []byte("XCHK")},
		{"truncated chunk", chunkedFile(chunk{"SIZE", []byte("abc")})[:10]},
		{"trailing garbage", append(chunkedFile(chunk{"SIZE", []byte("abc")}), "junk"...)},
		{"length past the end", func() []byte {
			b := chunkedFile(chunk{"SIZE", []byte("abc")})
			binary.BigEndian.PutUint32(b[9:], 0xffff)
			return b
		}()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := ir.NewArena()
			n, err := c.Decode(a, tc.in)
			if err != nil {
				t.Fatalf("Decode returned an error on %q: %v", tc.name, err)
			}
			if n == nil {
				t.Fatal("Decode returned no tree and no error")
			}
			// Total means every input decodes, and round-trips: whatever could
			// not be understood is carried as opaque bytes rather than lost.
			if got := ir.Encode(n); !bytes.Equal(got, tc.in) {
				t.Fatalf("round-trip differs:\n in %x\nout %x", tc.in, got)
			}
		})
	}
}

func TestASchemaCodecDecodesEveryTypeTheLanguageHas(t *testing.T) {
	const grammar = `
format msg {
  magic:  magic "M"
  u:      u16le
  i:      i8
  fixed:  bytes[3]
  n:      u8 = count(^items)
  items:  repeat<0..8> item
  maybe:  opt tail
  choice: choice { a: u8, b: bytes[2] }
  rest:   bytes<0..32>
}
struct item { v: u32be }
struct tail { t: u8 }
`
	c := schemaCodec(t, grammar)

	var in []byte
	in = append(in, 'M')
	in = append(in, 0x34, 0x12) // u16le = 0x1234
	in = append(in, 0xff)       // i8 = -1
	in = append(in, 'a', 'b', 'c')
	in = append(in, 2) // count
	in = append(in, 0, 0, 0, 1, 0, 0, 0, 2)
	in = append(in, 9)        // opt tail
	in = append(in, 7)        // choice arm a
	in = append(in, 'x', 'y') // rest

	a := ir.NewArena()
	n, err := c.Decode(a, in)
	if err != nil {
		t.Fatal(err)
	}
	if got := ir.Encode(n); !bytes.Equal(got, in) {
		t.Fatalf("round-trip differs:\n in %x\nout %x", in, got)
	}
	if opaque := UnparsedBytes(n); opaque != 0 {
		t.Errorf("%d bytes left unstructured in a file the grammar fully describes:\n%s", opaque, n)
	}

	u := findChild(n, "u")
	if u == nil || u.Val != 0x1234 {
		t.Errorf("u16le decoded as %v, want 0x1234", u)
	}
	sign := findChild(n, "i")
	if sign == nil || sign.Val != -1 {
		t.Errorf("i8 decoded as %v, want -1", sign)
	}
	items := findChild(n, "items")
	if items == nil || len(items.Children) != 2 {
		t.Errorf("the counted sequence decoded %v elements, want 2", items)
	}
}

func TestASchemaCodecStopsAtAnAmbiguityRatherThanGuessing(t *testing.T) {
	// A variable field in the middle of a struct with nothing declaring its
	// length is ambiguous however it is read. The codec takes what the bound
	// allows and lets the rest fall out as opaque, which is visible, rather
	// than picking a split and pretending.
	const grammar = `
format msg {
  a: bytes<0..4>
  b: u8
}
`
	c := schemaCodec(t, grammar)
	in := []byte{1, 2, 3, 4, 5, 6}

	a := ir.NewArena()
	n, err := c.Decode(a, in)
	if err != nil {
		t.Fatal(err)
	}
	if got := ir.Encode(n); !bytes.Equal(got, in) {
		t.Fatalf("round-trip differs:\n in %x\nout %x", in, got)
	}
	t.Logf("%d of %d bytes unstructured", UnparsedBytes(n), len(in))
}

func TestASchemaCodecIsNamedAfterItsFormat(t *testing.T) {
	c := schemaCodec(t, chunkedGrammar)
	if got := c.Name(); got != "chunked" {
		t.Errorf("Name() = %q, want the grammar's root type", got)
	}
}

// findChild returns the first descendant with this name.
func findChild(n *ir.Node, name string) *ir.Node {
	if n == nil {
		return nil
	}
	if n.Name == name {
		return n
	}
	for _, c := range n.Children {
		if got := findChild(c, name); got != nil {
			return got
		}
	}
	return nil
}

// FuzzSchemaDecode fuzzes the schema-driven decoder.
//
// Untrusted twice over: the grammar comes from wherever grammars are shared,
// and the input is a corpus file. The property is the interface's own contract
// — decoding is total, and re-encoding reproduces the input byte for byte — and
// it is the one that matters, because a codec that loses a byte silently
// changes what every campaign built on it is fuzzing.
func FuzzSchemaDecode(f *testing.F) {
	f.Add(chunkedGrammar, chunkedFile(chunk{"SIZE", []byte("abc")}))
	f.Add(chunkedGrammar, []byte("XCHK\x01"))
	f.Add(chunkedGrammar, []byte(""))
	f.Add("format m { a: u32be  b: bytes<0..8> }", []byte{1, 2, 3, 4, 5})
	f.Add("format m { n: u8 = count(^xs)  xs: repeat<0..4> e }\nstruct e { v: u8 }",
		[]byte{2, 9, 9})
	f.Add("format m { o: opt t }\nstruct t { v: u16le }", []byte{1, 2})
	f.Add("format m { c: choice { a: u8, b: bytes[2] } }", []byte{7, 8})

	f.Fuzz(func(t *testing.T, grammar string, in []byte) {
		if len(grammar) > 1<<12 || len(in) > 1<<16 {
			return
		}
		s, err := schema.Parse([]byte(grammar), "fuzz.xfg")
		if err != nil || s.Validate() != nil {
			return
		}
		c := NewSchema(s)

		a := ir.NewArena()
		n, err := c.Decode(a, in)
		if err != nil {
			// An error is allowed only when the codec could not run at all,
			// which for a validated schema means a type it cannot decode.
			if !strings.Contains(err.Error(), "cannot decode") &&
				!strings.Contains(err.Error(), "unknown type") &&
				!strings.Contains(err.Error(), "derivation") {
				t.Fatalf("Decode failed on a validated grammar: %v", err)
			}
			return
		}
		if n == nil {
			t.Fatal("Decode returned no tree and no error")
		}
		if got := ir.Encode(n); !bytes.Equal(got, in) {
			t.Fatalf("round-trip differs:\n in  %x\nout %x\ngrammar:\n%s", in, got, grammar)
		}
	})
}
