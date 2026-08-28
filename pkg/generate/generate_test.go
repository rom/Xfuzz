package generate

import (
	"bytes"
	"encoding/binary"
	"hash/crc32"
	"os"
	"path/filepath"
	"testing"

	"github.com/rom/Xfuzz/pkg/codec"
	"github.com/rom/Xfuzz/pkg/ir"
	"github.com/rom/Xfuzz/pkg/rng"
	"github.com/rom/Xfuzz/pkg/schema"
)

func loadSchema(t testing.TB, name string) *schema.Schema {
	t.Helper()
	s, err := schema.ParseFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("parsing %s: %v", name, err)
	}
	return s
}

// containerValid mirrors what a PNG reader checks before looking at any image
// data: the signature, that every chunk is wholly present, and that every CRC
// matches.
func containerValid(b []byte) bool {
	sig := []byte{0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a}
	if len(b) < len(sig) || !bytes.Equal(b[:len(sig)], sig) {
		return false
	}
	pos, chunks := len(sig), 0
	for pos < len(b) {
		if pos+12 > len(b) {
			return false
		}
		size := uint64(binary.BigEndian.Uint32(b[pos:]))
		end := uint64(pos) + 12 + size
		if end > uint64(len(b)) {
			return false
		}
		if binary.BigEndian.Uint32(b[int(end)-4:]) != crc32.ChecksumIEEE(b[pos+4:int(end)-4]) {
			return false
		}
		pos, chunks = int(end), chunks+1
	}
	return chunks > 0
}

// TestGeneratedInputsAreValid is M2's second exit criterion: a schema written in
// the DSL produces inputs a real parser accepts.
func TestGeneratedInputsAreValid(t *testing.T) {
	g := New(loadSchema(t, "png.xfg"))
	a := ir.NewArena()
	r := rng.Derive(1, 0, rng.StreamGenerate)

	const trials = 2000
	valid, chunks := 0, 0
	for i := 0; i < trials; i++ {
		a.Reset()
		n, err := g.Generate(a, r)
		if err != nil {
			t.Fatalf("trial %d: %v", i, err)
		}
		if err := ir.Validate(n); err != nil {
			t.Fatalf("trial %d: generated an invalid tree: %v", i, err)
		}
		out := ir.Encode(n)
		if containerValid(out) {
			valid++
		}
		chunks += len(n.Child("chunks").Children)
	}

	t.Logf("%d/%d generated files pass container validation; %.1f chunks per file on average",
		valid, trials, float64(chunks)/trials)
	if valid != trials {
		t.Errorf("only %d of %d generated files are valid; generation with fixups should "+
			"produce a well-formed container every time", valid, trials)
	}
}

// TestGeneratedInputsRoundTripThroughTheCodec checks that the DSL and the
// hand-written Go codec agree on the format. A generated file must parse back
// into the same structure the codec would have produced.
func TestGeneratedInputsRoundTripThroughTheCodec(t *testing.T) {
	g := New(loadSchema(t, "png.xfg"))
	a := ir.NewArena()
	r := rng.Derive(2, 0, rng.StreamGenerate)

	for i := 0; i < 300; i++ {
		a.Reset()
		n, err := g.Generate(a, r)
		if err != nil {
			t.Fatal(err)
		}
		out := ir.Encode(n)

		parsed, err := codec.PNG{}.Decode(nil, out)
		if err != nil {
			t.Fatalf("trial %d: the codec could not decode a generated file: %v", i, err)
		}
		if got := codec.UnparsedBytes(parsed); got != 0 {
			t.Fatalf("trial %d: the codec left %d bytes of a generated file unparsed;\n"+
				"the schema and the codec disagree about the format", i, got)
		}
		if again := ir.Encode(parsed); !bytes.Equal(again, out) {
			t.Fatalf("trial %d: re-encoding after a codec round trip changed the bytes", i)
		}
		wantChunks := len(n.Child("chunks").Children)
		gotChunks := len(parsed.Child("chunks").Children)
		if wantChunks != gotChunks {
			t.Fatalf("trial %d: generated %d chunks, the codec found %d", i, wantChunks, gotChunks)
		}
	}
}

func TestGenerationIsDeterministic(t *testing.T) {
	s := loadSchema(t, "png.xfg")
	run := func() []byte {
		g := New(s)
		a := ir.NewArena()
		r := rng.Derive(0xD00D, 0, rng.StreamGenerate)
		var last []byte
		for i := 0; i < 20; i++ {
			a.Reset()
			n, err := g.Generate(a, r)
			if err != nil {
				t.Fatal(err)
			}
			last = ir.Encode(n)
		}
		return last
	}
	if !bytes.Equal(run(), run()) {
		t.Error("the same seed produced different generated inputs")
	}
}

func TestGenerationRespectsBounds(t *testing.T) {
	g := New(loadSchema(t, "png.xfg"))
	a := ir.NewArena()
	r := rng.Derive(3, 0, rng.StreamGenerate)

	for i := 0; i < 500; i++ {
		a.Reset()
		n, err := g.Generate(a, r)
		if err != nil {
			t.Fatal(err)
		}
		chunks := n.Child("chunks")
		if len(chunks.Children) < 1 || len(chunks.Children) > 64 {
			t.Fatalf("generated %d chunks, outside the declared 1..64", len(chunks.Children))
		}
		for _, c := range chunks.Children {
			if got := len(c.Child("type").Raw); got != 4 {
				t.Fatalf("generated a %d-byte chunk type, want exactly 4", got)
			}
			if got := len(c.Child("data").Raw); got > 4096 {
				t.Fatalf("generated %d bytes of data, past the declared 4096", got)
			}
		}
	}
}

func TestSignatureIsImmutableAndCorrect(t *testing.T) {
	g := New(loadSchema(t, "png.xfg"))
	a := ir.NewArena()
	n, err := g.Generate(a, rng.New(1))
	if err != nil {
		t.Fatal(err)
	}
	sig := n.Child("signature")
	if !sig.Immutable() {
		t.Error("a magic field must be marked immutable so mutators leave it alone")
	}
	want := []byte{0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a}
	if !bytes.Equal(sig.Raw, want) {
		t.Errorf("signature = %x, want %x", sig.Raw, want)
	}
}

func TestDerivedFieldsAreComputed(t *testing.T) {
	g := New(loadSchema(t, "png.xfg"))
	a := ir.NewArena()
	n, err := g.Generate(a, rng.New(5))
	if err != nil {
		t.Fatal(err)
	}
	for i, c := range n.Child("chunks").Children {
		wantLen := int64(len(c.Child("data").Raw))
		if got := c.Child("length").Val; got != wantLen {
			t.Errorf("chunk %d length = %d, want %d", i, got, wantLen)
		}
		payload := append(append([]byte(nil), c.Child("type").Raw...), c.Child("data").Raw...)
		if got, want := c.Child("crc").Val, int64(crc32.ChecksumIEEE(payload)); got != want {
			t.Errorf("chunk %d crc = %#x, want %#x", i, got, want)
		}
	}
}

func TestGenerationWithoutFixupLeavesDerivationsUnset(t *testing.T) {
	g := New(loadSchema(t, "png.xfg"))
	g.Fix = false
	a := ir.NewArena()
	n, err := g.Generate(a, rng.New(6))
	if err != nil {
		t.Fatal(err)
	}
	c := n.Child("chunks").Children[0]
	if len(c.Child("data").Raw) > 0 && c.Child("length").Val != 0 {
		t.Error("with fixups disabled the derived length should be left at its placeholder")
	}
	if containerValid(ir.Encode(n)) && len(c.Child("data").Raw) > 0 {
		t.Error("an unfixed tree should not normally pass container validation")
	}
}

func TestGenerateReportsUnknownRoot(t *testing.T) {
	g := New(&schema.Schema{Root: "missing", Types: map[string]*schema.Type{}})
	if _, err := g.Generate(ir.NewArena(), rng.New(1)); err == nil {
		t.Error("generating from a schema with no root type must fail")
	}
}

func TestGenerationSteadyStateAllocations(t *testing.T) {
	g := New(loadSchema(t, "png.xfg"))
	a := ir.NewArena()
	r := rng.New(9)
	step := func() {
		a.Reset()
		if _, err := g.Generate(a, r); err != nil {
			panic(err)
		}
	}
	for i := 0; i < 200; i++ {
		step()
	}
	// Generation draws variable sizes, so the arena occasionally has to take a
	// larger buffer than any it holds. What must not happen is an allocation on
	// every input.
	if n := testing.AllocsPerRun(200, step); n > 2 {
		t.Errorf("generation allocated %v times per input; the arena should absorb nearly all of it", n)
	}
}

func TestSchemaFileIsReadable(t *testing.T) {
	// The .xfg file is documentation as much as it is input, so a change that
	// makes it unparseable should fail loudly.
	src, err := os.ReadFile(filepath.Join("testdata", "png.xfg"))
	if err != nil {
		t.Fatal(err)
	}
	s, err := schema.Parse(src, "png.xfg")
	if err != nil {
		t.Fatal(err)
	}
	if s.Root != "png" {
		t.Errorf("root = %q, want png", s.Root)
	}
	if _, ok := s.Lookup("chunk"); !ok {
		t.Error("the chunk type is missing")
	}
}

func BenchmarkGenerate(b *testing.B) {
	g := New(loadSchema(b, "png.xfg"))
	a := ir.NewArena()
	r := rng.New(1)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		a.Reset()
		if _, err := g.Generate(a, r); err != nil {
			b.Fatal(err)
		}
	}
}
