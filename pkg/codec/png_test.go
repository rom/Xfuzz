package codec

import (
	"bytes"
	"encoding/binary"
	"hash/crc32"
	"image"
	"image/color"
	"image/png"
	"sort"
	"testing"

	"github.com/rom/Xfuzz/pkg/ir"
)

// Codecs as values: a composite literal cannot begin an if-statement init
// clause, and these read better anyway.
var (
	pngCodec = PNG{}
	rawCodec = Raw{}
)

// --- corpus -----------------------------------------------------------------

// buildPNG assembles a PNG from a signature and raw chunks, so tests can craft
// exact bytes including deliberately wrong ones.
func buildPNG(chunks ...[]byte) []byte {
	out := append([]byte(nil), pngSignature...)
	for _, c := range chunks {
		out = append(out, c...)
	}
	return out
}

// chunkBytes builds a well-formed chunk with a correct length and CRC.
func chunkBytes(typ string, data []byte) []byte {
	b := make([]byte, 0, pngChunkOverhead+len(data))
	b = binary.BigEndian.AppendUint32(b, uint32(len(data)))
	b = append(b, typ...)
	b = append(b, data...)
	return binary.BigEndian.AppendUint32(b, crc32.ChecksumIEEE(b[4:]))
}

// realPNGs renders a spread of genuine PNG files with the standard encoder:
// different colour models and sizes, so the corpus is not one shape repeated.
func realPNGs(t testing.TB) [][]byte {
	t.Helper()
	var out [][]byte

	imgs := []image.Image{
		image.NewGray(image.Rect(0, 0, 1, 1)),
		image.NewRGBA(image.Rect(0, 0, 8, 8)),
		image.NewNRGBA(image.Rect(0, 0, 17, 3)),
		image.NewPaletted(image.Rect(0, 0, 4, 4), color.Palette{color.Black, color.White}),
		image.NewGray16(image.Rect(0, 0, 32, 32)),
	}
	for i, im := range imgs {
		if rgba, ok := im.(*image.RGBA); ok {
			for y := 0; y < 8; y++ {
				for x := 0; x < 8; x++ {
					rgba.Set(x, y, color.RGBA{uint8(x * 32), uint8(y * 32), uint8(i * 50), 255})
				}
			}
		}
		var buf bytes.Buffer
		for _, lvl := range []png.CompressionLevel{png.DefaultCompression, png.BestSpeed} {
			buf.Reset()
			enc := png.Encoder{CompressionLevel: lvl}
			if err := enc.Encode(&buf, im); err != nil {
				t.Fatalf("encoding fixture %d: %v", i, err)
			}
			out = append(out, append([]byte(nil), buf.Bytes()...))
		}
	}
	return out
}

// corpus is every input the round-trip property must hold for: real files,
// hand-crafted structures, and malformed data. The malformed entries are the
// point — a strict parser would reject exactly these, and they are the seeds
// worth having.
func corpus(t testing.TB) map[string][]byte {
	t.Helper()
	c := map[string][]byte{
		"empty":               {},
		"one byte":            {0x89},
		"short signature":     pngSignature[:7],
		"signature only":      append([]byte(nil), pngSignature...),
		"not a png":           []byte("GIF89a and then some bytes"),
		"all zeroes":          make([]byte, 64),
		"signature + garbage": append(append([]byte(nil), pngSignature...), 0xff, 0xfe, 0xfd),

		"minimal": buildPNG(
			chunkBytes("IHDR", make([]byte, 13)),
			chunkBytes("IEND", nil),
		),
		"empty chunk data": buildPNG(chunkBytes("tEXt", nil)),
		"several chunks": buildPNG(
			chunkBytes("IHDR", make([]byte, 13)),
			chunkBytes("tEXt", []byte("Comment\x00hello")),
			chunkBytes("IDAT", bytes.Repeat([]byte{0x42}, 300)),
			chunkBytes("IEND", nil),
		),
		"trailing data after IEND": append(
			buildPNG(chunkBytes("IEND", nil)),
			[]byte("appended junk")...),
	}

	// A chunk whose declared length runs past the end of the file.
	truncated := buildPNG(chunkBytes("IDAT", bytes.Repeat([]byte{1}, 40)))
	c["truncated chunk"] = truncated[:len(truncated)-10]

	// A declared length near 2^32, which must not wrap into a small offset.
	huge := append([]byte(nil), pngSignature...)
	huge = binary.BigEndian.AppendUint32(huge, 0xfffffff0)
	huge = append(huge, "IDAT"...)
	huge = append(huge, 1, 2, 3, 4)
	c["absurd declared length"] = huge

	// A well-formed structure carrying a deliberately wrong CRC.
	bad := buildPNG(chunkBytes("IHDR", make([]byte, 13)))
	bad[len(bad)-1] ^= 0xff
	c["corrupt crc"] = bad

	// A well-formed structure whose length field disagrees with reality is not
	// representable without truncating the file, so it appears as a short chunk
	// followed by opaque bytes.
	for i, b := range realPNGs(t) {
		c[string(rune('a'+i))+" real png"] = b
	}
	return c
}

// --- the round-trip property ------------------------------------------------

// TestRoundTripIsByteExact is the codec's defining invariant, and the one that
// makes a corpus safe to import: whatever goes in comes back out unchanged,
// valid or not. A codec that "helpfully" repaired a file on the way in would
// silently rewrite the corpus.
func TestRoundTripIsByteExact(t *testing.T) {
	for name, src := range corpus(t) {
		t.Run(name, func(t *testing.T) {
			tree, err := pngCodec.Decode(nil, src)
			if err != nil {
				t.Fatalf("Decode returned an error for a malformed input; decoding must be total: %v", err)
			}
			if err := ir.Validate(tree); err != nil {
				t.Fatalf("decoded tree is structurally invalid: %v", err)
			}
			if got := ir.Encode(tree); !bytes.Equal(got, src) {
				t.Errorf("round trip changed the bytes:\n got %x\nwant %x", got, src)
			}
		})
	}
}

func TestRawRoundTripIsByteExact(t *testing.T) {
	for name, src := range corpus(t) {
		t.Run(name, func(t *testing.T) {
			tree, err := rawCodec.Decode(nil, src)
			if err != nil {
				t.Fatal(err)
			}
			if got := ir.Encode(tree); !bytes.Equal(got, src) {
				t.Errorf("raw round trip changed the bytes")
			}
		})
	}
}

// --- structure --------------------------------------------------------------

func TestDecodeStructure(t *testing.T) {
	src := buildPNG(
		chunkBytes("IHDR", make([]byte, 13)),
		chunkBytes("tEXt", []byte("k\x00v")),
		chunkBytes("IEND", nil),
	)
	tree, err := pngCodec.Decode(nil, src)
	if err != nil {
		t.Fatal(err)
	}

	chunks := tree.Child("chunks")
	if chunks == nil || len(chunks.Children) != 3 {
		t.Fatalf("expected 3 chunks, got %v", chunks)
	}
	want := []string{"IHDR", "tEXt", "IEND"}
	for i, w := range want {
		if got := ChunkType(chunks.Children[i]); got != w {
			t.Errorf("chunk %d type = %q, want %q", i, got, w)
		}
	}
	if got := chunks.Children[0].Child("length").Val; got != 13 {
		t.Errorf("IHDR length = %d, want 13", got)
	}
	if got := len(chunks.Children[1].Child("data").Raw); got != 3 {
		t.Errorf("tEXt data length = %d, want 3", got)
	}
	if UnparsedBytes(tree) != 0 {
		t.Errorf("a well-formed PNG must be fully structured, %d bytes opaque", UnparsedBytes(tree))
	}
	if f := StructuredFraction(tree); f != 1 {
		t.Errorf("StructuredFraction = %v, want 1", f)
	}
}

func TestDecodePreservesWrongValues(t *testing.T) {
	src := buildPNG(chunkBytes("IHDR", make([]byte, 13)))
	src[len(src)-1] ^= 0xff // corrupt the CRC
	tree, err := pngCodec.Decode(nil, src)
	if err != nil {
		t.Fatal(err)
	}
	chunk := tree.Child("chunks").Children[0]

	stored := chunk.Child("crc").Val
	correct := int64(crc32.ChecksumIEEE(src[12 : len(src)-4]))
	if stored == correct {
		t.Fatal("the fixture's CRC was not actually corrupted")
	}
	if got := ir.Encode(tree); !bytes.Equal(got, src) {
		t.Error("a corrupt CRC must survive decoding: decode preserves, fixup repairs")
	}

	// And a fixup is what repairs it.
	if err := ir.Fixup(tree, ir.Suppress{}); err != nil {
		t.Fatal(err)
	}
	if got := chunk.Child("crc").Val; got != correct {
		t.Errorf("after fixup crc = %#x, want %#x", got, correct)
	}
}

func TestUnparsedBytesAreReported(t *testing.T) {
	src := append(buildPNG(chunkBytes("IEND", nil)), []byte("1234567890")...)
	tree, err := pngCodec.Decode(nil, src)
	if err != nil {
		t.Fatal(err)
	}
	if got := UnparsedBytes(tree); got != 10 {
		t.Errorf("UnparsedBytes = %d, want 10", got)
	}
	if f := StructuredFraction(tree); f <= 0 || f >= 1 {
		t.Errorf("StructuredFraction = %v, want a value strictly between 0 and 1", f)
	}

	// A file that is not a PNG at all is entirely opaque, which is the signal
	// that the campaign's schema does not match its corpus.
	tree, _ = pngCodec.Decode(nil, []byte("not a png"))
	if f := StructuredFraction(tree); f != 0 {
		t.Errorf("StructuredFraction of a non-PNG = %v, want 0", f)
	}
}

// --- the payoff: structured mutation produces files that still parse ---------

// TestStructuralMutationProducesAValidPNG is the end-to-end justification for
// the IR. A chunk is inserted into a real file, the derived length and CRC are
// recomputed, and the standard library decoder — which validates every CRC —
// accepts the result. Byte-level mutation cannot do this.
func TestStructuralMutationProducesAValidPNG(t *testing.T) {
	src := realPNGs(t)[1]
	if _, err := png.Decode(bytes.NewReader(src)); err != nil {
		t.Fatalf("fixture is not decodable to begin with: %v", err)
	}

	a := ir.NewArena()
	decoded, err := pngCodec.Decode(nil, src)
	if err != nil {
		t.Fatal(err)
	}
	tree := a.Clone(decoded)

	// Insert a tEXt chunk before IEND, with a deliberately wrong length and CRC
	// that the fixup must repair.
	chunks := tree.Child("chunks")
	last := len(chunks.Children) - 1
	text := ir.Struct("chunk",
		ir.Derived("length", 4, ir.BigEndian, *pngLengthDerivation),
		ir.Blob("type", []byte("tEXt")),
		ir.Blob("data", []byte("Comment\x00inserted by Xfuzz")),
		ir.Derived("crc", 4, ir.BigEndian, *pngCRCDerivation),
	)
	text.Child("length").Val = 0xdead
	text.Child("crc").Val = 0xbeef

	chunks.Children = append(chunks.Children, nil)
	copy(chunks.Children[last+1:], chunks.Children[last:])
	chunks.Children[last] = text

	if err := ir.Fixup(tree, ir.Suppress{}); err != nil {
		t.Fatal(err)
	}

	out := ir.Encode(tree)
	if bytes.Equal(out, src) {
		t.Fatal("the mutation had no effect")
	}
	if _, err := png.Decode(bytes.NewReader(out)); err != nil {
		t.Fatalf("the mutated file no longer decodes: %v\n"+
			"this is the whole point of derived fields — mutate the structure, "+
			"then restore what the target validates", err)
	}

	// And the inserted chunk survived the trip.
	reparsed, err := pngCodec.Decode(nil, out)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, c := range reparsed.Child("chunks").Children {
		if ChunkType(c) == "tEXt" {
			found = true
			if got := c.Child("length").Val; got != int64(len("Comment\x00inserted by Xfuzz")) {
				t.Errorf("inserted chunk length = %d, want %d", got, len("Comment\x00inserted by Xfuzz"))
			}
		}
	}
	if !found {
		t.Error("the inserted chunk is missing from the re-parsed file")
	}
}

// TestSuppressedChecksumReachesValidationCode shows the other half of ASR-0014:
// with checksum fixups suppressed, the output is structurally correct but fails
// CRC validation — which is how a fuzzer reaches a target's checksum-checking
// code at all.
func TestSuppressedChecksumReachesValidationCode(t *testing.T) {
	src := realPNGs(t)[1]
	tree, err := pngCodec.Decode(nil, src)
	if err != nil {
		t.Fatal(err)
	}
	chunks := tree.Child("chunks")
	data := chunks.Children[0].Child("data")
	data.Raw = append(append([]byte(nil), data.Raw...), 0xff)

	if err := ir.Fixup(tree, ir.Suppress{Checksum: true}); err != nil {
		t.Fatal(err)
	}
	out := ir.Encode(tree)

	if _, err := png.Decode(bytes.NewReader(out)); err == nil {
		t.Error("with checksums suppressed the decoder should reject the file; " +
			"a fuzzer that always writes a correct CRC never tests CRC validation")
	}

	// The length field, which was not suppressed, is still correct.
	reparsed, _ := pngCodec.Decode(nil, out)
	first := reparsed.Child("chunks").Children[0]
	if got, want := first.Child("length").Val, int64(len(first.Child("data").Raw)); got != want {
		t.Errorf("length = %d, want %d: suppressing checksums must not suppress lengths", got, want)
	}
}

// --- registry ---------------------------------------------------------------

func TestRegistry(t *testing.T) {
	if _, err := Get("png"); err != nil {
		t.Errorf("png must be registered: %v", err)
	}
	if _, err := Get("nope"); err == nil {
		t.Error("an unknown codec must not resolve")
	}
	// Membership and order, not position: the list is sorted, so asserting that
	// png is first was an assertion about which codecs happen to exist, and it
	// broke the moment one was added whose name sorts earlier.
	names := Names()
	if !sort.StringsAreSorted(names) {
		t.Errorf("Names = %v, want them sorted", names)
	}
	for _, want := range []string{"png", "raw"} {
		if sort.SearchStrings(names, want) >= len(names) || !contains(names, want) {
			t.Errorf("Names = %v, want it to include %q", names, want)
		}
	}
	if c, ok := ForExtension(".png"); !ok || c.Name() != "png" {
		t.Errorf("ForExtension(.png) = %v, %v", c, ok)
	}
	if c, ok := ForExtension("bin"); !ok || c.Name() != "raw" {
		t.Errorf("ForExtension(bin) = %v, %v", c, ok)
	}
	if _, ok := ForExtension("unknown"); ok {
		t.Error("an unclaimed extension must not resolve")
	}
}

func TestRegisterRejectsDuplicates(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("re-registering a codec name must panic: it would change how " +
				"every corpus entry is parsed")
		}
	}()
	Register(pngCodec)
}

// --- self-fuzzing (docs/TESTS.md layer 7) -----------------------------------

// FuzzPNGDecode fuzzes the codec's own parser. Corpus files are untrusted input
// (docs/SECURITY.md, T5), and a fuzzing tool with an unfuzzed parser has no
// credibility. The round-trip invariant is checked on every input, so the fuzzer
// hunts for correctness failures as well as crashes.
func FuzzPNGDecode(f *testing.F) {
	for _, src := range corpus(f) {
		f.Add(src)
	}
	f.Fuzz(func(t *testing.T, src []byte) {
		tree, err := pngCodec.Decode(nil, src)
		if err != nil {
			t.Fatalf("Decode must be total, got %v", err)
		}
		if err := ir.Validate(tree); err != nil {
			t.Fatalf("decoded an invalid tree: %v", err)
		}
		if got := ir.Encode(tree); !bytes.Equal(got, src) {
			t.Fatalf("round trip is not byte-exact\n got %x\nwant %x", got, src)
		}
	})
}

func BenchmarkPNGDecode(b *testing.B) {
	src := realPNGs(b)[8]
	a := ir.NewArena()
	b.SetBytes(int64(len(src)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		a.Reset()
		if _, err := pngCodec.Decode(a, src); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkPNGDecodeFixEncode(b *testing.B) {
	src := realPNGs(b)[8]
	decoded, err := pngCodec.Decode(nil, src)
	if err != nil {
		b.Fatal(err)
	}
	a := ir.NewArena()
	fx := ir.NewFixer()
	b.SetBytes(int64(len(src)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		a.Reset()
		tree := a.Clone(decoded)
		d := tree.Child("chunks").Children[0].Child("data")
		d.Raw[0] ^= 0xff
		if _, err := fx.Fix(tree, ir.Suppress{}); err != nil {
			b.Fatal(err)
		}
	}
}

func contains(names []string, want string) bool {
	for _, n := range names {
		if n == want {
			return true
		}
	}
	return false
}
