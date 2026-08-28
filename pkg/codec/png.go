package codec

import (
	"bytes"
	"encoding/binary"

	"github.com/rom/Xfuzz/pkg/ir"
)

func init() { Register(PNG{}) }

// Signature is the eight-byte PNG file header.
var pngSignature = []byte{0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a}

// pngChunkOverhead is the fixed cost of a chunk: a 4-byte length, a 4-byte
// type, and a 4-byte CRC.
const pngChunkOverhead = 12

// The derivations every PNG chunk shares. Derivation values are immutable, so
// one instance is shared by every chunk of every tree rather than allocated per
// chunk during a corpus import.
var (
	pngLengthDerivation = &ir.Derivation{
		Kind: ir.DeriveLength,
		From: ir.Sibling("data"),
	}
	pngCRCDerivation = &ir.Derivation{
		Kind: ir.DeriveChecksum,
		Algo: "crc32",
		From: ir.Sibling("type"),
		To:   ir.Sibling("data"),
	}
)

// PNG decodes the PNG container: a signature followed by length-prefixed,
// CRC-protected chunks.
//
// The container is the point, not the image. It is the archetype of the format
// family that defeats byte-level fuzzing — mutate a byte in the middle and the
// length no longer matches, the CRC fails, and the decoder rejects the file
// before reaching any interesting code. It exercises both derivation classes
// that matter: a length over a sibling and a checksum over a sibling range.
//
// Chunk payloads are left opaque. Fuzzing the compressed IDAT stream is a job
// for a zlib codec composed underneath this one, not for the container parser.
type PNG struct{}

// Name implements Codec.
func (PNG) Name() string { return "png" }

// Extensions implements Codec.
func (PNG) Extensions() []string { return []string{"png"} }

// Decode implements Codec.
//
// Values are taken from the file rather than recomputed, so a chunk carrying a
// wrong length or a corrupt CRC round-trips byte for byte. Repair happens only
// when a fixup is explicitly run.
func (PNG) Decode(a *ir.Arena, src []byte) (*ir.Node, error) {
	root := a.Alloc(ir.KindStruct, "png")
	root.Children = a.AllocKids(3)

	if len(src) < len(pngSignature) || !bytes.Equal(src[:len(pngSignature)], pngSignature) {
		// Not a PNG at all. The tree is still valid and still round-trips; it is
		// simply unstructured, which StructuredFraction will report.
		root.Children = append(root.Children, Opaque(a, src))
		return root, nil
	}

	sig := a.Alloc(ir.KindBytes, "signature")
	sig.Raw = src[:len(pngSignature)]
	root.Children = append(root.Children, sig)

	// Count first so the child slice is sized exactly; growing it would defeat
	// the arena when a campaign re-decodes inputs.
	end := scanPNGChunks(src)
	chunks := a.Alloc(ir.KindRepeat, "chunks")
	chunks.Children = a.AllocKids(countPNGChunks(src, end))
	root.Children = append(root.Children, chunks)

	for pos := len(pngSignature); pos < end; {
		size := int(binary.BigEndian.Uint32(src[pos:]))
		chunks.Children = append(chunks.Children, decodePNGChunk(a, src[pos:pos+pngChunkOverhead+size]))
		pos += pngChunkOverhead + size
	}

	if end < len(src) {
		// A truncated final chunk, trailing garbage, or data appended after
		// IEND. All of it is preserved so the input survives round-tripping.
		root.Children = append(root.Children, Opaque(a, src[end:]))
	}
	return root, nil
}

// decodePNGChunk builds one chunk from exactly its bytes.
func decodePNGChunk(a *ir.Arena, b []byte) *ir.Node {
	size := len(b) - pngChunkOverhead

	ch := a.Alloc(ir.KindStruct, "chunk")
	ch.Children = a.AllocKids(4)

	length := a.Alloc(ir.KindDerived, "length")
	length.Width, length.Endian = 4, ir.BigEndian
	length.Val = int64(binary.BigEndian.Uint32(b[0:4]))
	length.Derive = pngLengthDerivation

	typ := a.Alloc(ir.KindBytes, "type")
	typ.Raw = b[4:8]

	data := a.Alloc(ir.KindBytes, "data")
	data.Raw = b[8 : 8+size]

	crc := a.Alloc(ir.KindDerived, "crc")
	crc.Width, crc.Endian = 4, ir.BigEndian
	crc.Val = int64(binary.BigEndian.Uint32(b[8+size:]))
	crc.Derive = pngCRCDerivation

	ch.Children = append(ch.Children, length, typ, data, crc)
	return ch
}

// scanPNGChunks returns the offset just past the last chunk that is wholly
// present. Everything from there to the end of the input is unparsed.
func scanPNGChunks(src []byte) int {
	pos := len(pngSignature)
	for {
		if pos+pngChunkOverhead > len(src) {
			return pos
		}
		size := uint64(binary.BigEndian.Uint32(src[pos:]))
		// Widened to 64 bits deliberately: a declared length near 2^32 must not
		// wrap into a small positive offset. A fuzzer will produce that input.
		next := uint64(pos) + pngChunkOverhead + size
		if next > uint64(len(src)) {
			return pos
		}
		pos = int(next)
	}
}

func countPNGChunks(src []byte, end int) int {
	n := 0
	for pos := len(pngSignature); pos < end; n++ {
		pos += pngChunkOverhead + int(binary.BigEndian.Uint32(src[pos:]))
	}
	return n
}

// ChunkType returns a chunk node's four-character type, or "" if the node is
// not a chunk.
func ChunkType(chunk *ir.Node) string {
	if chunk == nil {
		return ""
	}
	t := chunk.Child("type")
	if t == nil {
		return ""
	}
	return string(t.Raw)
}
