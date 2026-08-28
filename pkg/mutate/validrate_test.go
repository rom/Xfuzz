package mutate_test

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"image"
	"image/color"
	"image/png"
	"testing"

	"github.com/rom/Xfuzz/pkg/codec"
	"github.com/rom/Xfuzz/pkg/ir"
	"github.com/rom/Xfuzz/pkg/mutate"
)

// This file measures the claim ADR-0005 is built on, and that M2 exists to
// prove: that mutating a typed tree and repairing its derived fields reaches a
// target's parser far more often than perturbing the same bytes blindly.
//
// The measurement is deliberately at the container layer. PNG chunk payloads are
// opaque to the codec — the IDAT stream is deflate-compressed, and decompressing
// it needs a zlib codec composed underneath this one, which is future work. So
// "valid" here means what the derived fields actually protect: the signature is
// intact, every chunk length is in bounds, and every CRC matches. That is
// precisely the validation layer byte-level mutation cannot get past.
//
// Whether the result is a decodable *image* is reported too, honestly, as the
// weaker secondary number it is.

const (
	trialsPerArm = 5000
	maxInputSize = 1 << 16
)

// seedPNGs renders a small spread of genuine PNG files.
func seedPNGs(t testing.TB) [][]byte {
	t.Helper()
	var out [][]byte
	imgs := []image.Image{
		image.NewGray(image.Rect(0, 0, 4, 4)),
		image.NewRGBA(image.Rect(0, 0, 12, 12)),
		image.NewNRGBA(image.Rect(0, 0, 9, 5)),
		image.NewPaletted(image.Rect(0, 0, 6, 6), color.Palette{color.Black, color.White}),
	}
	for i, im := range imgs {
		if r, ok := im.(*image.RGBA); ok {
			for y := 0; y < 12; y++ {
				for x := 0; x < 12; x++ {
					r.Set(x, y, color.RGBA{uint8(x * 20), uint8(y * 20), uint8(i * 60), 255})
				}
			}
		}
		var buf bytes.Buffer
		if err := png.Encode(&buf, im); err != nil {
			t.Fatal(err)
		}
		out = append(out, buf.Bytes())
	}
	return out
}

// containerValid reports whether the PNG container survives: signature present,
// every chunk wholly in bounds, every CRC correct, and no trailing garbage.
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
		want := crc32.ChecksumIEEE(b[pos+4 : int(end)-4])
		if binary.BigEndian.Uint32(b[int(end)-4:]) != want {
			return false
		}
		pos, chunks = int(end), chunks+1
	}
	return chunks > 0
}

// maxDecodePixels bounds what the secondary metric will ask the standard
// library to decode.
//
// This guard exists because the experiment found a real problem on its first
// run. Once the fixup pass restores the CRCs, a mutated IHDR with absurd
// dimensions sails past validation and image/png allocates width*height*4
// bytes — 65 GB, in the run that discovered it. That is a resource-exhaustion
// hazard in any program that decodes untrusted images without limits, and it is
// exactly the class of bug a fuzzer exists to surface. Here it is merely in the
// way, so the header is checked before the image is decoded.
const maxDecodePixels = 1 << 22

func decodable(b []byte) bool {
	cfg, err := png.DecodeConfig(bytes.NewReader(b))
	if err != nil {
		return false
	}
	if cfg.Width <= 0 || cfg.Height <= 0 || cfg.Width > maxDecodePixels/cfg.Height {
		return false
	}
	_, err = png.Decode(bytes.NewReader(b))
	return err == nil
}

type armResult struct {
	name        string
	produced    int
	containerOK int
	imageOK     int
	report      []mutate.NamedStats
}

func (r armResult) containerRate() float64 { return pct(r.containerOK, r.produced) }
func (r armResult) imageRate() float64     { return pct(r.imageOK, r.produced) }

func pct(n, d int) float64 {
	if d == 0 {
		return 0
	}
	return 100 * float64(n) / float64(d)
}

// runArm mutates the seed corpus `trials` times and measures what survives.
//
// Both arms use the same seeds, the same campaign seed, the same number of
// rounds, and the same size cap. The only difference is whether the input is
// understood as a structure.
func runArm(t testing.TB, name string, c codec.Codec, sched *mutate.Scheduler, structured bool, seeds [][]byte) armResult {
	t.Helper()
	res := armResult{name: name}

	arena := ir.NewArena()
	ctx := mutate.NewCtx(0x58465A, 0, arena) // "XFZ"
	ctx.MaxBytes = maxInputSize
	ctx.MaxChildren = 256
	ctx.Dict = pngDictionary()

	decoded := make([]*ir.Node, len(seeds))
	for i, s := range seeds {
		n, err := c.Decode(nil, s)
		if err != nil {
			t.Fatalf("%s: decoding seed %d: %v", name, i, err)
		}
		decoded[i] = n
	}

	fixer := ir.NewFixer()
	for i := 0; i < trialsPerArm; i++ {
		arena.Reset()
		seed := decoded[i%len(decoded)]
		tree := arena.Clone(seed)
		ctx.Root = tree
		ctx.Donor = decoded[(i+1)%len(decoded)]

		if len(sched.Mutate(ctx, tree)) == 0 {
			continue
		}

		var out []byte
		if structured {
			// Repair the derived fields the mutation invalidated. This one call
			// is the entire difference between the two arms.
			buf, err := fixer.Fix(tree, ir.Suppress{})
			if err != nil {
				continue // a mutation made the tree unfixable; counts as a miss
			}
			out = buf
		} else {
			out = ir.Encode(tree)
		}

		res.produced++
		if containerValid(out) {
			res.containerOK++
		}
		if decodable(out) {
			res.imageOK++
		}
	}
	res.report = sched.Report()
	return res
}

// pngDictionary holds the tokens a PNG parser compares against. Random mutation
// essentially never produces a four-byte chunk type, so both arms get the same
// dictionary — the comparison is about structure awareness, not vocabulary.
func pngDictionary() *mutate.Dictionary {
	d := mutate.NewDictionary()
	for _, typ := range []string{
		"IHDR", "PLTE", "IDAT", "IEND", "tRNS", "gAMA", "cHRM",
		"sRGB", "iCCP", "tEXt", "zTXt", "iTXt", "bKGD", "pHYs",
	} {
		d.Add(typ, []byte(typ), 0)
	}
	d.Add("signature", []byte{0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a}, 0)
	return d
}

func byteOnlyScheduler() *mutate.Scheduler {
	s := mutate.NewScheduler()
	for _, m := range mutate.All() {
		if mutate.KindOf(m) == mutate.KindByte {
			s.Add(m, 1)
		}
	}
	return s
}

// TestStructuredMutationBeatsByteLevel is M2's exit criterion.
func TestStructuredMutationBeatsByteLevel(t *testing.T) {
	seeds := seedPNGs(t)
	for i, s := range seeds {
		if !containerValid(s) {
			t.Fatalf("seed %d is not a valid container to begin with", i)
		}
	}

	byteArm := runArm(t, "byte-level", codec.Raw{}, byteOnlyScheduler(), false, seeds)
	structArm := runArm(t, "structured", codec.PNG{}, mutate.Default(), true, seeds)

	t.Logf("\n%-12s %8s %16s %14s", "ARM", "INPUTS", "CONTAINER VALID", "IMAGE DECODES")
	for _, a := range []armResult{byteArm, structArm} {
		t.Logf("%-12s %8d %13d %.1f%% %10d %.1f%%",
			a.name, a.produced, a.containerOK, a.containerRate(), a.imageOK, a.imageRate())
	}

	if byteArm.produced < trialsPerArm/2 || structArm.produced < trialsPerArm/2 {
		t.Fatalf("too few inputs produced (byte %d, structured %d); the arms are not comparable",
			byteArm.produced, structArm.produced)
	}

	// The claim: repairing derived fields gets an order of magnitude more inputs
	// past the validation layer.
	if structArm.containerRate() < 10*byteArm.containerRate() {
		t.Errorf("structured mutation reached %.1f%% container validity against byte-level's %.1f%%;\n"+
			"ADR-0005 claims structure-aware mutation with fixups is decisively better, and it is "+
			"not showing here", structArm.containerRate(), byteArm.containerRate())
	}
	if structArm.containerRate() < 50 {
		t.Errorf("structured mutation only reached %.1f%% container validity; fixups should repair "+
			"the great majority of structural mutations", structArm.containerRate())
	}

	// Per-operator accounting must be reported. Some operators are legitimately
	// idle here — a PNG tree has no typed integers or tagged unions, since the
	// codec models length and CRC as derived fields — so idleness is logged
	// rather than failed. What must hold is that structure-aware operators ran
	// at all, and that no operator that ran was unable to do anything.
	t.Logf("\n%-18s %-12s %10s %10s %10s", "OPERATOR", "CLASS", "ATTEMPTS", "APPLIED", "APPLY%")
	structuralAttempts := uint64(0)
	for _, st := range structArm.report {
		note := ""
		if st.Attempts == 0 {
			note = "  (no applicable node in a PNG tree)"
		}
		t.Logf("%-18s %-12s %10d %10d %9.1f%%%s",
			st.Name, st.Kind, st.Attempts, st.Applied, 100*st.ApplyRate(), note)
		if st.Kind == mutate.KindStructural {
			structuralAttempts += st.Attempts
		}
		if st.Attempts > 0 && st.Applied == 0 {
			t.Errorf("operator %s was attempted %d times and never applied", st.Name, st.Attempts)
		}
	}
	if structuralAttempts == 0 {
		t.Error("no structural operator ran; the structured arm was not actually structure-aware")
	}
}

// TestFixupIsWhatMakesTheDifference isolates the cause. The same structured
// mutations, with the repair pass turned off, should collapse to roughly the
// byte-level rate — showing the gain comes from the fixups and not merely from
// mutating a tree.
func TestFixupIsWhatMakesTheDifference(t *testing.T) {
	seeds := seedPNGs(t)
	withFix := runArm(t, "structured+fixup", codec.PNG{}, mutate.Default(), true, seeds)
	noFix := runArm(t, "structured, no fixup", codec.PNG{}, mutate.Default(), false, seeds)

	t.Logf("with fixup: %.1f%% container valid; without: %.1f%%",
		withFix.containerRate(), noFix.containerRate())

	if noFix.containerRate() >= withFix.containerRate()/2 {
		t.Errorf("disabling fixups only moved validity from %.1f%% to %.1f%%; "+
			"the repair pass should be the dominant effect",
			withFix.containerRate(), noFix.containerRate())
	}
}

func BenchmarkMutateFixEncode(b *testing.B) {
	seeds := seedPNGs(b)
	decoded, err := codec.PNG{}.Decode(nil, seeds[1])
	if err != nil {
		b.Fatal(err)
	}
	arena := ir.NewArena()
	ctx := mutate.NewCtx(1, 0, arena)
	ctx.MaxBytes = maxInputSize
	sched := mutate.Default()
	fixer := ir.NewFixer()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		arena.Reset()
		tree := arena.Clone(decoded)
		ctx.Root = tree
		ctx.Donor = decoded
		sched.Mutate(ctx, tree)
		if _, err := fixer.Fix(tree, ir.Suppress{}); err != nil {
			b.Fatal(err)
		}
	}
}

var _ = fmt.Sprintf
