package generate

import (
	"testing"

	"github.com/rom/Xfuzz/pkg/rng"
)

func TestRandomIntStaysInsideItsWidth(t *testing.T) {
	// A value generated for a one-byte field that does not fit in a byte is
	// truncated by the encoder, so the tree and the bytes disagree about what
	// was generated. The width is the mask.
	r := rng.New(7)
	for _, width := range []uint8{1, 2, 4} {
		limit := int64(1)<<(8*uint(width)) - 1
		for i := 0; i < 1000; i++ {
			v := randomInt(r, width)
			if v < 0 || v > limit {
				t.Fatalf("width %d produced %d, outside 0..%d", width, v, limit)
			}
		}
	}
	// Eight bytes is the whole word, sign and all.
	var negative bool
	for i := 0; i < 1000 && !negative; i++ {
		negative = randomInt(r, 8) < 0
	}
	if !negative {
		t.Error("a full-width value never used its top bit in a thousand draws")
	}
}
