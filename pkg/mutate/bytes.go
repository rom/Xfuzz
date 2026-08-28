package mutate

import "github.com/rom/Xfuzz/pkg/ir"

// Byte-level operators. These are the classic mutations that work on any input
// with no knowledge of its format, and they remain essential even with a schema:
// a structured field's payload is still bytes, and formats always have regions
// a grammar does not describe.

// interesting8, interesting16 and interesting32 are the boundary values that
// disproportionately trigger bugs: signedness flips, off-by-ones around zero,
// and the limits of each width. Anything derived from a length or an index tends
// to break at exactly these.
var (
	interesting8 = []int64{
		-128, -1, 0, 1, 16, 32, 64, 100, 127,
	}
	interesting16 = []int64{
		-32768, -129, 128, 255, 256, 512, 1000, 1024, 4096, 32767,
	}
	interesting32 = []int64{
		-2147483648, -100663046, -32769, 32768, 65535, 65536, 100663045, 2147483647,
	}
	interesting64 = []int64{
		-9223372036854775808, -2147483649, 2147483648, 4294967295, 4294967296,
		9223372036854775807,
	}
)

// arithMax bounds the delta an arithmetic operator applies. Small deltas walk a
// value across a nearby boundary; large ones may as well be random.
const arithMax = 35

// BitFlip flips a run of 1, 2, or 4 adjacent bits.
type BitFlip struct{}

func (BitFlip) Name() string                     { return "bitflip" }
func (BitFlip) Kind() Kind                       { return KindByte }
func (BitFlip) CanApply(c *Ctx, n *ir.Node) bool { return isPayload(n) }

func (BitFlip) Mutate(c *Ctx, n *ir.Node) bool {
	bits := 1 << c.Rand.Intn(3) // 1, 2 or 4
	total := len(n.Raw) * 8
	if total < bits {
		return false
	}
	at := c.Rand.Intn(total - bits + 1)
	for i := 0; i < bits; i++ {
		p := at + i
		n.Raw[p/8] ^= 1 << (p % 8)
	}
	return true
}

// ByteFlip inverts a run of 1, 2, or 4 bytes.
type ByteFlip struct{}

func (ByteFlip) Name() string                     { return "byteflip" }
func (ByteFlip) Kind() Kind                       { return KindByte }
func (ByteFlip) CanApply(c *Ctx, n *ir.Node) bool { return isPayload(n) }

func (ByteFlip) Mutate(c *Ctx, n *ir.Node) bool {
	width := 1 << c.Rand.Intn(3)
	if len(n.Raw) < width {
		return false
	}
	at := c.Rand.Intn(len(n.Raw) - width + 1)
	for i := 0; i < width; i++ {
		n.Raw[at+i] ^= 0xff
	}
	return true
}

// Arith adds or subtracts a small value from an 8, 16, or 32-bit window,
// interpreted in either byte order.
//
// Both orders are tried because the operator has no idea how the target reads
// the bytes, and getting it wrong wastes the mutation.
type Arith struct{}

func (Arith) Name() string                     { return "arith" }
func (Arith) Kind() Kind                       { return KindByte }
func (Arith) CanApply(c *Ctx, n *ir.Node) bool { return isPayload(n) }

func (Arith) Mutate(c *Ctx, n *ir.Node) bool {
	width := 1 << c.Rand.Intn(3)
	if len(n.Raw) < width {
		return false
	}
	at := c.Rand.Intn(len(n.Raw) - width + 1)
	delta := int64(c.Rand.IntRange(1, arithMax))
	if c.Rand.Bool() {
		delta = -delta
	}
	e := ir.BigEndian
	if c.Rand.Bool() {
		e = ir.LittleEndian
	}
	w := uint8(width)
	v := ir.ReadInt(n.Raw[at:at+width], w, e, false)
	writeInt(n.Raw[at:at+width], v+delta, w, e)
	return true
}

// Interesting writes a boundary value into an 8, 16, or 32-bit window.
type Interesting struct{}

func (Interesting) Name() string                     { return "interesting" }
func (Interesting) Kind() Kind                       { return KindByte }
func (Interesting) CanApply(c *Ctx, n *ir.Node) bool { return isPayload(n) }

func (Interesting) Mutate(c *Ctx, n *ir.Node) bool {
	width := 1 << c.Rand.Intn(3)
	if len(n.Raw) < width {
		return false
	}
	at := c.Rand.Intn(len(n.Raw) - width + 1)
	var pool []int64
	switch width {
	case 1:
		pool = interesting8
	case 2:
		pool = interesting16
	default:
		pool = interesting32
	}
	v := pool[c.Rand.Intn(len(pool))]
	e := ir.BigEndian
	if c.Rand.Bool() {
		e = ir.LittleEndian
	}
	writeInt(n.Raw[at:at+width], v, uint8(width), e)
	return true
}

// RandomByte replaces one byte with a different random value.
type RandomByte struct{}

func (RandomByte) Name() string                     { return "randbyte" }
func (RandomByte) Kind() Kind                       { return KindByte }
func (RandomByte) CanApply(c *Ctx, n *ir.Node) bool { return isPayload(n) }

func (RandomByte) Mutate(c *Ctx, n *ir.Node) bool {
	at := c.Rand.Intn(len(n.Raw))
	// XOR with a non-zero value so the operator always changes something;
	// reporting a change that did not happen corrupts per-operator accounting.
	n.Raw[at] ^= byte(c.Rand.IntRange(1, 255))
	return true
}

// SetBlock overwrites a run with a single repeated byte, which is how large
// uniform regions and padding get explored.
type SetBlock struct{}

func (SetBlock) Name() string                     { return "setblock" }
func (SetBlock) Kind() Kind                       { return KindByte }
func (SetBlock) CanApply(c *Ctx, n *ir.Node) bool { return isPayload(n) }

func (SetBlock) Mutate(c *Ctx, n *ir.Node) bool {
	at := c.Rand.Intn(len(n.Raw))
	length := c.Rand.IntRange(1, min(len(n.Raw)-at, 64))
	var v byte
	if c.Rand.Bool() {
		v = n.Raw[c.Rand.Intn(len(n.Raw))]
	} else {
		v = c.Rand.Byte()
	}
	for i := at; i < at+length; i++ {
		n.Raw[i] = v
	}
	return true
}

// InsertBytes lengthens a payload with a run of repeated or random bytes.
type InsertBytes struct{}

func (InsertBytes) Name() string { return "insert" }
func (InsertBytes) Kind() Kind   { return KindByte }
func (InsertBytes) CanApply(c *Ctx, n *ir.Node) bool {
	return isWritable(n) && c.canGrow(n) > 0
}

func (InsertBytes) Mutate(c *Ctx, n *ir.Node) bool {
	room := c.canGrow(n)
	if room <= 0 {
		return false
	}
	count := c.Rand.IntRange(1, min(room, 64))
	at := c.Rand.Intn(len(n.Raw) + 1)
	var fill byte
	if len(n.Raw) > 0 && c.Rand.Bool() {
		fill = n.Raw[c.Rand.Intn(len(n.Raw))]
	} else {
		fill = c.Rand.Byte()
	}
	n.Raw = insertRun(c, n.Raw, at, count, fill)
	return true
}

// DeleteBytes removes a run from a payload.
type DeleteBytes struct{}

func (DeleteBytes) Name() string { return "delete" }
func (DeleteBytes) Kind() Kind   { return KindByte }
func (DeleteBytes) CanApply(c *Ctx, n *ir.Node) bool {
	return isPayload(n) && len(n.Raw) > 1 && c.canShrink(n) > 0
}

func (DeleteBytes) Mutate(c *Ctx, n *ir.Node) bool {
	room := c.canShrink(n)
	if room <= 0 {
		return false
	}
	at := c.Rand.Intn(len(n.Raw))
	length := c.Rand.IntRange(1, min(min(len(n.Raw)-at, room), 64))
	n.Raw = append(n.Raw[:at], n.Raw[at+length:]...)
	return true
}

// CopyBytes duplicates a run from elsewhere in the same payload, either
// overwriting or inserting. Self-copying is how repeated structures — records,
// escape sequences, nested delimiters — get multiplied.
type CopyBytes struct{}

func (CopyBytes) Name() string                     { return "copy" }
func (CopyBytes) Kind() Kind                       { return KindByte }
func (CopyBytes) CanApply(c *Ctx, n *ir.Node) bool { return isPayload(n) && len(n.Raw) > 1 }

func (CopyBytes) Mutate(c *Ctx, n *ir.Node) bool {
	src := c.Rand.Intn(len(n.Raw))
	length := c.Rand.IntRange(1, min(len(n.Raw)-src, 64))

	if c.Rand.Bool() {
		// Overwrite in place.
		dst := c.Rand.Intn(len(n.Raw))
		length = min(length, len(n.Raw)-dst)
		if length == 0 {
			return false
		}
		copy(n.Raw[dst:dst+length], n.Raw[src:src+length])
		return true
	}

	room := c.canGrow(n)
	if room <= 0 {
		return false
	}
	length = min(length, room)
	dst := c.Rand.Intn(len(n.Raw) + 1)
	// The source run is captured before the shift, since inserting moves it.
	tmp := c.Arena.Buf(length)
	copy(tmp, n.Raw[src:src+length])
	n.Raw = insertRun(c, n.Raw, dst, length, 0)
	copy(n.Raw[dst:dst+length], tmp)
	return true
}

// insertRun opens a gap of count bytes at position at, filling it with fill.
func insertRun(c *Ctx, b []byte, at, count int, fill byte) []byte {
	b = c.Arena.GrowBytes(b, count)
	b = b[:len(b)+count]
	copy(b[at+count:], b[at:])
	for i := at; i < at+count; i++ {
		b[i] = fill
	}
	return b
}

// writeInt stores v into a byte window in the given order. It mirrors the
// encoder so that a mutated window reads back as the value written.
func writeInt(dst []byte, v int64, width uint8, e ir.Endian) {
	u := uint64(v)
	if e == ir.LittleEndian {
		for i := 0; i < int(width); i++ {
			dst[i] = byte(u >> (8 * i))
		}
		return
	}
	for i := 0; i < int(width); i++ {
		dst[i] = byte(u >> (8 * (int(width) - 1 - i)))
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
