package feedback

import (
	"encoding/binary"
	"math/bits"
)

// Comparison logging and value profiling.
//
// A fuzzer that cannot get past `if (magic != 0xDEADBEEF)` is behind a
// one-in-four-billion guess, and mutation does not fix that. Two things do, and
// both need the same data: the operands of the comparisons the program actually
// performed.
//
// Knowing them, the fuzzer can find the value it supplied inside its own input
// and write the value the program wanted in its place — a four-byte magic
// number becomes one directed edit instead of four billion guesses. That is
// input-to-state substitution, and it lives in the engine's CmpLogStage because
// it produces new inputs rather than judging old ones.
//
// The same operands also say how *close* a comparison came. A four-byte compare
// that matched three bytes is nearly right, and a campaign that treats "closer"
// as new coverage can climb a comparison it could never jump. That is value
// profiling, and it lives here, because it is a feedback like any other.
//
// See ADR-0007.

// CmpRegionSize is the size of the shared region the runtime writes comparisons
// into. It must match XFUZZ_CMP_SIZE in the C runtime.
const CmpRegionSize = 1 << 18

// The record layout, matching struct xfuzz_cmp_rec. A mismatch means the fuzzer
// reads a different table than the target writes, and every operand it recovers
// is nonsense — so the sizes are named here and asserted by a test that compiles
// the runtime and compares.
const (
	CmpHeaderSize  = 16
	CmpRecordSize  = 40
	CmpOperandSize = 16
)

// CmpKind distinguishes an integer comparison from a memory one.
type CmpKind uint8

// The comparison kinds, matching XFUZZ_CMP_INT and XFUZZ_CMP_MEM.
const (
	CmpInt CmpKind = 1
	CmpMem CmpKind = 2
)

func (k CmpKind) String() string {
	switch k {
	case CmpInt:
		return "int"
	case CmpMem:
		return "mem"
	}
	return "unknown"
}

// CmpRecord is one comparison the target performed.
type CmpRecord struct {
	// Loc identifies the comparison site, spread across the map so that two
	// nearby sites do not collide.
	Loc uint32

	// Kind says how to read the operands: an integer of Size bytes,
	// little-endian, or Size bytes of memory.
	Kind CmpKind

	// Size is how many bytes of each operand are meaningful.
	Size uint8

	// Hit is how many leading bytes matched, for a memory comparison. It is the
	// direct measure of how close the comparison came.
	Hit uint16

	// A and B are the operands. For a constant comparison the compiler puts the
	// constant second, which is what substitution wants: replace what the input
	// supplied with what the program expected.
	A, B [CmpOperandSize]byte
}

// AUint and BUint return the operands as integers, valid when Kind is CmpInt.
func (r CmpRecord) AUint() uint64 { return leUint(r.A[:], int(r.Size)) }

// BUint returns the second operand as an integer.
func (r CmpRecord) BUint() uint64 { return leUint(r.B[:], int(r.Size)) }

func leUint(b []byte, n int) uint64 {
	if n > 8 {
		n = 8
	}
	var v uint64
	for i := 0; i < n && i < len(b); i++ {
		v |= uint64(b[i]) << (8 * i)
	}
	return v
}

// CmpObserver reads the comparison table the runtime wrote.
//
// Like the coverage map, it points at the shared region rather than copying it:
// at fork-server rates a copy of a quarter of a megabyte per execution would
// cost more than the execution. Unlike the coverage map, it has to reset the
// count before each run — the table is written from the front, and a target
// that did not reset it would append this execution's comparisons to the last
// one's and every stage downstream would work from a mixture.
type CmpObserver struct {
	name    string
	region  []byte
	records []CmpRecord

	// dropped counts entries the target could not fit. A campaign where this is
	// large is one whose substitutions come only from the beginning of each
	// execution, which is worth knowing and not worth failing over.
	dropped uint64
}

// NewCmpObserver returns an observer over a shared comparison region.
func NewCmpObserver(name string, region []byte) *CmpObserver {
	return &CmpObserver{name: name, region: region}
}

// Name implements Observer.
func (o *CmpObserver) Name() string { return o.name }

// Pre implements Observer. It clears the count so the target starts writing at
// the front, and publishes the region's capacity so a target built against a
// different runtime version cannot be read past its end.
func (o *CmpObserver) Pre() error {
	o.records = o.records[:0]
	if len(o.region) < CmpHeaderSize {
		return nil
	}
	binary.LittleEndian.PutUint32(o.region[0:], 0)
	binary.LittleEndian.PutUint32(o.region[8:], 0)
	return nil
}

// Post implements Observer: it decodes what the target wrote.
func (o *CmpObserver) Post(ExitKind) error {
	o.records = o.records[:0]
	if len(o.region) < CmpHeaderSize {
		return nil
	}
	count := binary.LittleEndian.Uint32(o.region[0:])
	capacity := binary.LittleEndian.Uint32(o.region[4:])
	o.dropped += uint64(binary.LittleEndian.Uint32(o.region[8:]))

	// The target's own capacity bounds the read, and so does the region. Both,
	// because the count comes from a program that is being fuzzed: a target
	// that scribbled over the header must not be able to make the fuzzer read
	// past the mapping.
	max := uint32((len(o.region) - CmpHeaderSize) / CmpRecordSize)
	if capacity > 0 && capacity < max {
		max = capacity
	}
	if count > max {
		count = max
	}

	for i := uint32(0); i < count; i++ {
		off := CmpHeaderSize + int(i)*CmpRecordSize
		var r CmpRecord
		r.Loc = binary.LittleEndian.Uint32(o.region[off:])
		r.Kind = CmpKind(o.region[off+4])
		r.Size = o.region[off+5]
		r.Hit = binary.LittleEndian.Uint16(o.region[off+6:])
		copy(r.A[:], o.region[off+8:off+8+CmpOperandSize])
		copy(r.B[:], o.region[off+24:off+24+CmpOperandSize])
		if r.Size == 0 || r.Size > CmpOperandSize {
			continue
		}
		o.records = append(o.records, r)
	}
	return nil
}

// Reset implements Observer.
func (o *CmpObserver) Reset() { o.records = o.records[:0] }

// Records returns the comparisons from the most recent execution. The slice is
// reused between executions, so a caller that needs to keep one copies it.
func (o *CmpObserver) Records() []CmpRecord { return o.records }

// Dropped returns how many comparisons the target could not fit, across the
// whole campaign.
func (o *CmpObserver) Dropped() uint64 { return o.dropped }

// Region returns the shared buffer, for wiring into an executor.
func (o *CmpObserver) Region() []byte { return o.region }

// ValueProfile turns "how close did this comparison come" into coverage.
//
// A comparison is a cliff: either the input matched and the program went one
// way, or it did not and the program went the other, and coverage sees nothing
// in between. Value profiling puts a slope on the cliff. It records, per
// comparison site, how many bits of the two operands agreed — and a new
// (site, closeness) pair counts as new signal, exactly like a new edge.
//
// The effect is that an input which gets three bytes of a four-byte magic number
// right is kept, and the campaign has something to mutate towards the fourth. It
// is what makes a comparison ladder climbable without a dictionary, at the cost
// of a corpus that grows along every comparison in the program.
//
// Bits agreed rather than bytes, because a byte-granular measure gives a
// four-byte comparison five distinguishable states and a bit-granular one gives
// it thirty-three. The finer measure is what carries a campaign through a
// checksum, where no byte is ever individually right.
type ValueProfile struct {
	name string
	obs  *CmpObserver

	// seen is the set of (site, closeness) pairs already recorded, in the same
	// masked-index form the coverage map uses so that its size is bounded.
	seen []byte

	// pending is what the most recent judgement would add, held until Append so
	// that a feedback in a stack can be overruled without having already folded
	// the input into its own state.
	pending []uint32
	newHits int
}

// DefaultValueProfileSize bounds the value-profile map.
//
// A quarter of the coverage map. Value profiling is a secondary signal — it
// exists to get past comparisons, not to describe the program — and giving it a
// map as large as coverage's would let a single checksum-heavy target fill
// memory with states that differ in one bit and mean nothing.
const DefaultValueProfileSize = 1 << 14

// NewValueProfile returns a value-profile feedback over a comparison observer.
func NewValueProfile(name string, obs *CmpObserver, size int) *ValueProfile {
	if size <= 0 {
		size = DefaultValueProfileSize
	}
	return &ValueProfile{name: name, obs: obs, seen: make([]byte, size)}
}

// Name implements Feedback.
func (v *ValueProfile) Name() string { return v.name }

// Covered returns how many distinct (site, closeness) pairs have been seen.
func (v *ValueProfile) Covered() int {
	n := 0
	for _, b := range v.seen {
		if b != 0 {
			n++
		}
	}
	return n
}

// IsInteresting implements Feedback.
func (v *ValueProfile) IsInteresting(_ []Observer, _ ExitKind) (bool, Score, error) {
	v.pending = v.pending[:0]
	v.newHits = 0
	if v.obs == nil || len(v.seen) == 0 {
		return false, Score{}, nil
	}

	mask := uint32(len(v.seen) - 1)
	for _, r := range v.obs.Records() {
		idx := (r.Loc ^ closeness(r)) & mask
		if v.seen[idx] == 0 {
			v.pending = append(v.pending, idx)
			v.newHits++
		}
	}
	if v.newHits == 0 {
		return false, Score{}, nil
	}
	return true, Score{
		NewSignal: v.newHits,
		Novelty:   float64(v.newHits) / float64(max(1, len(v.obs.Records()))),
	}, nil
}

// Append implements Feedback.
func (v *ValueProfile) Append() {
	for _, idx := range v.pending {
		v.seen[idx] = 1
	}
	v.pending = v.pending[:0]
	v.newHits = 0
}

// Discard implements Feedback.
func (v *ValueProfile) Discard() {
	v.pending = v.pending[:0]
	v.newHits = 0
}

// closeness measures how nearly a comparison passed, as a small integer.
//
// For an integer comparison, the number of bits that differ: zero would mean
// equal, which the runtime does not record, so the useful range is one upwards
// and smaller is closer. For a memory comparison the runtime already counted
// the matching prefix, which is the better measure there — a string comparison
// that matched six characters is closer than one that matched two, whatever the
// bits of the seventh happen to be.
func closeness(r CmpRecord) uint32 {
	if r.Kind == CmpMem {
		return uint32(r.Hit)
	}
	n := int(r.Size)
	if n > 8 {
		n = 8
	}
	return uint32(bits.OnesCount64(leUint(r.A[:], n) ^ leUint(r.B[:], n)))
}
