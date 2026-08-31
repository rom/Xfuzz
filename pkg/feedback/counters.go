package feedback

import (
	"encoding/binary"
	"fmt"
)

// Inline counters: coverage from a compiler that does not call back.
//
// Clang's trace-pc-guard hands the runtime a callback per basic block, so
// coverage can be written straight into the shared map and there is nothing to
// collect afterwards. Some compilers instrument differently. Go's
// `-d=libfuzzer` increments a byte in an array of its own and never calls
// anything, so the coverage of an execution lives in the target's memory and
// somebody has to go and get it.
//
// The runtime solves that by not copying at all: it re-maps the pages holding
// the array onto the shared region, so every increment lands directly in memory
// the fuzzer can read. What arrives here is therefore the target's counter array
// itself, live, and this observer's whole job is to fold it into a coverage map
// the rest of the engine already understands.
//
// The granularity is blocks, not edges. A counter is per basic block and there
// is no ordering information, so two inputs that ran the same blocks in
// different orders are indistinguishable — the same limitation ADR-0027 records
// for the block-trace backends, declared for the same reason rather than
// papered over.

// CounterRegionSize is the size of the region the runtime maps counters into.
// It must equal XFUZZ_CNT_SIZE in the C source.
const CounterRegionSize = 1 << 18

// CounterMagic is the word the runtime writes to say the region is real.
// It must equal XFUZZ_CNT_MAGIC.
const CounterMagic uint32 = 0x434E5432 // "CNT2"

// counterHeaderSize is the fixed prefix the runtime writes: magic, offset,
// count, failed.
const counterHeaderSize = 16

// CounterObserver reads the target's inline counter array.
type CounterObserver struct {
	name   string
	region []byte
	m      *CoverageMap

	// count is how many counters the target registered, and covered how many of
	// them the last execution touched. Both are reported: a target that
	// registered none is one whose instrumentation did not take, and that looks
	// exactly like a target with no reachable code.
	count   int
	covered int

	// failed carries the runtime's own reason for not mapping the array, which
	// is the only place that reason exists.
	failed uint32
}

// NewCounterObserver returns an observer over a counter region.
func NewCounterObserver(name string, region []byte, m *CoverageMap) *CounterObserver {
	return &CounterObserver{name: name, region: region, m: m}
}

// Name implements Observer.
func (o *CounterObserver) Name() string { return o.name }

// Pre implements Observer: it clears the counters before the target runs.
//
// The counters *are* the region, so clearing them here is what makes an
// execution's coverage its own rather than the accumulation of every execution
// before it. The header is left alone: the target writes it once, at startup,
// and a fresh process rewrites it anyway.
func (o *CounterObserver) Pre() error {
	if len(o.region) <= counterHeaderSize {
		return nil
	}
	clear(o.region[counterHeaderSize:])
	return nil
}

// Post implements Observer: it folds the counters into the coverage map.
func (o *CounterObserver) Post(ExitKind) error {
	counters, err := o.counters()
	if err != nil || counters == nil {
		return err
	}
	o.covered = 0
	buf := o.m.Buffer()
	if len(buf) == 0 {
		return nil
	}
	mask := uint32(len(buf) - 1)
	for i, c := range counters {
		if c == 0 {
			continue
		}
		o.covered++
		// Spread, because a counter index is a dense small integer and the map
		// is a hash table: without it the first few hundred blocks would land in
		// the first few hundred slots and the rest of the map would stay empty,
		// which is a hash collision problem disguised as a coverage one.
		slot := SpreadIndex(uint32(i)) & mask
		if buf[slot] < 255 {
			buf[slot]++
		}
	}
	return nil
}

// Reset implements Observer.
func (o *CounterObserver) Reset() {
	o.covered = 0
	_ = o.Pre()
}

// Count returns how many counters the target registered, and Covered how many
// the last execution touched.
func (o *CounterObserver) Count() int   { return o.count }
func (o *CounterObserver) Covered() int { return o.covered }

// counters returns the live counter array, or nil when the target has not
// registered one.
func (o *CounterObserver) counters() ([]byte, error) {
	if len(o.region) < counterHeaderSize {
		return nil, nil
	}
	magic := binary.LittleEndian.Uint32(o.region[0:4])
	if magic != CounterMagic {
		// Not an error: a target that never ran, or one built without the
		// instrumentation, leaves the region as the zeros the fuzzer wrote.
		return nil, nil
	}
	offset := binary.LittleEndian.Uint32(o.region[4:8])
	count := binary.LittleEndian.Uint32(o.region[8:12])
	o.failed = binary.LittleEndian.Uint32(o.region[12:16])
	o.count = int(count)

	if o.failed != 0 {
		return nil, fmt.Errorf("%s: the target could not map its counter array into the "+
			"shared region (reason %d); it has %d counters and the region holds %d bytes",
			o.name, o.failed, count, len(o.region))
	}
	end := uint64(offset) + uint64(count)
	if count == 0 || end > uint64(len(o.region)) {
		return nil, fmt.Errorf("%s: the target reported %d counters at offset %d, which is "+
			"outside the %d-byte region", o.name, count, offset, len(o.region))
	}
	return o.region[offset:end], nil
}

// SpreadIndex scatters a dense index across a hash map.
//
// The same mixer the C runtime applies to its guard identifiers and the same one
// the block-trace backends apply to an address, so a campaign that switches
// between a clang-instrumented and a Go-instrumented build of the same program
// gets comparable map densities rather than one that clusters into the first
// few hundred slots.
func SpreadIndex(i uint32) uint32 {
	x := i
	x ^= x >> 16
	x *= 0x7FEB352D
	x ^= x >> 15
	x *= 0x846CA68B
	x ^= x >> 16
	return x
}
