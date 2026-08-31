package feedback

import (
	"encoding/binary"
	"fmt"
)

// Directed fuzzing: keeping an input because it went somewhere closer.
//
// A coverage-guided campaign keeps an input that reached code nothing had
// reached. That is the right question for finding bugs anywhere and the wrong
// one for finding a bug *there* — in the function a crash report names, the
// lines a patch touched, the parser a report says is broken. An input that
// reached no new code but got two calls nearer the place under investigation is
// progress, and coverage cannot see it at all (ADR-0007).
//
// Distance is measured in basic blocks along the program's own control flow, by
// the analysis that produced the distance map. Everything here consumes that
// map through a small interface, so this package does not depend on binary
// analysis and a campaign can supply distances from anywhere.

// BlockRegionSize is the size of the shared region an instrumented target writes
// its executed block addresses into. It must match XFUZZ_BB_SIZE in the runtime.
const BlockRegionSize = 1 << 20

// blockHeaderSize is the header the runtime writes before the addresses.
const blockHeaderSize = 32

// BlockDistance answers how far a basic block is from a directed campaign's
// target.
//
// An interface rather than the concrete map, so that pkg/feedback does not
// depend on binary analysis: the core judges, and where the numbers came from is
// not its business. It is also what lets a campaign supply distances computed by
// something else entirely — a profiler, a coverage report from a previous run, a
// plugin.
type BlockDistance interface {
	// Of returns a block's distance, and whether it has one at all. A block with
	// no route to any target has none, and scoring it as merely "far" would make
	// every input look like partial progress.
	Of(block uint64) (uint32, bool)

	// MaxDistance is the largest finite distance, which normalises a score.
	MaxDistance() uint32
}

// BlockObserver records which basic blocks an execution entered.
//
// Two sources feed it and it does not care which. An emulated or traced target
// reports block addresses directly, because watching a process is how that tier
// works; an instrumented target writes them into a shared region, which is what
// the runtime's block trace is for. Both arrive as link-time addresses, which is
// the only form that means the same thing twice.
type BlockObserver struct {
	name   string
	region []byte
	blocks []uint64

	// base is subtracted from the addresses an instrumented target reports.
	// A position-independent binary is loaded somewhere new on every execution,
	// so a runtime address identifies a block only within one run.
	base     uint64
	haveBase bool

	// anchorLink is the link-time address of the symbol the runtime publishes
	// the runtime address of. The difference is the load base.
	anchorLink uint64

	dropped uint64
}

// NewBlockObserver returns an observer over an optional shared region.
//
// region may be nil, for a tier that reports blocks by calling RecordBlocks
// rather than by having the target write them.
func NewBlockObserver(name string, region []byte) *BlockObserver {
	return &BlockObserver{name: name, region: region}
}

// SetAnchor gives the observer the link-time address of the symbol the runtime
// publishes at run time, so the load base can be recovered.
func (o *BlockObserver) SetAnchor(linkTime uint64) { o.anchorLink = linkTime }

// Name implements Observer.
func (o *BlockObserver) Name() string { return o.name }

// Pre implements Observer. It clears the count so the target writes from the
// front: without this, one execution's blocks would be appended to the last
// one's and every input would look like it had reached everything.
func (o *BlockObserver) Pre() error {
	o.blocks = o.blocks[:0]
	if len(o.region) >= blockHeaderSize {
		binary.LittleEndian.PutUint32(o.region[0:], 0)
		binary.LittleEndian.PutUint32(o.region[8:], 0)
	}
	return nil
}

// Post implements Observer.
func (o *BlockObserver) Post(ExitKind) error {
	if len(o.region) < blockHeaderSize {
		return nil
	}
	count := binary.LittleEndian.Uint32(o.region[0:])
	capacity := binary.LittleEndian.Uint32(o.region[4:])
	o.dropped += uint64(binary.LittleEndian.Uint32(o.region[8:]))
	anchor := binary.LittleEndian.Uint64(o.region[16:])

	if !o.haveBase && anchor != 0 && o.anchorLink != 0 && anchor >= o.anchorLink {
		o.base, o.haveBase = anchor-o.anchorLink, true
	}

	// Bounded by the region as well as by the target's own count. The count is
	// written by a program that is being fuzzed, so a target that scribbled over
	// its header must not be able to make the fuzzer read past the mapping.
	max := uint32((len(o.region) - blockHeaderSize) / 8)
	if capacity > 0 && capacity < max {
		max = capacity
	}
	if count > max {
		count = max
	}

	o.blocks = o.blocks[:0]
	for i := uint32(0); i < count; i++ {
		pc := binary.LittleEndian.Uint64(o.region[blockHeaderSize+int(i)*8:])
		if pc < o.base {
			continue
		}
		o.blocks = append(o.blocks, pc-o.base)
	}
	return nil
}

// Reset implements Observer.
func (o *BlockObserver) Reset() { o.blocks = o.blocks[:0] }

// RecordBlocks is how a tier that watches the process supplies what it saw.
//
// Structural, not imported: pkg/executor declares the interface and this
// implements it without naming it, so the dependency stays one-way (ARCHITECTURE
// section 2).
func (o *BlockObserver) RecordBlocks(blocks []uint64) {
	o.blocks = append(o.blocks[:0], blocks...)
}

// Blocks returns the addresses the most recent execution entered. The slice is
// reused, so a caller that needs to keep one copies it.
func (o *BlockObserver) Blocks() []uint64 { return o.blocks }

// Dropped returns how many block records the target could not fit.
func (o *BlockObserver) Dropped() uint64 { return o.dropped }

// Region returns the shared buffer, for wiring into an executor.
func (o *BlockObserver) Region() []byte { return o.region }

// DistanceFeedback keeps an input that got closer to a target than anything
// before it.
//
// Closeness is the mean distance of the blocks the execution entered, which is
// the measure AFLGo established and the one that behaves sensibly: a minimum
// would be dominated by whichever single block happened to be nearest and would
// stop distinguishing inputs as soon as any of them reached the target's
// function, while a mean falls as more of the execution happens near the target.
//
// Blocks with no route to any target are excluded rather than scored as far. An
// execution that spent most of its time in unrelated code should not look worse
// than one that barely ran; what matters is where it went among the places that
// can lead to the target.
type DistanceFeedback struct {
	name string
	obs  *BlockObserver
	dist BlockDistance

	// best is the closest mean distance any admitted input achieved. An input
	// has to beat it to be interesting, which is what makes this a descent
	// rather than a filter that admits everything within some threshold.
	best float64

	pending    float64
	hasPending bool
}

// NewDistanceFeedback returns a directed feedback over a block observer and a
// distance map.
func NewDistanceFeedback(name string, obs *BlockObserver, dist BlockDistance) *DistanceFeedback {
	return &DistanceFeedback{name: name, obs: obs, dist: dist, best: -1}
}

// Name implements Feedback.
func (f *DistanceFeedback) Name() string { return f.name }

// Closest returns the best mean distance reached so far, and whether any input
// has produced one. It is what a campaign reports as its progress towards the
// target, and the number an operator watches to decide whether direction is
// working.
func (f *DistanceFeedback) Closest() (float64, bool) {
	if f.best < 0 {
		return 0, false
	}
	return f.best, true
}

// IsInteresting implements Feedback.
func (f *DistanceFeedback) IsInteresting(_ []Observer, _ ExitKind) (bool, Score, error) {
	f.hasPending = false
	if f.obs == nil || f.dist == nil {
		return false, Score{}, nil
	}

	var sum float64
	var n int
	for _, b := range f.obs.Blocks() {
		d, ok := f.dist.Of(b)
		if !ok {
			continue
		}
		sum += float64(d)
		n++
	}
	if n == 0 {
		// The execution went nowhere that leads to a target.
		//
		// Reported as maximally distant, not as no information. Score.Distance
		// is normalised with zero meaning *at* the target, so an empty score
		// would tell the schedule that an input which never came near the target
		// had arrived at it — and a directed schedule would then spend its whole
		// budget on precisely the inputs that went the wrong way.
		return false, Score{Distance: 1}, nil
	}
	mean := sum / float64(n)

	// Normalised, so the score means the same thing whatever the program's
	// diameter: 0 at the target and 1 as far away as anything gets.
	norm := mean
	if m := f.dist.MaxDistance(); m > 0 {
		norm = mean / float64(m)
	}
	score := Score{Distance: norm}

	if f.best >= 0 && mean >= f.best {
		return false, score, nil
	}
	f.pending, f.hasPending = mean, true
	score.NewSignal = 1
	return true, score, nil
}

// Append implements Feedback.
func (f *DistanceFeedback) Append() {
	if f.hasPending {
		f.best = f.pending
		f.hasPending = false
	}
}

// Discard implements Feedback.
func (f *DistanceFeedback) Discard() { f.hasPending = false }

// String reports the campaign's progress towards its target.
func (f *DistanceFeedback) String() string {
	if d, ok := f.Closest(); ok {
		return fmt.Sprintf("%s: closest %.2f blocks", f.name, d)
	}
	return f.name + ": nothing has reached the target's neighbourhood yet"
}
