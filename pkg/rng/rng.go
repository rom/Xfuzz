// Package rng provides the deterministic randomness every fuzzing decision
// draws from.
//
// ASR-0008 makes reproducibility a hard requirement: the same campaign file,
// seed, and target must produce an identical sequence of executions, and every
// finding must replay from stored artifacts alone. That rules out global or
// implicitly seeded randomness anywhere in the engine.
//
// Two properties matter beyond determinism:
//
// Independent streams. Seed selection, mutator choice, mutator parameters, and
// scheduling each draw from their own stream, so adding a stage cannot perturb
// another stage's sequence. Without that, any change to the engine reshuffles
// every campaign and old findings stop replaying.
//
// Addressable position. The generator is counter-based rather than
// state-chaining, so a stream's position is a number that can be recorded in a
// testcase's provenance and seeked back to in O(1). That is what makes
// "reconstruct this input from its parent and the operators applied" work.
package rng

import "math/bits"

// golden is 2^64 divided by the golden ratio, the standard SplitMix64
// increment. Successive multiples are well spread across the 64-bit space,
// which is what makes counter-based generation sound.
const golden = 0x9E3779B97F4A7C15

// mix is the SplitMix64 finalizer: a bijection with good avalanche, so counter
// values that differ by one produce unrelated outputs.
func mix(x uint64) uint64 {
	x = (x ^ (x >> 30)) * 0xBF58476D1CE4E5B9
	x = (x ^ (x >> 27)) * 0x94D049BB133111EB
	return x ^ (x >> 31)
}

// Stream identifies an independent sequence within one worker.
//
// Each concern gets its own stream so that a change to one does not shift the
// others. New streams must be appended, never inserted: renumbering an existing
// stream changes every campaign that used it.
type Stream uint32

// The engine's streams.
const (
	StreamSeedSelect    Stream = iota // which corpus entry to fuzz next
	StreamMutatorSelect               // which operator to apply
	StreamMutatorParam                // the operator's parameters
	StreamStructure                   // structural choices: which node, how many
	StreamSplice                      // donor selection for crossover
	StreamGenerate                    // grammar-driven generation
	StreamSchedule                    // power schedule and energy
	StreamState                       // protocol state selection
	numStreams
)

var streamNames = [...]string{
	StreamSeedSelect:    "seed-select",
	StreamMutatorSelect: "mutator-select",
	StreamMutatorParam:  "mutator-param",
	StreamStructure:     "structure",
	StreamSplice:        "splice",
	StreamGenerate:      "generate",
	StreamSchedule:      "schedule",
	StreamState:         "state",
}

func (s Stream) String() string {
	if int(s) < len(streamNames) && streamNames[s] != "" {
		return streamNames[s]
	}
	return "stream(" + itoa(uint64(s)) + ")"
}

func itoa(v uint64) string {
	if v == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	return string(b[i:])
}

// Rand is a counter-based pseudorandom source. It is not safe for concurrent
// use; each worker's fuzz loop is single-threaded and owns its streams.
type Rand struct {
	base uint64
	ctr  uint64
}

// New returns a stream seeded directly.
func New(seed uint64) *Rand { return &Rand{base: mix(seed)} }

// Derive returns the stream for one concern within one worker, seeded
// H(campaign_seed, worker_id, stream) as ASR-0008 specifies. The same three
// inputs always produce the same sequence, on any machine.
func Derive(campaignSeed uint64, workerID uint32, s Stream) *Rand {
	h := mix(campaignSeed + golden)
	h = mix(h ^ (uint64(workerID)+1)*golden)
	h = mix(h ^ (uint64(s)+1)*golden)
	return &Rand{base: h}
}

// Fork returns an independent sub-stream, for work that must be reproducible on
// its own — replaying one mutation without replaying the whole campaign.
func (r *Rand) Fork(tag uint64) *Rand {
	return &Rand{base: mix(r.base ^ (tag+1)*golden)}
}

// Position returns how many values the stream has produced. Recording it in a
// testcase's provenance is what allows the exact sequence to be replayed.
func (r *Rand) Position() uint64 { return r.ctr }

// Seek moves the stream to a position, so a recorded provenance can be resumed.
func (r *Rand) Seek(pos uint64) { r.ctr = pos }

// Clone returns a copy positioned identically.
func (r *Rand) Clone() *Rand { return &Rand{base: r.base, ctr: r.ctr} }

// Uint64 returns the next value.
func (r *Rand) Uint64() uint64 {
	r.ctr++
	return mix(r.base + r.ctr*golden)
}

// Uint32 returns the next value truncated to 32 bits.
func (r *Rand) Uint32() uint32 { return uint32(r.Uint64() >> 32) }

// Byte returns a random byte.
func (r *Rand) Byte() byte { return byte(r.Uint64() >> 56) }

// Bool returns a random boolean.
func (r *Rand) Bool() bool { return r.Uint64()>>63 != 0 }

// Intn returns a value in [0, n). It panics for n <= 0.
//
// The bound is applied by Lemire's multiply-shift rather than a modulo, which
// is both faster and free of the low-bit bias modulo introduces.
func (r *Rand) Intn(n int) int {
	if n <= 0 {
		panic("rng: Intn requires a positive bound")
	}
	return int(r.uint64n(uint64(n)))
}

// Int64n returns a value in [0, n).
func (r *Rand) Int64n(n int64) int64 {
	if n <= 0 {
		panic("rng: Int64n requires a positive bound")
	}
	return int64(r.uint64n(uint64(n)))
}

// IntRange returns a value in [lo, hi]. It panics if hi < lo.
func (r *Rand) IntRange(lo, hi int) int {
	if hi < lo {
		panic("rng: IntRange requires hi >= lo")
	}
	if hi == lo {
		return lo
	}
	return lo + r.Intn(hi-lo+1)
}

func (r *Rand) uint64n(n uint64) uint64 {
	hi, lo := bits.Mul64(r.Uint64(), n)
	if lo < n {
		// Reject the biased tail. The loop runs with probability below n/2^64,
		// so in practice never, but leaving it out would skew short ranges.
		thresh := -n % n
		for lo < thresh {
			hi, lo = bits.Mul64(r.Uint64(), n)
		}
	}
	return hi
}

// Float64 returns a value in [0, 1).
func (r *Rand) Float64() float64 { return float64(r.Uint64()>>11) / (1 << 53) }

// Chance reports whether an event with the given probability occurs. A
// probability at or below zero never fires; at or above one it always does.
func (r *Rand) Chance(p float64) bool {
	switch {
	case p <= 0:
		return false
	case p >= 1:
		return true
	}
	return r.Float64() < p
}

// Fill writes random bytes into b.
func (r *Rand) Fill(b []byte) {
	for i := 0; i < len(b); {
		v := r.Uint64()
		for j := 0; j < 8 && i < len(b); j++ {
			b[i] = byte(v)
			v >>= 8
			i++
		}
	}
}

// Pick returns a random index into a collection of the given length, or -1 when
// it is empty.
func (r *Rand) Pick(n int) int {
	if n <= 0 {
		return -1
	}
	return r.Intn(n)
}

// Weighted returns an index chosen in proportion to the given weights, or -1
// when every weight is zero. Negative weights are treated as zero.
func (r *Rand) Weighted(weights []int) int {
	total := 0
	for _, w := range weights {
		if w > 0 {
			total += w
		}
	}
	if total == 0 {
		return -1
	}
	pick := r.Intn(total)
	for i, w := range weights {
		if w <= 0 {
			continue
		}
		pick -= w
		if pick < 0 {
			return i
		}
	}
	return len(weights) - 1
}

// Shuffle permutes n elements using the given swap, matching the convention of
// the standard library's sort and rand packages.
func (r *Rand) Shuffle(n int, swap func(i, j int)) {
	for i := n - 1; i > 0; i-- {
		swap(i, r.Intn(i+1))
	}
}
