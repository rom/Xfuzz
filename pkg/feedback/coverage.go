package feedback

import (
	"encoding/binary"
	"fmt"
)

// DefaultMapSize is the coverage bitmap size, matching the AFL convention so
// that externally instrumented binaries interoperate (ASR-0013).
//
// The size is a collision trade-off: too small and distinct edges alias onto one
// another, hiding coverage; too large and clearing and scanning it costs more
// than the execution being measured.
const DefaultMapSize = 1 << 16

// CoverageMap holds per-execution edge counters.
//
// The buffer is usually shared memory the target writes into directly, which is
// why the executor can replace it: a fork server hands over a mapping rather
// than copying bytes back after every run.
type CoverageMap struct {
	name    string
	buf     []byte
	backend string
}

// NewCoverageMap returns an observer over a freshly allocated map.
func NewCoverageMap(name string, size int) *CoverageMap {
	if size <= 0 {
		size = DefaultMapSize
	}
	return &CoverageMap{name: name, buf: make([]byte, size)}
}

// Name implements Observer.
func (m *CoverageMap) Name() string { return m.name }

// Buffer returns the counter array, for an executor to publish as shared memory.
func (m *CoverageMap) Buffer() []byte { return m.buf }

// SetBuffer points the observer at externally owned storage, such as a shared
// memory segment the target writes into.
func (m *CoverageMap) SetBuffer(b []byte) { m.buf = b }

// Size returns the number of counters.
func (m *CoverageMap) Size() int { return len(m.buf) }

// Backend records which instrumentation produced this map.
//
// Coverage semantics differ between backends — edge versus block, hitcount
// bucketing, collision rates — so a corpus is not portable across them without
// re-measurement (ADR-0002). Recording the backend is what makes that
// detectable rather than a silent inconsistency.
func (m *CoverageMap) Backend() string     { return m.backend }
func (m *CoverageMap) SetBackend(b string) { m.backend = b }

// Pre implements Observer: clear the counters before the target runs.
func (m *CoverageMap) Pre() error {
	clear(m.buf)
	return nil
}

// Post implements Observer.
func (m *CoverageMap) Post(ExitKind) error { return nil }

// Reset implements Observer.
func (m *CoverageMap) Reset() { clear(m.buf) }

// Hit reports the counter at an index, for tests and diagnostics.
func (m *CoverageMap) Hit(i int) byte { return m.buf[i] }

// Covered counts the entries touched by the most recent execution.
func (m *CoverageMap) Covered() int {
	n := 0
	for _, c := range m.buf {
		if c != 0 {
			n++
		}
	}
	return n
}

// Signature is a fingerprint of the coverage this execution produced.
//
// Corpus trimming needs to ask "did shortening the input change where it goes?"
// A signature answers that in one comparison, where diffing whole maps would
// cost more than the executions being compared. Buckets rather than raw counts,
// so that a loop running a different number of times does not read as a
// different path.
func (m *CoverageMap) Signature() uint64 {
	const (
		offset64 = 14695981039346656037
		prime64  = 1099511628211
	)
	h := uint64(offset64)
	for i, c := range m.buf {
		if c == 0 {
			continue
		}
		h = (h ^ uint64(uint32(i))) * prime64
		h = (h ^ uint64(bucketOf[c])) * prime64
	}
	return h
}

// bucketOf maps a raw hit count onto AFL's logarithmic buckets: 1, 2, 3, 4-7,
// 8-15, 16-31, 32-127, 128+.
//
// Bucketing rather than counting exactly is what keeps a loop from looking like
// new coverage on every iteration. Without it a campaign fills its corpus with
// inputs that differ only in how many times they went round the same loop.
var bucketOf = func() [256]byte {
	var t [256]byte
	for i := range t {
		switch {
		case i == 0:
			t[i] = 0
		case i == 1:
			t[i] = 1
		case i == 2:
			t[i] = 2
		case i == 3:
			t[i] = 4
		case i <= 7:
			t[i] = 8
		case i <= 15:
			t[i] = 16
		case i <= 31:
			t[i] = 32
		case i <= 127:
			t[i] = 64
		default:
			t[i] = 128
		}
	}
	return t
}()

// MapFeedback admits inputs that reach a bucket of a counter no previous
// execution reached. It is the feedback that makes a fuzzer coverage-guided.
type MapFeedback struct {
	name string
	m    *CoverageMap

	// virgin holds the buckets seen so far, one byte of flags per counter.
	virgin []byte

	// pending records the changes the most recent judgement would commit, so
	// that Append is a replay and Discard is a no-op. Keeping the indices rather
	// than a copy of the map means the cost is proportional to what was new, not
	// to the map size.
	pendingIdx  []int32
	pendingBits []byte

	covered int
}

// NewMapFeedback returns a coverage feedback over a map observer.
func NewMapFeedback(name string, m *CoverageMap) *MapFeedback {
	return &MapFeedback{name: name, m: m, virgin: make([]byte, len(m.buf))}
}

// Name implements Feedback.
func (f *MapFeedback) Name() string { return f.name }

// Covered returns how many counters have been reached at least once. This is
// the number a campaign's coverage-over-time chart plots.
func (f *MapFeedback) Covered() int { return f.covered }

// Size returns the map size.
func (f *MapFeedback) Size() int { return len(f.virgin) }

// Density returns the share of counters reached, which is the signal that a map
// is too small: as it approaches saturation, distinct edges start colliding and
// new coverage stops being visible.
func (f *MapFeedback) Density() float64 {
	if len(f.virgin) == 0 {
		return 0
	}
	return float64(f.covered) / float64(len(f.virgin))
}

// IsInteresting implements Feedback.
func (f *MapFeedback) IsInteresting(_ []Observer, _ ExitKind) (bool, Score, error) {
	if len(f.m.buf) != len(f.virgin) {
		return false, Score{}, fmt.Errorf("coverage map is %d bytes but the feedback tracks %d; "+
			"the executor and the feedback disagree about the map size", len(f.m.buf), len(f.virgin))
	}
	f.pendingIdx = f.pendingIdx[:0]
	f.pendingBits = f.pendingBits[:0]

	buf := f.m.buf
	// Scan eight counters at a time. Most of a coverage map is zero on any given
	// execution, and skipping a whole word at once is what keeps the scan from
	// dominating a fast target's execution time.
	i := 0
	for ; i+8 <= len(buf); i += 8 {
		if binary.LittleEndian.Uint64(buf[i:]) == 0 {
			continue
		}
		for j := i; j < i+8; j++ {
			f.check(buf, j)
		}
	}
	for ; i < len(buf); i++ {
		f.check(buf, i)
	}

	n := len(f.pendingIdx)
	if n == 0 {
		return false, Score{}, nil
	}
	return true, Score{
		NewSignal: n,
		Novelty:   float64(n) / float64(len(buf)),
	}, nil
}

func (f *MapFeedback) check(buf []byte, i int) {
	c := buf[i]
	if c == 0 {
		return
	}
	b := bucketOf[c]
	if f.virgin[i]&b != 0 {
		return
	}
	f.pendingIdx = append(f.pendingIdx, int32(i))
	f.pendingBits = append(f.pendingBits, f.virgin[i]|b)
}

// Append implements Feedback.
func (f *MapFeedback) Append() {
	for k, idx := range f.pendingIdx {
		if f.virgin[idx] == 0 {
			f.covered++
		}
		f.virgin[idx] = f.pendingBits[k]
	}
	f.pendingIdx = f.pendingIdx[:0]
	f.pendingBits = f.pendingBits[:0]
}

// Discard implements Feedback.
func (f *MapFeedback) Discard() {
	f.pendingIdx = f.pendingIdx[:0]
	f.pendingBits = f.pendingBits[:0]
}

// Virgin exposes the accumulated bucket map, for checkpointing and for
// differential comparison between instrumentation backends.
func (f *MapFeedback) Virgin() []byte { return f.virgin }

// LoadVirgin restores an accumulated map, so a campaign resumes where it
// stopped rather than re-discovering everything it already had (ASR-0012).
func (f *MapFeedback) LoadVirgin(v []byte) error {
	if len(v) != len(f.virgin) {
		return fmt.Errorf("saved coverage map is %d bytes, expected %d", len(v), len(f.virgin))
	}
	copy(f.virgin, v)
	f.covered = 0
	for _, b := range f.virgin {
		if b != 0 {
			f.covered++
		}
	}
	return nil
}
