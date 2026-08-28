package rng

import (
	"math"
	"testing"
)

// TestDeterminism is the property ASR-0008 rests on: the same three inputs
// produce the same sequence, always and everywhere.
func TestDeterminism(t *testing.T) {
	a := Derive(0xDEADBEEF, 3, StreamMutatorParam)
	b := Derive(0xDEADBEEF, 3, StreamMutatorParam)
	for i := 0; i < 1000; i++ {
		if x, y := a.Uint64(), b.Uint64(); x != y {
			t.Fatalf("draw %d diverged: %d != %d", i, x, y)
		}
	}
}

// TestStreamsAreIndependent is what lets a stage be added without reshuffling
// every existing campaign.
func TestStreamsAreIndependent(t *testing.T) {
	const seed, worker = 42, 1
	seen := map[uint64]Stream{}
	for s := Stream(0); s < numStreams; s++ {
		r := Derive(seed, worker, s)
		for i := 0; i < 64; i++ {
			v := r.Uint64()
			if prev, dup := seen[v]; dup {
				t.Fatalf("stream %s draw %d collided with stream %s", s, i, prev)
			}
			seen[v] = s
		}
	}
}

func TestWorkersAreIndependent(t *testing.T) {
	seen := map[uint64]uint32{}
	for w := uint32(0); w < 16; w++ {
		r := Derive(7, w, StreamSeedSelect)
		for i := 0; i < 64; i++ {
			v := r.Uint64()
			if prev, dup := seen[v]; dup {
				t.Fatalf("worker %d draw %d collided with worker %d", w, i, prev)
			}
			seen[v] = w
		}
	}
}

// TestSeekReplaysExactly is what makes provenance work: a recorded position is
// enough to reproduce the draws that followed it.
func TestSeekReplaysExactly(t *testing.T) {
	r := New(99)
	for i := 0; i < 50; i++ {
		r.Uint64()
	}
	pos := r.Position()
	want := make([]uint64, 20)
	for i := range want {
		want[i] = r.Uint64()
	}

	r.Seek(pos)
	for i, w := range want {
		if got := r.Uint64(); got != w {
			t.Fatalf("after seeking to %d, draw %d = %d, want %d", pos, i, got, w)
		}
	}

	// A clone continues identically without disturbing the original.
	r.Seek(pos)
	c := r.Clone()
	for i := range want {
		if x, y := r.Uint64(), c.Uint64(); x != y {
			t.Fatalf("clone diverged at draw %d: %d != %d", i, x, y)
		}
	}
}

func TestForkIsIndependent(t *testing.T) {
	r := New(5)
	a, b := r.Fork(1), r.Fork(2)
	same := 0
	for i := 0; i < 100; i++ {
		if a.Uint64() == b.Uint64() {
			same++
		}
	}
	if same > 1 {
		t.Errorf("forks with different tags produced %d identical draws", same)
	}
	if r.Fork(1).Uint64() != New(5).Fork(1).Uint64() {
		t.Error("forking must be deterministic")
	}
}

func TestPositionCountsDraws(t *testing.T) {
	r := New(1)
	if r.Position() != 0 {
		t.Errorf("a fresh stream is at position %d, want 0", r.Position())
	}
	for i := 1; i <= 10; i++ {
		r.Uint64()
		if got := r.Position(); got != uint64(i) {
			t.Errorf("after %d draws, position = %d", i, got)
		}
	}
}

// TestIntnIsUnbiased checks the bound is applied without the low-bit skew a
// modulo would introduce. A biased mutator parameter quietly under-explores
// part of the input space.
func TestIntnIsUnbiased(t *testing.T) {
	const n, draws = 7, 700000
	counts := make([]int, n)
	r := New(0xABCDEF)
	for i := 0; i < draws; i++ {
		v := r.Intn(n)
		if v < 0 || v >= n {
			t.Fatalf("Intn(%d) returned %d, out of range", n, v)
		}
		counts[v]++
	}
	expected := float64(draws) / n
	for i, c := range counts {
		if dev := math.Abs(float64(c)-expected) / expected; dev > 0.02 {
			t.Errorf("bucket %d has %d draws, %.1f%% from the expected %.0f", i, c, dev*100, expected)
		}
	}
}

func TestIntnPanicsOnNonPositive(t *testing.T) {
	for _, n := range []int{0, -1} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("Intn(%d) must panic rather than return a meaningless value", n)
				}
			}()
			New(1).Intn(n)
		}()
	}
}

func TestIntRange(t *testing.T) {
	r := New(3)
	for i := 0; i < 1000; i++ {
		if v := r.IntRange(-5, 5); v < -5 || v > 5 {
			t.Fatalf("IntRange(-5,5) = %d", v)
		}
	}
	if v := r.IntRange(4, 4); v != 4 {
		t.Errorf("IntRange(4,4) = %d, want 4", v)
	}
	defer func() {
		if recover() == nil {
			t.Error("an inverted range must panic")
		}
	}()
	r.IntRange(5, 4)
}

func TestWeighted(t *testing.T) {
	r := New(11)
	counts := map[int]int{}
	weights := []int{0, 10, 90, -3}
	for i := 0; i < 100000; i++ {
		counts[r.Weighted(weights)]++
	}
	if counts[0] != 0 {
		t.Errorf("a zero weight was selected %d times", counts[0])
	}
	if counts[3] != 0 {
		t.Errorf("a negative weight was selected %d times", counts[3])
	}
	ratio := float64(counts[2]) / float64(counts[1])
	if ratio < 8 || ratio > 10 {
		t.Errorf("weights 10:90 produced a ratio of %.2f, want about 9", ratio)
	}
	if got := r.Weighted([]int{0, 0}); got != -1 {
		t.Errorf("all-zero weights returned %d, want -1", got)
	}
	if got := r.Weighted(nil); got != -1 {
		t.Errorf("no weights returned %d, want -1", got)
	}
}

func TestFillAndPick(t *testing.T) {
	r := New(13)
	b := make([]byte, 37)
	r.Fill(b)
	zeros := 0
	for _, c := range b {
		if c == 0 {
			zeros++
		}
	}
	if zeros > 5 {
		t.Errorf("Fill produced %d zero bytes of %d; it may not be filling the tail", zeros, len(b))
	}
	if got := r.Pick(0); got != -1 {
		t.Errorf("Pick(0) = %d, want -1", got)
	}
	for i := 0; i < 100; i++ {
		if v := r.Pick(3); v < 0 || v > 2 {
			t.Fatalf("Pick(3) = %d", v)
		}
	}
}

func TestChance(t *testing.T) {
	r := New(17)
	if r.Chance(0) || r.Chance(-1) {
		t.Error("a non-positive probability must never fire")
	}
	if !r.Chance(1) || !r.Chance(2) {
		t.Error("a probability at or above one must always fire")
	}
	hits := 0
	for i := 0; i < 100000; i++ {
		if r.Chance(0.25) {
			hits++
		}
	}
	if hits < 24000 || hits > 26000 {
		t.Errorf("Chance(0.25) fired %d times in 100000", hits)
	}
}

func TestShuffleIsAPermutation(t *testing.T) {
	r := New(19)
	s := make([]int, 50)
	for i := range s {
		s[i] = i
	}
	r.Shuffle(len(s), func(i, j int) { s[i], s[j] = s[j], s[i] })

	seen := make(map[int]bool, len(s))
	moved := 0
	for i, v := range s {
		if seen[v] {
			t.Fatalf("value %d appears twice", v)
		}
		seen[v] = true
		if v != i {
			moved++
		}
	}
	if moved == 0 {
		t.Error("Shuffle left every element in place")
	}
}

func TestStreamNames(t *testing.T) {
	for s := Stream(0); s < numStreams; s++ {
		if s.String() == "" {
			t.Errorf("stream %d has no name", s)
		}
	}
	if got := Stream(999).String(); got != "stream(999)" {
		t.Errorf("unknown stream rendered as %q", got)
	}
}

func TestNoAllocations(t *testing.T) {
	r := New(23)
	buf := make([]byte, 64)
	weights := []int{1, 2, 3}
	if n := testing.AllocsPerRun(1000, func() {
		_ = r.Uint64()
		_ = r.Intn(100)
		_ = r.Float64()
		_ = r.Weighted(weights)
		r.Fill(buf)
	}); n != 0 {
		t.Errorf("drawing allocated %v times per run; this is the innermost hot path", n)
	}
}

func BenchmarkUint64(b *testing.B) {
	r := New(1)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = r.Uint64()
	}
}

func BenchmarkIntn(b *testing.B) {
	r := New(1)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = r.Intn(64)
	}
}
