package bench

import (
	"github.com/rom/Xfuzz/internal/testenv"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// benchBuf is sized so that one iteration costs microseconds rather than
// nanoseconds. A sub-nanosecond benchmark cannot be gated at 10% on any real
// machine: the measurement noise exceeds the threshold.
var benchBuf = make([]byte, 4096)

// mix is deterministic, allocation-free work standing in for the engine's hot
// path until there is one to measure.
func mix(buf []byte, seed uint64) uint64 {
	h := seed
	for i := range buf {
		buf[i] = byte(h)
		h = h*6364136223846793005 + 1442695040888963407
		h ^= h >> 33
	}
	return h
}

// BenchmarkHarnessOverhead is the noise floor every other benchmark is read
// against, and the first baseline M0 records.
func BenchmarkHarnessOverhead(b *testing.B) {
	b.SetBytes(int64(len(benchBuf)))
	b.ReportAllocs()
	var h uint64
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h = mix(benchBuf, h)
	}
	if h == 0 {
		b.Fatal("optimised away")
	}
	ReportExecRate(b, int64(b.N))
}

// BenchmarkZeroAlloc guards the allocation gate itself: it must report
// 0 allocs/op, so a change that makes the harness allocate becomes visible.
func BenchmarkZeroAlloc(b *testing.B) {
	buf := make([]byte, 256)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for j := range buf {
			buf[j] = byte(i + j)
		}
	}
}

func TestAssertNoAllocsAcceptsNonAllocating(t *testing.T) {
	buf := make([]byte, 32)
	AssertNoAllocs(t, "fill", func() {
		for i := range buf {
			buf[i] = byte(i)
		}
	})
}

func TestCheckFloor(t *testing.T) {
	if err := CheckFloor(TierForkServer, 6000); err != nil {
		t.Errorf("6000 execs/s should clear the T2 floor: %v", err)
	}
	if err := CheckFloor(TierForkServer, 4000); err == nil {
		t.Error("4000 execs/s should fail the T2 floor of 5000")
	}
	if err := CheckFloor(TierSession, 1); err != nil {
		t.Errorf("ungated tiers must not fail: %v", err)
	}
}

// TestFloorsMatchDocumentation keeps the gated floors and docs/TESTS.md from
// drifting apart. The table in the documentation is the specification; this
// asserts the code implements it.
func TestFloorsMatchDocumentation(t *testing.T) {
	root, err := findRepoRoot(".")
	if err != nil {
		t.Fatal(err)
	}
	body := testenv.ReadDoc(t, filepath.Join(root, "docs", "TESTS.md"))
	row := regexp.MustCompile(`(?m)^\| (T\d) ([^|]+?) \| ([\d,]+) exec/s \|$`)
	documented := map[Tier]float64{}
	names := map[Tier]string{}
	for _, m := range row.FindAllStringSubmatch(string(body), -1) {
		v, err := strconv.ParseFloat(strings.ReplaceAll(m[3], ",", ""), 64)
		if err != nil {
			t.Fatalf("unparseable floor %q: %v", m[3], err)
		}
		documented[Tier(m[1])] = v
		names[Tier(m[1])] = strings.TrimSpace(m[2])
	}
	if len(documented) == 0 {
		t.Fatal("no executor floor table found in docs/TESTS.md")
	}
	for _, f := range Floors {
		want, ok := documented[f.Tier]
		if !ok {
			t.Errorf("tier %s is gated in code but absent from docs/TESTS.md", f.Tier)
			continue
		}
		if want != f.ExecsPS {
			t.Errorf("tier %s: code floor %.0f, documented floor %.0f", f.Tier, f.ExecsPS, want)
		}
		if got := names[f.Tier]; got != f.Name {
			t.Errorf("tier %s: code name %q, documented name %q", f.Tier, f.Name, got)
		}
	}
	for tier := range documented {
		if _, ok := FloorFor(tier); !ok {
			t.Errorf("tier %s is documented with a floor but not gated in code", tier)
		}
	}
}

func findRepoRoot(start string) (string, error) {
	d, err := filepath.Abs(start)
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(d, "go.mod")); err == nil {
			return d, nil
		}
		p := filepath.Dir(d)
		if p == d {
			return "", os.ErrNotExist
		}
		d = p
	}
}
