package main

import "testing"

const sample = `goos: linux
goarch: amd64
pkg: github.com/rom/Xfuzz/bench
BenchmarkHarnessOverhead-8   	1000000000	         0.25 ns/op	   4000000 execs/s
BenchmarkZeroAlloc-8         	 5000000	       240 ns/op	       0 B/op	       0 allocs/op
PASS
ok  	github.com/rom/Xfuzz/bench	1.5s
`

func TestParse(t *testing.T) {
	got := Parse(sample)
	if len(got) != 2 {
		t.Fatalf("expected 2 benchmarks, got %d: %v", len(got), got)
	}
	// The -8 GOMAXPROCS suffix must be stripped so results compare across hosts.
	r, ok := got["BenchmarkHarnessOverhead"]
	if !ok {
		t.Fatalf("GOMAXPROCS suffix not stripped: %v", got)
	}
	if r.Metrics["ns/op"] != 0.25 {
		t.Errorf("ns/op = %v, want 0.25", r.Metrics["ns/op"])
	}
	if r.Metrics["execs/s"] != 4000000 {
		t.Errorf("execs/s = %v, want 4000000", r.Metrics["execs/s"])
	}
	if got["BenchmarkZeroAlloc"].Metrics["allocs/op"] != 0 {
		t.Errorf("allocs/op = %v, want 0", got["BenchmarkZeroAlloc"].Metrics["allocs/op"])
	}
}

func TestCompareDetectsSlowdown(t *testing.T) {
	base := map[string]Result{"B": {"B", map[string]float64{"ns/op": 100}}}
	cur := map[string]Result{"B": {"B", map[string]float64{"ns/op": 120}}}
	f, _, _ := Compare(base, cur, 0.10, nil)
	if len(f) != 1 || !f[0].Regressed {
		t.Errorf("a 20%% slowdown must regress at a 10%% threshold: %v", f)
	}
}

func TestCompareToleratesNoise(t *testing.T) {
	base := map[string]Result{"B": {"B", map[string]float64{"ns/op": 100}}}
	cur := map[string]Result{"B": {"B", map[string]float64{"ns/op": 105}}}
	f, _, _ := Compare(base, cur, 0.10, nil)
	if f[0].Regressed {
		t.Errorf("a 5%% slowdown must not regress at a 10%% threshold: %v", f)
	}
}

func TestCompareTreatsRatesAsHigherIsBetter(t *testing.T) {
	base := map[string]Result{"B": {"B", map[string]float64{"execs/s": 10000}}}

	slower := map[string]Result{"B": {"B", map[string]float64{"execs/s": 8000}}}
	f, _, _ := Compare(base, slower, 0.10, nil)
	if !f[0].Regressed {
		t.Error("a 20% drop in execs/s must regress")
	}

	faster := map[string]Result{"B": {"B", map[string]float64{"execs/s": 20000}}}
	f, _, _ = Compare(base, faster, 0.10, nil)
	if f[0].Regressed {
		t.Error("a doubling of execs/s must not regress")
	}
}

func TestCompareTreatsAllocationsExactly(t *testing.T) {
	base := map[string]Result{"B": {"B", map[string]float64{"allocs/op": 0}}}
	cur := map[string]Result{"B": {"B", map[string]float64{"allocs/op": 1}}}
	f, _, _ := Compare(base, cur, 0.50, nil)
	if !f[0].Regressed {
		t.Error("any increase in allocs/op must regress, regardless of threshold")
	}

	same := map[string]Result{"B": {"B", map[string]float64{"allocs/op": 0}}}
	f, _, _ = Compare(base, same, 0.10, nil)
	if f[0].Regressed {
		t.Error("unchanged allocs/op must not regress")
	}
}

func TestCompareReportsAddedAndMissing(t *testing.T) {
	base := map[string]Result{"Gone": {"Gone", map[string]float64{"ns/op": 1}}}
	cur := map[string]Result{"New": {"New", map[string]float64{"ns/op": 1}}}
	_, missing, added := Compare(base, cur, 0.10, nil)
	if len(missing) != 1 || missing[0] != "Gone" {
		t.Errorf("missing = %v, want [Gone]", missing)
	}
	if len(added) != 1 || added[0] != "New" {
		t.Errorf("added = %v, want [New]", added)
	}
}

func TestParseTakesMedianAcrossCounts(t *testing.T) {
	// A -count 5 run with one large outlier. The median must ignore it; a mean
	// would not, and the gate would fail for no reason.
	const multi = `BenchmarkX-8	100	100 ns/op
BenchmarkX-8	100	102 ns/op
BenchmarkX-8	100	101 ns/op
BenchmarkX-8	100	9000 ns/op
BenchmarkX-8	100	99 ns/op
`
	got := Parse(multi)
	if v := got["BenchmarkX"].Metrics["ns/op"]; v != 101 {
		t.Errorf("ns/op = %v, want the median 101 (a mean would give ~1880)", v)
	}
}

func TestMedianEvenCount(t *testing.T) {
	if v := median([]float64{4, 1, 3, 2}); v != 2.5 {
		t.Errorf("median = %v, want 2.5", v)
	}
	if v := median(nil); v != 0 {
		t.Errorf("median of nothing = %v, want 0", v)
	}
}

func TestGateUnitsLimitWhatCanFail(t *testing.T) {
	base := map[string]Result{"B": {"B", map[string]float64{"ns/op": 100, "allocs/op": 0}}}
	cur := map[string]Result{"B": {"B", map[string]float64{"ns/op": 500, "allocs/op": 0}}}

	// Timing is host-dependent: when only allocations are gated, a 5x slowdown
	// is reported but must not fail the build.
	f, _, _ := Compare(base, cur, 0.10, map[string]bool{"allocs/op": true})
	for _, x := range f {
		if x.Unit == "ns/op" {
			if x.Regressed {
				t.Error("ns/op must not fail the build when it is not gated")
			}
			if x.Gated {
				t.Error("ns/op must be reported as not gated")
			}
			if x.Delta < 3 {
				t.Errorf("the slowdown must still be measured and reported, got delta %v", x.Delta)
			}
		}
	}

	// With no restriction, the same slowdown fails.
	f, _, _ = Compare(base, cur, 0.10, nil)
	found := false
	for _, x := range f {
		if x.Unit == "ns/op" && x.Regressed {
			found = true
		}
	}
	if !found {
		t.Error("with all units gated, a 5x slowdown must fail")
	}
}

func TestGatedAllocationRegressionStillFails(t *testing.T) {
	base := map[string]Result{"B": {"B", map[string]float64{"allocs/op": 0}}}
	cur := map[string]Result{"B": {"B", map[string]float64{"allocs/op": 2}}}
	f, _, _ := Compare(base, cur, 0.10, map[string]bool{"allocs/op": true})
	if !f[0].Regressed {
		t.Error("an allocation regression must fail even when only allocations are gated")
	}
}
