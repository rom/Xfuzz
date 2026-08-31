// Command benchcmp compares a Go benchmark run against a recorded baseline and
// fails when a gated metric regresses.
//
// docs/TESTS.md section 7 makes throughput a build gate rather than a
// suggestion. This is the tool that enforces it: it reads `go test -bench`
// output, matches benchmarks by name, and exits non-zero when any metric moves
// the wrong way by more than the threshold.
//
// Allocation counts are compared exactly, not against the threshold: they are
// deterministic, and the fuzz loop is required to be allocation-free in steady
// state.
//
// Usage:
//
//	benchcmp -baseline bench/baseline.txt -current bench/current.txt
//	benchcmp -baseline bench/baseline.txt -current bench/current.txt -threshold 0.15
package main

import (
	"flag"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
)

// Result is one benchmark's measured metrics, keyed by unit.
type Result struct {
	Name    string
	Metrics map[string]float64
}

// direction reports whether a larger value is better for a given unit.
// Rates ("execs/s", "MB/s") improve upward; costs ("ns/op", "B/op",
// "allocs/op") improve downward.
func higherIsBetter(unit string) bool { return strings.HasSuffix(unit, "/s") }

// exact reports whether a unit must match exactly rather than within the
// threshold.
func exact(unit string) bool { return unit == "allocs/op" }

// set turns a comma-separated flag value into a lookup.
func set(csv string) map[string]bool {
	m := map[string]bool{}
	for _, v := range strings.Split(csv, ",") {
		if v = strings.TrimSpace(v); v != "" {
			m[v] = true
		}
	}
	return m
}

// Parse reads `go test -bench` output.
//
// A benchmark line looks like:
//
//	BenchmarkFoo-8   	 1000000	      1234 ns/op	   0 B/op	   0 allocs/op
//
// Two normalisations matter for a gate that must not be flaky:
//
// The trailing name suffix (-8) is the GOMAXPROCS the benchmark ran at; it is
// stripped so results compare across machines with different core counts.
//
// When the run used -count > 1, a benchmark appears on several lines. Parse
// takes the MEDIAN of each metric rather than the last or the mean. This is the
// statistical comparison docs/TESTS.md section 7 calls for: shared CI runners
// produce occasional large outliers, and a median absorbs them where a mean
// does not. A gate that fails randomly is a gate people learn to ignore.
func Parse(r string) map[string]Result {
	samples := map[string]map[string][]float64{}
	for _, line := range strings.Split(r, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 || !strings.HasPrefix(fields[0], "Benchmark") {
			continue
		}
		name := stripProcs(fields[0])
		// fields[1] is the iteration count; metrics are value/unit pairs after it.
		if _, err := strconv.Atoi(fields[1]); err != nil {
			continue
		}
		for i := 2; i+1 < len(fields); i += 2 {
			v, err := strconv.ParseFloat(fields[i], 64)
			if err != nil {
				continue
			}
			if samples[name] == nil {
				samples[name] = map[string][]float64{}
			}
			unit := fields[i+1]
			samples[name][unit] = append(samples[name][unit], v)
		}
	}

	out := make(map[string]Result, len(samples))
	for name, units := range samples {
		metrics := make(map[string]float64, len(units))
		for unit, vs := range units {
			metrics[unit] = median(vs)
		}
		out[name] = Result{Name: name, Metrics: metrics}
	}
	return out
}

// median returns the middle value of vs, averaging the two middle values for an
// even count. vs is copied so the caller's slice keeps its order.
func median(vs []float64) float64 {
	if len(vs) == 0 {
		return 0
	}
	s := append([]float64(nil), vs...)
	sort.Float64s(s)
	n := len(s)
	if n%2 == 1 {
		return s[n/2]
	}
	return (s[n/2-1] + s[n/2]) / 2
}

func stripProcs(name string) string {
	if i := strings.LastIndex(name, "-"); i > 0 {
		if _, err := strconv.Atoi(name[i+1:]); err == nil {
			return name[:i]
		}
	}
	return name
}

// Finding is a single regression or notable change.
type Finding struct {
	Benchmark string
	Unit      string
	Baseline  float64
	Current   float64
	Delta     float64 // signed fraction; negative is an improvement
	Regressed bool    // exceeded the threshold AND this unit is gated
	Gated     bool    // whether this unit can fail the build
}

func (f Finding) String() string {
	verdict := "ok"
	switch {
	case f.Regressed:
		verdict = "REGRESSED"
	case !f.Gated:
		verdict = "(not gated)"
	}
	return fmt.Sprintf("%-40s %-10s %12.2f -> %12.2f  %+7.1f%%  %s",
		f.Benchmark, f.Unit, f.Baseline, f.Current, f.Delta*100, verdict)
}

// Compare evaluates current against baseline at the given threshold.
//
// gateUnits, when non-empty, restricts which units can fail the build; other
// units are still measured and reported. This exists because timing is
// host-dependent: a baseline recorded on one machine says nothing about
// absolute ns/op on another, whereas allocation counts are deterministic and
// compare meaningfully anywhere. CI gates allocations against the committed
// baseline and gates timings only when both measurements come from the same
// runner.
//
// hostDependent names benchmarks for which that last sentence is false, and
// they exist. "Allocation counts are deterministic" holds for a computation; it
// does not hold for anything that spawns a process through the safety layer,
// because how many allocations a spawn costs depends on which confinement
// mechanisms the host actually provides. Measured across two hosts: the three
// spawning benchmarks each reported allocations up by 37-45% while bytes went
// *down* by 3-8%, which is not a regression but the same work divided
// differently. On a pull request both sides are measured on one runner and
// everything is comparable again, so this exemption applies only to the
// push-time comparison against a baseline recorded elsewhere.
func Compare(baseline, current map[string]Result, threshold float64, gateUnits map[string]bool, hostDependent map[string]bool) (findings []Finding, missing, added []string) {
	for name := range baseline {
		if _, ok := current[name]; !ok {
			missing = append(missing, name)
		}
	}
	for name := range current {
		if _, ok := baseline[name]; !ok {
			added = append(added, name)
		}
	}
	sort.Strings(missing)
	sort.Strings(added)

	names := make([]string, 0, len(current))
	for name := range current {
		if _, ok := baseline[name]; ok {
			names = append(names, name)
		}
	}
	sort.Strings(names)

	for _, name := range names {
		base, cur := baseline[name], current[name]
		units := make([]string, 0, len(cur.Metrics))
		for u := range cur.Metrics {
			if _, ok := base.Metrics[u]; ok {
				units = append(units, u)
			}
		}
		sort.Strings(units)

		for _, unit := range units {
			b, c := base.Metrics[unit], cur.Metrics[unit]
			var delta float64
			if b != 0 {
				delta = (c - b) / b
			} else if c != 0 {
				delta = 1
			}
			// Normalise so that a positive delta always means "worse".
			worse := delta
			if higherIsBetter(unit) {
				worse = -delta
			}
			regressed := worse > threshold
			if exact(unit) {
				regressed = c > b
			}
			gated := len(gateUnits) == 0 || gateUnits[unit]
			if hostDependent[name] {
				gated = false
			}
			findings = append(findings, Finding{
				Benchmark: name, Unit: unit, Baseline: b, Current: c,
				Delta: delta, Regressed: regressed && gated, Gated: gated,
			})
		}
	}
	return findings, missing, added
}

func main() {
	baselinePath := flag.String("baseline", "bench/baseline.txt", "recorded baseline benchmark output")
	currentPath := flag.String("current", "", "current benchmark output to compare (required)")
	threshold := flag.Float64("threshold", 0.10, "fraction a metric may worsen before failing")
	failOnMissing := flag.Bool("fail-on-missing", false, "fail if a baseline benchmark is absent from the current run")
	hostDependent := flag.String("host-dependent", "",
		"comma-separated benchmark names whose metrics are not comparable across hosts; measured and reported, never gated")
	gateUnits := flag.String("gate-units", "",
		"comma-separated units that may fail the build (default: all). Use \"allocs/op,B/op\" when the two runs come from different machines, since timing is host-dependent.")
	flag.Parse()

	gate := set(*gateUnits)

	if *currentPath == "" {
		fmt.Fprintln(os.Stderr, "benchcmp: -current is required")
		flag.Usage()
		os.Exit(2)
	}

	baseline, err := readResults(*baselinePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "benchcmp: %v\n", err)
		fmt.Fprintf(os.Stderr, "benchcmp: record one with `make bench-baseline`\n")
		os.Exit(2)
	}
	current, err := readResults(*currentPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "benchcmp: %v\n", err)
		os.Exit(2)
	}

	findings, missing, added := Compare(baseline, current, *threshold, gate, set(*hostDependent))

	fmt.Printf("%-40s %-10s %12s    %12s  %8s  %s\n", "BENCHMARK", "UNIT", "BASELINE", "CURRENT", "DELTA", "VERDICT")
	regressions := 0
	for _, f := range findings {
		fmt.Println(f)
		if f.Regressed {
			regressions++
		}
	}
	for _, n := range added {
		fmt.Printf("%-40s %s\n", n, "(new — not in baseline)")
	}
	for _, n := range missing {
		fmt.Printf("%-40s %s\n", n, "(missing from current run)")
	}

	if len(findings) == 0 && len(added) == 0 {
		fmt.Fprintln(os.Stderr, "benchcmp: no benchmark results parsed; check the input files")
		os.Exit(2)
	}

	if *failOnMissing && len(missing) > 0 {
		fmt.Fprintf(os.Stderr, "\nbenchcmp: %d baseline benchmark(s) missing from the current run\n", len(missing))
		os.Exit(1)
	}
	if regressions > 0 {
		fmt.Fprintf(os.Stderr, "\nbenchcmp: %d regression(s) beyond the %.0f%% threshold\n", regressions, *threshold*100)
		os.Exit(1)
	}
	scope := "all units"
	if len(gate) > 0 {
		scope = "gated units: " + *gateUnits
	}
	fmt.Fprintf(os.Stderr, "\nbenchcmp: %d metric(s) compared (%s), no regressions\n", len(findings), scope)
}

func readResults(path string) (map[string]Result, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	res := Parse(string(b))
	if len(res) == 0 {
		return nil, fmt.Errorf("%s: no benchmark results found", path)
	}
	return res, nil
}
