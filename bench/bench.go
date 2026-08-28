// Package bench is the performance harness that makes ASR-0007 enforceable.
//
// Throughput is a requirement, not an aspiration: a fuzzer 10x too slow is not
// 10% worse, it is a fuzzer that never reaches the bug. Go makes it entirely
// possible to write a correct fuzzer that is 50x too slow, so the floors below
// are recorded as data, measured in CI, and gated against a stored baseline.
//
// The harness exists before the engine deliberately (docs/MVP_PLAN.md, M0) so
// that the first hot-path commit is already measured.
package bench

import (
	"fmt"
	"testing"
)

// Tier identifies an executor tier from ADR-0009.
type Tier string

// The executor tiers, fastest first.
const (
	TierInProc     Tier = "T0"
	TierPersistent Tier = "T1"
	TierForkServer Tier = "T2"
	TierProcPool   Tier = "T3"
	TierSubprocess Tier = "T4"
	TierEmulated   Tier = "T5"
	TierSession    Tier = "T6"
	TierDriver     Tier = "T7"
)

// Floor is the minimum sustained single-core execution rate a tier must reach
// on the reference host, per ASR-0007 and docs/TESTS.md section 7.
type Floor struct {
	Tier    Tier
	Name    string
	ExecsPS float64 // executions per second, single core
}

// Floors are the gated tiers. T6 (session) and T7 (driver) are excluded: their
// rates are dominated by the target's own latency, so a fixed floor would
// measure the target rather than Xfuzz.
var Floors = []Floor{
	{TierInProc, "in-process", 50000},
	{TierPersistent, "persistent", 50000},
	{TierForkServer, "fork server", 5000},
	{TierProcPool, "process pool", 300},
	{TierSubprocess, "subprocess", 300},
	{TierEmulated, "emulated", 200},
}

// FloorFor returns the gated floor for a tier.
func FloorFor(t Tier) (Floor, bool) {
	for _, f := range Floors {
		if f.Tier == t {
			return f, true
		}
	}
	return Floor{}, false
}

// MaxEngineOverhead is the share of wall-clock time the engine may spend on
// scheduling, mutation, feedback, and bookkeeping, excluding target execution
// (ASR-0007).
const MaxEngineOverhead = 0.10

// MinScalingEfficiency is the aggregate throughput a campaign must retain when
// scaling from 1 to N workers, as a fraction of N (ASR-0007).
const MinScalingEfficiency = 0.85

// RegressionThreshold is the fraction by which a gated metric may worsen before
// the build fails (docs/TESTS.md section 7).
const RegressionThreshold = 0.10

// ReportExecRate records a benchmark's execution rate so that tools/benchcmp
// can gate it. Rates are compared as higher-is-better.
func ReportExecRate(b *testing.B, execs int64) {
	b.Helper()
	if b.Elapsed() <= 0 {
		return
	}
	b.ReportMetric(float64(execs)/b.Elapsed().Seconds(), "execs/s")
}

// AssertNoAllocs fails the test unless f allocates nothing across repeated
// calls. The fuzz loop must be allocation-free in steady state (ASR-0007), and
// allocation counts are deterministic, so this is an exact assertion rather
// than a threshold.
func AssertNoAllocs(t *testing.T, name string, f func()) {
	t.Helper()
	if n := testing.AllocsPerRun(100, f); n != 0 {
		t.Errorf("%s: allocates %.0f time(s) per run; the fuzz loop must be allocation-free in steady state", name, n)
	}
}

// CheckFloor reports whether a measured rate meets its tier's floor.
func CheckFloor(t Tier, measured float64) error {
	f, ok := FloorFor(t)
	if !ok {
		return nil
	}
	if measured < f.ExecsPS {
		return fmt.Errorf("tier %s (%s): measured %.0f execs/s, floor is %.0f execs/s",
			f.Tier, f.Name, measured, f.ExecsPS)
	}
	return nil
}
