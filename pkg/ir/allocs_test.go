package ir

import "testing"

// allocsPerRun exists so allocation assertions can be used from benchmarks and
// tests alike without importing testing at every call site.
func allocsPerRun(runs int, f func()) float64 { return testing.AllocsPerRun(runs, f) }
