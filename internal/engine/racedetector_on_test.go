//go:build race

package engine

// raceDetector reports whether this binary was built with -race.
//
// It changes what a timing measurement means. The race detector instruments
// every memory access in Go code and none in the target, which is a native
// binary in another process — so the fuzzer's own work slows by several times
// while the work it is being compared against does not. An overhead budget
// measured under it is measuring the detector.
const raceDetector = true
