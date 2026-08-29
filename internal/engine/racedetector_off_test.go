//go:build !race

package engine

// raceDetector reports whether this binary was built with -race. See the
// -race build of this file for why it matters.
const raceDetector = false
