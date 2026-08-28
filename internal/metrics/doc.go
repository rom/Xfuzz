// Package metrics provides counters, historical series, and health diagnostics.
//
// The defining failure mode of a fuzzing campaign is silent: it runs for a week,
// looks busy, and finds nothing because the harness rejected every input, the
// target restarts on each execution, or instrumentation was never active.
// Named diagnostics ("stability is 40%", "0% of inputs reach the harness",
// "coverage map is empty") exist to convert that invisible failure into a
// reported one.
//
// Retention is bounded and downsampled; an unbounded metric history is a memory
// leak.
package metrics
