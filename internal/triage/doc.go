// Package triage turns crashes into findings: classify, bucket, minimise,
// verify reproducibility.
//
// Raw crashing inputs are not the product. A productive campaign yields
// thousands of them mapping to a handful of distinct bugs, and separating them
// is the actual labour of fuzzing.
//
// Bucketing is multi-signal and versioned rather than a single stack hash:
// hashing the top frame merges distinct bugs, hashing the full stack splits one
// bug across hundreds of buckets. Re-bucketing an existing finding set with a
// new strategy is supported and preserves triage state.
//
// Runs asynchronously with its own executor pool, decoupled from the fuzz loop.
package triage
