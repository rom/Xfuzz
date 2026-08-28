// Package engine is the fuzz loop: scheduling, stages, and the per-worker
// runtime.
//
// The loop is single-threaded and allocation-free in steady state. Corpus
// writes, statistics aggregation, corpus sync, and triage all happen off this
// path, batched and bounded, so nothing can back-pressure execution.
//
// Every stochastic decision draws from a splittable RNG seeded
// H(campaign_seed || worker_id || stream_id), with separate streams per
// concern so that adding a stage does not perturb another stage's sequence.
// Wall-clock time and map iteration order never influence a fuzzing decision.
package engine
