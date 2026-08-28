// Package mutate provides typed mutation operators over the IR.
//
// Operators dispatch on node kind: bit and byte level operators on Bytes,
// boundary-value and arithmetic operators on Int, alternative switching on
// Choice, and insert/delete/reorder/duplicate on Repeat. Repeat operators are
// what make stateful session mutation fall out of ordinary mutation.
//
// Mutation is deterministic given an RNG stream, and every applied operator is
// recorded in the resulting testcase's provenance.
//
// See docs/adr/ADR-0005-unified-structured-input-ir.md.
package mutate
