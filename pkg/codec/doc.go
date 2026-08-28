// Package codec converts between wire bytes and the structured IR.
//
// Decoding is best-effort and partial: unrecognised regions degrade to opaque
// Bytes nodes rather than failing, because real corpora are full of malformed
// files and those are frequently the most valuable seeds.
//
// The round-trip parse -> serialise must be byte-exact for unmutated inputs.
// This invariant is enforced by property tests, not by convention.
//
// See docs/adr/ADR-0005-unified-structured-input-ir.md.
package codec
