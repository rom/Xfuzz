// Package corpus holds testcases, their provenance, and the seed schedulers
// that decide what to fuzz next.
//
// A Testcase is content-addressed and carries the provenance needed to
// reconstruct it: parent entry, operators applied, and RNG stream position.
// Schedulers consume a score vector rather than a single coverage count, so
// novelty, distance, rarity, and custom scores can be weighed together.
//
// Constraints:
//   - Must not import pkg/executor.
//
// See docs/adr/ADR-0007-composable-feedback-pipeline.md and
// docs/adr/ADR-0008-hybrid-corpus-store-with-afl-export.md.
package corpus
