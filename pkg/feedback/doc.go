// Package feedback defines the composable guidance pipeline:
// Observer -> Feedback -> Objective, feeding a score vector to the scheduler.
//
// An Observer records raw signal during execution and does not judge. A
// Feedback answers "is this worth keeping?" and owns the novelty state. An
// Objective answers "is this a finding?" — separate, because the same
// observation answers the two questions differently: a crash is a finding and
// usually a poor seed, while a novel edge is a good seed and not a finding.
//
// Feedbacks compose under a boolean algebra (All, Any, Not, Fast), which is
// what makes coverage-guided, directed, feedback-driven, and hybrid fuzzing
// configurations of one engine rather than four engine modes.
//
// Constraints:
//   - Must not import pkg/executor.
//   - The per-execution path holds a static ordered slice of concrete
//     implementations: no reflection, no interface boxing, no channel
//     round-trips.
//
// See docs/adr/ADR-0007-composable-feedback-pipeline.md.
package feedback
