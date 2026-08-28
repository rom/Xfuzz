// Package state models a target's protocol state machine and makes state a
// first-class feedback signal.
//
// The model is either declared in the campaign file or inferred by clustering
// observed responses, so stateful fuzzing works black-box. New states and new
// transitions are interesting alongside code coverage. The scheduler selects a
// target state first, then selects which message in the session to mutate.
//
// The same machinery serves GUI and TUI targets, where a state is a screen.
//
// See docs/adr/ADR-0006-explicit-state-machine-with-state-feedback.md.
package state
