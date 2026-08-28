// Package executor runs a target with an input and reports what happened.
//
// One interface, eight tiers, selected per campaign by probed target
// capability: T0 in-process, T1 persistent, T2 fork server, T3 process pool,
// T4 subprocess, T5 emulated, T6 session, T7 driver. Rates span six orders of
// magnitude; the core loop does not know which tier it is running on.
//
// Every tier shares the same contract: explicit reset semantics, enforced
// timeouts and resource limits, reported stability, pooled buffers, and — with
// no exceptions — process spawning and socket opening only through
// internal/safety.
//
// See docs/adr/ADR-0009-tiered-executors.md.
package executor
