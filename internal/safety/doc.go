// Package safety is the mandatory layer between the engine and every executor.
//
// No component outside this package and internal/platform may spawn a process
// or open an outbound socket. That constraint is enforced by the architecture
// lint in tools/archlint, not by convention.
//
// Two catastrophic failure modes are prevented structurally rather than
// documented: a target escaping to damage the host or the corpus, and traffic
// reaching a system the operator was never authorised to test. Targets are
// confined by default at the strongest level the platform supports, the level
// in force is reported, and a campaign may require a minimum and refuse to
// start below it. Outbound traffic is default-deny against an explicit
// allowlist. Scope decisions and violations are written to an append-only,
// hash-chained audit log that a campaign configuration cannot disable.
//
// See docs/adr/ADR-0012-sandbox-by-default-and-scope-guard.md and
// docs/SECURITY.md.
package safety
