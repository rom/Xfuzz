// Package driver implements the backends behind the T7 executor tier.
//
// One backend exists: tui, a program on a pseudo-terminal with an embedded
// terminal emulator watching what it draws. ADR-0013 puts it first deliberately.
// It is headless, needs no display server, runs identically in CI and on a
// developer's machine, and is fast by the standards of a domain where a hundred
// executions per second is exceptional. The desktop backends it names —
// accessibility trees on Linux, UI Automation on Windows, the accessibility API
// on macOS, a debugging protocol for the web — each need a platform, a session
// and a display; each is a separate mechanism with the same shape, and none of
// them is here yet.
//
// The shape is executor.DriverBackend: start the program, deliver an event,
// observe the state, reset. Everything above it — the corpus, the mutation
// operators over an IR Repeat, the feedback stack, triage — is the same machine
// the other tiers use, which is the point of putting GUI fuzzing behind the
// executor interface rather than building a second product.
package driver
