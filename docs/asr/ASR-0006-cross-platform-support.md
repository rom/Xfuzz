# ASR-0006: Cross-platform support

- **Status:** Accepted
- **Priority:** Must
- **Date:** 2026-08-28
- **Source:** Product brief — "primarily be run on linux, but there should be support to have it run on macos and windows"

## Requirement

- **Linux (amd64, arm64)** — the primary, fully featured platform. Every feature
  ships here first.
- **macOS (arm64, amd64)** — supported. Core fuzzing, all interfaces, and triage
  must work; platform-specific fast paths and isolation are best-effort.
- **Windows (amd64)** — supported. Core fuzzing, all interfaces, and triage must
  work; POSIX-specific mechanisms must have documented substitutes.

Feature availability per platform must be **explicit and machine-readable**, not
discovered at runtime through failure.

## Rationale

Security targets do not live only on Linux: desktop GUI applications, endpoint
agents, and proprietary formats are heavily Windows- and macOS-native. But
Linux-only mechanisms (`fork`, `ptrace`, namespaces, seccomp, `/proc`) are also
exactly what makes high-performance fuzzing possible. The architecture must let
Linux be fast without letting POSIX assumptions leak into portable code.

## Architectural impact

- Bans POSIX-only assumptions from engine-core packages; process control,
  sharing, isolation, and coverage transport all sit behind platform interfaces.
- No `fork` on Windows forces a **process-pool** design as the portable
  equivalent of a fork server, which in turn forces per-execution state reset to
  be an explicit contract (see ASR-0002).
- Isolation primitives differ so fundamentally (namespaces/seccomp/cgroups vs.
  Job Objects/restricted tokens vs. macOS sandbox profiles) that the safety layer
  must be an interface with a declared, per-platform *strength level* the
  operator can see.
- Cross-compilation must remain trivial, which constrains native-code usage
  (ADR-0017).
- CI must build and test on all three platforms, or "supported" is a claim
  without evidence.

## Acceptance criteria

- `GOOS=windows`/`GOOS=darwin` builds succeed with `CGO_ENABLED=0` and produce a
  binary that runs a subprocess-executor campaign end to end.
- `xfuzz doctor` reports, per platform, which executors, feedback backends, and
  isolation levels are available and which are unavailable and why.
- CI runs the full test suite on Linux, macOS, and Windows.

## Satisfied by

ADR-0002, ADR-0009, ADR-0012, ADR-0017, ADR-0022, ADR-0025, ADR-0026, ADR-0027
