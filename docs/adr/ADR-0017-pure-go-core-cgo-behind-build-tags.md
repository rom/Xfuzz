# ADR-0017: Pure-Go core, cgo behind build tags

- **Status:** Accepted
- **Date:** 2026-08-28
- **Serves:** ASR-0006, ASR-0007, ASR-0015

## Context

Two requirements pull in opposite directions. ASR-0006 and ASR-0015 want trivial
cross-compilation and a self-contained binary for Linux, macOS, and Windows —
which argues for pure Go. ASR-0007's throughput targets want fork servers, shared
memory, `ptrace`, and hardware tracing — which conventionally means C.

Enabling cgo globally costs cross-compilation simplicity, adds a C toolchain
requirement, and slows builds. Banning native code entirely forgoes the
high-throughput executor tiers.

## Decision

**The core is pure Go. Native code is confined behind build tags with pure-Go
fallbacks.**

- Engine, IR, mutators, feedback, scheduler, corpus, store, daemon, API, CLI, and
  console are **100 % pure Go**, and `CGO_ENABLED=0 GOOS=<any>` always produces a
  working binary.
- Platform mechanisms are reached through **`golang.org/x/sys` syscalls** wherever
  possible — shared memory, process control, namespaces, seccomp, cgroups, and
  Job Objects are all reachable without cgo. Much of what is conventionally
  assumed to need C does not.
- Where native code is genuinely required, it lives behind `//go:build cgo` with
  a pure-Go fallback and a **declared capability difference**, so a fallback build
  is slower or less featureful but never broken.
- Target-side components — the `xfuzz-rt` coverage runtime and the `xfuzz-cc`
  compiler wrapper (ADR-0001) — are C, but they compile into the **target**, not
  into Xfuzz. They are a separate build artifact and impose no cgo requirement on
  the fuzzer.
- Pure-Go dependencies are preferred throughout, notably `modernc.org/sqlite`
  (ADR-0008).
- Every release ships **both** a `CGO_ENABLED=0` portable build and, on Linux,
  a cgo-enabled build with the fast paths; `xfuzz doctor` reports which
  capabilities the running binary has.

## Consequences

**Positive**

- `GOOS=windows go build` works from a Linux laptop with no toolchain setup —
  which is what makes three-platform support realistic rather than aspirational.
- Single self-contained artifact per platform (ASR-0015).
- Fast builds, straightforward CI, and no C toolchain in the common path.
- The capability-difference discipline makes the portability/performance
  trade-off explicit and measurable rather than hidden.

**Negative**

- Some syscall-level work is harder in Go than in C, particularly seccomp filter
  construction and `ptrace` sequencing.
- Two build configurations to test on Linux (with and without cgo), doubling part
  of the CI matrix.
- Pure-Go fallbacks may be materially slower, and the gap must be measured and
  published rather than assumed small.
- Pure-Go SQLite is slower than the cgo build; acceptable off the hot path
  (ADR-0008) but requires verification.

**Neutral**

- Should a fast path prove impossible in pure Go, the escape hatch already exists
  — the build tag — without restructuring anything.

## Alternatives considered

- **Pure Go, no cgo ever.** Maximum simplicity. Rejected as an absolute: it
  forecloses hardware tracing and some instrumentation paths for a purity that
  the build-tag approach already delivers in the default build.
- **cgo freely on Linux.** Fastest Linux fast paths. Rejected: it makes macOS and
  Windows second-class by construction and complicates every build, in conflict
  with ASR-0006 and ASR-0015.
