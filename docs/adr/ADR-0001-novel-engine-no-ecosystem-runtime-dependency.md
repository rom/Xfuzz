# ADR-0001: Novel engine, no ecosystem runtime dependency

- **Status:** Accepted
- **Date:** 2026-08-28
- **Serves:** ASR-0001, ASR-0007, ASR-0013

## Context

The mature fuzzing ecosystem (AFL++, libFuzzer, honggfuzz, boofuzz, Nautilus)
represents years of engineering. Xfuzz could wrap those engines as an
orchestrator, embed them, or build its own.

The decisive constraint is ASR-0001: a *single* engine spanning files,
protocols, APIs, GUI, and TUI, with one corpus model, one feedback model, and one
triage pipeline. Existing engines each assume one domain in their core types —
libFuzzer's contract is a byte buffer and an in-process call; AFL++'s queue and
fork server assume a process consuming a file or stdin. Neither can represent a
protocol session or a GUI event sequence as a corpus entry without violence to
its own model. An orchestrator over them would inherit their assumptions and
would have to reconcile several incompatible corpus and coverage formats,
producing a fuzzer whose capability is the *intersection* of its backends rather
than the union.

## Decision

**Build the Xfuzz engine from scratch in Go**, owning the corpus model, input
representation, mutation engine, feedback pipeline, scheduler, executors, and
triage. Xfuzz has **no runtime dependency** on any existing fuzzer.

Independence is at the *implementation* level only. Xfuzz deliberately
interoperates at the *data and protocol* level (ADR-0008, ASR-0013):

- imports AFL/libFuzzer corpora and AFL dictionaries
- exports AFL-style `queue/`, `crashes/`, `hangs/` trees
- speaks the AFL fork-server protocol, so externally instrumented binaries work
- accepts `LLVMFuzzerTestOneInput`-style harnesses through a documented shim

Xfuzz also ships its own instrumentation toolchain (`xfuzz-cc` wrapper +
`xfuzz-rt` runtime) so that a user with source needs nothing else installed.

## Consequences

**Positive**

- The core is free to model an input as a *structured session*, which is what
  makes one engine across six domains possible at all.
- Every layer is instrumentable and testable in-process, so throughput and
  determinism (ASR-0007, ASR-0008) are engineering problems we can actually fix
  rather than properties inherited from a subprocess.
- No dependency on external toolchains at runtime; single-artifact deployment
  (ASR-0015) is achievable.
- No licence entanglement with GPL-licensed engines — a hard requirement given
  ADR-0018.

**Negative**

- We must re-earn a decade of accumulated tuning: power schedules, havoc operator
  weights, trimming heuristics, coverage bucketing. These are individually simple
  and collectively the difference between a working fuzzer and a good one.
- Instrumentation is real work — a compiler wrapper, a runtime, a fork server,
  and binary-only tracing (ADR-0002, ADR-0009).
- Credibility must be demonstrated empirically, not assumed; hence the benchmark
  requirement in ASR-0007 and the evaluation harness in ADR-0021.

**Neutral**

- Interoperability keeps the adoption path open without constraining the design.

## Alternatives considered

- **Pure orchestrator over existing engines.** Fastest to a demo. Rejected: the
  capability ceiling is the intersection of the wrapped engines, statefulness and
  GUI domains have no home, and corpus/coverage formats cannot be unified.
- **Native core plus adapters that also drive external engines.** Attractive
  hedge. Rejected as a *v1* commitment: maintaining external-engine adapters
  competes directly with making our own engine good, and every adapter drags its
  engine's assumptions back into our core types.
- **Concolic-hybrid as the headline differentiator.** Rejected as a starting
  point: it front-loads the hardest, least reliable subsystem before the corpus,
  mutation, and feedback machinery it depends on exists. Hybrid remains an
  explicit goal (ADR-0007), just not the foundation.
