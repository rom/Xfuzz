# ADR-0021: Layered, differential, and self-fuzzing test strategy

- **Status:** Accepted
- **Date:** 2026-08-28
- **Serves:** ASR-0007, ASR-0008, ASR-0011, ASR-0014

## Context

A fuzzer is unusually difficult to test. Its output is stochastic, its value is
measured over hours, and its most severe defects are **silent**: a fuzzer that
finds nothing looks identical to a fuzzer running against a hardened target. A
broken coverage map, an inverted feedback, or a mutator that only produces
invalid inputs will pass every unit test and produce a campaign that simply never
finds anything.

Conventional unit testing is therefore necessary and radically insufficient.

## Decision

Adopt a layered strategy in which each layer catches a class the others cannot:

1. **Unit tests** — per component, standard Go testing, race detector on.

2. **Property and round-trip tests** — the IR and codecs are the correctness
   foundation, and their invariants are checkable rather than exemplifiable:
   `parse → serialise` is byte-exact; `parse → mutate → fixup → serialise →
   parse` succeeds; fixups converge and are order-independent; mutators preserve
   type validity; derived fields are consistent after every operator.

3. **Planted-bug integration targets** — purpose-built targets with N known,
   distinct, documented bugs at graded difficulty (shallow crash, magic value,
   checksum-gated, state-dependent, deep path). These are the primary end-to-end
   assertion: a fuzzer that cannot find a planted bug in bounded time is broken,
   and this is the test that catches silent failure.

4. **Determinism and replay tests** — same seed, same campaign, single worker
   yields an identical execution trace; every finding replays on a different host
   (ASR-0008).

5. **Differential tests** — the same input through different executor tiers and
   different instrumentation backends must produce consistent coverage and
   outcomes. This is how backend-specific defects surface, since each backend is
   otherwise its own unverifiable island.

6. **Benchmark suite with CI regression gates** — the ASR-0007 tier table is
   executed in CI; a ≥ 10 % throughput regression fails the build. Coverage-over-
   time and time-to-first-bug on planted targets are tracked as effectiveness
   regressions.

7. **Self-fuzzing** — Xfuzz fuzzes its own attack surface with Go native fuzzing:
   IR codecs, grammar parser, campaign-file parser, corpus import, capture
   parsers, and the plugin protocol. These parse untrusted input (ASR-0010) and
   are therefore a genuine security boundary, not just a correctness one.

8. **Fault injection** — worker crashes, plugin deaths, disk-full, corrupted
   store, killed daemon. Asserts that recovery and resumability (ASR-0012)
   actually hold rather than being assumed.

9. **Cross-platform CI** — full suite on Linux, macOS, and Windows; build matrix
   covers `CGO_ENABLED` on and off (ADR-0017).

10. **Documentation and licence checks** — ASR/ADR traceability is linted, and a
    licence scan enforces ADR-0018's dependency policy.

Details in [`../TESTS.md`](../TESTS.md).

## Consequences

**Positive**

- Silent ineffectiveness — the defining failure mode of a fuzzer — is caught by
  planted-bug targets rather than discovered during an engagement.
- Performance is a tested property, so ASR-0007 is enforceable rather than
  aspirational.
- Property tests make the IR's invariants, the least intuitive part of the
  design, mechanically checked.
- Differential testing gives each instrumentation backend an oracle it would
  otherwise lack.
- Self-fuzzing is the strongest available evidence that a fuzzing tool takes its
  own parsing surface seriously.

**Negative**

- Substantial test infrastructure — planted-bug targets, a benchmark harness, a
  three-platform CI matrix — is a meaningful fraction of total project effort.
- Benchmark gates are inherently noisy on shared CI runners; they need dedicated
  or statistically robust measurement to avoid flaky failures that erode trust.
- End-to-end fuzzing tests are slow and probabilistic; they need generous bounds
  and fixed seeds to stay deterministic.
- Planted-bug targets can be over-fitted — the fuzzer gets good at *those* bugs.
  Mitigated by graded difficulty, periodic rotation, and external corpora.

**Neutral**

- Public benchmark evaluation against external known-bug suites is desirable and
  scheduled as a later phase.

## Alternatives considered

- **Standard Go rigor** (unit + integration + race, Linux CI). Rejected: it
  cannot detect silent ineffectiveness or performance regression, the two defects
  that matter most here.
- **Effectiveness-first** — an empirical evaluation harness as the primary signal
  with lighter unit testing. Rejected as primary: end-to-end effectiveness tests
  are slow and non-local, so a defect points at "the fuzzer" rather than at a
  component. Adopted as layer 3 and 6 rather than as the whole strategy.
- **Rigor minus benchmark gates.** Rejected: ASR-0007 is unverifiable without
  them, and an untested performance requirement is not a requirement.
