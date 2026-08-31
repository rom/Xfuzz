# ASR-0008: Reproducibility and determinism

- **Status:** Accepted
- **Priority:** Must
- **Date:** 2026-08-28
- **Source:** Derived — a finding that cannot be reproduced is not a finding

## Requirement

1. **Finding replay.** Every finding must be re-executable from stored artifacts
   alone, on another machine, producing the same observable outcome — including
   stateful findings, which replay as a full session.
2. **Campaign determinism.** Given the same campaign file, the same seed, the
   same target build, and a single worker, a campaign must produce an identical
   sequence of executions.
3. **Provenance.** Every corpus entry and every finding must record how it was
   derived: parent entry, mutation operators applied, generator decisions, and
   the worker and RNG stream that produced it.

Non-determinism originating in the *target* must be detected and reported, not
silently absorbed.

## Rationale

Reproducibility is the difference between a bug report and a rumour. It is also
the only practical way to debug a fuzzer: without deterministic replay, an
engine defect is indistinguishable from target flakiness. Provenance additionally
makes mutation strategy measurable — which operators actually produce coverage —
which feeds scheduling.

## Architectural impact

- Bans global and implicitly seeded randomness. Every stochastic decision draws
  from an explicit, per-worker, splittable RNG derived from
  `H(campaign_seed ‖ worker_id ‖ stream_id)`.
- Bans wall-clock time and map iteration order from influencing any fuzzing
  decision; time-based scheduling inputs must be quantised and recorded.
- Requires provenance to be compact enough to store for millions of entries —
  an operator log, not a copy of the input.
- Requires a **stability measurement**: re-executing the same input must yield
  the same coverage; the divergence rate is a reported campaign health metric,
  and a low-stability target must trigger a warning rather than corrupt the
  corpus.
- Findings must be stored with everything needed for replay: input/session,
  target invocation, environment, and the harness contract.

## Acceptance criteria

- `xfuzz replay <finding>` reproduces the outcome on a different host.
- Two single-worker runs of the same campaign file and seed produce
  byte-identical execution traces.
- Corpus stability is reported per campaign; targets below a configurable
  threshold raise a diagnostic.

## Satisfied by

ADR-0008, ADR-0015, ADR-0016, ADR-0021, ADR-0025, ADR-0029, ADR-0030, ADR-0035
