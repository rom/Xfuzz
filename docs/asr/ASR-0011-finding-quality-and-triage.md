# ASR-0011: Finding quality and triage

- **Status:** Accepted
- **Priority:** Must
- **Date:** 2026-08-28
- **Source:** Derived — output volume, not bug discovery, is the practical bottleneck

## Requirement

Xfuzz must deliver **findings**, not raw crash files:

1. **Deduplication** into stable buckets that survive minor target changes and do
   not split one bug across many buckets.
2. **Automatic minimization** of both the input (byte/structure level) and, for
   stateful campaigns, the session (message level), preserving the outcome.
3. **Classification** — crash type, faulting operation, sanitizer diagnosis where
   available, and a reproducibility rate.
4. **Reproducible artifacts** — every finding carries everything needed to
   re-run it (ASR-0008).
5. **Triage workflow** — findings carry state (new / triaged / confirmed /
   duplicate / won't-fix) with notes and export to report formats.

## Rationale

A productive campaign yields thousands of crashing inputs mapping to a handful of
distinct bugs. The work of separating them is the actual labour of fuzzing, and
it is where most tools stop. Poor bucketing is worse than none: it hides
distinct bugs inside a bucket the operator has already dismissed.

## Architectural impact

- Requires **multi-signal bucketing** rather than a single stack hash: fuzzers
  that hash only the top frame merge distinct bugs, and fuzzers that hash the full
  stack split one bug across hundreds of buckets. Bucketing must be a pluggable,
  versioned strategy with a documented default and a re-bucketing operation.
- Minimization is expensive and must run **asynchronously** in a triage pipeline
  decoupled from the fuzz loop, with its own scheduling and back-pressure.
- Reproducibility rate requires re-execution — so triage needs its own executor
  pool, and must handle targets that are non-deterministic.
- Findings are long-lived, mutable, queryable records — this is a database
  requirement, not a directory-of-files requirement.
- Sanitizer output parsing is target-toolchain-specific and must be pluggable.

## Acceptance criteria

- Against a target with N planted distinct bugs, triage produces close to N
  buckets — measured, with both over- and under-merging reported.
- Minimization reduces a typical crashing input by ≥ 80 % while preserving the
  bucket.
- Every finding is exportable as a self-contained reproduction package.
- Re-bucketing an existing finding set with a new strategy is a supported
  operation and does not lose triage state.

## Satisfied by

ADR-0008, ADR-0011, ADR-0021, ADR-0033
