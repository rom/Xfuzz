# ASR-0004: Pluggable guidance strategies

- **Status:** Accepted
- **Priority:** Must
- **Date:** 2026-08-28
- **Source:** Product brief — "Coverage-guided, Directed, Feedback-driven and Hybrid fuzzing"

## Requirement

Xfuzz must implement, and allow **simultaneous combination of**, at least:

1. **Coverage-guided** — maximise edge/block coverage novelty.
2. **Directed** — drive execution toward declared target locations (a patch, a
   function, a line, a stack signature), prioritising seeds by distance.
3. **Feedback-driven** — accept arbitrary user-defined signals as the notion of
   "interesting": a response field, a log line, a latency profile, an allocation
   count, a UI state, a domain-specific oracle.
4. **Hybrid** — combine mutational fuzzing with constraint reasoning to pass
   checks that random mutation cannot (magic values, checksums, comparisons).

These are not modes to select between; a single campaign must be able to run
coverage-guided *and* directed *and* a custom feedback simultaneously.

## Rationale

These four are conventionally separate research prototypes (AFL, AFLGo,
IJON-likes, Driller/QSYM). In practice an operator wants "cover broadly, but
weight toward this CVE's patch, and treat any 500 response as interesting."
Composability is the requirement; the four named strategies are just its most
common combinations.

## Architectural impact

- Demands a **composable feedback algebra**: feedback objects must combine under
  boolean operators with well-defined short-circuit and state-update semantics.
- Separates "is this input worth keeping?" (feedback) from "is this input a
  finding?" (objective) — the same observation may answer both differently.
- Requires the scheduler to consume a *vector* of per-seed scores, not a single
  coverage count, so that distance, rarity, and custom scores can be weighed.
- Hybrid requires a boundary where an external solver can be invoked
  asynchronously without stalling the fuzz loop, and where its failure is
  non-fatal.
- Directed requires an offline analysis artifact (distance map) with a defined
  lifecycle, cache, and staleness rule versus the target binary.

## Acceptance criteria

- A campaign file expresses a combined feedback stack, and the daemon reports
  which feedback admitted each corpus entry.
- A directed campaign reaches a declared target location measurably faster than
  the same campaign without direction.
- A custom feedback supplied as an out-of-process plugin or a script influences
  corpus admission without engine changes.
- Disabling the hybrid solver degrades throughput and depth but never correctness.

## Satisfied by

ADR-0006, ADR-0007, ADR-0010, ADR-0013, ADR-0028, ADR-0029, ADR-0030
