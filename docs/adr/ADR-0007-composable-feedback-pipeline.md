# ADR-0007: Composable feedback pipeline

- **Status:** Accepted
- **Date:** 2026-08-28
- **Serves:** ASR-0002, ASR-0003, ASR-0004, ASR-0014

## Context

ASR-0004 requires coverage-guided, directed, feedback-driven, and hybrid fuzzing
— and requires them to *combine*, not to be selected between. Implementing four
engine modes would duplicate scheduling, corpus, and execution plumbing four
times and still not support "coverage-guided **and** directed at this patch
**and** treating any 500 as interesting."

## Decision

Implement **one engine** whose guidance is assembled from composable parts:

```
Input ─► Executor ─► [Observers] ─► [Feedbacks] ─► admit to Corpus?
                          │
                          └───────► [Objectives] ─► record as Finding?
                                          │
                      Scheduler ◄─── score vector
```

- **`Observer`** — records raw signal during execution (coverage map, cmp
  operands, stdout, timing, allocations, state label, response, UI state).
  Observers do not judge.
- **`Feedback`** — interprets observations to answer *"is this worth keeping?"*
  and maintains the novelty state that makes the answer meaningful.
- **`Objective`** — interprets observations to answer *"is this a finding?"*
  Separated from `Feedback` because the same observation answers the two
  questions differently: a crash is a finding but usually a poor seed; a novel
  edge is a great seed and not a finding.
- **`Scheduler`** — consumes a **score vector** per seed (novelty, distance,
  rarity, custom scores) rather than a single scalar, and implements pluggable
  power schedules.

Feedbacks compose under a boolean algebra with defined short-circuit and
state-update semantics: `All`, `Any`, `Not`, and a fast-path variant that
evaluates cheap feedbacks before expensive ones.

The four named strategies are then *configurations*, not modes:

| Strategy | Composition |
| --- | --- |
| Coverage-guided | `MapFeedback(edge coverage)` |
| Directed | `Any(MapFeedback, DistanceFeedback(targets))` with a distance-weighted schedule |
| Feedback-driven | `Any(MapFeedback, CustomFeedback(plugin/script))` |
| Hybrid | Above, plus `CmpLogStage` and an optional `ConcolicStage` |

Built-in feedbacks include map/edge coverage with hitcount bucketing, value
profile, distance-to-target, state and transition novelty, response novelty,
timing, allocation growth, and UI-state novelty.

**Hybrid is staged deliberately.** `CmpLogStage` — comparison-operand logging and
input-to-state substitution (Redqueen-style) — is native, cheap, and captures
most of the practical benefit on magic values and checksums. Full concolic
execution sits behind an **asynchronous, non-blocking `ConcolicStage`** with a
`Solver` interface: it must never stall the fuzz loop, and its failure must
degrade the campaign rather than break it. The concrete symbolic backend is
deliberately **deferred** to a later ADR.

## Consequences

**Positive**

- One engine, one corpus, one scheduler for every guidance strategy — and
  arbitrary combinations, which is the actual requirement.
- New guidance is a new `Feedback`, implementable as a plugin or script
  (ADR-0010) with no engine change.
- Black-box operation falls out naturally: an empty feedback set with
  response/timing feedbacks is a valid configuration (ASR-0003).
- Attribution is possible — the daemon can report which feedback admitted each
  seed, which is central to the introspection requirement (ASR-0012).

**Negative**

- Per-execution dispatch across a feedback list is on the hottest path. It must
  be a static ordered slice of concrete implementations with no interface
  boxing or reflection, and it must be benchmarked (ASR-0007).
- Composed feedbacks can interact pathologically — an over-permissive custom
  feedback floods the corpus and starves coverage exploration. Corpus admission
  needs per-feedback quotas and reporting.
- Directed mode requires an offline distance-map analysis artifact with a
  lifecycle, cache, and staleness rule against the target binary.

**Deferred**

- Concolic backend selection (native tracer vs. external SMT solver integration).

**Realised in v0.3**

- `CmpLogStage` and value profiling, over comparison operands the runtime writes
  into a region of their own
  ([ADR-0028](ADR-0028-comparison-logging-in-the-runtime.md)). The engine gained
  an ordered stage list to hold them: mutation was the whole loop until there was
  something to run beside it.
- `DistanceFeedback`, the offline distance artifact, and the distance-weighted
  schedule ([ADR-0029](ADR-0029-directed-fuzzing-over-block-distance.md)),
  including the staleness rule this record asked for.
- The `ConcolicStage` boundary — the `Solver` interface, the asynchronous
  machinery that keeps it off the loop, and the degradation rules. No symbolic
  backend ships, which is this record's deferral honoured rather than worked
  around: a placeholder behind that boundary would answer queries and a campaign
  would believe it. A campaign with a solver is not reproducible, and that is
  stated rather than hidden.

## Alternatives considered

- **Mode-selected engines.** Simpler per-mode mental model. Rejected: it
  duplicates plumbing and structurally forbids combining strategies, which is the
  explicit requirement.
- **Coverage core with directed/hybrid as bolt-on plugins.** Fastest to a solid
  coverage fuzzer. Rejected: it privileges coverage in the core types, making
  every non-coverage signal a second-class citizen — bad for black-box (ASR-0003)
  and for the custom-oracle domains.
