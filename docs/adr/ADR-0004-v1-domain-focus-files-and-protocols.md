# ADR-0004: v1 domain focus — file formats and network protocols

- **Status:** Accepted
- **Date:** 2026-08-28
- **Serves:** ASR-0001, ASR-0002

## Context

ASR-0001 names six target domains. Building all six to depth simultaneously would
spread effort so thin that none would validate the shared abstractions, and the
abstractions are the entire thesis. A proving ground must be chosen — one that
maximally *stresses* the shared spine rather than one that is merely easiest.

## Decision

**v1 proves the engine on file formats and network protocols.**

The pair is chosen because it spans the widest architectural distance of any pair
in the matrix:

| Axis | File formats | Network protocols |
| --- | --- | --- |
| State | Stateless | Stateful |
| Execution unit | One input | A session of messages |
| Rate | 10³–10⁵ exec/s | 10⁰–10² exec/s |
| Feedback | Code coverage | Code coverage + state coverage |
| Reset | Process exit | Reconnect / restart |
| Input model | Structured tree | Sequence of structured trees |

Anything satisfying both simultaneously has, by construction, an input model, a
scheduler, a feedback pipeline, and a statistics layer that do not privilege one
domain. The remaining domains — CLI tools, APIs (ADR-0014), GUI and TUI
(ADR-0013) — are variations that reuse this spine, and their adapters are phased
work in ADR-0020.

Interfaces for all six domains are designed in v1 even where implementations are
not; the CLI-tool adapter is a near-trivial specialisation of the file adapter
and ships in v1 alongside it.

## Consequences

**Positive**

- The riskiest abstraction question — "can one corpus and scheduler serve both a
  100k/s stateless loop and a 10/s stateful session?" — is answered in v1, when
  the answer is still cheap to act on.
- Two complete, genuinely useful fuzzers exist at v1 rather than six partial ones.
- The rate disparity forces rate-adaptive statistics and UI early, which is
  otherwise a painful retrofit.

**Negative**

- GUI/TUI and API fuzzing — the most distinctive parts of the product — are not
  demonstrable at v1.
- Some adapter-boundary awkwardness will surface only when the deferred domains
  are built; some interface churn should be expected and budgeted.

**Neutral**

- Ordering, not scope reduction: ASR-0001 remains binding in full.

## Alternatives considered

- **File formats only.** Cleanest and most proven path. Rejected: it defers
  statefulness, and statefulness is precisely the assumption that silently
  calcifies into the corpus and scheduler if not present from the start.
- **Protocols and APIs first.** Directly targets the stateful goal. Rejected: it
  defers the high-throughput path, and throughput assumptions calcify just as
  badly — an engine tuned only at 10 exec/s will not survive contact with 100k.
- **GUI/TUI first.** Highest originality. Rejected: slowest executions and the
  weakest feedback signal make it the worst possible basis for tuning the core
  loop.
