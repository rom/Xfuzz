# ADR-0006: Explicit state machine with state feedback

- **Status:** Accepted
- **Date:** 2026-08-28
- **Serves:** ASR-0002, ASR-0004

> **Amendment (v0.9).** The active automata learning this record defers by name
> is now implemented, and has its own record:
> [ADR-0035](ADR-0035-active-automata-learning.md). Nothing here changes —
> inference stays, guidance stays, and learning runs before both — so a campaign
> that does not ask for it behaves exactly as this record describes.

## Context

ASR-0002 requires genuine stateful fuzzing: reaching bugs that need a specific
sequence of interactions. Code coverage alone is a poor guide here — two
sequences can cover identical code while leaving the target in entirely different
states, and the bug lives in the state, not the line.

## Decision

Model the target's protocol as an **explicit state machine** and treat state as a
**first-class feedback signal**:

- **`StateModel`** — states and legal transitions. Either *declared* in the
  campaign file, or *inferred* by clustering observed responses (status codes,
  response-shape fingerprints, banner or header changes).
- **`StateFn`** — maps an observed response to a state label. Pluggable
  (ADR-0010); defaults cover status-code and response-fingerprint extraction.
- **`StateObserver`** — records the sequence of state labels traversed by a
  session.
- **`StateFeedback`** — admits a session as interesting when it reaches a new
  state or exercises a new transition, composing with code-coverage feedback
  under the algebra of ADR-0007.
- **`StateScheduler`** — selects the next state to target (biasing toward rare,
  recently discovered, or under-explored states), then selects which message in
  the session to mutate — the message-selection split that makes stateful
  fuzzing tractable.

Sessions are IR `Repeat` nodes (ADR-0005), so sequence mutation is ordinary
mutation.

Per-execution **reset semantics** are an explicit contract in the campaign file —
`none`, `reconnect`, `restart`, or `snapshot` — because the fuzzer's correctness
assumptions depend on which one holds, and getting it wrong silently corrupts
both corpus and findings.

## Consequences

**Positive**

- Findings are attributable to a protocol state, which makes them far easier to
  understand and report than a bare crashing byte sequence.
- State coverage is reportable and visualisable (the console's state-machine
  view), turning "have we explored this protocol?" into a measurable question.
- The approach works black-box: state inference needs only responses, so stateful
  fuzzing does not require instrumentation.
- Declared and inferred models are the same object, so a user can start inferred
  and progressively add declarations where inference is wrong.

**Negative**

- Inference quality determines fuzzer quality on black-box targets, and response
  clustering is genuinely hard: too coarse and distinct states merge, too fine
  and every nonce spawns a state. Clustering must be tunable and its output
  inspectable, or failures are undiagnosable.
- Declared models are labour, and a wrong model actively misleads the scheduler.
- Reset semantics interact with throughput: `restart` per session is correct but
  slow, and this is the dominant cost on stateful campaigns.

**Deferred**

- **Active automata learning** (L\*-style) to infer models is attractive and
  explicitly out of scope for v1; it warrants its own ADR.

## Alternatives considered

- **Snapshot/restore (Nyx-style).** Very fast and deterministic. Rejected for
  v1: it requires KVM and deep Linux-specific machinery, conflicting with
  ASR-0006's portability requirement, and it solves *reset cost* rather than
  *state exploration*. Retained as a candidate executor tier for later.
- **Session-as-input with no state model.** Simplest — the whole sequence is just
  a structured input, guided by code coverage. Rejected as the primary mechanism:
  it cannot tell the scheduler which states are unexplored, which is exactly the
  guidance stateful fuzzing needs. It remains available as a degenerate
  configuration (no `StateFn` declared).
- **Learned model as the primary mechanism.** Highest originality. Rejected for
  v1 as a research effort that would block the delivery of a working stateful
  fuzzer.
