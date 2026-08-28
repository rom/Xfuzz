# ASR-0002: Stateless and stateful fuzzing

- **Status:** Accepted
- **Priority:** Must
- **Date:** 2026-08-28
- **Source:** Product brief — "work both as stateful fuzzer and a stateless fuzzer"

## Requirement

Xfuzz must support both:

- **Stateless fuzzing** — each execution is independent; the target is reset (or
  is inherently memoryless) between inputs. The unit of work is one input.
- **Stateful fuzzing** — the target carries state across deliveries; reaching a
  bug requires a *specific sequence* of inputs. The unit of work is a session,
  and the fuzzer must reason about which protocol state it is in.

Both must share the same corpus, scheduler, mutator, feedback, and triage
machinery.

## Rationale

Statefulness is not a domain (network) property — it is an axis. A file parser
with a persistent cache is stateful; a REST endpoint may be stateless. Modelling
statefulness as a separate *tool* duplicates every subsystem. Modelling it as a
property of the input and the feedback stack keeps one engine.

## Architectural impact

- The unit stored in the corpus must be able to represent a **sequence** as
  naturally as a single message. A stateless input is a session of length one.
- Requires a first-class notion of **observed target state** — a label derived
  from target responses or instrumentation — which participates in feedback and
  scheduling, not merely in reporting.
- Requires per-execution **reset semantics** to be an explicit, configurable
  contract (`none`, `reconnect`, `restart`, `snapshot`), because the fuzzer's
  correctness assumptions depend on it.
- Mutation operators must include *sequence-level* operators (insert message,
  delete message, reorder, duplicate, splice sub-sequences) alongside
  message-level ones.

## Acceptance criteria

- A stateful campaign discovers a bug reachable only after a valid multi-step
  handshake, and the recorded finding replays deterministically as a sequence.
- Coverage of protocol **states** and **transitions** is reported separately from
  code coverage.
- The same mutator configuration is valid in both modes, with sequence-level
  operators inert when sequence length is fixed at one.

## Satisfied by

ADR-0004, ADR-0005, ADR-0006, ADR-0007, ADR-0013, ADR-0014
