# ADR-0015: Single-node multi-core process parallelism

- **Status:** Accepted
- **Date:** 2026-08-28
- **Serves:** ASR-0007, ASR-0008, ASR-0015

## Context

ASR-0007 requires near-linear scaling to a host's core count. Distributed
multi-host fuzzing is valuable but is a distinct engineering problem —
coordinator, worker registration, corpus synchronisation, partition tolerance,
deployment — and building it before the single-node engine is good would be
optimising the wrong bottleneck.

Within a node, the parallelism unit could be a goroutine or a process.

## Decision

**Scale within one host, using processes as the unit of parallelism. Distributed
fuzzing is explicitly out of scope for v1.**

- A campaign runs **N worker processes** supervised by the daemon, defaulting to
  the physical core count.
- Each worker runs an independent engine instance with its **own deterministic
  RNG stream**, seeded `H(campaign_seed ‖ worker_id)` (ASR-0008).
- Workers share the corpus **through the daemon's store** (ADR-0008): new
  interesting inputs are published to an event bus and fanned out to siblings,
  giving AFL-style corpus sync without a network protocol.
- **Ensemble fuzzing** is supported: workers may run different strategies —
  different mutator weights, power schedules, or feedback stacks — from one
  campaign file. Strategy diversity across workers is a well-established win over
  N identical workers.
- Within a worker, goroutines handle I/O and observation; the fuzz loop itself is
  single-threaded to keep it allocation-free and cache-friendly.

Processes rather than goroutines, because:

1. A target that corrupts memory or exits must not take siblings down. With T0
   in-process execution (ADR-0009) this is not hypothetical.
2. Go's GC is process-global; one worker's allocation pressure would tax all of
   them.
3. Per-worker sandboxing (ADR-0012) is a process-level mechanism.
4. Crash isolation makes worker restart a routine, cheap recovery.

Distributed fuzzing is **deferred, not excluded**. The daemon boundary
(ADR-0003) is exactly where a coordinator would attach, and corpus sync is
already an event-bus operation rather than a direct memory share — so v2 adds a
transport, not a redesign.

## Consequences

**Positive**

- Full utilisation of the machine most fuzzing actually runs on, with crash
  isolation between workers.
- Ensemble strategies come free from the multi-process design.
- Determinism is preserved per worker, so a finding remains replayable even from
  a 32-worker campaign (ASR-0008).
- Substantially less machinery than a distributed system, and no distributed
  failure modes to debug while the engine is still young.

**Negative**

- No multi-host scale in v1 — a real limitation for large campaigns, and one to
  state plainly rather than paper over.
- Cross-process corpus sync has latency: a worker's discovery reaches siblings in
  milliseconds, not instantly, so some duplicated work is inherent.
- Process supervision, restart, and health monitoring are engineering the
  goroutine model would not need.
- Per-worker memory overhead is higher than per-goroutine.

**Neutral**

- The console's fleet view is deferred with it (ADR-0011).

## Alternatives considered

- **Goroutine-based workers.** Lower overhead, simpler. Rejected: no crash
  isolation, shared GC, and no path to per-worker sandboxing.
- **Full distributed early.** Enables serious scale sooner. Rejected: it would
  consume the effort that makes the core engine good, and a distributed system
  multiplying a mediocre engine is still mediocre.
