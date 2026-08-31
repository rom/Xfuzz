# ASR-0007: Throughput and scalability

- **Status:** Accepted
- **Priority:** Must
- **Date:** 2026-08-28
- **Source:** Derived — a fuzzer that is not fast is not a fuzzer

## Requirement

On a commodity 8-core Linux host, for a small C parser target:

| Executor tier | Target sustained rate (single core) |
| --- | --- |
| Persistent in-process harness | ≥ 50,000 exec/s |
| Fork server + shared-memory coverage | ≥ 5,000 exec/s |
| Subprocess exec per input | ≥ 300 exec/s |
| Emulated / traced binary-only | ≥ 200 exec/s |

Engine overhead — scheduling, mutation, feedback evaluation, and bookkeeping,
excluding target execution — must stay **below 10 % of wall-clock time** at these
rates. Aggregate throughput must scale near-linearly to the host's physical core
count.

Distributed multi-host fuzzing is **out of scope for v1** (ADR-0015) but must not
be architecturally excluded.

## Rationale

Fuzzing effectiveness is superlinear in executions: a 10× throughput deficit is
not a 10 % worse tool, it is a tool that never reaches the bug. Go's GC and
scheduler make it entirely possible to write a *correct* fuzzer that is 50×
too slow, so throughput must be an explicit, measured, regression-gated
requirement rather than an aspiration.

## Architectural impact

- The hot loop must be **allocation-free in steady state**: input buffers,
  coverage maps, and observation records are pooled and reused, never
  re-allocated per execution.
- Forbids `interface{}`/reflection and channel round-trips on the per-execution
  path; feedback dispatch must be a static, ordered slice of concrete
  implementations.
- Coverage transport must be shared memory, not pipes or serialisation.
- Persistence (corpus writes, statistics) must be off the hot path — batched,
  asynchronous, and bounded.
- Forces the parallelism unit to be a **process**, not a goroutine: a target that
  corrupts memory or exits must not take down siblings or the engine, and GC
  pressure must not be shared across workers.
- Requires a permanent benchmark harness with CI regression gates (ASR is
  unverifiable otherwise).

## Acceptance criteria

- Published benchmark suite reproduces the table above and runs in CI.
- A ≥ 10 % throughput regression on any tier fails the build.
- `xfuzz stat` reports engine overhead as a first-class metric so users can see
  when the fuzzer, not the target, is the bottleneck.
- Scaling from 1 to N workers yields ≥ 0.85 × N aggregate throughput up to the
  physical core count.

## Satisfied by

ADR-0001, ADR-0002, ADR-0009, ADR-0015, ADR-0017, ADR-0021, ADR-0027, ADR-0028
