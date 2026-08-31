# ADR-0009: Tiered executors

- **Status:** Accepted
- **Date:** 2026-08-28
- **Serves:** ASR-0001, ASR-0003, ASR-0006, ASR-0007

## Context

ASR-0007 sets throughput targets spanning three orders of magnitude, and ASR-0001
requires six delivery mechanisms — a byte buffer, a process invocation, a socket
session, an HTTP request, a synthetic input event, a PTY write. ASR-0006 forbids
POSIX assumptions in portable code, and Windows has no `fork`, which is the
mechanism most high-performance fuzzers are built on.

No single execution strategy spans this. But every strategy answers the same
question — *run the target with this input and report what happened* — so they
can share one interface.

## Decision

Define one **`Executor` interface** and implement it as a set of **tiers**,
selected per campaign by target capability:

| Tier | Executor | Mechanism | Typical rate | Platforms |
| --- | --- | --- | --- | --- |
| T0 | `InProc` | Direct call into a Go harness, `recover()` for panics | 10⁵–10⁶/s | all |
| T1 | `Persistent` | Long-lived harness looping over inputs via shared memory | 10⁴–10⁵/s | all |
| T2 | `ForkServer` | Fork server + shared-memory coverage bitmap | 10³–10⁴/s | Linux, macOS |
| T3 | `ProcPool` | Pre-spawned process pool (the portable stand-in for T2) | 10²–10³/s | all, required on Windows |
| T4 | `Subprocess` | One `exec` per input | 10²–10³/s | all |
| T5 | `Emulated` | QEMU-user, Frida, Intel PT, or ptrace tracing | 10¹–10²/s | mostly Linux |
| T6 | `Session` | Connection-oriented protocol/API sessions | 10⁰–10²/s | all |
| T7 | `Driver` | GUI/TUI drivers (ADR-0013) | 10⁻¹–10¹/s | platform-dependent |

**T3's place in that order has a precondition, added 2026-08-31.** The rates
above read as properties of the tiers. T3's is not: a pool is faster than T4
only because the next process is created *while* the current one runs, and that
overlap needs a core to happen on. Given one the win is large; on a saturated or
two-core machine the spawn merely moves and the two tiers converge. Measured
with the same target on both: 1383 against 634 exec/s on a 4-core host, and 256
against 239 — a ratio of 1.07 — on a 2-core CI runner.

This matters for where T3 is deployed rather than whether it is worth having.
It is the portable stand-in for the fork server, so it runs where there is no
fork server, and a single-core Windows container is exactly the shape of host
that gets no benefit from it. `TestTiersAreOrderedAsADR0009Claims` asserts the
T3-over-T4 ordering only where the host can supply the overlap, and logs the
ratio everywhere so the convergence is visible.

Common contract across all tiers:

- **Reset semantics** are explicit (`none`/`reconnect`/`restart`/`snapshot`),
  since correctness depends on which holds (ADR-0006).
- **Timeouts and resource limits** are enforced by the executor, not the target.
- **Every spawn and every connection passes through the safety layer** — no
  executor creates a process or a socket directly (ADR-0012).
- Executors report **stability**: re-executing an input must reproduce its
  coverage, and the divergence rate is a campaign health metric (ASR-0008).
- **Buffers are pooled**; steady-state execution allocates nothing (ASR-0007).

T2's fork server speaks the **AFL fork-server protocol** so externally
instrumented binaries work (ASR-0013), while Xfuzz's own `xfuzz-cc`/`xfuzz-rt`
toolchain provides a self-contained path (ADR-0001).

The tier is **probed and reported**, with an operator override and the ability to
require a minimum tier.

## Consequences

**Positive**

- Each domain and each target gets an execution strategy suited to it, without
  the core loop knowing which.
- Windows support does not require `fork`: T3 is the portable equivalent and is
  also the fallback everywhere.
- The tier table makes performance expectations explicit and testable rather than
  implied.

**Negative**

- Eight implementations, each with distinct platform failure modes; this is the
  largest single block of engineering in the project.
- T1/T2 require a target-side runtime component, so they are not zero-effort for
  users; T3/T4 must always work so there is a no-setup path.
- Reset semantics differ per tier and interact with statefulness; incorrect
  pairing produces silently wrong results, so this needs explicit validation at
  campaign start rather than trust.

**Neutral**

- v1 implements T0, T2, T3, T4, and T6 (ADR-0020); the rest are phased. The
  interface is fixed in v1 so later tiers are additions, not retrofits.

## Alternatives considered

- **Pure-Go fork server only, no native shim.** Maximum portability. Rejected as
  the sole strategy: it forgoes the highest-throughput paths, and ASR-0007's
  targets are not reachable without them. Adopted *partially* — the client side
  is pure Go (ADR-0017).
- **Subprocess-only for v1.** Simplest, unblocks everything else. Rejected as the
  end state: an engine tuned only at 300 exec/s bakes in assumptions that break
  at 100k. Retained as the always-available baseline tier (T4).
- **Sidecar harness protocol for everything.** Language-agnostic and clean.
  Rejected as universal: it imposes a per-target harness even for a black-box
  binary that could just be executed. Adopted as the T1 mechanism specifically.
