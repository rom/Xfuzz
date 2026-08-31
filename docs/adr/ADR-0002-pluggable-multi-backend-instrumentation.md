# ADR-0002: Pluggable multi-backend instrumentation

- **Status:** Accepted
- **Date:** 2026-08-28
- **Serves:** ASR-0003, ASR-0006, ASR-0007

## Context

ASR-0003 requires useful operation on black-, grey-, and white-box targets. The
available coverage signal differs entirely by target:

| Target | Available signal |
| --- | --- |
| C/C++ with source | Compiler instrumentation (edge, cmp, value profile) |
| Go with source | Native Go coverage counters |
| Rust with source | Compiler instrumentation |
| JVM / .NET / Python | Runtime agents and tracing hooks |
| Stripped native binary | Emulation, dynamic rewriting, hardware trace, or breakpoints |
| Fully opaque service | None — responses, timing, and exit status only |

These differ in transport (shared memory, agent socket, trace buffer), in
granularity (edge, block, function), in fidelity, and in overhead by two orders
of magnitude. No single mechanism covers the range.

## Decision

Define one **`Observer` interface** for extracting per-execution signal, and
implement it with **independent, selectable backends**:

| Backend | Mechanism | Platform |
| --- | --- | --- |
| `sancov` | `xfuzz-cc`-injected edge counters in shared memory | Linux, macOS, Windows |
| `gocov` | Go native coverage counters | all (deferred past v0.1, [ADR-0026](ADR-0026-gocov-deferred-blackbox-is-the-off-linux-path.md)) |
| `forkserver` | AFL-protocol shared-memory bitmap | Linux, macOS |
| `frida` | Dynamic instrumentation of stripped binaries | Linux, macOS, Windows |
| `qemu` | User-mode emulation with block tracing | Linux |
| `intelpt` | Hardware branch trace | Linux, capable CPUs |
| `ptrace-bb` | Basic-block breakpoints (low-fidelity fallback) | Linux, macOS |
| `agent` | Language-runtime agent (JVM/.NET/Python) | all |
| `blackbox` | Exit status, output hash, timing, response shape | all |

Backend selection is **capability-probed, not user-declared**: the operator
declares what the target *is*, and the daemon probes and selects, reporting the
chosen backend, its measured overhead, and anything requested but unavailable.
The operator may pin a backend explicitly, and may require a minimum granularity
and have the campaign refuse to start below it.

Critically, `blackbox` is a **fully supported backend, not a failure state**. The
core loop treats an empty coverage map as valid input, degrading to
response-novelty and timing feedback plus randomised scheduling.

## Consequences

**Positive**

- The visibility spectrum becomes a configuration property rather than a fork in
  the product.
- Adding a language or platform is a new backend, not a core change.
- Overhead is measured and comparable across backends, so an operator can trade
  fidelity for speed with evidence.

**Negative**

- Large surface area: each backend is a distinct engineering effort with distinct
  platform quirks and failure modes.
- Coverage semantics differ subtly between backends (edge vs. block, hitcount
  bucketing, collision rates). Corpora are therefore **not** portable across
  backends without re-measurement, and the coverage map must record which backend
  produced it.
- Probing adds startup latency and its own class of confusing failures, which
  makes `xfuzz doctor` (ASR-0006) mandatory rather than a nicety.

**Neutral**

- Backends beyond `sancov`, `gocov`, `forkserver`, and `blackbox` are phased work
  (ADR-0020); the interface is fixed in v1 so later additions are not retrofits.
  `gocov` itself moved out of v0.1 during the release audit
  ([ADR-0026](ADR-0026-gocov-deferred-blackbox-is-the-off-linux-path.md)): Go's
  coverage format has no public reader, and the v0.1 set is `sancov`,
  `forkserver`, and `blackbox`.
- The three binary-only backends — `ptrace-bb`, `qemu`, `frida` — landed in v0.2.
  What they return, and why all three return the same thing, is
  [ADR-0027](ADR-0027-block-traces-are-the-binary-only-currency.md): a block
  trace in link-time addresses, folded into a coverage map by one shared piece of
  code. `ptrace-bb` and `frida` resolve blocks rather than edges, and say so, so
  a campaign cannot require a precision they do not have.
- `sancov` grew a second and third region in v0.3: comparison operands
  ([ADR-0028](ADR-0028-comparison-logging-in-the-runtime.md)) and, for a directed
  campaign, executed block addresses
  ([ADR-0029](ADR-0029-directed-fuzzing-over-block-distance.md)). Both are
  separately optional and inert unless attached.
- `intelpt` and `agent` remain unimplemented.

## Alternatives considered

- **Source-instrumented only.** Fastest to strong results. Rejected: it makes
  closed-source targets — a large share of real engagements — unreachable, and
  violates ASR-0003.
- **Binary-only first.** Maximises applicability. Rejected as the starting point:
  the slowest and noisiest signal would be the basis for tuning every heuristic
  in the engine, biasing the whole design.
- **Go-native only.** Trivial instrumentation. Rejected: the interesting memory-
  safety target population is native code.
