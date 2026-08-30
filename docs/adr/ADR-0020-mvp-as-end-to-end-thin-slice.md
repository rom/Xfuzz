# ADR-0020: MVP as an end-to-end thin slice

- **Status:** Accepted
- **Date:** 2026-08-28
- **Serves:** all ASRs

## Context

The architecture is broad: six domains, eight executor tiers, nine
instrumentation backends, three extension tiers, a daemon, and a console.
Sequencing determines which risks are discovered while they are still cheap.

The three credible sequencings are: go deep on one layer first (a strong
stateless engine, CLI only), build every layer shallowly across all domains, or
build one narrow path through every layer.

## Decision

**v0.1 is a thin slice through every layer, with nothing faked.**

Narrow in *breadth*, complete in *depth*. Every architectural layer is really
implemented, but only along one path per layer:

| Layer | In v0.1 | Deferred |
| --- | --- | --- |
| Domains | File formats, CLI tools, one network protocol | APIs, GUI, TUI |
| Executors | T0, T2, T3, T4, T6 | T1, T5, T7 |
| Instrumentation | `sancov`, `forkserver`, `blackbox` | `gocov` ([ADR-0026](ADR-0026-gocov-deferred-blackbox-is-the-off-linux-path.md)), `frida`, `qemu`, `intelpt`, `ptrace-bb`, `agent` |
| IR | Full node set, fixups, byte + structured mutators | Advanced grammar importers |
| Grammar | Native `.xfg` DSL, one worked format | protobuf, ASN.1, ABNF, Kaitai, OpenAPI importers |
| Feedback | Map coverage, state, response, timing; full algebra | Distance (directed), value profile, concolic |
| State | Declared + inferred state model, state feedback and scheduling | Automata learning |
| Corpus | SQL + blob store, AFL import/export, minimisation, bucketing | Advanced re-bucketing strategies |
| Safety | Linux sandbox, scope guard, audit log | macOS/Windows isolation beyond `minimal` |
| Parallelism | N worker processes, corpus sync, ensembles | Distributed |
| Interfaces | Daemon, CLI, console (all v1 views) | Fleet view, RBAC |
| Extensions | Native tier complete; plugin + Starlark for feedback/oracles | Full plugin coverage of every extension point |
| Platforms | Linux full; macOS/Windows via T3/T4 + `blackbox` | Platform fast paths |

The rule that makes this work: **no layer may be stubbed.** A thin slice with a
mocked store or a fake feedback pipeline proves nothing, because the integration
risk is precisely what the slice exists to retire.

The proof obligation for v0.1 is that both v1 domains work end to end: a
coverage-guided file-format campaign at target throughput, and a stateful
protocol campaign discovering a bug reachable only after a valid handshake —
both launched from a file, monitored in the console, triaged to a minimised
reproducible finding.

Detailed milestones are in [`../MVP_PLAN.md`](../MVP_PLAN.md).

## Consequences

**Positive**

- The riskiest questions in the design — does one corpus serve 100k/s and 10/s?
  does structured IR mutation survive the hot loop's allocation budget? does the
  feedback algebra stay cheap enough? — are answered while the code is small
  enough to change.
- Every subsequent phase is an *addition* along a dimension already proven, not
  a retrofit.
- There is a usable, honest product at v0.1 rather than a demo.

**Negative**

- v0.1 is unimpressive in breadth relative to the vision; the most distinctive
  domains (GUI/TUI, API) are absent, which is a real marketing cost.
- Building every layer at once means no layer gets deep initial tuning; the file
  fuzzer will not match AFL++ at v0.1, and saying so plainly is part of the
  decision.
- Requires discipline to keep the slice thin under pressure to add "just one more
  backend".

**Neutral**

- Interfaces for deferred capabilities are designed in v1 even when unimplemented,
  which is what keeps later additions cheap.

## Alternatives considered

- **Engine-deep, headless first.** Proves the engine is genuinely competitive
  before building around it, and is the most defensible technically. Rejected: it
  defers all integration risk — daemon, store, console, statefulness — to a point
  where the engine's assumptions have already hardened around one domain.
- **Two-track (engine deep + platform against a mock engine).** Faster in
  parallel. Rejected: a mock engine hides exactly the integration mismatches the
  slice exists to find, and interface contracts drift when only one side is real.
- **Breadth-first skeleton across all six domains.** Validates the abstractions
  hardest. Rejected: shallow implementations everywhere make it impossible to tell
  whether an abstraction is wrong or merely unfinished, and nothing is usable.
