# Changelog

All notable changes to Xfuzz are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Until v1.0, minor versions may contain breaking changes to the campaign file
format, the plugin protocol, and the on-disk store schema. Each such change is
listed here with its migration path.

## [Unreleased]

### Added — Design baseline (2026-08-28)

Initial architecture and design record. No executable code yet; this release
establishes the decisions that the implementation will follow.

**Documentation**

- `docs/DESIGN.md` — product design: problem, principles, core model, capability
  matrix, campaign format, interfaces, non-goals, risks.
- `docs/ARCHITECTURE.md` — components, package layout, core interfaces, fuzz
  loop, data flow, storage model, concurrency, platform abstraction, API surface,
  extension points, traceability matrix.
- `docs/SECURITY.md` — threat model (10 threats), controls, residual risks,
  responsible use, vulnerability reporting.
- `docs/TESTS.md` — ten-layer test strategy targeting the two defining failure
  modes of a fuzzer: silent ineffectiveness and performance regression.
- `docs/MVP_PLAN.md` — nine milestones (M0–M8) to v0.1, with dependencies, exit
  criteria, risk register, and post-v0.1 roadmap.

**Architecturally Significant Requirements** — 15 records in `docs/asr/`

Multi-domain target coverage; stateless and stateful fuzzing; black-, grey-, and
white-box operation; pluggable guidance strategies; dual CLI and web interface;
cross-platform support; throughput and scalability; reproducibility and
determinism; extensibility; safety, isolation, and authorization; finding quality
and triage; observability and resumability; corpus and format interoperability;
input validity and structure awareness; operability and deployment.

**Architecture Decision Records** — 21 records in `docs/adr/`

| ADR | Decision |
| --- | --- |
| 0001 | Novel engine from scratch, no ecosystem runtime dependency |
| 0002 | Pluggable multi-backend instrumentation |
| 0003 | Daemon core with thin CLI and web clients |
| 0004 | v1 domain focus: file formats and network protocols |
| 0005 | Unified structured input IR with derived fields and fixups |
| 0006 | Explicit state machine with state as a feedback signal |
| 0007 | Composable feedback pipeline (Observer → Feedback → Objective → Scheduler) |
| 0008 | Hybrid corpus store: SQL metadata + content-addressed blobs + AFL export |
| 0009 | Tiered executors, T0–T7 |
| 0010 | Three-tier extensibility: native Go, out-of-process plugins, Starlark |
| 0011 | Full campaign console as an embedded SPA |
| 0012 | Sandbox by default and scope guard |
| 0013 | GUI/TUI driver adapters with UI-state feedback |
| 0014 | Traffic-replay-driven API fuzzing |
| 0015 | Single-node multi-core process parallelism |
| 0016 | Config-only campaign definition |
| 0017 | Pure-Go core with cgo behind build tags |
| 0018 | Proprietary commercial license |
| 0019 | Module path `github.com/rom/Xfuzz` |
| 0020 | MVP as an end-to-end thin slice |
| 0021 | Layered, differential, and self-fuzzing test strategy |

**Project scaffolding**

- `go.mod` — module `github.com/rom/Xfuzz`, Go 1.24.
- `LICENSE` — proprietary commercial notice (ADR-0018).
- `NOTICE` — third-party inventory with the dependency licence policy.
- `README.md`, `.gitignore`.

### Open decisions

Deliberately deferred, each requiring its own ADR before implementation:

- Concolic/symbolic backend for hybrid fuzzing (boundary defined in ADR-0007).
- Distributed fuzzing coordinator and corpus sync protocol (out of scope per
  ADR-0015).
- Snapshot-based execution as an executor tier (rejected for v1 in ADR-0006).
- Grammar inference from corpora.

[Unreleased]: https://github.com/rom/Xfuzz/commits/main
