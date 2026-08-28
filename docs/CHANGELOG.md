# Changelog

All notable changes to Xfuzz are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Until v1.0, minor versions may contain breaking changes to the campaign file
format, the plugin protocol, and the on-disk store schema. Each such change is
listed here with its migration path.

## [Unreleased]

### Added — M1 Input IR and codecs (2026-08-28)

The structured input representation from ADR-0005, and the first two codecs.
This was the milestone carrying the design's central risk: whether a typed tree
can be mutated, repaired, and encoded without allocating, at fuzzing rates.

**`pkg/ir` — the unified input representation**

- Nine node kinds (`Bytes`, `Int`, `Str`, `Struct`, `Repeat`, `Choice`, `Opt`,
  `Ref`, `Derived`) with traversal, structural validation, and equality.
- Generic encoding: the wire form of a tree is the concatenation of its leaves
  in document order, so format knowledge is confined to decoding.
- Relative references (`^data`, `^^hdr.len`, `/chunks[0]`) resolved against an
  ancestor chain, with a textual form and parser. Nodes carry no parent
  pointers, which keeps them small and copy-on-write simple.
- Four derivation classes — `Length`, `Count`, `Offset`, `Checksum` — with an
  addend, twelve built-in checksum algorithms, and a registry for more.
- The fixup pass: sizes and offsets computed once (no derived value can change
  any node's size, so they cannot cycle), then checksums ordered by span
  containment with Kahn's algorithm in document order. Mutually covering
  checksums are reported as cycles; a checksum covering its own field requires
  an explicit `SelfZero`, which is how IPv4 and similar formats define it.
- `Suppress` leaves chosen derivations inconsistent on purpose, per class or per
  node — without which a fuzzer could never reach a target's validation code.
- `Arena`: a bump allocator over fixed slabs with `Reset`, plus copy-on-write
  path copying. Payloads are copied rather than shared so in-place byte mutation
  cannot corrupt the corpus entry a clone came from.

**`pkg/codec` — bytes to trees**

- `Codec` interface and registry, with lookup by name and by file extension.
- `raw`: the degenerate codec, so unstructured targets need no special handling
  anywhere else in the engine.
- `png`: signature plus length-prefixed, CRC-protected chunks — the archetype of
  the format family that defeats byte-level fuzzing.
- Decoding is **total and preserving**: malformed input yields a partial tree
  with unrecognised bytes kept in opaque nodes, and values read from the file are
  preserved even when wrong. Decode preserves; fixup repairs.
- `UnparsedBytes` and `StructuredFraction` report how much of a seed a codec
  actually understood — the signal that a campaign's schema does not match its
  corpus.

**Measured** (all zero-alloc, so gated on every platform)

| Operation | Cost |
| --- | --- |
| PNG decode | 148 ns/op, 620 MB/s |
| Clone + mutate + fixup + encode | 1.8 µs/op (~545k/s) |
| Copy-on-write mutation | 69 ns/op |

**Tests**

- Property and round-trip tests per TESTS.md § 3: byte-exact round trip,
  idempotent and order-independent fixups, zero steady-state allocation, no
  aliasing across arena generations.
- `FuzzPNGDecode` checks the round-trip invariant on every input; 3.8M
  executions found no crash and no violation.
- End-to-end: a chunk inserted through the IR and fixed up is accepted by the
  standard library's PNG decoder, which validates every CRC; with checksum
  fixups suppressed it is correctly rejected.

### Changed

- ARCHITECTURE.md § 3.1 now carries the implemented interfaces and the reasoning
  behind two departures from the sketch: scalar detail is stored inline rather
  than behind a `Meta` pointer, and the Arena is a bump allocator with `Reset`
  rather than a free list with `Release`.

### Added — M0 Foundation (2026-08-28)

Repository skeleton and the quality machinery that every later milestone is
measured against. No engine code yet; M1 (input IR and codecs) is next.

**Module skeleton**

- Package layout per ARCHITECTURE.md § 2: `pkg/` (11 packages), `internal/`
  (10 packages), `cmd/` (4 commands), `bench/`, `tools/`.
- Each package carries a `doc.go` stating its responsibility and its
  architectural constraints, with the governing ADR named.
- `internal/version` with link-time build identity and cgo detection, so
  `--version` reports whether the fast paths are available (ADR-0017).
- `cmd/xfuzz`, `cmd/xfuzzd`, `cmd/xfuzz-worker`, `cmd/xfuzz-cc` build and report
  version; they exit non-zero pending implementation rather than pretending.

**Enforcement tooling** — each rule the documentation claims is now a Go test

- `tools/archlint` — the seven layering rules of ARCHITECTURE.md § 2:
  `pkg-no-internal`, `core-no-executor`, `platform-build-tags`,
  `spawn-confinement`, `dial-confinement`, `no-cmd-import`, `no-stdlib-plugin`.
  Exceptions sit in an explicit allowlist. Its own tests assert that every rule
  fires against a deliberately violating fixture.
- `tools/docslint` — ASR/ADR traceability across record headers, both indexes,
  and the ARCHITECTURE matrix, plus link resolution across `docs/`. Also tests
  that it detects injected drift.
- `tools/licensecheck` — the ADR-0018 dependency policy against a
  machine-readable `NOTICE` inventory: missing entries, stale entries, version
  drift, and forbidden or unknown licences all fail the build.
- `tools/benchcmp` — benchmark regression gate with median-of-N sampling and
  provenance-aware gating (timings gate only when both runs come from the same
  host; allocation counts gate everywhere).

**Performance harness**

- `bench/` with the ASR-0007 executor floors as data, a `TestFloorsMatchDocumentation`
  test tying them to TESTS.md § 7, an allocation assertion helper, and a
  committed `bench/baseline.txt`.

**Build and CI**

- `Makefile` with the TESTS.md § 13 target set plus `bench-baseline`,
  `bench-check`, `cross`, `lint-*`, and `ci`.
- `.github/workflows/ci.yml`: lint, test on Linux/macOS/Windows, `CGO_ENABLED=0`
  build, cross-compile matrix, `govulncheck`, and benchmark gating.

### Changed

- `internal/sync` renamed to `internal/corpussync` — the original name would
  shadow the standard library at every use site. ARCHITECTURE.md § 2 updated.
- ARCHITECTURE.md § 2 now states the layering rules as a table naming each
  enforced lint rule, and records `tools/`, `bench/`, `.github/`, and
  `internal/version`.
- TESTS.md § 7 documents the benchmark noise mitigations; § 10 replaces the
  aspirational CI matrix with the one that exists, and states two gaps plainly
  (no race detector on Windows, no native arm64 execution); § 11 adds
  architecture boundaries as a checked layer; § 13 matches the Makefile.
- `NOTICE` restructured with a machine-readable Components table and an explicit
  allowed/conditional/forbidden licence policy.

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
