# Architecture Decision Records (ADR)

Each ADR captures one architecturally significant decision: the context that
forced it, the decision itself, its consequences, and the alternatives that were
rejected and why. ADRs are immutable once accepted — a changed mind produces a
*new* ADR that supersedes the old one, so the reasoning history stays intact.

Every ADR names the [ASRs](../asr/README.md) it serves. Format is a lightly
extended Nygard template.

## Status values

| Status | Meaning |
| --- | --- |
| `Proposed` | Drafted, not yet accepted |
| `Accepted` | Binding on the implementation |
| `Superseded by ADR-NNNN` | No longer binding; see the named ADR |
| `Deprecated` | No longer binding; nothing replaces it |

## Index

| ID | Title | Status | Serves |
| --- | --- | --- | --- |
| [ADR-0001](ADR-0001-novel-engine-no-ecosystem-runtime-dependency.md) | Novel engine, no ecosystem runtime dependency | Accepted | ASR-0001, ASR-0007, ASR-0013 |
| [ADR-0002](ADR-0002-pluggable-multi-backend-instrumentation.md) | Pluggable multi-backend instrumentation | Accepted | ASR-0003, ASR-0006, ASR-0007 |
| [ADR-0003](ADR-0003-daemon-core-with-thin-clients.md) | Daemon core with thin clients | Accepted | ASR-0005, ASR-0010, ASR-0012, ASR-0015 |
| [ADR-0004](ADR-0004-v1-domain-focus-files-and-protocols.md) | v1 domain focus: file formats and network protocols | Accepted | ASR-0001, ASR-0002 |
| [ADR-0005](ADR-0005-unified-structured-input-ir.md) | Unified structured input IR | Accepted | ASR-0001, ASR-0002, ASR-0013, ASR-0014 |
| [ADR-0006](ADR-0006-explicit-state-machine-with-state-feedback.md) | Explicit state machine with state feedback | Accepted | ASR-0002, ASR-0004 |
| [ADR-0007](ADR-0007-composable-feedback-pipeline.md) | Composable feedback pipeline | Accepted | ASR-0002, ASR-0003, ASR-0004, ASR-0014 |
| [ADR-0008](ADR-0008-hybrid-corpus-store-with-afl-export.md) | Hybrid corpus store with AFL export | Accepted | ASR-0008, ASR-0011, ASR-0012, ASR-0013, ASR-0015 |
| [ADR-0009](ADR-0009-tiered-executors.md) | Tiered executors | Accepted | ASR-0001, ASR-0003, ASR-0006, ASR-0007 |
| [ADR-0010](ADR-0010-three-tier-extensibility.md) | Three-tier extensibility model | Accepted | ASR-0004, ASR-0009, ASR-0014 |
| [ADR-0011](ADR-0011-full-campaign-console.md) | Full campaign console as an embedded SPA | Accepted | ASR-0005, ASR-0011, ASR-0012, ASR-0015 |
| [ADR-0012](ADR-0012-sandbox-by-default-and-scope-guard.md) | Sandbox by default and scope guard | Accepted | ASR-0006, ASR-0010 |
| [ADR-0013](ADR-0013-gui-tui-driver-adapters.md) | GUI/TUI driver adapters with UI-state feedback | Accepted | ASR-0001, ASR-0002, ASR-0004 |
| [ADR-0014](ADR-0014-traffic-replay-driven-api-fuzzing.md) | Traffic-replay-driven API fuzzing | Accepted | ASR-0001, ASR-0002, ASR-0010 |
| [ADR-0015](ADR-0015-single-node-multi-core-parallelism.md) | Single-node multi-core process parallelism | Accepted | ASR-0007, ASR-0008, ASR-0015 |
| [ADR-0016](ADR-0016-config-only-campaign-definition.md) | Config-only campaign definition | Accepted | ASR-0005, ASR-0008, ASR-0010, ASR-0015 |
| [ADR-0017](ADR-0017-pure-go-core-cgo-behind-build-tags.md) | Pure-Go core, cgo behind build tags | Accepted | ASR-0006, ASR-0007, ASR-0015 |
| [ADR-0018](ADR-0018-proprietary-commercial-license.md) | Proprietary commercial license | Accepted | — |
| [ADR-0019](ADR-0019-module-path-and-repository-identity.md) | Module path and repository identity | Accepted | — |
| [ADR-0020](ADR-0020-mvp-as-end-to-end-thin-slice.md) | MVP as an end-to-end thin slice | Accepted | all |
| [ADR-0021](ADR-0021-layered-differential-and-self-fuzzing-tests.md) | Layered, differential, and self-fuzzing test strategy | Accepted | ASR-0007, ASR-0008, ASR-0011, ASR-0014 |

Three ADRs serve no single ASR: **ADR-0018** and **ADR-0019** are project
constraints (licensing, identity) rather than responses to a requirement, and
**ADR-0020** is a sequencing decision that serves every ASR by deciding when each
is satisfied.

## Open questions

Decisions deliberately deferred, to be resolved by future ADRs:

- **Hybrid/concolic solver backend.** ADR-0007 defines the boundary; the concrete
  symbolic-execution backend (native tracer vs. external SMT integration) is
  unresolved.
- **Distributed fuzzing.** Explicitly out of scope for v1 (ADR-0015); the
  coordinator protocol and corpus-sync design need their own ADR before v2.
- **Snapshot-based execution.** Rejected for v1 in ADR-0006 as a state mechanism;
  revisit as an executor tier if throughput on restart-heavy targets proves
  limiting.
- **Grammar inference from corpora.** Desirable (ASR-0014) but unscoped; needs an
  ADR covering the inference approach and its failure modes.
