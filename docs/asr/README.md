# Architecturally Significant Requirements (ASR)

An ASR is a requirement that materially constrains the architecture — one where
choosing differently would change the structure of the system, not just the
contents of a function.

Each ASR is a single file, `ASR-NNNN-slug.md`. ASRs are the *inputs* to
architecture; [ADRs](../adr/README.md) are the *decisions* made in response.
Every ADR names the ASRs it serves; every ASR names the ADRs that satisfy it.

## Status values

| Status | Meaning |
| --- | --- |
| `Proposed` | Captured, not yet accepted into the baseline |
| `Accepted` | Part of the architectural baseline; ADRs must satisfy it |
| `Deferred` | Accepted in principle, explicitly out of scope for the current phase |
| `Superseded` | Replaced by a later ASR (which is named in the file) |

## Index

| ID | Title | Status | Priority |
| --- | --- | --- | --- |
| [ASR-0001](ASR-0001-multi-domain-target-coverage.md) | Multi-domain target coverage | Accepted | Must |
| [ASR-0002](ASR-0002-stateless-and-stateful-fuzzing.md) | Stateless and stateful fuzzing | Accepted | Must |
| [ASR-0003](ASR-0003-black-grey-white-box-operation.md) | Black-, grey-, and white-box operation | Accepted | Must |
| [ASR-0004](ASR-0004-pluggable-guidance-strategies.md) | Pluggable guidance strategies | Accepted | Must |
| [ASR-0005](ASR-0005-dual-interface-cli-and-web.md) | Dual interface: CLI and web console | Accepted | Must |
| [ASR-0006](ASR-0006-cross-platform-support.md) | Cross-platform support | Accepted | Must |
| [ASR-0007](ASR-0007-throughput-and-scalability.md) | Throughput and scalability | Accepted | Must |
| [ASR-0008](ASR-0008-reproducibility-and-determinism.md) | Reproducibility and determinism | Accepted | Must |
| [ASR-0009](ASR-0009-extensibility.md) | Extensibility | Accepted | Must |
| [ASR-0010](ASR-0010-safety-isolation-and-authorization.md) | Safety, isolation, and authorization | Accepted | Must |
| [ASR-0011](ASR-0011-finding-quality-and-triage.md) | Finding quality and triage | Accepted | Must |
| [ASR-0012](ASR-0012-observability-and-resumability.md) | Observability and resumability | Accepted | Must |
| [ASR-0013](ASR-0013-corpus-and-format-interoperability.md) | Corpus and format interoperability | Accepted | Should |
| [ASR-0014](ASR-0014-input-validity-and-structure-awareness.md) | Input validity and structure awareness | Accepted | Must |
| [ASR-0015](ASR-0015-operability-and-deployment.md) | Operability and deployment | Accepted | Should |

## Traceability

Every ASR is satisfied by at least one ADR, and every ADR serves at least one
ASR. The matrix is maintained in [`../ARCHITECTURE.md`](../ARCHITECTURE.md)
§ Traceability and is checked by the documentation lint in CI
(see [`../TESTS.md`](../TESTS.md) § Documentation tests).
