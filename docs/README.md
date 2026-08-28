# Xfuzz Documentation

Documentation for Xfuzz, a universal fuzzing platform.

## Start here

| Document | What it covers |
| --- | --- |
| [DESIGN.md](DESIGN.md) | What Xfuzz is, the problem it solves, design principles, core model, campaign format |
| [ARCHITECTURE.md](ARCHITECTURE.md) | Components, packages, interfaces, data flow, storage, concurrency, traceability |
| [MVP_PLAN.md](MVP_PLAN.md) | Milestones M0–M8 to v0.1, dependencies, exit criteria, risks, roadmap |
| [SECURITY.md](SECURITY.md) | Threat model, controls, residual risks, responsible use, reporting |
| [TESTS.md](TESTS.md) | Ten-layer test strategy and definition of done |
| [CHANGELOG.md](CHANGELOG.md) | Release history |

## Decision records

| Directory | Contents |
| --- | --- |
| [asr/](asr/README.md) | 15 Architecturally Significant Requirements — the constraints |
| [adr/](adr/README.md) | 21 Architecture Decision Records — the decisions, with rejected alternatives |

ASRs are the *inputs* to architecture; ADRs are the *decisions* made in response.
Every ADR names the ASRs it serves; the matrix is in
[ARCHITECTURE.md § 11](ARCHITECTURE.md#11-traceability) and is linted in CI.

## Reading paths

**Evaluating the design** → DESIGN.md → ARCHITECTURE.md § 1–5 → adr/ADR-0005,
ADR-0007, ADR-0009 (the three decisions that shape everything else).

**Implementing** → MVP_PLAN.md → ARCHITECTURE.md § 2–3 → TESTS.md § 14.

**Assessing safety** → SECURITY.md → adr/ADR-0012 → TESTS.md § 12.

**Understanding a specific choice** → adr/README.md index; each ADR records the
alternatives that were rejected and why.

## Conventions

- ADRs and ASRs are **immutable once accepted**. A changed decision produces a
  new ADR that supersedes the old one, so the reasoning history stays intact.
- Every architectural change updates an ADR or adds one — enforced by the
  definition of done in [TESTS.md § 14](TESTS.md#14-definition-of-done).
- Docs are linted in CI: traceability, link resolution, and campaign-file examples
  validated against the published JSON Schema.
