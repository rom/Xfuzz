# Xfuzz

**A universal fuzzing platform.** One engine, one corpus model, and one triage
pipeline spanning file formats, command-line tools, network protocols, APIs, GUI
applications, and TUI applications — stateless or stateful, black-box, grey-box,
or white-box, driven from a CLI or a web console.

> **Status: M5 complete — it is a tool now.** A campaign is a file,
> `xfuzz run campaign.yaml` runs it, and a daemon owns it from there: multiple
> worker processes sharing a corpus, live metrics and findings over an
> HTTP/JSON API, findings verified and minimised as they arrive, and a run that
> survives losing the daemon. Multi-worker campaigns scale at 94%
> efficiency; behind them are a structured IR, 24 mutation operators, the
> `.xfg` grammar language, a fork server, a C coverage runtime, a composable
> feedback pipeline, a content-addressed store, and a Linux sandbox that
> reports what is actually in force rather than what was asked for. M6
> (stateful protocol fuzzing) is next. See
> [docs/MVP_PLAN.md](docs/MVP_PLAN.md) for the path to v0.1.

## The idea

Fuzzing tooling is fragmented into incompatible islands — one tool for file
parsers, another for protocols, another for APIs, effectively nothing for GUIs.
An operator working across them learns four tools, maintains four corpora, and
triages crashes four different ways.

But those tools differ mainly in **how an input is delivered and how a response
is observed**. Everything downstream — scheduling seeds, mutating inputs,
deciding what is interesting, deduplicating crashes, minimising reproducers — is
the same problem wearing different clothes.

Xfuzz factors delivery and observation out, so one engine serves all of them.

## What that buys

- **Structured inputs by default.** A typed IR with derived fields — lengths,
  offsets, checksums — recomputed after every mutation, so inputs survive
  validation instead of dying in the first CRC check. Each fixup is suppressible,
  so the validation code is fuzzable too.
- **State as a signal.** For stateful targets, new protocol states and transitions
  are as interesting as new code edges — and the state model can be inferred from
  responses, so it works black-box.
- **Composable guidance.** Coverage-guided, directed, feedback-driven, and hybrid
  are not modes to pick between; they compose. "Cover broadly, weight toward this
  patch, and treat any 500 as interesting" is one campaign.
- **Findings, not crash files.** Asynchronous triage: classify, bucket, minimise,
  verify reproducibility.
- **Safe by default.** Targets are sandboxed and outbound traffic is
  scope-guarded without opting in, with a hash-chained audit log.
- **Reproducible by construction.** Deterministic RNG streams and full provenance;
  every finding replays on another machine.

## Documentation

Everything lives in [`docs/`](docs/README.md):

| | |
| --- | --- |
| [DESIGN.md](docs/DESIGN.md) | Problem, principles, core model, campaign format |
| [ARCHITECTURE.md](docs/ARCHITECTURE.md) | Components, interfaces, data flow, traceability |
| [MVP_PLAN.md](docs/MVP_PLAN.md) | Milestones to v0.1 |
| [SECURITY.md](docs/SECURITY.md) | Threat model and controls |
| [TESTS.md](docs/TESTS.md) | Test strategy |
| [CHANGELOG.md](docs/CHANGELOG.md) | Release history |
| [adr/](docs/adr/README.md) | 24 architecture decisions, with rejected alternatives |
| [asr/](docs/asr/README.md) | 15 architecturally significant requirements |

## Building

Requires Go 1.25 or later. No other toolchain is needed for the default build.

```
make build      # all five commands into bin/
make test       # unit and property tests, race detector on
make lint       # gofmt, vet, architecture, docs, and licence checks
make ci         # everything CI runs
make help       # every target
```

## A first campaign

```
xfuzz init --target ./parser > campaign.yaml
xfuzz validate campaign.yaml     # schema and semantics, without running it
xfuzz explain campaign.yaml      # every setting that will apply, defaults marked
xfuzz run campaign.yaml          # starts a private daemon if none is running
```

Fuzzing behaviour lives in the file, never in flags: what ran should be a
reviewable artefact rather than a shell history entry (ADR-0016). `xfuzz doctor`
reports what the host can enforce and why anything is missing, before a campaign
depends on it.

The architecture is enforced, not merely documented: `tools/archlint` fails the
build when a layering rule in
[ARCHITECTURE.md § 2](docs/ARCHITECTURE.md#2-package-layout) is broken, and its
own tests prove each rule can fire. `tools/docslint` does the same for decision
record traceability, and `tools/licensecheck` for the dependency licence policy.

## Platforms

Linux (primary, full capability), macOS, and Windows. Capability differences are
reported explicitly by `xfuzz doctor` rather than discovered through failure.

## Responsible use

Xfuzz is built for **authorised** security testing: your own software, systems
you have written permission to test, and sanctioned research or CTF
environments. The scope guard and authorization record make the boundary explicit
and auditable — they are not a substitute for having authorization. See
[docs/SECURITY.md](docs/SECURITY.md).

## License

Proprietary and confidential. All rights reserved. See [LICENSE](LICENSE).
