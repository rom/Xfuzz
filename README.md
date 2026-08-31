# Xfuzz

**A universal fuzzing platform.** One engine, one corpus model, and one triage
pipeline spanning file formats, command-line tools, network protocols, APIs, GUI
applications, and TUI applications — stateless or stateful, black-box, grey-box,
or white-box, driven from a CLI or a web console.

> **Status: closing out v0.1.** All eight milestones are done and the ten
> clauses of the definition of done are being worked one at a time, with what
> was run recorded against each
> ([MVP_PLAN § 6.1](docs/MVP_PLAN.md)). A campaign can be extended without
> touching Xfuzz — an out-of-process plugin in any language, or four lines of
> hermetic Starlark beside the campaign file. Nine injected faults each have a
> defined behaviour and a test that injects them for real. Every untrusted
> parser fuzzes itself in CI. macOS and Windows run a real subprocess campaign
> rather than being assumed to. A campaign is repeatable: pin `seed:` and two
> runs find the same corpus by the same derivation, and a finding's store
> carries to another machine and still replays.
>
> Auditing the decision records against the code is what has found most of what
> was wrong, rather than the tests: a grammar that had never reached the
> mutation loop (fixed, and the same comparison went from a tie to a corpus
> twice as valid as byte-level mutation's); a whole executor tier listed in
> scope and never built; a campaign seed that could be reported but not pinned;
> a security suite written in M4 that no CI job had ever run; and a documented
> Go build incantation that does not link. See [docs/GUIDE.md](docs/GUIDE.md)
> to use it and [docs/MVP_PLAN.md](docs/MVP_PLAN.md) for what remains.

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
- **A screen is a state.** A terminal program is driven on a real pseudo-terminal
  with an emulator watching what it draws, and a novel screen — or a novel move
  between two screens — is new coverage. It is the same state machine a protocol
  campaign builds, with a state function that reads a screen.
- **Captured traffic, not a specification.** An API campaign starts from a
  recording: it carries the requests a client actually sends, the values that
  chain between them, and the identity they were sent as. A specification has
  none of those, which is why replaying one identity's session as another is a
  class of finding only a capture makes reachable.
- **Grammars you did not have to write.** ABNF from an RFC, a Kaitai definition
  from a hex editor, a `.proto`, an OpenAPI document, a JSON Schema, an ASN.1
  module — imported to a grammar, with a report of everything the import could
  not translate.
- **State as a signal.** For stateful targets, new protocol states and transitions
  are as interesting as new code edges — and the state model can be inferred from
  responses, so it works black-box. Protocol coverage is reported beside code
  coverage rather than folded into it: a campaign can hold code coverage flat
  while discovering a new state, and that is the case worth seeing.
- **Composable guidance.** Coverage-guided, directed, feedback-driven, and hybrid
  are not modes to pick between; they compose. "Cover broadly, weight toward this
  patch, and treat any 500 as interesting" is one campaign.
- **Binaries you cannot rebuild.** Coverage from a stripped executable with no
  source and nothing linked in, by watching it run — breakpoints, user-mode
  emulation, or dynamic instrumentation. It costs one to two orders of magnitude
  of throughput and it is reported honestly: how much of the program the analysis
  could see, and how much it could not.
- **Past the magic number.** The target's own comparison operands are read back
  and written into the input, so a four-byte constant is one edit rather than
  four billion guesses — and a comparison that nearly passed counts as progress,
  which is what gets a campaign through a checksum.
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

Requires Go 1.26 or later. No other toolchain is needed for the default build.

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

A stateful campaign differs by one block. Add a `session:` saying where the
target listens and Xfuzz fuzzes conversations instead of inputs — the corpus,
the mutators, the scheduler and the triage pipeline are the same machinery,
because statefulness is an axis rather than a second tool:

```yaml
session:
  address: unix:/tmp/target-{worker}.sock
  framing: line
state:
  fn: status          # a reply's leading status code is the protocol state
```

`xfuzz states` then shows the state machine the campaign has explored, with the
response that produced each label — because a state label is a hash, and a hash
explains nothing.

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
