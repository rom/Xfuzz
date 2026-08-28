# Xfuzz — Design

> **Status:** Design baseline for v0.1. Every decision here is recorded as an
> [ADR](adr/README.md) and traces to an [ASR](asr/README.md).

## 1. What Xfuzz is

Xfuzz is a **universal fuzzing platform**: one engine, one corpus model, and one
triage pipeline that spans file formats, command-line tools, network protocols,
APIs, GUI applications, and TUI applications — stateless or stateful, black-box,
grey-box, or white-box, driven from a CLI or a web console.

## 2. The problem

Fuzzing works. Fuzzing *tooling* is fragmented into incompatible islands:

| Target | Conventional tool | Corpus format | State model | Interface |
| --- | --- | --- | --- | --- |
| File parsers | AFL++, libFuzzer, honggfuzz | Directory of blobs | none | CLI |
| Network protocols | boofuzz, AFLNet | Bespoke | ad-hoc | CLI/Python |
| REST APIs | RESTler, Schemathesis | Spec-derived | ad-hoc | CLI |
| GUI/TUI | (largely nothing) | — | — | — |

An operator working across these learns four tools, maintains four corpora,
triages crashes four different ways, and cannot transfer a single insight between
them. The techniques do not actually differ that much — what differs is **how an
input is delivered and how a response is observed**. Everything downstream of
that — scheduling seeds, mutating inputs, deciding what is interesting,
deduplicating crashes, minimising reproducers — is the same problem wearing
different clothes.

Xfuzz's thesis: **factor the delivery and observation out, and one engine serves
all of them.**

### 2.1 The four failure modes Xfuzz targets

1. **Wasted throughput on invalid inputs.** Byte-mutating a structured format
   means most executions die in a length check or a CRC. Addressed by the
   structured IR with automatic fixups (§4.1).
2. **Blind stateful fuzzing.** Code coverage cannot tell you which protocol
   states you have never reached. Addressed by state as a feedback signal (§4.3).
3. **Crash triage as the real bottleneck.** Thousands of crashing inputs, a
   handful of bugs, and manual sorting in between. Addressed by the triage
   pipeline (§4.5).
4. **Silent ineffectiveness.** A campaign that runs for a week and finds nothing
   looks identical to one running against hardened code. Addressed by
   observability, health diagnostics, and stability measurement (§4.6).

## 3. Design principles

1. **One spine, many adapters.** The engine core knows nothing about files,
   sockets, or windows. Domains differ only in `Executor` and `Observer`.
2. **Structure is the default; bytes are the degenerate case.** An unstructured
   blob is a one-node tree, not a separate code path.
3. **Everything that guides is composable.** Coverage, direction, state, custom
   oracles, and solver assistance all combine under one algebra rather than
   living in separate modes.
4. **Degrade, never fail.** Losing coverage, a solver, or a plugin reduces
   effectiveness; it never breaks a campaign. Black-box is a supported mode, not
   an error state.
5. **Reproducible by construction.** Every execution derives from an explicit RNG
   stream; every finding replays from stored artifacts on another machine.
6. **Safe by default.** Targets are sandboxed and traffic is scope-guarded
   without the operator opting in.
7. **The file is the truth.** A campaign is a declarative artifact. CLI and
   console are two views of it and hold no hidden state.
8. **Measured, not assumed.** Throughput, stability, per-mutator yield, and
   engine overhead are metrics with regression gates.

## 4. Core model

### 4.1 Inputs are typed trees — ADR-0005

Everything Xfuzz mutates is one representation:

```
Session                        (Repeat)
├── Message[0]                 (Struct)
│   ├── magic     : Bytes      "\x89PNG"
│   ├── length    : Derived    LengthOf(payload)
│   ├── type      : Choice     {IHDR, IDAT, IEND, ...}
│   ├── payload   : Bytes
│   └── crc       : Derived    ChecksumOver(crc32, type..payload)
└── Message[1]  ...
```

Two properties make this work in practice:

**Derived fields and the fixup pass.** After any mutation, derived nodes —
lengths, counts, offsets, checksums — are recomputed in dependency order. This is
what lets structural mutation produce inputs that survive validation. Each fixup
is **individually suppressible** with a configurable violation probability,
because a fuzzer that always writes correct checksums can never test checksum
validation.

**Partial parsing.** Codecs lift real corpus files into the IR best-effort;
anything unrecognised degrades to an opaque `Bytes` node. Real corpora are full
of malformed files, and a strict parser would reject exactly the seeds worth
having.

The consequence that matters most: **a stateless input is a session of length
one**, so statelessness and statefulness are one representation, and sequence
mutation (insert, delete, reorder, duplicate, splice) is ordinary mutation.

### 4.2 Guidance is composable — ADR-0007

```
Input ─► Executor ─► [Observers] ─► [Feedbacks] ─► admit to Corpus?
                          │
                          └───────► [Objectives] ─► record as Finding?
                                          │
                      Scheduler ◄─── score vector
```

- **Observer** records raw signal; it does not judge.
- **Feedback** answers *"worth keeping?"* and owns the novelty state.
- **Objective** answers *"is this a finding?"* — separate, because a crash is a
  finding and usually a poor seed, while a novel edge is a great seed and not a
  finding.
- **Scheduler** consumes a score *vector* (novelty, distance, rarity, custom).

The four requested strategies are configurations, not modes:

| Strategy | Composition |
| --- | --- |
| Coverage-guided | `MapFeedback(edges)` |
| Directed | `Any(MapFeedback, DistanceFeedback(targets))` + distance-weighted schedule |
| Feedback-driven | `Any(MapFeedback, CustomFeedback(script or plugin))` |
| Hybrid | any of the above + `CmpLogStage` + optional `ConcolicStage` |

They combine freely — "cover broadly, weight toward this patch, and treat any 500
as interesting" is one campaign, not three.

### 4.3 State is a first-class signal — ADR-0006

For stateful targets, Xfuzz maintains a state machine — declared in the campaign
file or inferred by clustering observed responses — and treats **new states and
new transitions as interesting** alongside code coverage. The scheduler picks a
target state first, then picks which message in the session to mutate.

This works black-box, since state inference needs only responses. The same
machinery serves GUI/TUI, where a "state" is a screen (ADR-0013).

### 4.4 Execution is tiered — ADR-0009

One `Executor` interface, eight tiers from an in-process Go harness at 10⁶/s to a
GUI driver at 10⁻¹/s. The tier is probed and reported; the operator can pin one
or require a minimum. Reset semantics (`none`/`reconnect`/`restart`/`snapshot`)
are an explicit contract, because correctness depends on which holds.

### 4.5 Findings, not crash files — ADR-0008, ASR-0011

Raw crashes are not the product. The triage pipeline runs asynchronously,
off the fuzz loop:

```
crash ─► classify ─► bucket ─► minimise ─► re-run for reproducibility rate ─► Finding
```

Bucketing is **multi-signal and versioned**, not a single stack hash — hashing
the top frame merges distinct bugs, hashing the full stack splits one bug into
hundreds. Re-bucketing an existing finding set with a new strategy is a supported
operation that preserves triage state.

### 4.6 Campaigns are observable and resumable — ASR-0012

Live metrics (exec/s, coverage, stability, engine overhead, per-mutator yield,
per-state progress), historical series for plateau detection, atomic
checkpointing for restart survival, and **named health diagnostics** for the
classic silent failures: "stability is 40 %", "0 % of inputs reach the harness",
"coverage map is empty".

## 5. Capability matrix

| Axis | Coverage |
| --- | --- |
| **Domains** | files, CLI tools, network protocols, APIs, GUI, TUI |
| **State** | stateless, stateful (declared or inferred model) |
| **Visibility** | black-box, grey-box, white-box |
| **Guidance** | coverage-guided, directed, feedback-driven, hybrid — combinable |
| **Input generation** | corpus mutation, grammar generation, or both interleaved |
| **Instrumentation** | sancov, Go native, fork server, Frida, QEMU, Intel PT, ptrace, runtime agents, black-box |
| **Interfaces** | CLI, web console, gRPC/REST API |
| **Platforms** | Linux (full), macOS, Windows |
| **Extensibility** | native Go, out-of-process plugins, Starlark scripting |

## 6. What a campaign looks like

A campaign is a declarative file (ADR-0016). This is the *entire* interface — the
console is a visual editor over it, and the CLI runs it.

```yaml
version: 1
name: libpng-decode

target:
  kind: file                    # file | cli | net | api | gui | tui
  binary: ./build/png_harness
  input: stdin
  instrumentation: auto         # probed; reports what it selected

input:
  schema: schemas/png.xfg       # structured IR schema
  seeds: corpora/png/           # AFL/libFuzzer directories import directly
  dictionary: dicts/png.dict
  fixups:
    checksum: 0.95              # 5% of inputs deliberately break the CRC
    length:   0.99

guidance:
  feedback:
    - map: {granularity: edge, buckets: afl}
    - timing: {outlier_sigma: 4}
  objectives:
    - crash
    - sanitizer
    - hang: {timeout: 5s}
  schedule: {power: fast, exploit_ratio: 0.2}

mutators:
  - havoc:  {weight: 60}
  - splice: {weight: 20}
  - structured: {weight: 20}    # tree-aware, fixup-preserving

safety:
  isolation: strong             # refuses to start if unavailable
  limits: {memory: 2GiB, cpu: 1, pids: 8, wallclock: 10s}

run:
  workers: auto
  until: {coverage_plateau: 30m, or_time: 24h}
```

A stateful protocol campaign differs only in `target.kind`, an added `state:`
block, and session-level mutators — the same engine, the same corpus, the same
triage.

## 7. Interfaces

**CLI** — runs, inspects, and validates campaign files:

```
xfuzz init <target>          scaffold a campaign file
xfuzz validate <file>        schema + semantic validation
xfuzz explain <file>         fully resolved effective config, defaults included
xfuzz run <file>             launch (auto-starts a private daemon if needed)
xfuzz stat <campaign>        live metrics
xfuzz findings <campaign>    list, filter, export
xfuzz replay <finding>       deterministic re-execution
xfuzz minimize <finding>     re-run minimisation
xfuzz corpus import|export   AFL/libFuzzer interop
xfuzz doctor                 platform capabilities and why anything is missing
```

**Web console** — campaigns, live metrics, coverage visualisation, state-machine
view, findings triage, corpus browser (IR tree and hex), config editor, grammar
workbench, safety and audit. Embedded in the binary; no CDN, no external assets.

**API** — gRPC with a REST/JSON gateway; the single source of truth both clients
speak to (ADR-0003).

## 8. Non-goals

Explicitly **not** in scope, so the boundaries are honest:

- **Not a distributed fuzzing platform in v1** (ADR-0015). Single-host,
  multi-core. The daemon boundary is where a coordinator would attach in v2.
- **Not a static analyser.** White-box artifacts (CFG, distances) exist to *guide
  fuzzing*, not to report findings on their own.
- **Not an exploitation framework.** Xfuzz finds and triages crashes; it does not
  weaponise them.
- **Not a drop-in AFL++ replacement.** It interoperates with AFL corpora,
  dictionaries, harnesses, and the fork-server protocol (ADR-0001), but it is a
  different engine with different trade-offs, and at v0.1 it will not match
  AFL++'s tuning on pure file fuzzing.
- **Not an unattended scanner.** Scope guard and authorization records exist
  precisely because pointing it at arbitrary infrastructure is not a supported
  workflow (ADR-0012).

## 9. Key risks

| Risk | Mitigation |
| --- | --- |
| Structured IR too slow for the hot loop | Pooled/arena nodes, copy-on-write subtrees, benchmark gates from day one (ADR-0021) |
| Go GC pressure caps throughput | Allocation-free steady state, process-per-worker, measured engine overhead as a first-class metric |
| Breadth dilutes depth | Thin-slice MVP (ADR-0020); interfaces designed for deferred work, implementations phased |
| State inference too coarse or too fine | Tunable clustering, inspectable state graph, declared-model override |
| Sandbox cost taxes throughput | Per-worker, not per-execution, setup; measured and reported |
| Building a fuzzer that silently finds nothing | Planted-bug targets as a primary CI assertion (ADR-0021) |

## 10. Where to go next

- [ARCHITECTURE.md](ARCHITECTURE.md) — components, packages, data flow, interfaces
- [MVP_PLAN.md](MVP_PLAN.md) — phased implementation plan
- [SECURITY.md](SECURITY.md) — threat model and controls
- [TESTS.md](TESTS.md) — test strategy
- [adr/](adr/README.md) — every decision, with alternatives and consequences
- [asr/](asr/README.md) — the requirements that constrain the architecture
