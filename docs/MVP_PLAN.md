# Xfuzz — MVP Implementation Plan

> Implements [ADR-0020](adr/ADR-0020-mvp-as-end-to-end-thin-slice.md): v0.1 is a
> **thin slice through every layer, with nothing faked**.

## 1. The shape of v0.1

Narrow in *breadth*, complete in *depth*. Every architectural layer is really
implemented, but only along one path per layer.

The governing rule: **no layer may be stubbed.** A thin slice with a mocked store
or a fake feedback pipeline proves nothing, because integration risk is precisely
what the slice exists to retire. If a milestone cannot be completed honestly, it
is descoped — never faked.

### 1.1 In and out of v0.1

| Layer | v0.1 | Deferred |
| --- | --- | --- |
| Domains | File formats, CLI tools, one network protocol | APIs, GUI, TUI |
| Executors | T0, T2, T3, T4, T6 | T1, T5, T7 |
| Instrumentation | `sancov`, `gocov`, `forkserver`, `blackbox` | `frida`, `qemu`, `intelpt`, `ptrace-bb`, `agent` |
| IR | Full node set, fixups, byte + structured mutators | — |
| Grammar | Native `.xfg` DSL, one worked format | protobuf, ASN.1, ABNF, Kaitai, OpenAPI importers |
| Feedback | Map coverage, state, response, timing; full algebra | Distance (directed), value profile, concolic |
| State | Declared + inferred model, state feedback and scheduling | Automata learning |
| Corpus | SQL + blob store, AFL import/export, minimisation, bucketing | Advanced re-bucketing |
| Safety | Linux sandbox (`strong`), scope guard, audit log | macOS/Windows beyond `minimal` |
| Parallelism | N worker processes, corpus sync, ensembles | Distributed |
| Interfaces | Daemon, CLI, console (all v1 views) | Fleet view, RBAC |
| Extensions | Native complete; plugin + Starlark for feedback/oracles | Full plugin coverage |
| Platforms | Linux full; macOS/Windows via T3/T4 + `blackbox`/`gocov` | Platform fast paths |

### 1.2 The v0.1 proof obligation

Two campaigns, both launched from a file, monitored in the console, and triaged
to a minimised reproducible finding:

1. **Stateless.** A coverage-guided file-format campaign against a
   checksum-protected format, sustaining ≥ 5,000 exec/s on a fork-server target,
   with a demonstrably higher valid-input rate than byte-level mutation of the
   same corpus.
2. **Stateful.** A protocol campaign that discovers a bug reachable **only** after
   a valid multi-step handshake, reporting state coverage separately from code
   coverage.

If both hold, the architecture is validated and every later phase is an addition
along a proven dimension.

## 2. Milestones

Estimates are engineering-effort ranges for a small focused team, not calendar
commitments.

### M0 — Foundation *(1–2 weeks)*

Repository, toolchain, and the discipline that makes everything after it
measurable.

- Module layout per ARCHITECTURE.md § 2; `pkg/` ↛ `internal/` enforced by lint.
- CI: build, vet, `-race` test, cross-compile matrix, `govulncheck`, licence scan
  against ADR-0018's policy, docs traceability lint.
- Benchmark harness skeleton with baseline recording — **before** any hot-path
  code exists, so regressions are visible from the first commit.
- `Makefile` targets from TESTS.md § 13.

**Exit:** CI green on Linux, macOS, Windows; an empty benchmark records a
baseline; licence and docs lints pass.

---

### M1 — Input IR and codecs *(3–4 weeks)* — the highest-risk milestone

The foundation everything else stands on, and the one place where a wrong
decision is expensive to unwind.

- `pkg/ir`: full node set, arena allocation, copy-on-write subtrees, traversal.
- Derived fields and the fixup pass: dependency ordering, cycle handling,
  idempotence, per-constraint suppression.
- `pkg/codec`: byte-blob codec plus one real structured format (**PNG** — chunked,
  length-prefixed, CRC-protected: it exercises every derivation kind).
- Best-effort partial parsing degrading unparsed regions to `Bytes`.
- Property tests per TESTS.md § 3, including the zero-allocation assertion.

**Exit:** Round-trip is byte-exact across a real PNG corpus; fixups are idempotent
and order-independent; steady-state mutation allocates zero; a malformed corpus
imports without error.

**Risk:** if the IR cannot be made allocation-free at target rates, the design
premise is wrong. This is deliberately confronted first, while it is cheap.

---

### M2 — Mutation and generation *(2–3 weeks)*

- `pkg/mutate`: byte-level operators (bitflip, arithmetic, interesting values,
  block ops), structured operators (type-aware, `Choice` switching, `Repeat`
  insert/delete/reorder/duplicate), splice/crossover across corpus entries.
- Mutator scheduling with weights and per-operator yield accounting.
- `pkg/schema`: the `.xfg` grammar DSL — parser, validator, and generation.
- `pkg/generate`: grammar-driven generation, interleavable with mutation.
- Dictionary support with AFL `.dict` import.

**Exit:** Structured mutation of the PNG corpus produces a materially higher valid
rate than byte-level mutation of the same corpus, measured and recorded;
generation from `.xfg` produces valid inputs; per-mutator yield is reported.

---

### M3 — Execution and feedback *(4–5 weeks)*

The engine becomes a fuzzer.

- `pkg/executor`: T4 (subprocess), T3 (process pool), T2 (fork server, AFL-
  protocol compatible), T0 (in-process Go).
- `xfuzz-cc` + `xfuzz-rt`: compiler wrapper and coverage runtime (ADR-0001).
- Instrumentation backends: `sancov`, `gocov`, `forkserver`, `blackbox`.
- Capability probing, reporting, override, and minimum-tier enforcement.
- `pkg/feedback`: Observer/Feedback/Objective with the full boolean algebra;
  map coverage with hitcount bucketing, timing, response novelty.
- Objectives: crash, sanitizer output parsing, hang.
- `pkg/corpus`: testcase, provenance, corpus, power schedules.
- `internal/engine`: the fuzz loop, stages, per-worker deterministic RNG streams.

**Exit:** A single-worker coverage-guided campaign finds all `simple_parser` and
`magic_parser` planted bugs within budget; T2 sustains ≥ 5,000 exec/s; engine
overhead < 10 %; two runs with the same seed produce identical traces.

---

### M4 — Storage, triage, and safety *(3–4 weeks)*

Turns crashes into findings and makes the tool safe to run.

- `internal/store`: SQL metadata (`modernc.org/sqlite`), content-addressed blob
  store, schema versioning and migrations, disk budgets with culling, atomic
  checkpointing, blob GC.
- AFL/libFuzzer corpus import and export.
- `internal/triage`: classification, multi-signal bucketing, input and session
  minimisation, reproducibility verification — all asynchronous, off the hot path.
- `internal/safety`: Linux sandbox (namespaces, seccomp, cgroups v2), scope guard
  with layered enforcement, authorization records, hash-chained audit log.
- Security tests per TESTS.md § 12.

**Exit:** `chunked_format` planted bugs produce approximately the correct bucket
count; minimisation reduces reproducers ≥ 80 % preserving the bucket; every
sandbox escape and scope-guard bypass test fails to escape; a campaign killed and
resumed loses at most the checkpoint window.

---

### M5 — Daemon, API, and CLI *(3–4 weeks)*

- `pkg/campaign`: YAML schema, JSON Schema publication, resolution, validation,
  includes and profiles, termination conditions.
- `internal/api`: gRPC services and REST gateway per ARCHITECTURE.md § 9.
- `internal/daemon`: campaign manager, worker supervision, event bus with
  downsampling, corpus sync between workers, ensemble strategies.
- `cmd/xfuzz`: the full command set, with daemon auto-start.
- `internal/metrics`: counters, historical series, named health diagnostics.

**Exit:** Multi-worker campaigns scale ≥ 0.85 × N; `xfuzz explain` renders the
fully resolved config; killing the daemon mid-campaign resumes cleanly; CLI/API
parity test passes.

---

### M6 — Stateful protocol fuzzing *(3–4 weeks)*

The second half of the proof obligation.

- `pkg/state`: state model, `StateFn`, response clustering for inference,
  state and transition feedback, state-then-message scheduling.
- T6 session executor: connection lifecycle, reset policies, sync and timeouts.
- Session-level mutators (already IR `Repeat` operators from M2 — this milestone
  wires and tunes them).
- One real protocol end to end.

**Exit:** `stateful_proto` planted bugs are found, including the one reachable
only after a valid handshake; state coverage is reported separately; a stateful
finding replays as a full session on another host.

---

### M7 — Web console *(4–5 weeks)*

- TypeScript SPA, Vite build, `embed.FS` embedding, no external assets.
- All v1 views (ARCHITECTURE.md § 9, ADR-0011): campaigns, campaign detail,
  coverage, state machine, findings triage, corpus browser, config editor,
  grammar workbench, safety and audit.
- WebSocket live updates with server-side downsampling and batching.
- Comment-preserving campaign-file round-trip.

**Exit:** A campaign is configurable, launchable, monitorable, and triageable
entirely from the console; the console operates against a 100k exec/s campaign
without unbounded memory growth in browser or daemon; edited configs round-trip
with comments intact.

---

### M8 — Extensions and hardening *(2–3 weeks)*

- `pkg/plugin`: out-of-process protocol (feedbacks, mutators, objectives) with
  batching, versioning, and contained failure.
- Starlark host: hermetic, step- and allocation-bounded, for oracles and
  campaign-local logic.
- Fault-injection suite (TESTS.md § 9).
- Self-fuzzing entry points for every untrusted parser, wired into CI.
- macOS and Windows verification of the T3/T4 + `blackbox`/`gocov` path.
- Documentation: user guide, grammar authoring guide, `xfuzz doctor` coverage.

**Exit:** Both v0.1 proof-obligation campaigns pass on Linux; macOS and Windows
run a subprocess campaign end to end; all fault-injection tests pass; self-fuzzing
runs clean in CI.

---

## 3. Sequencing and dependencies

```
M0 Foundation
     │
     ▼
M1 IR + codecs ──────────────┐   ← highest risk, confronted first
     │                       │
     ▼                       ▼
M2 Mutation + grammar    M3 Execution + feedback
     │                       │
     └──────────┬────────────┘
                ▼
        M4 Store + triage + safety
                │
                ▼
        M5 Daemon + API + CLI
                │
        ┌───────┴────────┐
        ▼                ▼
M6 Stateful         M7 Web console        ← parallelisable
        └───────┬────────┘
                ▼
        M8 Extensions + hardening
                │
                ▼
             v0.1
```

M2 and M3 can overlap once M1's interfaces are fixed. M6 and M7 are independent
of each other and both depend only on M5. Total sequential effort: roughly
25–34 weeks of focused work; less with parallelism across M2/M3 and M6/M7.

## 4. Risk register

| Risk | Milestone | Impact | Mitigation |
| --- | --- | --- | --- |
| IR too slow / allocation-heavy for the hot loop | M1 | Design premise fails | Confronted first; arena + CoW; allocation assertions and benchmark gates from M0 |
| Fork server correctness across libc and platform variants | M3 | Fast tier unusable | AFL-protocol compatibility gives a reference; T3/T4 always available as fallback |
| Feedback dispatch overhead at 100k exec/s | M3 | Throughput target missed | Static concrete slice, no boxing; overhead measured as a first-class metric |
| SQLite write contention with N workers | M4/M5 | Store becomes a bottleneck | Writes funnel through daemon, WAL, batching; store is off the hot path by design |
| Sandbox setup cost per execution | M4 | Throughput tax | Per-worker/pooled-process setup, never per execution; measured |
| State inference too coarse or too fine | M6 | Stateful fuzzing ineffective | Tunable clustering, inspectable state graph, declared-model override |
| Console scope expands without bound | M7 | Schedule slip | v1 view list is fixed in ADR-0011; fleet view and RBAC explicitly deferred |
| Planted-bug over-fitting | M3–M6 | False confidence | Graded difficulty, target rotation, external corpora cross-check |
| Benchmark gate flakiness on shared CI | M0 onward | Gates get ignored | Dedicated runners, repeated sampling with statistical comparison |

## 5. After v0.1

Sequenced by dependency and by how much each de-risks the remaining vision:

| Version | Theme | Contents |
| --- | --- | --- |
| **v0.2** | Binary-only targets | T5 emulated executor; `frida`, `qemu`, `ptrace-bb` backends; stripped-binary workflow |
| **v0.3** | Directed + hybrid | Distance feedback and CFG analysis; `CmpLogStage`; value profile; concolic boundary |
| **v0.4** | APIs | Traffic capture (HAR, pcap, recording proxy); data-dependency inference; authorization oracles (ADR-0014) |
| **v0.5** | TUI and GUI | T7 driver executor; PTY + terminal emulator; UI-state feedback; accessibility drivers (ADR-0013) |
| **v0.6** | Grammar ecosystem | protobuf, ASN.1, ABNF, Kaitai, JSON Schema, OpenAPI importers |
| **v0.7** | Platform parity | macOS and Windows fast paths and isolation above `minimal` |
| **v1.0** | Scale | Distributed fuzzing: coordinator, corpus sync protocol, fleet view (needs its own ADR) |

## 6. Definition of done for v0.1

1. Both proof-obligation campaigns (§ 1.2) pass on Linux.
2. All planted-bug targets in scope are found within their budgets, with correct
   bucket counts.
3. Benchmark gates met on every implemented executor tier.
4. Determinism and cross-host replay hold.
5. All security tests pass; no sandbox or scope-guard escape.
6. Fault-injection suite passes; resume after daemon kill is clean.
7. CI green on Linux, macOS, and Windows, with and without cgo.
8. Self-fuzzing runs clean on every untrusted parser.
9. Docs current: ADRs match the implementation, traceability lint passes,
   `CHANGELOG.md` complete.
10. A new user can install one binary, run `xfuzz init`, and reach a first finding
    without reading source.
