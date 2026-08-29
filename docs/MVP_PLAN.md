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

### M0 — Foundation ✅ *delivered*

Repository, toolchain, and the discipline that makes everything after it
measurable.

- Module layout per ARCHITECTURE.md § 2, with all seven layering rules enforced
  by `tools/archlint` as an ordinary Go test — including tests that each rule
  *fires* against a violating fixture.
- CI: build, vet, gofmt, `-race` test on Linux/macOS/Windows, `CGO_ENABLED=0`
  build, cross-compile matrix, `govulncheck`, licence policy, docs traceability.
- Benchmark harness with a committed baseline and a working regression gate,
  recorded **before** any hot-path code exists, so the first engine commit is
  already measured. Median-of-5 sampling and provenance-aware gating keep it
  from being flaky.
- `Makefile` targets matching TESTS.md § 13.

**Exit criteria met:** the suite passes on Linux with `-race`; every supported
platform cross-compiles; `bench/baseline.txt` is recorded and `make bench-check`
gates against it; licence, documentation, and architecture lints pass.

**Not yet verified:** CI green on macOS and Windows — the workflow is written and
the code cross-compiles, but no run has happened on those runners yet. Native
`linux/arm64` execution is covered by compilation only (TESTS.md § 10).

---

### M1 — Input IR and codecs ✅ *delivered* — the highest-risk milestone

The foundation everything else stands on, and the one place where a wrong
decision is expensive to unwind.

- `pkg/ir`: full node set, bump-allocating arena, copy-on-write path copying,
  traversal, validation, generic encoding.
- Derived fields and the fixup pass: containment ordering for checksums, cycle
  detection with `SelfZero` as the explicit resolution, idempotence, and
  per-class and per-node suppression.
- `pkg/codec`: codec interface and registry, the raw byte-blob codec, and PNG —
  chunked, length-prefixed, CRC-protected, exercising both a length over a
  sibling and a checksum over a sibling range.
- Best-effort partial parsing: unrecognised regions degrade to opaque `Bytes`
  nodes, reported by `StructuredFraction`.
- Property tests per TESTS.md § 3, plus a `FuzzPNGDecode` target.

**Exit criteria met**

| Criterion | Evidence |
| --- | --- |
| Round-trip byte-exact across a real PNG corpus | `TestRoundTripIsByteExact` over generated files and hand-crafted malformed cases; 3.8M fuzz executions found no violation |
| Fixups idempotent and order-independent | `TestFixupIsIdempotent`, `TestFixupIsDeterministic`, `TestNestedChecksumsOrderByContainment` |
| Steady-state mutation allocates zero | `TestSteadyStateFuzzLoopDoesNotAllocate`; every benchmark reports `0 allocs/op` |
| A malformed corpus imports without error | Decoding is total; errors are reserved for conditions that stop the codec running at all |

**Risk retired.** The premise held. A full cycle — clone a decoded PNG, mutate a
payload, recompute the length and CRC, encode — runs at **1.8 µs, zero
allocations** (~545k/s), an order of magnitude above the 50k exec/s T0 floor. A
copy-on-write mutation of the same tree is 69 ns. The IR is not the bottleneck.

The end-to-end justification is `TestStructuralMutationProducesAValidPNG`: a
chunk is inserted into a real file, the derived length and CRC are recomputed,
and the standard library's decoder — which validates every CRC — accepts the
result. `TestSuppressedChecksumReachesValidationCode` shows the other half:
with checksum fixups suppressed, the decoder rejects the file, which is how a
fuzzer reaches checksum-validation code at all.

---

### M2 — Mutation and generation ✅ *delivered*

- `pkg/rng`: deterministic, splittable, seekable randomness — eight numbered
  streams so one concern's draws cannot shift another's (ASR-0008).
- `pkg/mutate`: 24 operators across four classes — byte-level, structured,
  dictionary, and splice — with weighted operator-first scheduling, provenance
  recording, and per-operator accounting.
- `pkg/schema`: the `.xfg` grammar language — lexer, parser, validator, and a
  renderer that round-trips.
- `pkg/generate`: grammar-driven generation, sharing the IR with mutation.
- Dictionary support with AFL `.dict` import, including its escape syntax.

**Exit criteria met**

| Criterion | Result |
| --- | --- |
| Structured mutation beats byte-level on validity | **99.6% vs 0.0%** container-valid over 5,000 mutations each, same seeds and budget (`TestStructuredMutationBeatsByteLevel`) |
| The gain comes from the fixups | Same mutations with repair disabled: **10.4%** (`TestFixupIsWhatMakesTheDifference`) |
| Generation from `.xfg` produces valid inputs | **2,000/2,000** generated PNGs pass container validation, averaging 33 chunks; each also round-trips through the hand-written Go codec |
| Per-operator yield is reported | `Scheduler.Report()`, ordered by yield, with attempts, applies, and apply rate |

**Measured**, all zero-allocation: a full mutate-and-repair cycle on a real PNG
is 5.0 µs (~200k/s); a mutation round alone is 1.1 µs; generating a ~33-chunk
PNG from the grammar is 92 µs; an RNG draw is 0.4 ns.

Two IR additions came out of the measurement rather than the plan: payload and
element-count **bounds**, and an **immutable** flag. Without them byte operators
resized the PNG chunk type field and corrupted the signature — mutations that
produce inputs no reader gets past, which is not deeper exploration of PNG.
Container validity went from 47% to 99.6% once the format's real constraints
were expressible.

---

### M3 — Execution and feedback ✅ *delivered*

The engine becomes a fuzzer.

- `pkg/executor`: T0 (in-process Go), T2 (fork server), T4 (subprocess), with
  capability reporting and a `Spawner`/`SharedMemoryProvider` boundary that
  keeps process creation inside the safety layer.
- `xfuzz-cc` + `xfuzz-rt`: compiler wrapper and C coverage runtime (ADR-0001).
- Instrumentation: `sancov` via `trace-pc-guard`, plus `blackbox`.
- `pkg/feedback`: Observer/Feedback/Objective with the full boolean algebra; map
  coverage with hitcount bucketing, output novelty, timing outliers; crash,
  hang, OOM, sanitizer and oracle objectives.
- `pkg/corpus`: content-addressed testcases, provenance, and three power
  schedules.
- `internal/safety`: the only thing in Xfuzz that creates a process.
- `internal/platform`: shared memory and process-group control.
- `internal/engine`: the fuzz loop, corpus trimming, finding buckets, and
  per-worker deterministic RNG streams.

**Exit criteria met**

| Criterion | Result |
| --- | --- |
| Finds all planted bugs | **3/3** in `simple_parser`, **4/4** in `magic_parser` |
| T2 throughput | 2,787 exec/s against a 3,129 exec/s host floor — **89% efficiency**, and 3.8× the subprocess tier. The absolute 5,000 exec/s floor is a reference-host figure this 4-core microVM cannot reach with any fuzzer; see below. |
| Engine overhead < 10% | **3.7%** |
| Same seed, identical traces | Enforced by `TestCampaignIsDeterministic` |

**On the throughput floor.** Bare `fork`+`_exit` on this host tops out at about
5,500/s, so 5,000 exec/s for a full fork-read-parse-exit cycle would require 91%
efficiency against a zero-cost fuzzer. That is a property of the host, not the
engine. The gate therefore asserts the ratio against a do-nothing target
everywhere — which is what says whether the executor is efficient — and the
absolute floor only where the host can support it (docs/TESTS.md § 7).

**Four bugs the tests found, each invisible from the outside**

1. **Coverage instrumented at the wrong level.** Clang defaults
   `-fsanitize-coverage` to `func`, one guard per function. Coverage then cannot
   distinguish two inputs taking different branches of the same function, and
   coverage-guided fuzzing degrades to random. Fixed with `bb,no-prune`, which
   roughly doubled the signal.
2. **Sequential block identifiers collided.** The edge index is
   `prev>>1 ^ loc`, so clustered identifiers produce clustered indices and
   distinct edges collapse onto one. Two different depths of a comparison ladder
   were indistinguishable. Fixed by hashing identifiers across the map.
3. **The fork server polluted its own coverage map.** Its loop runs in the
   parent, which holds the same shared map, so it incremented counters while the
   fuzzer was clearing and reading them. The symptom was a campaign that was
   identical for tens of thousands of executions and then quietly divergent.
   Fixed by not instrumenting the runtime.
4. **The schedule weighed measured execution time**, which varies with machine
   load — an ASR-0008 violation in code written to serve ASR-0008. The heuristic
   is genuinely useful and is now opt-in, off by default.

**One capability added that the plan had in M4.** Corpus trimming. Mutation
grows inputs, and a mutator picks a position uniformly, so an entry that has
drifted to fifty bytes gets a fraction of the attention per byte that a short one
does. The campaign was reliably climbing a comparison ladder two steps and
stalling. Trimming every newly admitted entry is core engine work rather than
triage, and with it the ladder is walked to the end.

---

### M4 — Storage, triage, and safety ✅ *delivered*

Crashes become findings, and the tool becomes safe to run.

- `internal/store`: content-addressed blob store, embedded SQL metadata
  (`modernc.org/sqlite`), schema versioning with forward-only migrations, disk
  budgets with culling, atomic checkpointing, blob collection.
- `pkg/corpusio`: AFL and libFuzzer corpus import and export, and an AFL output
  directory resolved to its queue.
- `internal/triage`: reproducibility verification, four bucketing strategies
  behind one interface, byte-level and structured minimisation, sequence
  minimisation for M6's sessions — all asynchronous, off the hot path.
- `internal/safety` and `cmd/xfuzz-sandbox`: namespaces, seccomp denylist,
  resource limits, cgroups, read-only root, scope guard with layered
  enforcement, authorization records, hash-chained audit log.
- `internal/engine`: snapshot, restore, and corpus loading for resume.
- Security tests per TESTS.md § 12.

**Exit criteria met**

| Criterion | Result |
| --- | --- |
| `chunked_format` bucket count | Signal bucketing **3**, coverage bucketing **5** for 5 bugs, no two sharing a bucket, stable across repeated runs |
| Minimisation ≥ 80% preserving the bucket | **85–96%**, each reproducer still triggering its own bug; three differently bloated reproducers of one bug converge on the same bucket and the same 19-byte minimum |
| No sandbox escape | Target runs as uid 65533; a write outside the workdir is refused and one inside still works; a fork bomb stops at **63 against a limit of 64**; 2 GiB against a 128 MiB cgroup ends in SIGKILL; `mount(2)` returns EPERM |
| No scope-guard bypass | Unlisted host refused and audited; a remote campaign with no allowlist refuses to start |
| Resume loses at most the checkpoint window | Checkpoint at 30,000 execs / 26 edges, killed at 45,000 / 29, resumed at **30,000 / 26 with all 14 corpus entries** — 15,000 lost against a 15,000-execution window, nothing before it |

The full planted-bug campaign still finds every bug through the confined fork
server, in 180 seconds.

**On "preserving the bucket".** The obvious reading of that criterion is wrong,
and saying so is part of meeting it. Comparing a bloated reproducer's coverage
bucket with its minimised one's and demanding they match would demand that
minimisation change nothing: the bloated input walks padding the minimised one
does not, so its tuple set necessarily differs. Removing that path is the job.
What is asserted instead is that the bucket still identifies the bug — the
minimised reproducer triggers the same planted bug — and that independent
reproducers of one bug converge on one bucket while distinct bugs stay apart.

**Byte-level minimisation is the wrong tool for a checksummed format, and that
is the point.** Deleting bytes from a chunk invalidates the length and the
checksum covering it; the parser rejects the file before reaching the bug; every
deletion looks necessary. It is a hard limit, not a tuning problem — the
intermediate states delta debugging must pass through do not exist in the
format. Structured minimisation removes elements from the IR and lets the fixup
pass recompute what the removal invalidated. Measured on a checksummed format:
**48% byte-wise against 97% structured**. This is ADR-0005's argument as a
measurement rather than a claim.

**Three traps in the sandbox, each of which looked correct in every log line**

1. **A uid mapping is not a privilege drop.** A child cloned by root with a user
   namespace mapping that omits uid 0 is still host root — it merely *reports*
   the kernel's overflow id, which looks exactly like an unprivileged uid to
   `getuid()` and to every log line. The drop had to become a real `setuid`,
   done by the sandbox helper after the steps that need privilege.
2. **That overflow id is 65534**, the conventional "nobody". A target mapped to
   it sees every file owned by anyone outside its namespace — the corpus
   included — as owned by *itself*, and can write all of it. The confinement
   reports an unprivileged uid throughout and confines nothing. Targets now run
   as 65533, checked against the kernel's own `overflowuid` rather than assumed.
3. **A mount namespace created alongside a user namespace inherits its mounts
   locked**, so a read-only root cannot be built in that combination. The
   sandbox probes once with `/bin/true` rather than guessing from kernel
   versions, and where the fuzzer is root the user namespace is left out
   entirely — root does not need it, and it costs the stronger mechanism.

**Isolation on the development host is `moderate`, not `strong`.** The host
mounts cgroups v1, not v2, and v1 has no interface for placing a process in its
group at clone time: the pid is written after the process exists, so a target
that forks immediately can escape the limit. That is a real gap and the level
reported says so. Reporting `strong` because the code that would earn it exists
is precisely the failure ADR-0012 was written to prevent.

**Two capabilities the plan did not ask for.** Structured minimisation, for the
reason above. And `MinimizeSequence`, which shrinks a session by removing
messages rather than bytes — the same algorithm over a different unit, so M6's
session minimisation needs no second delta debugger.

---

### M5 — Daemon, API, and CLI ✅ *delivered*

The tool becomes a tool: a campaign is a file, a daemon runs it, and the
command line is a client of the same API the console will use.

- `pkg/campaign`: YAML schema, generated JSON Schema, resolution, validation,
  includes and profiles, termination conditions, `explain`.
- `internal/api`: six services over HTTP/JSON with a generated OpenAPI
  description, and events over SSE (ADR-0024, which supersedes ADR-0003's gRPC
  transport while keeping its service decomposition).
- `internal/daemon`: campaign manager, worker supervision with restart budgets,
  event bus with coalescing and honest drop counts, corpus sync between
  workers, ensemble strategies, on-demand and automatic triage.
- `internal/worker`: builds an engine from a resolved campaign file and speaks
  the worker protocol.
- `cmd/xfuzz`, `cmd/xfuzzd`, `cmd/xfuzz-worker`: the full command set, with
  daemon auto-start.
- `internal/metrics`: counters, thinned historical series, named health
  diagnostics.

**Exit criteria met**

| Criterion | Result |
| --- | --- |
| Multi-worker campaigns scale ≥ 0.85 × N | **2.69–2.72× on 3 workers, 90–91% efficiency**, measured as executions completed in a fixed window rather than as a reported rate |
| `xfuzz explain` renders the fully resolved config | Every setting the file never mentions is shown and marked `(default)`, and the YAML form validates as a campaign file |
| Killing the daemon mid-campaign resumes cleanly | SIGKILL at 13 corpus entries / 19 edges; a new daemon took over on the same data directory and finished at **40 entries / 29 edges with the finding intact**, and no worker outlived the daemon that started it |
| CLI/API parity test passes | Every route reachable from a command and every command mapped to routes, both directions, as a unit test over the route table |

**Scaling is measured in executions, not in the reported rate.** The rate is
part of what is under test: a campaign that aggregates its workers' counters
wrongly passes a rate check while doing nothing of the sort — which is exactly
the defect this milestone had. Executions completed in a fixed wall-clock
window is the number a person would count by hand.

**Three capabilities the plan did not list, and one it did.** `xfuzz replay`,
`xfuzz minimize` and `xfuzz doctor` are named in DESIGN.md § 7 and were missing
from "the full command set". Adding the first two meant connecting
`internal/triage` — built in M4, and until now resolved, validated, rendered by
`explain`, and doing nothing at all. The daemon owns it, because a finding is
re-examined after every worker has exited.

**A PID namespace changes the semantics of the program inside it.** The first
process in one is PID 1, and the kernel discards signals sent to PID 1 from
inside its own namespace unless a handler is installed. `abort(3)` raises
SIGABRT at itself, so a target executed directly inside a PID namespace never
aborts — glibc falls back to dereferencing a null pointer, and the campaign
records a segmentation fault where an assertion failed. Every `assert()`, every
Rust panic under `panic=abort`, and every sanitizer report would be filed under
the wrong bucket and minimised to preserve the wrong failure class, with
nothing anywhere reporting an error. The namespace is now used for fork-server
targets, whose executions are children and therefore unaffected, and left out
for one-shot ones. It was invisible until the milestone's own triage re-ran a
finding the fork server had already classified and disagreed with it.

**Relative paths belong to whoever typed them.** A campaign file names its
target relative to itself; the client, the daemon and each worker have three
different working directories, and only the client knows what the user meant.
Resolution now always produces absolute paths, and the daemon writes the
resolved configuration into the run's own directory and points workers at that
copy — so a worker runs what was submitted rather than re-resolving a file it
may not be able to see, and the directory ends up holding the record of what
ran.

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
