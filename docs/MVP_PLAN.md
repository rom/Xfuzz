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
| Instrumentation | `sancov`, `forkserver`, `blackbox` | `gocov` (see below), `frida`, `qemu`, `intelpt`, `ptrace-bb`, `agent` |
| IR | Full node set, fixups, byte + structured mutators | — |
| Grammar | Native `.xfg` DSL, one worked format | protobuf, ASN.1, ABNF, Kaitai, OpenAPI importers |
| Feedback | Map coverage, state, response, timing; full algebra | Distance (directed), value profile, concolic |
| State | Declared + inferred model, state feedback and scheduling | Automata learning |
| Corpus | SQL + blob store, AFL import/export, minimisation, bucketing | Advanced re-bucketing |
| Safety | Linux sandbox (`strong`), scope guard, audit log | macOS/Windows beyond `minimal` |
| Parallelism | N worker processes, corpus sync, ensembles | Distributed |
| Interfaces | Daemon, CLI, console (all v1 views) | Fleet view, RBAC |
| Extensions | Native complete; plugin + Starlark for feedback/oracles | Full plugin coverage |
| Platforms | Linux full; macOS/Windows via T3/T4 + `blackbox` | Platform fast paths |

**`gocov` moved to the deferred column, in M8.** ADR-0002 lists it as a v1
backend and it does not make v0.1. The reason is concrete rather than a matter
of effort. Go's coverage counters are written by the instrumented process into
`GOCOVERDIR` in a format that `internal/coverage` decodes and no public API
exposes; `runtime/coverage` can emit them but not read them. Collecting
per-execution coverage from a subprocess would therefore mean either a
file round-trip and a `go tool covdata` invocation per execution — which would
cost more than the execution — or a decoder for an unstable internal format.

Neither buys what it appears to. `gocov` was scoped as the grey-box path off
Linux, and on Windows it would not be one anyway: shared memory is a Unix
mechanism, so a Windows campaign has no coverage map to fill.

**An earlier draft of this section claimed a shorter route and was wrong.** It
said a Go target could have `sancov` coverage today by building with
`-gcflags=all=-d=libfuzzer` against the runtime `xfuzz-cc` ships. Trying it
during the v0.1 audit, it does not link: Go's libfuzzer mode emits against
libFuzzer's 8-bit counter interface, and `runtime/csrc/xfuzz-rt.c` implements
the trace-pc-guard interface, which is a different contract rather than a
subset of one. A pure-Go target behind a process boundary is `blackbox` in
v0.1. [ADR-0026](adr/ADR-0026-gocov-deferred-blackbox-is-the-off-linux-path.md)
records the decision, the measurement, and what the working route would take.

What macOS and Windows get in v0.1 is therefore T3/T4 with `blackbox`, which
ASR-0003 requires to be a supported mode rather than a failure state, and which
`test/e2e/portable_test.go` measures on all three platforms in CI.

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
| Multi-worker campaigns scale ≥ 0.85 × N | **1.89× on 2 workers, 94% efficiency** on a 4-core host, measured as executions completed in a fixed window rather than as a reported rate |
| `xfuzz explain` renders the fully resolved config | Every setting the file never mentions is shown and marked `(default)`, and the YAML form validates as a campaign file |
| Killing the daemon mid-campaign resumes cleanly | SIGKILL at 13 corpus entries / 19 edges; a new daemon took over on the same data directory and finished at **40 entries / 29 edges with the finding intact**, and no worker outlived the daemon that started it |
| CLI/API parity test passes | Every route reachable from a command and every command mapped to routes, both directions, as a unit test over the route table |

**Scaling is measured in executions, not in the reported rate.** The rate is
part of what is under test: a campaign that aggregates its workers' counters
wrongly passes a rate check while doing nothing of the sort — which is exactly
the defect this milestone had. Executions completed in a fixed wall-clock
window is the number a person would count by hand.

The worker count scales with the host, and at most half its cores are used. The
daemon, the client and the test itself run on the same machine, so a run with a
worker on every core measures the scheduler dividing the last one between the
fuzzer and the thing timing it — which is a fact about the host, not about
whether workers scale.

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

**What M5 does not do.** A restarted daemon does not remember the campaigns it
was running. Everything they produced is in the store — corpus, findings,
buckets, audit chain — and a resumed run picks all of it up, which is what the
exit criterion measures. What is missing is reaching a *finished* campaign's
findings without starting it again: `xfuzz replay` and `xfuzz minimize` need the
campaign loaded, and the only way to load one today is to run it. ADR-0003's
"triage tomorrow" is therefore only half delivered, and closing it needs
decisions this milestone did not need to make — whether an adopted campaign
whose target has since moved is readable or refused, and what
`xfuzz run` should mean for a name the daemon already holds. It is a
prerequisite for the console (M7), which is where those decisions have to be
made anyway.

---

### M6 — Stateful protocol fuzzing ✅ *delivered*

The second half of the proof obligation. A campaign fuzzes a conversation
rather than an input, and reaches a bug that needs a specific sequence.

- `pkg/state`: state model declared or inferred, `StateFn` with status-code and
  response-fingerprint defaults, a tunable normalisation pipeline for
  clustering, state and transition feedback, state-then-message scheduling.
- T6 session executor: connection lifecycle, the four reset policies, framing,
  and the three timeouts a protocol needs — connect, per reply, and per session.
- `pkg/codec.Session`, so a seed file is a conversation.
- Session-level mutators: the IR `Repeat` operators from M2, wired and bounded.
- `testdata/targets/stateful_proto.c` and its dictionary.

**Exit criteria met**

| Criterion | Result |
| --- | --- |
| `stateful_proto` bugs found, including the one behind a valid handshake | Bug 4 — the use-after-free reachable only through `AUTH`, `RESET`, `GET` in that order and no other — found in every run, minimised to the four-message session it needs and verified 5 of 5. Bug 1 likewise. Bugs 2 and 3 are reached too, in about half of runs each, and are recorded rather than required: see below |
| State coverage reported separately | States and transitions counted apart from code coverage everywhere they are reported, and `xfuzz states` renders the graph with one exemplar response per label |
| A stateful finding replays as a full session | Reproducers are stored as conversations and triage replays them through a session executor against its own server |

**A session is a funnel, and that is the whole difficulty.** The handshake has
to stay valid for anything past it to be reachable, so a mutator that picks a
uniformly random message of a uniformly random session spends nearly all of its
budget on the entrance. The scheduler picks a rarely-visited state to aim for,
picks a corpus entry known to reach it, finds the message that reached it in
that entry's own trace, and mutates at or after that point — usually, because
breaking the path is how a campaign discovers that the target accepts a message
out of order.

**Which bug the criterion turns on, and why it is bug 4.** Bug 2 was the
obvious exemplar — a `SET` whose value overruns, reachable only past `HELLO`
and a correct `AUTH` — and it is the one this milestone spent the longest
making reachable at all. But what makes it hard is a value grown past a length
nothing in the protocol suggests: difficulty in the payload, sitting behind a
funnel. Measured over five runs at eight minutes on four workers, it comes out
twice. Bug 4's difficulty is the sequence itself — auth-then-get is fine,
reset-then-get is refused for want of authentication, auth-reset-auth-get
reallocates, and only the three-step order faults — and it comes out every
time. That is the stronger demonstration of what state-then-message scheduling
buys, so it is what the criterion requires; bugs 2 and 3 are logged. A
criterion that fails half the time teaches people to re-run it rather than to
read it.

**A criterion has to measure the tool rather than the host it ran on.** M6's
reporting criterion asked for protocol coverage from a forty-five-second
campaign, which passes on an idle machine and, on one that has just finished
another campaign, reaches its time budget having executed nothing — four times
out of four. A campaign's budget has to exceed its own startup before anything
it reports means anything, and a criterion whose budget does not is measuring
the machine.

**Three choices, not two, and the middle one was missing for a while.** Aiming
at a state without choosing an entry that can reach it leaves the aim inert:
the entry comes from the coverage scheduler, an entry that never got there has
no informed place to cut, and the message choice degrades to "anywhere" on
nearly every execution. Measured on `stateful_proto`: 8 of 148 corpus entries
carried a complete handshake, so roughly 95% of the budget went where the aim
could not be acted on, and the bug behind the handshake stayed unreached for
the length of a campaign. It is worth stating because the missing step looked
like a tuning problem — the campaign was authenticating, exploring a dozen
states, and finding the shallow bug — rather than like a scheduler with a hole
in it.

**Every defect this milestone found was invisible.** Not one produced an error:
a campaign reported zero coverage while being guided by it, zero findings while
crashing thousands of times, and a corpus of three-byte fragments where it had
held four-message conversations. Two are worth stating in full because they are
general rather than particular to sessions.

*Trimming destroyed the thing it was trimming.* Candidates were delivered as one
long message rather than as a conversation, so the comparison deciding whether
to keep a reduction ran against an execution that never happened; and trimming
preserved code coverage only, which a session that authenticated and one that
did not both satisfy — the handshake's edges are in the accumulated map either
way. The corpus collapsed to fragments and the campaign lost every path past
the funnel it had spent minutes finding. Trimming now goes through the codec
and preserves the set of states reached as well as the coverage signature.

*A trace is evidence about the input that produced it.* The engine recorded a
mutant's trace against its parent whenever the mutant was not admitted, which
is nearly every execution, so the scheduler aimed using a map of somewhere
else. This is the M4 lesson in a new place: a measurement attributed to the
wrong subject is worse than no measurement, because it looks like guidance.

**What "found" means for a fuzzer, and how the criterion is written.** A
campaign is a sampling process, so a criterion about which bugs it finds is a
statement about a distribution. Bugs 1, 3 and 4 come out of a few minutes
reliably; bug 2 does not, because it needs the handshake *and* a value grown
past a length nothing in the protocol suggests — measured, about one mutation
of that message in forty-five reaches it, so what the budget has to buy is
mutations of that particular message rather than executions. The criterion is
budgeted for the tail and says so, rather than being quietly weakened to
something that always passes.

*The same lesson, once more, about the fuzzer's own actions.* Every campaign
filed a finding reading "target terminated abnormally", signal 9, against an
input that did nothing: a managed server restarted mid-session inherited that
session's timeout as its lifetime and was killed by it seconds later, in a
different session, and the kill was read as the target dying. A signal a target
cannot send itself is never evidence about an input — and a finding that
reproduces 0 times out of 5 was, all along, the tool reporting on itself.

**Byte-level trimming is the wrong unit for a session, as it was for a
checksummed format.** Preserving the state set makes it safe rather than
correct: the right operation deletes whole messages, which is `MinimizeSequence`
from M4 and belongs in the trim path rather than only in triage. It is recorded
here rather than done, because the measurement that would justify it is a
comparison this milestone did not need.

---

### M7 — Web console ✅ *delivered*

- Loading a finished campaign from its store, so its findings can be read and
  re-triaged without running it again (the half of ADR-0003's "triage tomorrow"
  M5 left open).
- TypeScript SPA, Vite build, `embed.FS` embedding, no external assets.
- All v1 views (ARCHITECTURE.md § 9, ADR-0011): campaigns, campaign detail,
  coverage, state machine, findings triage, corpus browser, config editor,
  grammar workbench, safety and audit.
- Live updates over server-sent events with server-side downsampling and
  batching. ADR-0011 said WebSocket; ADR-0024 is later, decided the transport
  for the whole API, and rejected it for a stream that is server-to-client by
  design. The ADR is corrected rather than left to contradict itself.
- Comment-preserving campaign-file round-trip.

**Exit criteria met**

| Criterion | Result |
| --- | --- |
| Configurable, launchable, monitorable and triageable entirely from the console | Driven over the daemon's own socket the way the console's `fetch` does: edit a document, create, start, watch it reach 2,974 executions and 18 edges, read health, history, workers, safety and corpus, then judge a finding and confirm a re-triage does not erase the judgement |
| No unbounded memory growth in browser or daemon under a high-rate campaign | 20,000 metrics events published in 5 ms are delivered to a keeping-up subscriber as **one** event carrying the newest value. Delivery is bounded by the coalescing interval, not the publish rate — and findings, which nobody can reconstruct from a later event, are never collapsed |
| Edited configs round-trip with comments intact | Asserted in the console's own path: comments, key order, paragraphs and indentation survive an edit made through `campaign.edit` |

**What the console is a client of, and why that matters.** It shares the
daemon's listener and has no privileged path of its own, so "can this be done
from the console" is exactly "is this a route". That made the criteria testable
without a browser — and it is also why building the console added four
capabilities to the *API* rather than to the console: loading a campaign from a
store, judging a finding, editing a document, sampling a grammar. Each has a
CLI counterpart, because the parity test refuses to let either interface hold a
capability the other lacks (ASR-0005).

**Building a view is how you find out what the API does not say.** Three
defects surfaced from looking at the rendered page rather than from any test. A
campaign's seed arrived as 14879488505964902000 where the CLI said
…903031, because JSON numbers are IEEE doubles in every browser and a seed is
half of what a byte-identical replay needs (ASR-0008). A throughput peak
rendered as 209.94420193630316. And `/v1/` — the API's own root — was answered
by the console, because `path.Clean` turns it into `/v1` and a prefix test does
not catch that.

**Two features were configured and never implemented.** `seeds.generate` was
validated — the file refused a count without a grammar, and refused a negative
one — and nothing acted on it, so a campaign with a grammar and no seed files
started with an empty corpus. And a person had nowhere to record a judgement:
every triage state was the machine's verdict, rewritten on each re-triage.
Both were found by building the view that would have shown them, which is the
argument for building views.

**The version header meant nothing until something depended on it.**
`APIVersion` was advertised on every response and compared by nobody, so
changing the seed's wire type left a stale CLI reporting "cannot unmarshal
string into Go struct field Status.seed". A client that reads a daemon it does
not understand does not fail, it misreads.

---

### M8 — Extensions and hardening ✅ *delivered*

- `pkg/plugin`: an out-of-process protocol for feedbacks, mutators and
  objectives — four length bytes and a JSON object over the plugin's own stdio
  (ADR-0025) — with batching where batching is real, versioning checked in the
  handshake, and failure that is sticky and contained.
- `pkg/plugin/script`: a hermetic Starlark host for oracles, mutators and
  protocol state functions, bounded by a step budget and an allocation budget.
- `internal/extension`: the campaign file's `extensions:` and `scripts:` blocks
  resolved into running, confined processes and loaded modules.
- The fault-injection suite of TESTS.md § 9, all nine faults injected for real.
- Self-fuzzing for every untrusted parser TESTS.md § 8 names, in CI, with the
  corpus cached across runs.
- macOS and Windows measured rather than assumed: a subprocess campaign, black
  box, against a Go target the test builds, on all three platforms in CI.
- [GUIDE.md](GUIDE.md), [GRAMMAR.md](GRAMMAR.md), and a test that walks the
  guide so it cannot go stale.

**Exit criteria met**

| Criterion | Result |
| --- | --- |
| Both v0.1 proof-obligation campaigns pass on Linux | **Stateless:** 1,208,068 executions at **6,711/s sustained** on the fork-server tier against the checksum-protected `chunked_format`, four findings in one bucket, every one verified 5 of 5 and minimised — 45%, 41%, 39% smaller. Its corpus is **48% valid against the byte-level arm's 25%** on identical seeds; the direct measurement of the rate, at the layer where inputs can be counted as they are produced, is 99.8% against 0.0%. **Stateful:** measured in `test/e2e/m6_test.go` — a bug behind a multi-step handshake, with protocol coverage reported beside code coverage. Its budget is now twenty thousand **sessions** rather than eight minutes: the criterion failed once under load and passed twice idle on identical code, because a campaign that reaches the handshake compounds and a quarter less throughput is most of the exploration |
| macOS and Windows run a subprocess campaign end to end | `test/e2e/portable_test.go`, run by CI on all three platforms: a campaign, a resume across daemon lifetimes, and `xfuzz doctor` checked against the platform it runs on. On Linux: 9,916 executions, both planted bugs found, two buckets. **The macOS and Windows legs run in CI and have not been executed on the machine this was developed on** |
| All fault-injection tests pass | 9 of 9. Four in `internal/store` (corrupt blob quarantined and the campaign continues, corrupt database refused on open, a full 2 MB tmpfs degrading with no partial blob left behind, a store from the future refused), three in `test/e2e` (a killed worker replaced and the corpus intact, a hanging target timed out and recorded as `map[hang:1]`, a fork bomb contained with the campaign finishing), one in `internal/worker` (a dying plugin ending its campaign with its own words), one in `test/e2e/m5_test.go` (a killed daemon resuming) |
| Self-fuzzing runs clean in CI | Ten targets across eight packages, `make fuzz-all`, corpus cached between runs. Locally: 1.8M executions of the grammar parser, 1M of the campaign parser, 2.5M of the schema codec's round-trip, 1M of the plugin frame decoder, 570k of the dictionary parser, 530k of the sanitizer parser, 420k of the API handlers, no crash. The API target found a real defect on its first run |

**The proof obligation found that a grammar never reached the hot loop.** Its
two arms — structured against byte-level, same seeds, same budget — came back
37 edges against 38 and 43% corpus validity against 40%. They were the same
campaign run twice: `format.grammar` generated seeds and `codecFor` returned
`codec.Raw` whatever the grammar said, so the fixup pass that ADR-0005 exists
for never ran in any campaign that asked for it. `codec.Schema` is the missing
half, and with it the same comparison is 48% against 25%, four findings against
two, and minimisation that reduces 45% where it managed 11%.

**Two other defects surfaced the same way.** `xfuzz init` wrote a campaign file
that `xfuzz validate` rejected — `workers.count: 0` with a comment saying "one
per core" — which is two commands into the documented path, and exactly the
class of defect nobody who already knows the tool would hit. And the API and
the console, which share a listener, decided which of them answered on the
*cleaned* path, so `/v1/campaigns/../../etc/passwd` cleaned to `/etc/passwd`
and a JSON client got an HTML page.

**`gocov` did not make v0.1**, for the reason recorded in § 1.1 above: Go's
coverage counters are written in a format no public API decodes, and it would
not have been the grey-box path on Windows anyway, where there is no coverage
map to fill. Writing that deferral up as
[ADR-0026](adr/ADR-0026-gocov-deferred-blackbox-is-the-off-linux-path.md) —
so the ADRs would stop listing a backend the code does not have — caught a
false claim in this document's own § 1.1, which had offered a Go build
incantation that does not link.

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
| **v0.2** | Binary-only targets | T5 emulated executor; `frida`, `qemu`, `ptrace-bb` backends; stripped-binary workflow — **done**, see § 7 |
| **v0.3** | Directed + hybrid | Distance feedback and CFG analysis; `CmpLogStage`; value profile; concolic boundary — **done**, see § 7 |
| **v0.4** | APIs | Traffic capture (HAR, pcap, recording proxy); data-dependency inference; authorization oracles (ADR-0014) — **done**, see § 7 |
| **v0.5** | TUI and GUI | T7 driver executor; PTY + terminal emulator; UI-state feedback; accessibility drivers (ADR-0013) — **TUI done**, desktop drivers not, see § 7 |
| **v0.6** | Grammar ecosystem | protobuf, ASN.1, ABNF, Kaitai, JSON Schema, OpenAPI importers — **done**, see § 7 |
| **v0.7** | Platform parity | Go coverage without clang; macOS Seatbelt and Windows job objects; ConPTY; Windows crashes classified as crashes — **done**, see § 7 |
| **v0.8** | The last domains | The web driver over the Chrome DevTools Protocol, and `gui-atspi` over Linux accessibility — **done**, see § 7; `gui-win` and `gui-mac` deferred with a reason (ADR-0034) |
| **v0.9** | Learning | Active automata learning, which ADR-0006 defers by name; corpus distillation — **done**, see § 7 |
| **v1.0** | Scale | Distributed fuzzing: coordinator, corpus sync protocol, fleet view (needs its own ADR) |

v0.8 and v0.9 were unsequenced when this table was written: § 5 named v0.7 and
then jumped to v1.0. They are filled in with the two things the record itself
says are missing — the last unmet domain in
[ASR-0001](asr/ASR-0001-multi-domain-target-coverage.md), and the one guidance
strategy [ADR-0006](adr/ADR-0006-explicit-state-machine-with-state-feedback.md)
defers by name — rather than with new ambitions.

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

### 6.1 Where each clause stands

Measured on Linux amd64 (Intel Xeon @ 2.80 GHz, 4 cores), 2026-08-30 and
2026-08-31. Each row names what was run, not what is believed.

| # | Clause | Status | Evidence |
| --- | --- | --- | --- |
| 1 | Both proof obligations pass | met | `test/e2e/v01_test.go`. Structured against byte-level on the same seeds and budget: 48% corpus validity against 25%, four findings against two, minimisation reducing 45% against 11%. Re-run at the end of the audit as part of the whole suite below |
| 2 | Planted bugs found within budget | met, with a stated cost | All four targets find every planted bug. `stateful_proto`'s slowest needs ~113,000 sessions where the exit criterion budgets 20,000, so two of its four are recorded rather than required. See § 6.2 |
| 3 | Benchmark gates on every tier | met | `BenchmarkInProc`, `BenchmarkForkServer`, `BenchmarkProcPool`, `BenchmarkSubprocess`, `BenchmarkSession` — one per implemented tier, all in `bench/baseline.txt`. `TestTiersAreOrderedAsADR0009Claims` additionally checks they come out in the order the tier table predicts, which no per-tier gate can see |
| 4 | Determinism and cross-host replay | met | `test/e2e/determinism_test.go`. Two runs of one file and seed, under separate daemons, produced the same corpus by the same derivation; a third with another seed differed. A store carried to a second data directory, daemon and target binary replayed three findings, three of three trials each |
| 5 | Security tests pass | met | `make test-security`: eleven tests, no skips. Now a CI job that fails on a skip, which it was not before this audit |
| 6 | Fault injection; clean resume | met | Nine of nine, M8, re-run in the suite below. Corrupt blob quarantined, corrupt database refused, full tmpfs degrading with no partial blob, a store from the future refused, killed worker replaced, hanging target recorded as a hang, fork bomb contained, dying plugin ending its campaign in its own words, killed daemon resuming |
| 7 | CI green on three platforms, with and without cgo | **was claimed on the wrong evidence; see § 6.3** | The commands were run locally and pass. CI itself was red for every run of this audit, and nobody looked until the release workflow checked out a tag |
| 8 | Self-fuzzing clean | met, after a fix | Ten targets across eight packages, re-run at 120s each after the audit's code changes: 35.1M executions, no crash. It failed the first time — `FuzzClassify` found a crash marker carrying a carriage return into its bucket key, which is the only defect this audit found by running something rather than by reading it. Clean on the re-run after the fix. In M8 the API target found a real path-cleaning defect on its first run |
| 9 | Docs current | met | `tools/docslint` passes; CHANGELOG complete, with a known-issues section. The audit produced ADR-0026 and fourteen corrections, of which thirteen came from reading the decision records against the code and one from a fuzzer. The sharpest was a documented Go build incantation that does not link |
| 10 | A new user reaches a finding | met | `test/e2e/guide_test.go` walks the guide's own commands against the shipped binaries. It found `xfuzz init` writing a file `xfuzz validate` rejects, two commands into the documented path |

The suite behind those rows, run once at the end with everything in place:
`make test-integration` — `-count=1 -race -p 1 -tags integration` across every
package — exit 0, no failures, 32 packages. `internal/engine` 737s (the
planted-bug campaigns and the tier-ordering check), `test/e2e` 1727s (every
milestone's exit criteria, the fault-injection suite, the guide walk, both
proof obligations, and determinism and cross-host replay). Plus
`make test-security` (11 tests, no skips), `CGO_ENABLED=0` build and test,
`make cross` for five platforms, and `make lint`.

`make fuzz-all FUZZTIME=120s`, by target:

| Target | Executions |
| --- | --- |
| `pkg/mutate.FuzzParseDictionary` | 8,255,555 |
| `pkg/plugin.FuzzReceive` | 7,769,428 |
| `pkg/codec.FuzzPNGDecode` | 6,106,663 |
| `pkg/plugin.FuzzServe` | 3,000,395 |
| `internal/triage.FuzzClassify` | 2,689,251 |
| `pkg/codec.FuzzSchemaDecode` | 2,454,195 |
| `internal/api.FuzzRequest` | 1,457,107 |
| `pkg/corpusio.FuzzImport` | 1,446,575 |
| `pkg/campaign.FuzzParse` | 988,731 |
| `pkg/schema.FuzzParse` | 959,518 |

The two that mattered most for this audit are near the bottom of that table
rather than the top, which is the point of running all of them:
`internal/api.FuzzRequest` and `pkg/campaign.FuzzParse` cover the request
decoder and the campaign file parser, both changed here. Rate is a property of
the target, not of how much it is worth fuzzing.

### 6.2 Clause 2, honestly

Three of the four planted-bug targets meet the clause outright, in
`internal/engine.TestCampaignFindsAllPlantedBugs`:

| Target | Bugs | Budget |
| --- | --- | --- |
| `simple_parser` | 3 of 3 | 500,000 executions |
| `magic_parser` | 4 of 4 | 600,000 executions, with a dictionary |
| `chunked_format` | 5 of 5 | 3,000,000 executions, through the schema codec — every bug sits behind a CRC the parser checks first, so the budget buys mutations that survive the fixup pass rather than executions |

That every bug lands in a bucket of its own is asserted separately, in
`test/e2e/v01_test.go`, because it is a claim about triage rather than about
exploration: two bugs that die of the same signal at the same depth must not be
filed as one, or finding the second stops counting as finding it.

`stateful_proto` finds all four of its bugs, and the qualification is about
what that costs rather than about whether it happens. Its four bugs are not
four samples of one difficulty; they are a gradient, and the budget that finds
the first is two orders of magnitude below the one that finds the last.

Measured over two runs, the second budgeted at 150,000 sessions and stopped by
its 55-minute backstop at 112,999 (34 sessions/s, 118 edges, 15 protocol
states, 158 transitions):

| Bug | What it needs | First seen |
| --- | --- | --- |
| 4 | The handshake, then AUTH, RESET, GET in that order and no other | ~2,700 sessions |
| 1 | The handshake | ~4,200 sessions |
| 2 | A SET whose value grows past a length nothing in the protocol suggests | ~39,700 sessions |
| 3 | Two transfers on one connection | between 42,000 and 113,000 sessions |

Bug 4 arriving before bug 1 is not a mistake in the table. Bug 4 needs a
*sequence* and bug 1 needs a *payload*, and state-then-message scheduling
explores sequences deliberately while payloads are still being sampled — which
is the whole claim ADR-0006 makes for state feedback, visible in the order the
bugs fall.

**The exit criterion requires bugs 1 and 4 at 20,000 sessions and records 2 and
3.** That is a decision about test economics, not about capability: requiring
bug 3 would make the criterion take the better part of an hour, and it would
rest on a single sample of where in a 70,000-session window the bug falls. A
criterion that runs for an hour is one people stop running, and one calibrated
from a single sample of a tail is one that fails for reasons nobody can act on.

What remains genuinely open is the *shape* of that tail rather than its
existence. One observation bounds bug 3 at under 113,000 sessions; it does not
say whether that is typical or lucky, and saying so needs many runs rather than
one longer one. Narrowing it is also the one place where a new mutation stage
would obviously pay: bugs 2 and 3 are both about a value or a connection being
pushed past what the protocol suggests, which nothing in the current stage set
targets on purpose.

### 6.3 The clause that was wrong, and why the rest are not

Clause 7 says "CI green on Linux, macOS, and Windows, with and without cgo".
It was marked met on the strength of `CGO_ENABLED=0 go build ./...`,
`make cross` and `make lint` passing **here**. Those are the same commands CI
runs, so the inference felt safe. It was not: CI had failed on every run of
this audit, and on every run for a long time before it.

The cause was one missing slash in `.gitignore`. The rule `corpus/`, written to
keep campaign output out of the repository, is unanchored — and an unanchored
gitignore pattern matches a directory of that name at any depth, so it also
matched `pkg/corpus/`. That package has never been committed. Every clone of
this repository has been a module that fails at `go build ./...`, and 11 of
CI's 14 jobs — every job that compiles Go — have been failing accordingly.

Nothing local could have caught it, and that is the point worth keeping. The
files are on disk here, so every build, test, lint, benchmark and campaign in
this session ran against a tree the repository does not contain. The audit's
whole method — read the record, check it against the code — cannot see a
difference between the code and *the code that was committed*. It took a fresh
checkout on a machine that had never seen this working tree, which is exactly
what the release workflow's verify job does and what no other job in the
project did.

The other nine clauses rest on measurements taken here, and are true of this
tree; the fix makes them true of the repository too, and `test/e2e` builds the
shipped binaries from source in the same checkout. But the honest statement is
that "it passes here" was never evidence for "CI is green", and this row should
have been checked against the runs rather than inferred. The remedy is
mechanical and now exists: a release cannot publish without a clean build of
the tagged commit on a machine that starts from `git clone`.

## 7. v0.2 to v0.9

Shipped after v0.1, in the order § 5 sequenced them. What each contains, what
was measured for it, and what it does not cover.

### 7.1 v0.2 — binary-only targets

| Piece | Where | Evidence |
| --- | --- | --- |
| Block recovery from a stripped executable | `pkg/binary` | Decoder agrees with `objdump` over 984,000 instructions; every block in the program's own functions survives `strip`, asserted against the unstripped analysis of the same binary |
| T5 executor over a `Tracer` interface | `pkg/executor/emulated.go` | Fold is order-aware and refuses to invent edges; portable tests with a fake backend |
| `ptrace-bb` | `internal/tracer/ptrace.go` | End to end: deeper inputs cover more, the same input covers the same, a crash is a crash, a hang is a hang, a cancelled context stops it |
| `qemu`, `frida` | `internal/tracer/` | Format readers tested against all three of QEMU's log shapes and both DRcov module-table versions; both backends exercised end to end against stub tools that emit the real formats |
| Config, probing, `doctor` | `pkg/campaign`, `internal/api` | Validation refuses a binary-only backend under a tier that cannot carry it; `doctor` names what is missing per backend |
| A finding with no instrumentation | `test/e2e/binary_only_test.go` | 239 executions, 23 coverage entries, 9 corpus entries, one finding, four seconds — against a stripped, uninstrumented target |

**Not covered.** `qemu` and `frida` have not been run against the real tools:
neither was installed on the machine where they were written. Their format
readers, command construction, spawn path, rebasing, folding and failure
reporting are all tested; the tools' own semantics are not. `ptrace-bb` is
Linux-only and `qemu` needs `qemu-user`; on macOS and Windows the binary-only
path is still `blackbox` (ADR-0026). `intelpt` and `agent` remain unimplemented.

### 7.2 v0.3 — directed and hybrid

| Piece | Where | Evidence |
| --- | --- | --- |
| Comparison operands in the runtime | `runtime/csrc/xfuzz-rt.c` | ABI asserted by building a real instrumented target and requiring the constants its source compares against to come back out |
| `CmpLogStage` | `internal/engine/cmplog.go` | Three gates of 32, 64 and 16 bits: bug found with the stage, nothing without, same seed and budget. And on `magic_parser` with its dictionary taken away: 23 coverage entries and two distinct bugs with substitution, 2 entries and none without — mutation alone never gets past the header |
| Value profile | `pkg/feedback/cmplog.go` | An input matching a gate exactly produces new signal where one that does not, does not |
| Engine stages | `internal/engine/stage.go` | One execute-and-judge path shared by every stage |
| Distance map and CFG analysis | `pkg/binary/distance.go` | Distance grows with call depth; a function with no route has none; a target address from another build is refused |
| `DistanceFeedback` and the schedule | `pkg/feedback/directed.go`, `pkg/corpus/schedule.go` | Directed reached 7.00 blocks against undirected's 8.50, both instrumented and scored identically |
| Concolic boundary | `internal/engine/concolic.go` | A one-second solver costs 1ms over 5000 executions; a failing one leaves the campaign complete; a prolific one cannot wedge it; closing the engine stops it |

**Not covered.** No symbolic backend ships, which is ADR-0007's deferral
honoured rather than an omission. Directed fuzzing needs block addresses, so it
works with `sancov` and the three binary-only backends and not with `blackbox`.
Comparison substitution needs an instrumented build; the memory-comparison hooks
fire only when the target also carries a sanitizer. A campaign with a solver is
not reproducible, and one enabling comparison logging pays for it on every
comparison the target performs, measured as within the noise of a fork-dominated
benchmark and not measured on a comparison-dominated one.

### 7.3 v0.4 — API fuzzing from captured traffic

| Piece | Where | Evidence |
| --- | --- | --- |
| Capture readers | `pkg/capture` | HAR, pcap and a flat session file; reassembly stops at gaps, overwrites retransmissions and takes only the non-overlapping tail of an overlap |
| Recording proxy | `internal/record` | CONNECT tunnelling, its own certificate authority, and every connection through the scope guard |
| Dependency inference | `pkg/capture/link.go` | Finds the token *and* the identifier in a login-create-use session; refuses values under eight bytes; forward only; deterministic across eight runs of the same capture |
| Credential handling | `pkg/capture/auth.go` | Recognised in requests and responses; the same secret gets the same placeholder; restoring a redacted session reproduces the original byte for byte |
| API tier | `pkg/executor/api.go` | Without links the replay 404s on the recorded identifier and with them it does not — the failure inference exists to prevent, measured rather than argued. Boundaries come from the tree, so a length-changing mutation still leaves two requests |
| Four oracles | `pkg/feedback/api.go` | Each tested for what it must *not* report: a 4xx, a new field, one slow response raising the bar, a public endpoint answering 200 |
| Campaign wiring | `pkg/campaign`, `internal/worker` | End to end: a capture becomes a seed, the requests reach a live service, and the status oracle produces the finding |

**Not covered.** Inference is textual containment, so a value the client
transforms between the response and the next request — base64, a hash, a
concatenation — is not found. Only JSON response bodies can be re-extracted; a
value that arrived in a header of an earlier *request* is sent unchanged. The
proxy has been exercised against Go's own client and server, not against a
browser. HTTP/2 and HTTP/3 are not read or spoken.

### 7.4 v0.5 — terminal user interfaces

| Piece | Where | Evidence |
| --- | --- | --- |
| T7 driver tier | `pkg/executor/driver.go` | Event order, the sequence bound, reset per sequence, the timeout, a backend that dies mid-sequence, and an undeliverable event skipped rather than fatal |
| Terminal emulator | `pkg/vt` | Deferred wrap, the scrolling region, the alternate buffer, SGR parameter consumption, UTF-8 split across writes, wide characters; a self-fuzzing entry point over a million executions |
| Pseudo-terminals | `internal/platform`, `internal/safety` | A real program in raw mode on the alternate screen, redrawing on SIGWINCH, driven end to end |
| Key and mouse encoding | `internal/driver/keys.go` | Application cursor mode changes the arrows and nothing else; a click on a program with no mouse tracking sends nothing |
| UI-state feedback | `pkg/state/screen.go` | A clock, a spinner and a progress bar are not states; five distinct screens are five states; deterministic across sixteen runs |
| Three oracles | `pkg/feedback/ui.go` | Each tested for what it must *not* report: an ordinary screen, a screen that never changed, a screen something has escaped from |
| Campaign wiring | `internal/worker` | End to end: a campaign file with a `driver` block finds the planted unrecoverable screen |

**Not covered.** One backend: `tui`. The four desktop backends ADR-0013 names
each need a platform, a session and a display, and none is implemented — the
capability is declared absent rather than approximated. Pseudo-terminals are a
Unix mechanism; Windows has ConPTY and it is not written. The emulator does not
implement scrollback, custom tab stops, double-width lines, mouse reporting back
from the program, or reflow on resize. Waiting for the interface to go quiet is
a wall-clock input to what the campaign observes, so the tier declares itself
non-deterministic.

### 7.5 v0.6 — the grammar ecosystem

| Piece | Where | Evidence |
| --- | --- | --- |
| Six importers | `pkg/schemaio` | Each import validates, survives being rendered and re-parsed by the tool's own parser, and generates a non-empty input through the real generator |
| ABNF | `abnf.go` | Repetition forms, folded continuation lines, incremental alternation, comments inside strings, a group inside an alternation, the core rules |
| Kaitai | `kaitai.go` | `size: field` inverted into a length derivation, and a generated file whose lengths agree with the fields they describe |
| JSON Schema | `jsonschema.go` | Sixteen generated documents parsed by `encoding/json`; required and optional members; a recursive `$ref` that terminates |
| OpenAPI | `openapi.go` | Sixteen generated requests read by the HTTP codec the API tier uses; no query string with a dangling separator |
| Protocol Buffers | `proto.go` | Sixteen generated frames walked key by key the way a decoder does; keys exact at field number 2000 |
| ASN.1 | `asn1.go` | Sixteen generated documents walked tag by tag, constructed types recursively |
| Self-fuzzed | `fuzz_test.go` | A million executions across all six; the two defects found are regression cases |

**Not covered.** The variable-length integer. Protobuf and DER both encode
values whose width depends on their value, and the schema language has only
fixed-width ones — so both importers generate the one-byte form and bound their
payloads to stay inside it, which caps a generated message at 127 bytes per
length-delimited field. Closing that means a variable-width integer in the IR,
touching the encoder, the fixup pass and every mutator. Value constraints
(`minimum`, `pattern`, `INTEGER (1..255)`) are reported rather than solved.
Kaitai expressions, ABNF prose-vals and JSON Schema's `not`/`if`/`then` have no
construction and are reported. Each importer is a documented subset and will
meet documents it does not cover; that is what the report is for.

### 7.6 v0.7 — platform parity

| Piece | Where | Evidence |
| --- | --- | --- |
| `gocov`: coverage for a Go target with no clang | `runtime/csrc/xfuzz-rt.c`, `pkg/feedback/counters.go` | Same target, same seeds, 20,000 executions: `gocov` kept 12 corpus entries, `blackbox` kept 2. A campaign whose every execution panics still admitted 6, which is the property the mapping exists for |
| `xfuzz-cc --go` | `cmd/xfuzz-cc/gobuild.go` | Builds a real Go target with the libfuzzer tag, the instrumentation flag and the external link, and the resulting binary registers its counters |
| macOS confinement | `internal/platform/seatbelt.go`, `confine_darwin.go` | Profile builder tested untagged: rule order (an allow before the blanket deny never applies), a path carrying a quote that would otherwise rewrite the policy, a trailing backslash, empty entries, the three standard devices |
| Windows job objects | `internal/platform/sandbox_windows.go` | Cross-built and cross-vetted; the level policy and the capability line are tested from Linux with injected capabilities |
| ConPTY | `internal/platform/pty_windows.go` | Cross-built and cross-vetted; the Unix terminal path was moved onto the same `platform.TTY` interface and its tests still pass |
| Windows crashes read as crashes | `internal/platform/exception.go` | Untagged mapping with tests: the faults a target dies of, an exit code of 1 that must **not** become a finding, and an unlisted NTSTATUS code that must still be a crash |
| Isolation levels off Linux | `internal/safety/sandbox.go` | A confined host reaches `moderate`; a host with only a job object stays `minimal` and the explanation says which half is missing |

**Not covered.** The macOS and Windows mechanisms are **unverified on their own
operating systems**: no macOS or Windows host is available to this project.
Everything is cross-built, cross-vetted (`go vet` passes for all three) and
unit-tested wherever the logic is pure — which is deliberately most of it, since
the profile builder and the exception mapping are the two places a mistake would
be silent. Applying a Seatbelt profile, creating a job object and starting a
target on a pseudo-console are not exercised. This is the same treatment § 7.1
gives `qemu` and `frida`, and for the same reason.

Windows filesystem confinement is not implemented: that needs a restricted or
low-integrity token, and Windows therefore stays at `minimal`. `sancov` on
Windows still has nowhere to write its map, because shared memory in
`internal/platform` is a Unix mechanism — so `gocov` closed the Go half of
ADR-0026's platform gap and not the C half. A ConPTY resize sends no signal,
because Windows has none to send, so a program that redraws only on `SIGWINCH`
does not redraw there. `gocov` reports block granularity, not edges, and refuses
the fork server.

### 7.7 v0.8 — the last domains

| Piece | Where | Evidence |
| --- | --- | --- |
| WebSocket client and CDP session | `internal/cdp` | Framing exercised against a server written in the test rather than against itself: replies correlated out of order, a fragmented message reassembled, a ping answered, an unmasked frame rejected, an oversized frame refused, a wrong handshake key refused, a dead browser failing every waiting call |
| `web` backend | `internal/driver/web.go` | End to end against real Chromium: the page's shape is read, typing does not become a new state and opening a panel does, a planted exception is found and an ordinary sequence produces nothing, a reset clears both the screen and the collected problems, a modal is dismissed rather than stalling, a resize takes effect |
| The whole machine on a web target | `internal/worker/tier_test.go` | A worker campaign reports the planted exception through the corpus, the mutators, the state model and the oracles |
| `gui-atspi` backend | `internal/atspi`, `internal/driver/gui.go` | End to end against a real GTK application: the accessibility tree is read, clicks land where the widget says it is, the state separates screens without letting a keystroke become one, a reset restarts the program |
| The whole machine on a desktop target | `internal/worker/tier_test.go` | A worker campaign finds a planted exception in four executions, reached by *duplicating* an event — the operator that exists because a sequence is an IR Repeat |
| One event vocabulary, three backends | `internal/driver/webkeys.go`, `guikeys.go` | Every key name the terminal backend knows is known to the other two, or the test fails |

**Not covered.** `gui-win` and `gui-mac`: UI Automation is COM on Windows and
the macOS accessibility API needs Objective-C, which ADR-0017 keeps out of the
fuzzer, and neither can be exercised by this project (ADR-0034). The desktop
backend cannot hold a modifier down — AT-SPI presses a keysym and releases it —
so `ctrl-c` is a skipped event with a stated reason rather than the wrong
keystroke. A desktop campaign needs a display, a session bus, an accessibility
bus and a toolkit bridge, so its tests skip where a CI image has none. A browser
cannot start under a campaign's ordinary address-space cap, so its sandbox drops
that one limit and raises the process floor.

### 7.8 v0.9 — learning and distillation

| Piece | Where | Evidence |
| --- | --- | --- |
| L* over Mealy machines | `pkg/learn` | Recovers a known protocol exactly and agrees with it on words it was never asked; finds an access sequence for every state; stops and says so on a target with no finite machine; never asks the target the same word twice; two runs learn the same machine; returns what it has when the target dies |
| The counterexample handling that terminates | `pkg/learn/lstar_test.go` | A three-state machine whose first two states differ only two symbols later, which the prefix-adding form never finishes on |
| Learning a real protocol | `internal/worker/tier_test.go` | Three states and nine transitions from thirty sessions against `stateful_proto`, two access sequences seeded, in two seconds |
| Corpus distillation | `pkg/corpus/distill.go` | Keeps a covering subset and never loses a feature; prefers the smaller entry; identical across twenty runs; the index agrees with the entries afterwards and a dropped input can be readmitted |
| Distillation against real coverage | `internal/engine` | One execution per entry and no more; refuses a campaign with no coverage rather than dropping entries at random |

**Not covered.** Learning needs a target that is deterministic from a reset. A
protocol whose replies carry a counter, or a session tier whose framing is
timing-based, makes the learner report exactly that rather than produce a
machine — which is the right answer and is not a machine. The equivalence
oracle samples rather than proves: there is none that can prove a program
equivalent to a machine, so the report says how many sequences it checked.
Distillation is not offered as a command; it runs on the interval a campaign
configures, and an operator who wants it once sets the interval and stops the
campaign.
