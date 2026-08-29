# Xfuzz — Test Strategy

> Implements [ADR-0021](adr/ADR-0021-layered-differential-and-self-fuzzing-tests.md).
> Serves ASR-0007 (throughput), ASR-0008 (reproducibility), ASR-0011 (finding
> quality), ASR-0014 (structure awareness).

## 1. The problem with testing a fuzzer

A fuzzer's most severe defects are **silent**. A broken coverage map, an inverted
feedback, a mutator that only emits invalid inputs, an executor that never
actually reaches the harness — every one of these passes a full unit-test suite
and produces a campaign that runs beautifully for a week and finds nothing.
There is no exception, no stack trace, and no failing assertion. It looks
identical to a fuzzer running against genuinely hardened code.

The second failure mode is **performance regression**. A fuzzer 10× too slow is
not 10 % worse; it is a fuzzer that never reaches the bug.

Unit tests detect neither. The strategy below is layered so that each layer
catches a class the others structurally cannot.

| Layer | Catches | Speed |
| --- | --- | --- |
| 1 Unit | Component logic errors | seconds |
| 2 Property / round-trip | IR and codec invariant violations | seconds |
| 3 Planted-bug integration | **Silent ineffectiveness** | minutes |
| 4 Determinism / replay | Non-reproducible findings | minutes |
| 5 Differential | Backend-specific defects | minutes |
| 6 Benchmark gates | **Performance regression** | minutes |
| 7 Self-fuzzing | Vulnerabilities in Xfuzz's own parsers | continuous |
| 8 Fault injection | Broken recovery and resumability | minutes |
| 9 Cross-platform CI | Platform-specific breakage | minutes |
| 10 Docs and licence | Traceability drift, licence violations | seconds |

## 2. Layer 1 — Unit tests

Standard Go testing per component, race detector always on
(`go test -race ./...`).

Coverage expectations, by risk rather than uniformly:

| Area | Target | Why |
| --- | --- | --- |
| `pkg/ir`, `pkg/codec` | ≥ 90 % | Correctness foundation for everything else |
| `pkg/feedback`, `pkg/corpus` | ≥ 85 % | Silent-failure surface |
| `internal/safety` | ≥ 90 % | Security-critical |
| `internal/store` | ≥ 85 % | Data integrity |
| Everything else | ≥ 70 % | — |

Line coverage is a floor, not a goal; layers 2–8 carry the real assurance.

## 3. Layer 2 — Property and round-trip tests

The IR is the least intuitive part of the design and the foundation of the rest,
so its invariants are checked mechanically rather than by example.

**Codec invariants**

```
parse(bytes) → serialise            ≡ bytes                    (byte-exact)
parse(malformed)                    → partial IR, never error  (ASR-0014)
serialise(parse(x))                 ≡ x, for all corpus files
```

**Fixup invariants**

```
fixup(fixup(n))                     ≡ fixup(n)                 (idempotent)
fixup(n) with suppress = ∅          → all derived fields consistent
fixup terminates                    for cyclic derivation graphs
fixup order                         independent of node visit order
```

**Mutator invariants**

```
mutate(n) preserves node type validity
mutate(n) then fixup                → parseable by the same schema
mutate is deterministic             given the same RNG stream
splice(a, b)                        produces a valid tree for compatible subtrees
```

**Arena invariants**

```
steady-state mutation               → zero heap allocations (testing.AllocsPerRun)
release then reuse                  → no aliasing between generations
```

Implemented with table-driven tests plus randomised property testing over
generated schemas, with failing cases shrunk and pinned as regression fixtures.

## 4. Layer 3 — Planted-bug integration targets

**This is the primary end-to-end assertion, and the only layer that detects
silent ineffectiveness.**

`testdata/targets/` contains purpose-built targets with known, distinct,
documented bugs at graded difficulty:

| Target | Bugs | Difficulty | Exercises |
| --- | --- | --- | --- |
| `simple_parser` | 3 | shallow | Basic mutation, crash detection |
| `magic_parser` | 4 | magic values | CmpLog, dictionary, value profile |
| `chunked_format` | 5 | checksum-gated | Structured IR, fixups |
| `nested_grammar` | 4 | deep structure | Grammar generation, tree mutation |
| `stateful_proto` | 5 | state-dependent | State model, session mutation |
| `slow_path` | 2 | algorithmic | Timing feedback |
| `leaky_service` | 2 | resource growth | Allocation feedback |
| `tui_app` | 3 | UI state | Driver executor, UI-state feedback |

Each bug has a documented expected time-to-discovery budget. The test asserts:

- **every** bug at its difficulty tier is found within its budget
- the correct number of distinct buckets is produced (over- and under-merging are
  both reported — ASR-0011)
- each finding replays deterministically
- minimisation reduces the reproducer by ≥ 80 % while preserving its bucket

A fuzzer that cannot find a planted bug is broken, regardless of what the unit
tests say.

**Over-fitting** is the known hazard: the fuzzer gets good at *these* bugs.
Mitigated by graded difficulty, periodic target rotation, and cross-checking
against external corpora.

## 5. Layer 4 — Determinism and replay

Enforces ASR-0008:

- **Trace equality.** Two single-worker runs of the same campaign file and seed
  produce byte-identical execution traces.
- **Cross-host replay.** Every finding replays on a different host and OS,
  producing the same outcome.
- **Stream independence.** Adding a stage does not perturb another stage's RNG
  sequence.
- **Provenance validity.** Replaying an entry's recorded provenance chain from its
  parent reconstructs it exactly.
- **Stability measurement.** Re-executing an input reproduces its coverage; the
  divergence rate is asserted below threshold for deterministic test targets.
- **Non-determinism detection.** A deliberately non-deterministic target is
  detected and reported, not silently absorbed.

## 6. Layer 5 — Differential tests

Each instrumentation backend and executor tier is otherwise an unverifiable
island. Differential testing gives each an oracle:

- The same input through **different executor tiers** (T0/T2/T3/T4) yields the
  same exit kind and consistent coverage.
- The same target through **different instrumentation backends** (`sancov`,
  `forkserver`, `frida`, `qemu`) yields consistent edge sets, allowing for
  documented granularity differences.
- The same campaign on **different platforms** produces comparable coverage.
- **Codec differential**: where an external reference parser exists, Xfuzz's codec
  agrees with it on accept/reject for a corpus.

## 7. Layer 6 — Benchmark suite and regression gates

Enforces ASR-0007. `bench/` executes the tier table in CI:

| Executor tier | Floor (single core, reference host) |
| --- | --- |
| T0 in-process | 50,000 exec/s |
| T1 persistent | 50,000 exec/s |
| T2 fork server | 5,000 exec/s |
| T3 process pool | 300 exec/s |
| T4 subprocess | 300 exec/s |
| T5 emulated | 200 exec/s |

These floors are stated for a commodity 8-core Linux host, and a host that
cannot reach one with a target that does nothing cannot reach it with a real
one either. Asserting an absolute number on such a host measures the host, not
the fuzzer. So the gate has two parts:

- **Always asserted:** a realistic target must run at a healthy fraction of the
  rate the same executor achieves against a do-nothing target. That ratio says
  whether the executor spends its time in the target or in the protocol around
  it, and it means the same thing on any machine.
- **Asserted where the host allows it:** the absolute floor. Where the host's own
  do-nothing rate is below the floor, the test says so and skips that assertion
  rather than reporting a failure it cannot attribute.

Also gated:

- **Engine overhead** < 10 % of wall-clock at each tier.
- **Scaling**: 1 → N workers yields ≥ 0.85 × N aggregate throughput up to the
  physical core count.
- **Steady-state allocations**: zero in the fuzz loop.
- **Effectiveness**: time-to-first-bug and coverage-over-time on planted targets
  tracked as regressions in their own right.

A ≥ 10 % regression on any gated metric **fails the build**. Allocation counts
are compared *exactly* rather than against the threshold: they are deterministic,
and the fuzz loop is required to be allocation-free in steady state.

Benchmarks are noisy on shared CI runners, and a flaky gate is worse than no gate
because people learn to ignore it. Two mitigations are implemented in
`tools/benchcmp`:

- **Median of repetitions.** Runs use `-count 5` and the tool takes the *median*
  of each metric, not the mean or the last sample. A median absorbs the
  occasional large outlier a shared runner produces; a mean does not.
- **Gate only what compares fairly.** Timing is host-dependent, so a baseline
  recorded on one machine says nothing about absolute ns/op on another. CI
  therefore gates by provenance:

  | Event | Reference | Gated |
  | --- | --- | --- |
  | Pull request | Base branch, measured on the *same* runner | every metric |
  | Push | `bench/baseline.txt`, recorded elsewhere | `allocs/op`, `B/op` only |

  Ungated metrics are still measured and printed, marked `(not gated)`, so a
  slowdown is visible even where it cannot fairly fail the build.

`bench/baseline.txt` is committed, and is re-recorded with `make bench-baseline`
only as part of a change that justifies the new numbers.

## 8. Layer 7 — Self-fuzzing

Xfuzz fuzzes its own untrusted-input surface using Go native fuzzing, run
continuously in CI with a persisted corpus (see [SECURITY.md](SECURITY.md) § 3.5):

| Parser | Untrusted source |
| --- | --- |
| `codec.Decode` (per format) | Corpus files |
| `.xfg` grammar parser | Shared grammars |
| Campaign file parser | Shared campaign files |
| AFL/libFuzzer corpus import | Downloaded corpora |
| Dictionary parser | Shared dictionaries |
| HAR / pcap capture parsers | Captured traffic |
| Sanitizer output parser | Target output |
| Plugin protocol decoder | Third-party plugins |
| API request handlers | Network clients |

Any crash, hang, or OOM is a release blocker. Corpora persist across CI runs so
coverage accumulates rather than restarting each build.

## 9. Layer 8 — Fault injection

Asserts that recovery and resumability (ASR-0012) actually hold:

| Injected fault | Required behaviour |
| --- | --- |
| Worker killed mid-execution | Daemon restarts it; corpus stays consistent |
| Daemon killed mid-campaign | Resume loses at most the checkpoint window; no corruption |
| Plugin process dies | Campaign fails cleanly with a clear error |
| Disk full during corpus write | Graceful degradation; reported; no corruption |
| Corrupted blob | Detected by digest; entry quarantined, campaign continues |
| Corrupted database | Detected on open; explicit error, never silent misbehaviour |
| Target hangs indefinitely | Timeout enforced; recorded as a hang |
| Target fork-bombs | Sandbox PID limit holds; campaign continues |
| Store opened by a newer version | Explicit version error |

## 10. Layer 9 — Cross-platform CI

| Job | Platform | Scope |
| --- | --- | --- |
| `test (ubuntu-latest)` | Linux amd64 | Full suite with `-race` |
| `test (macos-latest)` | macOS arm64 | Full suite with `-race`, minus Linux-only tiers |
| `test (windows-latest)` | Windows amd64 | Full suite, minus POSIX-only tiers |
| `integration` | Linux amd64 | Layer 3: planted-bug campaigns, behind the `integration` build tag |
| `nocgo` | Linux amd64 | Full suite with `CGO_ENABLED=0` (ADR-0017) |
| `cross` | Linux | Compiles `linux/{amd64,arm64}`, `darwin/{amd64,arm64}`, `windows/amd64` |
| `vuln` | Linux | `govulncheck` |

The campaign tests sit behind a build tag and run in their own job. They take
minutes, so leaving them in the default suite would make the pre-commit run too
slow to actually run before every commit — and a suite people skip catches
nothing.

Three deliberate gaps, stated rather than papered over:

- **The race detector does not run on Windows.** It requires a working cgo
  toolchain that the hosted image does not guarantee, and a job that fails for
  environmental reasons teaches people to ignore CI. The Windows job compensates
  by building every command in addition to running the suite. Revisit when a
  self-hosted Windows runner exists.
- **No native `linux/arm64` job.** arm64 is covered by compilation only until an
  arm64 runner is available. Compilation is not execution, and this is a real
  hole in the ASR-0006 claim, not a formality.
- **Instrumented targets need clang.** Where it is absent the integration tests
  skip with a reason rather than failing, because a missing toolchain is an
  environment gap and a suite that fails for environmental reasons is one people
  learn to ignore.

Platform-unavailable capabilities are asserted to **skip explicitly with a
reason**, never to fail silently or pass vacuously — the same information
`xfuzz doctor` reports to users.

## 11. Layer 10 — Architecture, documentation, and licence checks

Three rules that are cheap to state and expensive to leave unenforced. Each is a
Go test, so `go test ./...` runs all of them and no separate tool is required.

- **Architecture boundaries** (`tools/archlint`): the seven layering rules in
  `ARCHITECTURE.md` § 2 — `pkg/` never imports `internal/`, the core never
  imports the executor, only `internal/platform` carries GOOS constraints, only
  `internal/safety` spawns processes or dials out, nothing imports `cmd/`, and
  nothing imports Go's `plugin` package. Exceptions live in an explicit
  allowlist. The linter's own tests assert that **each rule fires** against a
  deliberately violating fixture: a lint that only ever passes is
  indistinguishable from one that checks nothing.
- **Documentation traceability** (`tools/docslint`): every ASR names ≥ 1
  satisfying ADR, every ADR names ≥ 1 served ASR, the two indexes and the matrix
  in `ARCHITECTURE.md` § 11 agree with the record headers, and every relative
  link in `docs/` resolves. Traceability drift is silent by nature, so this
  linter also tests that it detects an injected inconsistency.
- **Licence compliance** (`tools/licensecheck`): every module in `go.mod` must
  carry a `NOTICE` entry whose licence is in ADR-0018's allowed set. Missing
  entries, stale entries, version drift, and forbidden or unknown licences all
  fail the build — at the moment a dependency is added, not in a pre-release
  audit when removing it is expensive.

Also gated: **vulnerability scanning** (`govulncheck`) on every build, and once
the campaign schema exists, a **config schema check** that every example
campaign file in the docs validates against it.

## 11a. Milestone exit criteria

Each milestone in `MVP_PLAN.md` ends with criteria that are *measurements*, not
assertions: a bucket count, a reduction percentage, a scaling factor. From M5
they live in `test/e2e` as ordinary Go tests behind the `integration` tag, and
they run against the **shipped binaries** rather than the packages behind them.

That is the point of them being separate. A criterion about how a campaign
scales across worker processes, or about what survives losing the daemon, cannot
be answered from inside one package — and answering it in-process would skip
exactly the parts it is about: process launch, the descriptor protocol, the
store on disk, the client's working directory.

They also measure the thing rather than what the system reports about it. M5's
scaling criterion counts executions completed in a fixed window rather than
reading the reported rate, because the reported rate is part of what is under
test: a campaign that aggregates its workers' counters wrongly passes a rate
check while doing nothing of the sort. That defect was real, and a rate check
would have passed over it.

## 12. Security tests

Security properties from [SECURITY.md](SECURITY.md) are executable tests, not
claims:

| Test | Asserts | Implemented as |
| --- | --- | --- |
| Target keeps the fuzzer's identity | Deprivileged to a uid that is not the overflow id | `TestSecurityTargetIsDeprivileged` |
| Write outside workdir | Blocked by sandbox; a write *inside* still works | `TestSecurityWriteOutsideWorkdir` |
| Fork bomb | Contained near the configured limit | `TestSecurityForkBomb` |
| Memory exhaustion | Contained by cgroup/Job Object | `TestSecurityMemoryExhaustion` |
| Privileged syscall | Denied with `EPERM` by the seccomp filter | `TestSecurityPrivilegedSyscallIsDenied` |
| Seccomp filter pins the ABI | The program loads the architecture first | `TestSecuritySeccompFilterShape` |
| Connection to unlisted host | Blocked by scope guard, audited | `TestSecurityUnlistedHostIsRefused` |
| Campaign without scope allowlist | Refuses to start | `TestSecurityCampaignWithoutScopeRefusesToStart` |
| Campaign without an authorization record | Refuses to start | `TestAuthorizeRefusesRemoteWithoutARecord` |
| Public scope without acknowledgement | Refuses to start | `TestScopeRefusesPublicSpaceWithoutAcknowledgement` |
| Workdir unreachable by the target's identity | Refused at start, not on every execution | `TestSecurityWorkdirIsCheckedBeforeTheCampaignStarts` |
| Sandbox is on with no configuration | The zero policy still confines | `TestSecuritySandboxIsOnByDefault` |
| Audit log modified | Tamper detected by hash chain | `TestAuditDetectsModification`, `TestAuditDetectsDeletionFromTheMiddle` |
| Audit log truncated | Tamper detected by the mirrored chain head | `TestAuditDetectsTruncation` |
| Malformed fork-server handshake | Rejected without memory corruption | `TestForkServerRejects*` (silence, wrong magic, truncated word, 1 MiB of garbage) |
| Starlark attempts I/O | Fails; no I/O possible | M8, with the plugin layer |
| Oversized/deeply nested grammar | Rejected by limits, no OOM | M8 |
| Unauthenticated API request | Rejected | M5, with the API |

The escape attempts are pointed at `testdata/targets/escape.c`, a target written
to get out: it writes outside its directory, forks without bound, allocates
without bound, and calls a privileged syscall, and reports which of those it was
stopped doing. Each test distinguishes "contained" from "the program did not
run", because a sandbox test that passes because the target never started is
worse than no test.

Where a mechanism is unavailable on the host — no cgroup hierarchy, no user
namespaces, no seccomp — the corresponding test skips with the reason rather than
failing. A suite that fails for environmental reasons is a suite people learn to
ignore (§ 10). What must never happen is a test that passes because the mechanism
was silently not applied, which is why each one asserts the *effect* rather than
the configuration.

## 13. Running the tests

```
make test              # layers 1, 2 — fast, pre-commit
make test-integration  # layers 3, 4, 5, 8, and the milestone exit criteria
make test-security     # layer 12
make bench             # layer 6 — measure, writing bench/current.txt
make bench-check       # layer 6 — measure and gate against the baseline
make bench-baseline    # layer 6 — re-record the gated baseline
make fuzz              # layer 7 — every fuzz target against its seed corpus
make fuzz-target       # layer 7 — one target continuously (PKG=, FUZZ=)
make lint              # layer 10 + gofmt + vet
make lint-arch         # layer 10 — architecture boundaries
make lint-docs         # layer 10 — traceability and links
make lint-license      # layer 10 — dependency licence policy
make cross             # layer 9 — every supported platform compiles
make ci                # what CI runs on every push
make test-all          # everything except extended fuzzing
```

`make help` lists them all.

Pre-commit runs layers 1–2 plus lint. Pull requests run everything except
extended fuzzing. Nightly runs extended fuzzing and the full benchmark suite with
statistical comparison against the recorded baseline.

## 14. Definition of done

A change is complete when:

1. Unit tests cover the new code to its area's target.
2. New IR, codec, or mutator behaviour has property tests.
3. Behaviour reachable from an untrusted input has a self-fuzzing entry point.
4. Performance-relevant changes include benchmark results.
5. New platform code declares capability and skips explicitly where unavailable.
6. Security-relevant changes have a corresponding test in layer 12.
7. Architectural changes update the relevant ADR or add a new one.
8. `CHANGELOG.md` is updated.
