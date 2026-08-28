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

Also gated:

- **Engine overhead** < 10 % of wall-clock at each tier.
- **Scaling**: 1 → N workers yields ≥ 0.85 × N aggregate throughput up to the
  physical core count.
- **Steady-state allocations**: zero in the fuzz loop.
- **Effectiveness**: time-to-first-bug and coverage-over-time on planted targets
  tracked as regressions in their own right.

A ≥ 10 % regression on any gated metric **fails the build**.

Benchmarks are noisy on shared CI runners. Mitigation: dedicated runners where
possible, multiple repetitions with statistical comparison rather than a single
sample, and a warm-up discard — a flaky gate that people learn to ignore is worse
than no gate.

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
| `linux-cgo` | Linux amd64 | Full suite, all tiers, benchmarks |
| `linux-nocgo` | Linux amd64 | Full suite, `CGO_ENABLED=0` |
| `linux-arm64` | Linux arm64 | Full suite |
| `darwin` | macOS arm64 | Full suite minus Linux-only tiers |
| `windows` | Windows amd64 | Full suite minus POSIX-only tiers |
| `cross-build` | Linux | `GOOS`/`GOARCH` matrix compiles |

Platform-unavailable capabilities are asserted to **skip explicitly with a
reason**, never to fail silently or pass vacuously — the same information
`xfuzz doctor` reports to users.

## 11. Layer 10 — Documentation and licence checks

- **ASR/ADR traceability lint**: every ASR names ≥ 1 satisfying ADR, every ADR
  names ≥ 1 served ASR, all cross-references resolve, and the matrix in
  `ARCHITECTURE.md` § 11 matches the files.
- **Link check** across `docs/`.
- **Config schema check**: every example campaign file in the docs validates
  against the published JSON Schema.
- **Licence compliance**: dependency scan fails the build on any licence outside
  ADR-0018's allowed set, or on any dependency missing from `NOTICE`.
- **Vulnerability scan**: `govulncheck` on every build.

## 12. Security tests

Security properties from [SECURITY.md](SECURITY.md) are executable tests, not
claims:

| Test | Asserts |
| --- | --- |
| Write outside workdir | Blocked by sandbox |
| Fork bomb | Contained by PID limit |
| Memory exhaustion | Contained by cgroup/Job Object |
| Connection to unlisted host | Blocked by scope guard, audited |
| Campaign without scope allowlist | Refuses to start |
| Starlark attempts I/O | Fails; no I/O possible |
| Audit log modified | Tamper detected by hash chain |
| Malformed fork-server handshake | Rejected without memory corruption |
| Oversized/deeply nested grammar | Rejected by limits, no OOM |
| Unauthenticated API request | Rejected |

## 13. Running the tests

```
make test              # layers 1, 2 — fast, pre-commit
make test-integration  # layers 3, 4, 5, 8
make test-security     # layer 12
make bench             # layer 6, with regression comparison
make fuzz              # layer 7, time-bounded locally
make lint-docs         # layer 10
make test-all          # everything
```

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
