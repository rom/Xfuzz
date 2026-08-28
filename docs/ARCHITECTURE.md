# Xfuzz — Architecture

> Structural companion to [DESIGN.md](DESIGN.md). Where DESIGN explains *what and
> why*, this document specifies *how it is put together*: components, boundaries,
> interfaces, data flow, and the traceability matrix.

## 1. System overview

```
┌──────────────┐        ┌──────────────────┐
│  xfuzz (CLI) │        │  Web console     │   embedded SPA, embed.FS
└──────┬───────┘        └────────┬─────────┘
       │ gRPC                    │ REST + WebSocket
       └───────────┬─────────────┘
                   ▼
        ┌────────────────────────┐
        │      xfuzzd            │   control plane
        │  ┌──────────────────┐  │
        │  │ campaign manager │  │   lifecycle, config resolution, supervision
        │  │ event bus        │  │   downsampled fan-out, corpus sync
        │  │ triage pipeline  │  │   classify → bucket → minimise → verify
        │  │ safety layer     │  │   sandbox, scope guard, audit    ← chokepoint
        │  │ store            │  │   SQL metadata + CAS blobs
        │  └──────────────────┘  │
        └───────────┬────────────┘
                    │ supervises (process boundary)
       ┌────────────┼────────────┐
       ▼            ▼            ▼
  ┌─────────┐  ┌─────────┐  ┌─────────┐
  │ worker  │  │ worker  │  │ worker  │   independent engine instances
  │ ┌─────┐ │  └─────────┘  └─────────┘   own RNG stream, own strategy
  │ │loop │ │
  │ └──┬──┘ │
  └────┼────┘
       ▼ (always through the safety layer)
  ┌─────────┐
  │ target  │   sandboxed process / socket / PTY / display
  └─────────┘
```

Three process boundaries, each load-bearing:

| Boundary | Why it exists |
| --- | --- |
| client ↔ daemon | Campaigns outlive clients; one authorization and audit chokepoint (ADR-0003) |
| daemon ↔ worker | Crash isolation, independent GC, per-worker sandboxing (ADR-0015) |
| worker ↔ target | The target is hostile; isolation is mandatory (ADR-0012) |

## 2. Package layout

```
github.com/rom/Xfuzz
├── cmd/
│   ├── xfuzz/              CLI client
│   ├── xfuzzd/             daemon
│   ├── xfuzz-worker/       worker process
│   └── xfuzz-cc/           compiler wrapper (instrumentation)
├── pkg/                    public, stable API surface
│   ├── ir/                 input IR: nodes, fixups, traversal, arena
│   ├── schema/             .xfg grammar DSL, importers
│   ├── codec/              parse/serialise between bytes and IR
│   ├── mutate/             mutators, mutator scheduling
│   ├── generate/           grammar-driven generation
│   ├── feedback/           Observer, Feedback, Objective + algebra
│   ├── executor/           Executor interface + tiers T0–T7
│   ├── corpus/             corpus, testcase, provenance, scheduler
│   ├── state/              state model, inference, state scheduling
│   ├── campaign/           campaign config schema, resolution, validation
│   └── plugin/             external plugin protocol + Starlark host
├── internal/
│   ├── engine/             the fuzz loop, stages, worker runtime
│   ├── store/              SQL metadata + CAS blob store, migrations
│   ├── triage/             classify, bucket, minimise, verify
│   ├── safety/             sandbox, scope guard, audit log
│   ├── api/                gRPC services + REST gateway
│   ├── daemon/             campaign manager, supervision, event bus
│   ├── metrics/            counters, series, health diagnostics
│   ├── sync/               cross-worker corpus synchronisation
│   └── platform/           OS-specific: linux/ darwin/ windows/
├── web/                    TypeScript SPA → embedded static assets
├── runtime/                xfuzz-rt: C coverage runtime (target-side)
├── testdata/
│   ├── targets/            planted-bug integration targets
│   └── corpora/            reference corpora
├── bench/                  benchmark harness (ASR-0007 gates)
└── docs/
```

Rules that keep the layering honest:

- `pkg/` never imports `internal/`.
- `pkg/ir`, `pkg/feedback`, `pkg/corpus` never import `pkg/executor` — the core
  must not know how inputs are delivered.
- Nothing outside `internal/platform` uses build tags for OS differences.
- Nothing outside `internal/safety` spawns a process or opens a socket.

## 3. Core interfaces

Illustrative signatures fixing the contracts; details will move during
implementation, the boundaries will not.

### 3.1 Input IR — `pkg/ir`

```go
type Kind uint8

const (
    KindBytes Kind = iota; KindInt; KindStr; KindStruct
    KindRepeat; KindChoice; KindOpt; KindRef; KindDerived
)

type Node struct {
    Kind     Kind
    Name     string
    Children []*Node
    Raw      []byte      // leaf payload
    Meta     *NodeMeta   // type constraints, derivation rule, schema link
}

// Fixup recomputes derived nodes in dependency order after mutation.
// Suppressed derivations are left inconsistent on purpose (ASR-0014).
func Fixup(root *Node, suppress SuppressSet) error

type Arena interface {          // pooled allocation: ASR-0007 steady state
    New(Kind) *Node
    Clone(*Node) *Node          // copy-on-write subtree
    Release(*Node)
}
```

### 3.2 Execution and observation — `pkg/executor`, `pkg/feedback`

```go
type Executor interface {
    Run(ctx context.Context, in *ir.Node, obs []Observer) (ExitKind, error)
    Reset(ResetPolicy) error
    Capabilities() Caps          // tier, granularity, platform, measured overhead
}

type Observer interface {
    Pre() error                  // arm before execution
    Post(ExitKind) error         // harvest after execution
    Reset()
}

type Feedback interface {
    IsInteresting(obs []Observer) (bool, Score, error)
    Append(tc *corpus.Testcase)  // commit novelty state on admission
    Discard()                    // roll back on rejection
    Name() string                // attribution: which feedback admitted this seed
}

type Objective interface {
    IsFinding(obs []Observer, ek ExitKind) (bool, FindingMeta, error)
}

// Algebra — ADR-0007
func All(...Feedback) Feedback
func Any(...Feedback) Feedback
func Not(Feedback) Feedback
func Fast(cheap, expensive Feedback) Feedback   // short-circuit ordering
```

The hot path holds a **static ordered slice of concrete implementations**; no
reflection, no `interface{}` boxing per execution, no channel round-trips.

### 3.3 Corpus and scheduling — `pkg/corpus`

```go
type Testcase struct {
    ID         Digest          // content address
    Input      *ir.Node
    Meta       Metadata        // energy, exec time, coverage delta, state path
    Provenance Provenance      // parent, operators applied, RNG stream position
}

type Scheduler interface {
    Next(*Corpus) (*Testcase, Energy, error)
    Update(*Testcase, Score)
}
```

### 3.4 State — `pkg/state`

```go
type StateFn func(resp Response) Label       // pluggable; ADR-0010
type Model struct { States []Label; Transitions []Transition }

type StateScheduler interface {
    NextState(*Model) Label                  // which state to target
    NextMessage(sess *ir.Node, target Label) int   // which message to mutate
}
```

### 3.5 Safety — `internal/safety`

Every process spawn and every outbound connection routes through here. There is
no other path.

```go
type Sandbox interface {
    Level() Level                            // strong | moderate | minimal
    Spawn(ctx context.Context, spec ProcSpec) (Process, error)
}

type ScopeGuard interface {
    Allow(network, address string) error     // default-deny; ADR-0012
    Record(decision Decision)                // append-only, hash-chained audit
}
```

## 4. The fuzz loop

Inside one worker, single-threaded and allocation-free in steady state:

```
  ┌─► Scheduler.Next()                 pick seed + energy
  │        │
  │        ▼
  │   Stage.Perform()                  havoc / splice / structured / cmplog / trim
  │        │  Mutator.Mutate(input)
  │        │  ir.Fixup(input, suppress)
  │        ▼
  │   Executor.Run(input, observers)   through the safety layer
  │        │
  │        ▼
  │   Feedback.IsInteresting()  ──yes──► Corpus.Add()  ──► publish to event bus
  │   Objective.IsFinding()     ──yes──► Findings.Add() ──► triage pipeline
  │        │
  └────────┘
```

Off the hot path, asynchronous and bounded:

- corpus writes (batched to the store)
- statistics aggregation (counters → periodic flush)
- corpus sync from sibling workers (pull from the event bus)
- triage (its own executor pool in the daemon)

### 4.1 Determinism

Every stochastic decision draws from a splittable RNG seeded
`H(campaign_seed ‖ worker_id ‖ stream_id)`. Separate streams for seed selection,
mutation choice, mutation parameters, and scheduling keep them independent, so
adding a stage does not perturb another stage's sequence. Wall-clock time and map
iteration order never influence a fuzzing decision (ASR-0008).

## 5. Data flow: from seed to finding

```
seed file ──► codec.Decode ──► ir.Node ──► Corpus (store: SQL meta + CAS blob)
                                   │
                                   ▼
                            Scheduler picks
                                   │
                            Mutator + Fixup
                                   │
                            codec.Encode ──► bytes ──► Executor ──► target
                                                            │
                                        Observers ◄─────────┘
                                            │
                     ┌──────────────────────┴───────────────────┐
                     ▼                                          ▼
              Feedback: novel?                            Objective: finding?
                     │ yes                                      │ yes
                     ▼                                          ▼
              Corpus.Add + sync                         triage: classify →
                                                        bucket → minimise →
                                                        verify → Finding
                                                                │
                                                                ▼
                                                        console / CLI / export
```

## 6. Storage model

Hybrid, per ADR-0008.

**SQL metadata** (`modernc.org/sqlite`, WAL, writes funnelled through the daemon):

| Table | Contents |
| --- | --- |
| `campaign` | config digest, seed, status, checkpoint pointer, schema version |
| `testcase` | blob digest, coverage summary, energy, discovery time, provenance |
| `coverage` | per-campaign coverage state and history series |
| `finding` | bucket, classification, reproducibility rate, triage state, notes |
| `bucket` | bucketing strategy version, signature, representative finding |
| `worker` | pid, strategy, health, RNG stream position |
| `audit` | append-only, hash-chained safety and lifecycle events |

**Content-addressed blobs** on disk: inputs, sessions, minimised reproducers,
sanitizer output, captures. Digest-keyed, compressed, de-duplicated — the digest
doubles as stable provenance identity.

**Disk budgets** are enforced per campaign with a defined culling policy (corpus
minimisation by coverage redundancy; per-bucket finding caps), and culling is
reported rather than silent (ASR-0015).

**Checkpointing** writes corpus frontier, scheduler state, coverage state, and
per-worker RNG position in one atomic transaction.

## 7. Concurrency and process model

| Unit | Concurrency | Rationale |
| --- | --- | --- |
| Daemon | Goroutines per campaign, per client, per triage job | I/O-bound coordination |
| Worker | One fuzz-loop goroutine; goroutines for I/O and observation | Cache-friendly, allocation-free hot path |
| Target | Own process, sandboxed | Hostile code isolation |

Workers do not share memory. Corpus sync is publish/subscribe through the
daemon's event bus, which is also exactly where a v2 distributed coordinator
would attach without redesign (ADR-0015).

Ensemble fuzzing: workers in one campaign may run different mutator weights,
power schedules, or feedback stacks — strategy diversity beats N identical
workers.

## 8. Platform abstraction

Everything OS-specific lives in `internal/platform`. Pure Go by default, native
code only behind `//go:build cgo` with a fallback (ADR-0017).

| Concern | Linux | macOS | Windows |
| --- | --- | --- | --- |
| Fast execution | fork server (T2) | fork server (T2) | process pool (T3) |
| Shared memory | `memfd`/POSIX shm | POSIX shm | named file mapping |
| Isolation | namespaces, seccomp, cgroups v2 → `strong` | sandbox profile, rlimits → `moderate` | Job Objects, restricted tokens → `moderate` |
| Coverage | sancov, fork server, Frida, QEMU, Intel PT | sancov, fork server, Frida | sancov, Frida |
| GUI driver | AT-SPI + X11/Wayland | Accessibility API | UI Automation |

`xfuzz doctor` reports what is available on the running host and *why* anything
is not, so degraded capability is visible rather than mysterious.

## 9. API surface

gRPC services, with a REST/JSON gateway for the browser and scripting:

| Service | Responsibility |
| --- | --- |
| `CampaignService` | validate, create, start, pause, resume, stop, explain |
| `MetricsService` | live metrics, historical series, health diagnostics |
| `CorpusService` | browse, inspect (IR + hex), import, export, minimise |
| `FindingService` | list, filter, triage state, export, replay, re-bucket |
| `EventService` | streaming events (WebSocket/SSE), server-side downsampled |
| `AdminService` | workers, capabilities, audit log, version |

CLI commands and console views are both defined against this surface, and a
parity test asserts neither side has a capability the other lacks (ASR-0005).

Event streaming is **lossy by design** for high-rate events: the server
downsamples and batches so a browser can never back-pressure the engine.

## 10. Extension points

| Point | Interface | Native | Plugin | Script |
| --- | --- | --- | --- | --- |
| Mutator | `mutate.Mutator` | ✔ | ✔ | ✔ |
| Generator | `generate.Generator` | ✔ | ✔ | ✔ |
| Codec | `codec.Codec` | ✔ | ✔ | — |
| Schema importer | `schema.Importer` | ✔ | ✔ | — |
| Observer | `feedback.Observer` | ✔ | ✔ | — |
| Feedback | `feedback.Feedback` | ✔ | ✔ | ✔ |
| Objective / oracle | `feedback.Objective` | ✔ | ✔ | ✔ |
| Executor | `executor.Executor` | ✔ | ✔ | — |
| State function | `state.StateFn` | ✔ | ✔ | ✔ |
| Scheduler | `corpus.Scheduler` | ✔ | ✔ | ✔ |
| Bucketing | `triage.Bucketer` | ✔ | ✔ | ✔ |

Native is the reference tier; plugin and script bindings are generated from and
validated against the same interfaces so semantics cannot drift (ADR-0010).
Time spent inside extensions is reported as a first-class metric.

## 11. Traceability

Every ASR is satisfied by at least one ADR; every ADR serves at least one ASR.
CI lints this matrix (see [TESTS.md](TESTS.md) § Documentation tests).

| ASR | Satisfied by |
| --- | --- |
| ASR-0001 Multi-domain target coverage | ADR-0001, ADR-0004, ADR-0005, ADR-0009, ADR-0013, ADR-0014 |
| ASR-0002 Stateless and stateful fuzzing | ADR-0004, ADR-0005, ADR-0006, ADR-0007, ADR-0013, ADR-0014 |
| ASR-0003 Black-, grey-, and white-box operation | ADR-0002, ADR-0007, ADR-0009 |
| ASR-0004 Pluggable guidance strategies | ADR-0006, ADR-0007, ADR-0010, ADR-0013 |
| ASR-0005 Dual interface — CLI and web console | ADR-0003, ADR-0011, ADR-0016 |
| ASR-0006 Cross-platform support | ADR-0002, ADR-0009, ADR-0012, ADR-0017 |
| ASR-0007 Throughput and scalability | ADR-0001, ADR-0002, ADR-0009, ADR-0015, ADR-0017, ADR-0021 |
| ASR-0008 Reproducibility and determinism | ADR-0008, ADR-0015, ADR-0016, ADR-0021 |
| ASR-0009 Extensibility | ADR-0010 |
| ASR-0010 Safety, isolation, and authorization | ADR-0003, ADR-0012, ADR-0014, ADR-0016 |
| ASR-0011 Finding quality and triage | ADR-0008, ADR-0011, ADR-0021 |
| ASR-0012 Observability and resumability | ADR-0003, ADR-0008, ADR-0011 |
| ASR-0013 Corpus and format interoperability | ADR-0001, ADR-0005, ADR-0008 |
| ASR-0014 Input validity and structure awareness | ADR-0005, ADR-0007, ADR-0010, ADR-0021 |
| ASR-0015 Operability and deployment | ADR-0003, ADR-0008, ADR-0011, ADR-0015, ADR-0016, ADR-0017 |

Three ADRs appear in no row: **ADR-0018** (licensing) and **ADR-0019** (module
identity) are project constraints rather than responses to a requirement, and
**ADR-0020** (MVP sequencing) serves every ASR by deciding *when* each is
satisfied rather than *how*.

## 12. Architectural risks

| Risk | Where it bites | Mitigation |
| --- | --- | --- |
| IR allocation cost in the hot loop | `pkg/ir`, engine loop | Arena + copy-on-write; benchmark gates from the first commit |
| Feedback dispatch overhead | `pkg/feedback` | Static concrete slice, no boxing; measured engine overhead |
| SQLite write contention with N workers | `internal/store` | Writes funnel through the daemon, WAL, batched |
| Blob GC vs. database references | `internal/store` | Reference counting with a tested sweep; fault-injection tests |
| Sandbox setup cost per execution | `internal/safety` | Per-worker/per-pooled-process setup, never per execution |
| Coverage semantics differ per backend | `pkg/executor`, `pkg/feedback` | Backend recorded on every coverage map; differential tests |
| Console scaling on large corpora | `internal/api`, `web/` | Server-side aggregation; never push raw data |
