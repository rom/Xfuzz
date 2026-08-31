# Xfuzz — Architecture

> Structural companion to [DESIGN.md](DESIGN.md). Where DESIGN explains *what and
> why*, this document specifies *how it is put together*: components, boundaries,
> interfaces, data flow, and the traceability matrix.

## 1. System overview

```
┌──────────────┐        ┌──────────────────┐
│  xfuzz (CLI) │        │  Web console     │   embedded SPA, embed.FS
└──────┬───────┘        └────────┬─────────┘
       │ HTTP/JSON               │ HTTP/JSON + SSE
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
│   ├── xfuzz-cc/           compiler wrapper (instrumentation)
│   └── xfuzz-sandbox/      confines itself, then becomes the target (ADR-0022)
├── pkg/                    public, stable API surface
│   ├── rng/                deterministic, splittable, seekable randomness
│   ├── ir/                 input IR: nodes, fixups, traversal, arena
│   ├── schema/             .xfg grammar DSL, importers
│   ├── codec/              parse/serialise between bytes and IR, including the
│   │                       schema-driven one a .xfg grammar becomes
│   ├── mutate/             mutators, mutator scheduling
│   ├── generate/           grammar-driven generation
│   ├── feedback/           Observer, Feedback, Objective + algebra
│   ├── executor/           Executor interface + tiers T0-T7: T0 in-process,
│   │                       T2 fork server, T3 pool, T4 subprocess, T6 sessions
│   ├── corpus/             corpus, testcase, provenance, scheduler
│   ├── corpusio/           AFL and libFuzzer corpus import/export
│   ├── state/              state model, inference, state feedback, scheduling
│   ├── campaign/           campaign config schema, resolution, validation
│   ├── plugin/             external plugin protocol (ADR-0025)
│   │   └── script/         Starlark host: hermetic, bounded, campaign-local
├── internal/
│   ├── engine/             the fuzz loop, stages, worker runtime
│   ├── store/              SQL metadata + CAS blob store, migrations
│   ├── triage/             classify, bucket, minimise, verify
│   ├── safety/             sandbox, scope guard, audit log
│   ├── extension/          turns a campaign's plugin declarations into running,
│   │                       confined processes — the one place that may, because
│   │                       pkg/plugin cannot spawn and internal/safety must not
│   │                       know the protocol
│   ├── api/                HTTP/JSON services + SSE event stream (ADR-0024)
│   ├── client/             the API client the CLI is built on
│   ├── daemon/             campaign manager, supervision, event bus
│   ├── worker/             builds an engine from a campaign file, speaks the
│   │                       worker protocol
│   ├── metrics/            counters, series, health diagnostics
│   ├── corpussync/         cross-worker corpus synchronisation
│   ├── version/            build identity, injected at link time
│   ├── testenv/            fixtures for integration tests, and nothing else
│   └── platform/           OS-specific: shared memory, locks, process groups,
│                           signals, sandbox — one file per build constraint
├── web/                    TypeScript SPA → embedded static assets
├── runtime/                xfuzz-rt: the C coverage runtime, embedded for
│   └── csrc/               xfuzz-cc to compile into targets (never into Xfuzz)
├── test/
│   └── e2e/                milestone exit criteria, measured against the
│                           shipped binaries rather than the packages behind them
├── testdata/
│   ├── targets/            planted-bug integration targets
│   └── corpora/            reference corpora
├── bench/                  benchmark harness + gated baseline (ASR-0007)
├── tools/                  repo tooling, each enforcing a documented rule
│   ├── archlint/           the layering rules below
│   ├── docslint/           ASR/ADR traceability and link resolution
│   ├── licensecheck/       ADR-0018 dependency licence policy
│   └── benchcmp/           benchmark regression gate
├── .github/workflows/      CI matrix (docs/TESTS.md section 10)
└── docs/
```

`internal/corpussync` is named for its job rather than as `internal/sync`, which
would shadow the standard library at every use site.

Rules that keep the layering honest:

| Rule | Meaning |
| --- | --- |
| `pkg-no-internal` | `pkg/` never imports `internal/` |
| `core-no-executor` | `pkg/ir`, `pkg/feedback`, `pkg/corpus` never import `pkg/executor` — the core must not know how inputs are delivered |
| `platform-build-tags` | Nothing outside `internal/platform` carries GOOS or GOARCH build constraints (a bare `cgo` constraint is fine — ADR-0017) |
| `spawn-confinement` | Nothing outside `internal/safety` spawns a process; it reaches OS specifics through `internal/platform`. `cmd/xfuzz-cc`, `cmd/xfuzz-sandbox` and `internal/testenv` are allowlisted — the first two *are* exec wrappers and the third exists only to build test fixtures — and the allowlist is in the lint source where a reviewer sees it |
| `dial-confinement` | Nothing outside `internal/safety` opens an outbound connection — every one must pass the scope guard (ADR-0012) |
| `no-cmd-import` | Nothing imports `cmd/` |
| `no-stdlib-plugin` | Nothing imports Go's `plugin` package (rejected by ADR-0010) |

`pkg/rng` sits below everything because ASR-0008 forbids implicitly seeded
randomness anywhere in the engine: every stochastic decision draws from an
explicit stream, and the streams are numbered so that adding one cannot perturb
another.

These are enforced by `tools/archlint`, which runs as part of `go test ./...`,
not by convention. Exceptions live in an explicit allowlist in that package,
where they are visible in review; `tools/archlint` additionally tests that each
rule *fires* against a deliberately violating fixture, since a lint that only
ever passes is indistinguishable from one that checks nothing.

## 3. Core interfaces

Illustrative signatures fixing the contracts; details will move during
implementation, the boundaries will not.

### 3.1 Input IR — `pkg/ir`

```go
type Kind uint8

const (
    KindBytes Kind = iota + 1; KindInt; KindStr; KindStruct
    KindRepeat; KindChoice; KindOpt; KindRef; KindDerived
)

type Node struct {
    Kind   Kind
    Width  uint8   // KindInt, KindDerived: encoded byte width
    Endian Endian
    flags  uint8   // shared (copy-on-write), present, signed

    Sel int32      // KindChoice: selected alternative
    Val int64      // KindInt, KindDerived: the value

    Name     string
    Raw      []byte  // KindBytes, KindStr: the payload
    Children []*Node

    Derive *Derivation // KindDerived
    Target *Ref        // KindRef
}
```

Scalar detail is stored inline rather than behind a `Meta` pointer: the hot loop
pools these densely, and a second indirection per node costs both a cache miss
and an allocation to pool. `Derivation` and `Ref` are immutable, so their
pointers are shared by every clone rather than copied.

Encoding is generic — the wire form of a tree is the concatenation of its leaves
in document order — which is what confines format knowledge to *decoding*:

```go
func EncodedLen(n *Node) int
func AppendEncode(dst []byte, n *Node) []byte   // reuses dst; no allocation
```

Fixup recomputes derived values after mutation. A `Fixer` carries reusable
scratch state so that repeated fixups allocate nothing:

```go
type Fixer struct{ /* pooled buffers, maps, task lists */ }
func (f *Fixer) Fix(root *Node, sup Suppress) ([]byte, error) // returns the encoding
func Fixup(root *Node, sup Suppress) error                    // convenience; allocates
```

The pass is acyclic by construction. Every derived node has a fixed width, so no
derived *value* can change any node's *size*; sizes and offsets are therefore
computed once, up front. Length, Count, and Offset read only those and can never
form a cycle. Only Checksum reads other nodes' values, so only checksums are
ordered — by span containment, which is a partial order, resolved with Kahn's
algorithm in document order so the result is deterministic. A checksum covering
its own field is reported as a cycle unless `SelfZero` says how to resolve it.

```go
type Arena struct{ /* bump-allocated slabs */ }   // ASR-0007 steady state

func (a *Arena) New(k Kind) *Node
func (a *Arena) Clone(n *Node) *Node              // deep copy; shares nothing
func (a *Arena) Reset()                           // rewinds; frees nothing

func (a *Arena) Share(n *Node) *Node                            // mark copy-on-write
func (a *Arena) MutablePath(root **Node, steps ...Step) (*Node, error) // path-copy
```

The Arena is a bump allocator over fixed slabs rather than a free-list: `Reset`
rewinds the pointers, so after the first few iterations the slabs are large
enough and steady-state fuzzing allocates nothing. Slabs are fixed-size and
never reallocated, because growing one backing array would invalidate every
outstanding `*Node`. There is no `Release`; individual nodes are never returned.

Payloads are copied into the arena on clone rather than shared, so a mutator can
flip a bit in place — the fastest mutation there is — without corrupting the
corpus entry the clone came from.

### 3.2 Execution and observation — `pkg/executor`, `pkg/feedback`

```go
type Input struct {
    Bytes []byte   // the encoded form; what nearly every executor delivers
    Node  *ir.Node // the structure, for session and driver executors
}

type Executor interface {
    Name() string
    Run(ctx context.Context, in Input, obs []feedback.Observer) (feedback.ExitKind, error)
    Reset(ResetPolicy) error
    Capabilities() Caps   // tier, backend, granularity, platform, honesty flags
    Close() error
}

type Observer interface {
    Name() string
    Pre() error          // arm before execution
    Post(ExitKind) error // harvest after execution
    Reset()
}

type Feedback interface {
    Name() string
    IsInteresting(obs []Observer, ek ExitKind) (bool, Score, error)
    Append()  // commit the state observed by the most recent judgement
    Discard() // roll it back
}

type Objective interface {
    Name() string
    IsFinding(obs []Observer, ek ExitKind) (bool, Finding, error)
}

// Algebra — ADR-0007
func All(...Feedback) Feedback
func Any(...Feedback) Feedback
func Not(Feedback) Feedback
func Fast(cheap, expensive Feedback) Feedback   // short-circuit ordering
```

`Run` takes encoded bytes rather than a tree because the engine has already
encoded the input — the fixup pass returns the encoding — and encoding twice on
the hot path is pure waste. `Node` travels alongside for the executors that need
structure rather than a blob.

`Append` takes no argument. The obvious signature hands it the testcase, which
would make `pkg/feedback` depend on `pkg/corpus`; the engine already knows which
input it just judged, so the dependency buys nothing.

`ExitKind` lives in `pkg/feedback`, not `pkg/executor`: the core must not depend
on how inputs are delivered, so executors import feedback and never the reverse.
`ExitError` — the harness failed — is deliberately not a fault, because
reporting infrastructure failures as findings is how a fuzzer loses its
credibility.

The hot path holds a **static ordered slice of concrete implementations**; no
reflection, no `interface{}` boxing per execution, no channel round-trips.

#### The spawn boundary

`pkg/executor` cannot import `internal/safety` — `pkg/` never imports
`internal/` — and the architecture lint forbids it importing `os/exec` at all.
So it declares the interface and `internal/safety` implements it:

```go
type Spawner interface {
    Run(ctx context.Context, spec ProcSpec) (ProcResult, error)
    Start(ctx context.Context, spec ProcSpec) (Handle, error)
    IsolationLevel() string   // what is enforced, not what is planned
}

type SharedMemoryProvider interface {   // implemented in internal/platform
    Create(size int) (SharedMemory, error)
    Available() bool
}
```

That inversion is the point rather than a workaround. ADR-0012 makes confinement
mandatory, and the only way to guarantee a rule like that is to leave executors
no other way to start a process. The lint enforces the same rule from the other
side.

#### Tiers, measured

| Tier | Measured here | Notes |
| --- | --- | --- |
| T2 fork server, do-nothing target | 3,129 exec/s | the protocol floor |
| T2 with coverage collection | 3,103 exec/s | shared memory costs about 1% |
| T2 realistic target with coverage | 2,787 exec/s | 89% of the floor |
| T4 subprocess | 742 exec/s | 3.8× slower; what the fork server buys |

Measured on a 4-core Firecracker microVM where bare `fork`+`_exit` tops out at
about 5,500/s. ASR-0007's 5,000 exec/s floor is stated for a commodity 8-core
host; the gate asserts it only where the host can support it, and asserts the
ratio against the do-nothing floor everywhere (docs/TESTS.md § 7).

### 3.2a Mutation — `pkg/mutate`, `pkg/rng`

```go
type Mutator interface {
    Name() string
    CanApply(c *Ctx, n *ir.Node) bool   // cheap; called per node during selection
    Mutate(c *Ctx, n *ir.Node) bool     // false means "no change", not "error"
}

type Op struct {                        // one entry of a provenance chain
    Mutator string
    Path    []int                       // child indices from the root
    RandPos uint64                      // parameter-stream position
}

func (s *Scheduler) Mutate(c *Ctx, root *ir.Node) []Op
func (s *Scheduler) RecordOutcome(ops []Op, interesting, finding bool)
func (s *Scheduler) Report() []NamedStats
```

`CanApply` takes the context, not just the node, so an operator can decline when
its preconditions are absent — no dictionary, no donor, a length bound already
reached. Declining there rather than inside `Mutate` is what stops the scheduler
spending its budget on operators that cannot act.

Selection is **operator-first**: draw an operator by weight, then draw a node it
can act on. The reverse — pick a node, then choose among the operators that fit
it — was tried first and gives the mix to whichever operator has the broadest
applicability rather than to the configured weights.

Three independent RNG streams back one mutation round (`rng.StreamMutatorSelect`,
`StreamMutatorParam`, `StreamStructure`), so changing the operator mix does not
shift parameter draws, and vice versa. A recorded `Op` — operator, path, stream
position — is enough to reconstruct the mutation on a fresh tree.

### 3.2b Schema and generation — `pkg/schema`, `pkg/generate`

`pkg/schema` parses the `.xfg` grammar language into a `Schema`; `pkg/generate`
walks one to build IR trees. Generation complements mutation rather than
replacing it: mutation inherits its corpus's blind spots, while generation
reaches shapes no seed contained, at the cost of a real file's accumulated
realism. Both produce the same IR, so a campaign runs either or both.

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
type Sandbox struct { ... }                  // the confinement policy
func (s *Sandbox) Probe() (Level, platform.SandboxCapabilities)
func (s *Sandbox) Check(ctx context.Context) error   // refuse a campaign the host cannot confine
func (s *Sandbox) Explain() string                   // the level, and why it is not higher

type Scope struct { ... }                    // the network allowlist
func (s *Scope) Validate(remote bool) error  // refuse at start, not at the first packet
func (s *Scope) Check(ctx context.Context, addr netip.AddrPort) error
func (s *Scope) Dial(ctx context.Context, network, address string) (net.Conn, error)
```

Two mechanisms of the Linux sandbox — resource limits and the seccomp filter —
can only be installed by the process that will *become* the target, between fork
and exec. Go offers no hook there, so `cmd/xfuzz-sandbox` is that process: it
sets its own limits, installs its own filter, and execs the target, which
inherits both. This is the same shape as every other sandbox launcher, for the
same reason. Where the helper is absent, the isolation level reported drops
accordingly rather than the campaign silently running unlimited.

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

A stateful campaign is the same picture with one substitution: the unit is a
session rather than an input, so the executor delivers a sequence of messages
and reads a reply to each, a state observer labels those replies, and state
novelty joins code coverage in the feedback stack. The corpus, the scheduler,
the mutators and the triage pipeline are unchanged — which is ASR-0002's whole
claim, that statefulness is an axis rather than a second tool.

What is genuinely different is *which* part of the input gets mutated. A session
is a funnel: the handshake has to stay valid for anything past it to be
reachable, so a mutator picking a uniformly random message spends nearly all its
budget on the entrance. The state scheduler picks a rarely-visited state to aim
for, finds the message that reached it in that session's own trace, and mutates
at or after that point (ADR-0006).

The two halves of that fork run in different processes. Everything down to
`Objective` is the worker's, in its hot loop; triage is the daemon's, on a
bounded queue. A worker that waited for a reproducer to be re-run a hundred
times would be a worker that had stopped fuzzing, and the queue is bounded
because a campaign that has found an easy bug produces findings faster than they
can be triaged — the overflow is dropped and counted rather than allowed to
stall the loop.

Triage stays available after the campaign has finished, which is the point of
the daemon owning findings rather than the workers: `xfuzz replay` and
`xfuzz minimize` re-run a reproducer through the same runner, days later, on a
campaign whose workers are long gone (ADR-0003).

## 6. Storage model

Hybrid, per ADR-0008. Schema version 1 is implemented in `internal/store`.

**SQL metadata** (`modernc.org/sqlite`, WAL, `synchronous=NORMAL`, one writer):

| Table | Contents |
| --- | --- |
| `meta` | schema version, audit chain head |
| `campaign` | name, config digest, seed, status, timestamps |
| `testcase` | blob digest, size, coverage, energy counters, discovery time, provenance |
| `bucket` | bucketing strategy, signature, kind, count, first seen |
| `finding` | bucket, classification, reproducibility trials and rate, triage state, notes |
| `checkpoint` | coverage map, execution count, corpus size, per-stream RNG positions |
| `audit` | append-only, hash-chained safety and lifecycle events |

Per-campaign coverage history and per-worker health arrive with the daemon in
M5; the checkpoint carries what a resume needs today.

**Content-addressed blobs** on disk under a two-level fan-out: inputs, minimised
reproducers, and later sessions and captures. The digest doubles as stable
provenance identity, so de-duplication and integrity checking are the same
mechanism.

Two invariants make the pair safe together. The blob is written before the row
that points at it, so a crash can only leave an orphan — which collection
reclaims — never a row promising a payload that was never written. And a blob is
written to a temporary name and renamed into place, so a reader never observes a
partial one.

**Disk budgets** are enforced per campaign. Culling never touches favoured
entries or finding reproducers, ranks the rest by coverage per byte, and breaks
ties on the digest so two runs of a campaign cull identically. A budget that
cannot be met after culling is reported as such rather than silently exceeded
(ASR-0015).

**Blob collection** keeps anything younger than a grace window, because a live
payload is always briefly unreferenced by construction.

**Checkpointing** is a single-row upsert inside a transaction, so a checkpoint is
either wholly the old one or wholly the new one. It holds the accumulated
coverage map (deflated), the execution count, the corpus size, and each RNG
stream's position by name. The corpus is *not* in it: every admitted entry is
already durable when it is found, and putting it in the checkpoint would mean
rewriting the whole corpus on every one.

**The audit log** is hash-chained, with every field length-prefixed before
hashing so that moving a character across a field boundary is not an undetectable
edit, and with the chain head mirrored in `meta` so that truncation is detectable
as well as modification. This is tamper evidence, not tamper proofing: anyone who
can write the database can rewrite the chain and the head together. What it buys
is that accidental corruption, a partial restore and a careless edit are all
caught, and that a deliberate rewrite has to be deliberate.

### 6.1 Triage — `internal/triage`

Triage is what makes a finding count a count of bugs. It is asynchronous by
construction: every operation re-runs the target, minimisation hundreds of times,
and none of it may happen on the fuzz loop's thread (§ 4). The engine records a
finding and moves on; a worker picks it up, and its queue is bounded so that a
campaign producing findings faster than they can be triaged is slowed by nothing.

```go
type Runner interface {                      // triage owns no executor
    Run(ctx context.Context, input []byte) (Outcome, error)
}

type Strategy interface {                    // bucketing is a judgement
    Name() string
    Signature(o Outcome, c Class) (string, bool)
}
```

Four strategies, because each is wrong in a different direction — frames need
symbols, markers need a program that names its own failures, coverage splits one
bug when the path in varies, signals merge unrelated bugs — and a chain that
tries them in order of evidence quality and records which one produced each
signature.

Two minimisers. Byte-level delta debugging cannot reduce a checksum-protected
format at all: deleting bytes invalidates the length and checksum covering them,
the parser bails before reaching the bug, and every deletion looks necessary.
Structured minimisation removes elements from the IR and lets the fixup pass
recompute what the removal invalidated — which is what the IR is for (ADR-0005),
applied where its absence is most expensive. Both preserve the failure *class*,
not merely "it still crashes", so a minimiser cannot wander to a different bug
and hand back its reproducer.

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

HTTP/JSON, described by a generated OpenAPI document (ADR-0024, which supersedes
ADR-0003's gRPC transport choice while keeping its service decomposition and its
daemon architecture intact). Six route groups:

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
downsamples and batches so a browser can never back-pressure the engine. It is
carried as server-sent events over the same listener, which is a close fit for a
stream that is server-to-client and droppable, and which reconnects without
client code.

The default listener is a **Unix domain socket** with filesystem permissions;
TCP with token authentication is opt-in and never the default (ADR-0003,
ADR-0012).

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
Time spent inside extensions is reported as a first-class metric —
`plugin_calls` and `plugin_seconds` on every metrics snapshot, with a
`plugin-slow` diagnostic when a campaign is spending more of its wall clock
inside an extension than in its target.

The plugin tier speaks the protocol in ADR-0025: framed JSON over the plugin's
own standard input and output, spawned and confined by `internal/safety` like
any other untrusted process, resolved from the campaign file by
`internal/extension`. A campaign names its plugins and the extensions it takes
from each; a name the plugin does not provide is a refusal at startup rather
than an extension that silently never fires.

The script tier is Starlark, chosen for hermeticity rather than familiarity: no
filesystem, no network, no clock, no imports, and deterministic execution, which
is what lets an untrusted campaign file carry logic without forfeiting replay
(ASR-0008, ASR-0010). A hermetic language can still loop forever and still build
a gigabyte string, so every call is bounded by a step budget and an allocation
budget, and a script that exceeds either is cancelled with a message naming
which.

**v1 scope.** The columns above are the design. What M8 delivers is the plugin
protocol with the three extension points ADR-0020 scoped for v1 — feedbacks,
mutators and objectives — and the script tier with objectives, mutators and
state functions. The remaining plugin points are the same protocol with more
message types, each needing its own wire representation of what it operates on.

A script has no feedbacks, and that is a property rather than a gap. Starlark
freezes a module's globals after it loads, so a script cannot accumulate
anything between calls — and a feedback's whole value is the novelty state it
accumulates. A feedback that needs memory belongs to the plugin tier, where a
process can remember.

## 11. Traceability

Every ASR is satisfied by at least one ADR; every ADR serves at least one ASR.
CI lints this matrix (see [TESTS.md](TESTS.md) § Documentation tests).

| ASR | Satisfied by |
| --- | --- |
| ASR-0001 Multi-domain target coverage | ADR-0001, ADR-0004, ADR-0005, ADR-0009, ADR-0013, ADR-0014 |
| ASR-0002 Stateless and stateful fuzzing | ADR-0004, ADR-0005, ADR-0006, ADR-0007, ADR-0013, ADR-0014 |
| ASR-0003 Black-, grey-, and white-box operation | ADR-0002, ADR-0007, ADR-0009, ADR-0026, ADR-0027 |
| ASR-0004 Pluggable guidance strategies | ADR-0006, ADR-0007, ADR-0010, ADR-0013, ADR-0028, ADR-0029 |
| ASR-0005 Dual interface — CLI and web console | ADR-0003, ADR-0011, ADR-0016, ADR-0024 |
| ASR-0006 Cross-platform support | ADR-0002, ADR-0009, ADR-0012, ADR-0017, ADR-0022, ADR-0025, ADR-0026, ADR-0027 |
| ASR-0007 Throughput and scalability | ADR-0001, ADR-0002, ADR-0009, ADR-0015, ADR-0017, ADR-0021, ADR-0027, ADR-0028 |
| ASR-0008 Reproducibility and determinism | ADR-0008, ADR-0015, ADR-0016, ADR-0021, ADR-0025, ADR-0029 |
| ASR-0009 Extensibility | ADR-0010, ADR-0025 |
| ASR-0010 Safety, isolation, and authorization | ADR-0003, ADR-0012, ADR-0014, ADR-0016, ADR-0022 |
| ASR-0011 Finding quality and triage | ADR-0008, ADR-0011, ADR-0021 |
| ASR-0012 Observability and resumability | ADR-0003, ADR-0008, ADR-0011, ADR-0024, ADR-0029 |
| ASR-0013 Corpus and format interoperability | ADR-0001, ADR-0005, ADR-0008 |
| ASR-0014 Input validity and structure awareness | ADR-0005, ADR-0007, ADR-0010, ADR-0021, ADR-0028 |
| ASR-0015 Operability and deployment | ADR-0003, ADR-0008, ADR-0011, ADR-0015, ADR-0016, ADR-0017, ADR-0023, ADR-0024 |

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
