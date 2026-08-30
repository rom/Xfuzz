# ADR-0026: `gocov` deferred; `blackbox` is the off-Linux path for v0.1

- **Status:** Accepted
- **Date:** 2026-08-30
- **Serves:** ASR-0003, ASR-0006

## Context

[ADR-0002](ADR-0002-pluggable-multi-backend-instrumentation.md) lists nine
instrumentation backends and names four of them — `sancov`, `gocov`,
`forkserver`, `blackbox` — as v1 work, with the rest phased.
[ADR-0020](ADR-0020-mvp-as-end-to-end-thin-slice.md) carries the same four into
the MVP scope table and, in its platform row, gives macOS and Windows
"T3/T4 + `blackbox`/`gocov`".

Three of the four exist. `gocov` does not, and the reason it does not is worth
recording as a decision rather than leaving as an unexplained absence, because
an ADR that lists a backend the code does not have is indistinguishable from an
ADR the code has drifted away from.

The gap is not effort. Go's coverage counters live in the instrumented process
and are written to `GOCOVERDIR` on exit, in a binary format that
`internal/coverage` decodes and no public API exposes. `runtime/coverage` can
emit that format; nothing in the standard library reads it back. Per-execution
coverage from a Go subprocess would therefore need one of:

- a file round-trip plus a `go tool covdata` invocation per execution, which
  costs more than the execution it measures — at T4's measured 559 exec/s the
  process spawn is already the dominant cost, and this would add a second one;
- a decoder for `internal/coverage`'s format, which is explicitly unstable and
  would break on a toolchain bump — against [ADR-0023](ADR-0023-go-1-25-toolchain-floor.md),
  whose whole point is that the floor moves forward;
- or in-process execution only, which is T0, where the Go harness already
  reports coverage through `pkg/feedback` without any of this.

## Decision

**`gocov` moves to the deferred column for v0.1.** The v0.1 instrumentation set
is `sancov`, `forkserver`, and `blackbox`.

**`blackbox` is the whole of the off-Linux story, and that is a supported mode
rather than a shortfall.** [ASR-0003](../asr/ASR-0003-black-grey-white-box-operation.md)
requires black-box operation to be first-class, and ADR-0002 already says the
core loop treats an empty coverage map as valid input. macOS and Windows get
T3 and T4 against `blackbox`, which `test/e2e/portable_test.go` runs on all
three platforms in CI.

**A pure-Go target out of process therefore gets `blackbox` in v0.1, and the
route that looks like it should work does not.** MVP_PLAN claimed one — build
with `-gcflags=all=-d=libfuzzer` against the runtime `xfuzz-cc` already ships,
"the same instrumentation by a shorter route". It was never tried. It does not
link:

```console
$ go build -tags libfuzzer -gcflags=all=-d=libfuzzer -o t .
runtime.libfuzzerTraceCmp4: relocation target __sanitizer_cov_trace_cmp4 not defined
... __sanitizer_cov_8bit_counters_init not defined
... __sanitizer_cov_pcs_init not defined
... __sanitizer_weak_hook_strcmp not defined
```

Go's libfuzzer mode emits against libFuzzer's **8-bit counter** interface —
the target owns an array of per-block counters that the runtime reads — while
`runtime/csrc/xfuzz-rt.c` implements the **trace-pc-guard** interface, where
the runtime owns the map and the target's instrumentation calls into it once
per edge. Those are two different contracts, not one contract with a missing
symbol. The claim is corrected in MVP_PLAN § 1.1 rather than left standing.

**The scope tables in ADR-0002 and ADR-0020 are amended to point here** rather
than being left to disagree with the code. Neither decision is reversed:
ADR-0002's backend interface is unchanged and `gocov` remains a listed backend
for a later version; only its v1 timing moves.

## Consequences

**Positive**

- The ADRs and the code agree, which is the property `tools/docslint` exists to
  protect and the one clause 9 of the v0.1 definition of done asks for.
- No unstable-internal-format dependency, so a toolchain bump cannot break a
  coverage backend.
- The effort saved went into T3, which is what macOS and Windows actually run
  on and which had no implementation at all.
- Writing this down cost one build and caught a false claim in MVP_PLAN that
  would have been read as a supported workflow.

**Negative**

- A pure-Go target fuzzed out of process gets no coverage at all in v0.1.
  Not "unless it is rebuilt": there is no build of it that this version can
  read. In process it is fully covered — that is T0, where a Go harness reports
  through `pkg/feedback` directly — so the gap is precisely the Go target that
  must run behind a process boundary. `blackbox` plus response and timing
  feedback is what remains.
- Windows in v0.1 is black-box in every configuration. `sancov` needs shared
  memory, which `internal/platform` provides on Unix only, so even an
  instrumented target has nowhere to write its map. This is a platform gap
  larger than `gocov` and is not closed by this decision.

**Neutral**

- Revisiting is cheap and the trigger is external: if Go ever exposes a public
  reader for its coverage format, `gocov` becomes an ordinary backend
  implementation against an interface that already fits it.

## Alternatives considered

- **Ship `gocov` via `go tool covdata` per execution.** Correct, portable, and
  uses only public interfaces. Rejected on measurement: a covdata invocation is
  itself a process spawn and a file parse, so the backend would roughly halve
  the throughput of the tier it is meant to make useful.
- **Decode `internal/coverage`'s format directly.** Fast, and the format is
  stable in practice across a given toolchain. Rejected: "stable in practice"
  is what breaks silently, and it would break as a wrong coverage map rather
  than a compile error — a corpus quietly guided by noise.
- **Teach the runtime libFuzzer's 8-bit counter interface.** This is the one
  that would actually work, and it is now the recommended route for a later
  version, so the shape is worth recording. It needs
  `__sanitizer_cov_8bit_counters_init` to remember the target's counter range,
  `__sanitizer_cov_pcs_init` and the `trace_cmp` and `weak_hook` family as
  accepted no-ops, and an `atexit` fold of the counter array into the shared
  map — which works because every tier that needs it runs one input per process
  lifetime. Rejected for v0.1 on honesty rather than effort: the result is
  *block* coverage, not the edge coverage every heuristic in the engine was
  tuned against, so it needs its own `Granularity` reporting and its own
  measurement before a corpus built with it can be trusted.
- **A `//go:build xfuzz` counter-injection pass of our own.** A source rewriter
  that adds our counters instead of Go's, so the map is ours to read and stays
  edge-shaped. Rejected for v0.1 as a second instrumentation toolchain to
  maintain, and strictly more work than the interface above for the same
  targets.
- **Leave the ADRs as written and treat the absence as a to-do.** Rejected:
  that is precisely the silent drift the traceability lint exists to catch, and
  a scope table nobody trusts is worse than one with a deferral in it.
