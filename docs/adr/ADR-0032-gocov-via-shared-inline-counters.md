# ADR-0032: `gocov` lands by mapping the target's counters into the fuzzer

- **Status:** Accepted
- **Date:** 2026-08-31
- **Serves:** ASR-0003, ASR-0006

## Context

[ADR-0026](ADR-0026-gocov-deferred-blackbox-is-the-off-linux-path.md) deferred
`gocov` for v0.1 and left a precise gap behind it: a Go target that must run
behind a process boundary gets no coverage at all, and Windows is black-box in
every configuration. It also named the route that would work — Go's
`-d=libfuzzer` mode emits libFuzzer's **8-bit counter** interface, so a runtime
that implements that interface rather than `trace-pc-guard` would get the
signal — and rejected it for v0.1 on honesty rather than effort: the result is
block coverage, which needs its own granularity reporting and its own
measurement before a corpus built with it can be trusted.

That measurement is the work this record closes. One thing the earlier sketch
got wrong is worth stating first, because it is the whole design.

**ADR-0026 proposed an `atexit` fold of the counter array into the shared map,
and that does not work for a Go target.** Go does not leave through the C
runtime: it exits with the `exit_group` system call and runs no `atexit`
handler and no destructor. A crashing execution never reaches one either, on any
language — and a crashing execution is precisely the one whose coverage decides
whether the input that caused it enters the corpus. A fold at exit would
therefore report nothing for a Go target that exits normally and nothing for any
target that dies, which is the coverage that matters most.

## Decision

**The counters are not copied at exit; they are mapped.** When the target
registers its counter array through `__sanitizer_cov_8bit_counters_init`, the
runtime `mmap`s the pages holding that array `MAP_FIXED|MAP_SHARED` onto the
fuzzer's shared region. From that instruction on, every increment the target
performs lands in memory the fuzzer already has open. There is nothing to
collect, nothing to hook, and no moment at which the collection can be missed.

**A crashing execution therefore reports its coverage.** This is not a side
benefit; it is the property the design is chosen for. Measured on a target whose
every execution panics: 6 corpus entries admitted, against the 0 a fold-at-exit
scheme can produce.

**Alignment is handled by saving and restoring the page.** A counter array does
not begin on a page boundary, so the mapping covers the enclosing pages and the
header records the offset at which the array actually starts. The bytes that
share the first and last pages are read before the mapping and written back
after it, because those bytes belong to whatever the linker placed next to the
array and a fuzzer that zeroes them corrupts the target.

**The backend reports block granularity, and says so.** A counter is per basic
block with no ordering, so two inputs that ran the same blocks in a different
order are indistinguishable. That is the same limitation
[ADR-0027](ADR-0027-block-traces-are-the-binary-only-currency.md) records for
the binary-only backends, declared through the same `Granularity` field rather
than presented as edges.

**The fork server is refused with `gocov`, not silently disabled.** The runtime's
fork-server constructor runs before Go's own initialisation registers the counter
array, so a forked child would inherit a mapping of an array that did not exist
yet. The campaign gets the subprocess tier and a stated reason.

**`gocov` is measured against `blackbox` on the same target and seeds, and the
difference is the justification.** Over 20,000 executions of the same Go target:
`gocov` kept 12 corpus entries, `blackbox` kept 2.

## Consequences

**Positive**

- A pure-Go target out of process is grey-box, which closes the gap ADR-0026
  named as its main cost — and closes it on every platform the mapping works on,
  not only Linux.
- Coverage survives a crash, which no collect-at-exit scheme can offer.
- Nothing depends on `internal/coverage` or on any unstable format, so the
  toolchain floor can keep moving (ADR-0023).
- The target needs no source change: `xfuzz-cc --go` sets the build tag, the
  instrumentation flag and the external link, and existing build commands pass
  through.

**Negative**

- Block coverage, not edges. A campaign against a Go target has a coarser signal
  than one against a clang-built target, and the corpus reflects it.
- The fork server is unavailable for this backend, so the tier is T4 rather than
  T2 and the throughput is the process-spawn rate.
- The mapping is a Unix mechanism. Windows Go targets are still black-box, and
  the reason has moved from "no backend" to "no shared mapping", which is
  [ADR-0033](ADR-0033-platform-isolation-and-terminal-parity.md)'s territory.

**Neutral**

- ADR-0026 is amended rather than superseded: its analysis of the covdata and
  `internal/coverage` routes stands unchanged, and only the deferral it records
  is lifted. Its "teach the runtime the 8-bit counter interface" alternative is
  what happened, with the `atexit` step replaced.

## Alternatives considered

- **Fold the array at exit, as ADR-0026 sketched.** Rejected on the evidence
  above: Go never runs the handler, and no target runs it when it crashes.
- **A pipe or a signal at the end of each execution to trigger the fold.** Adds
  a round trip per execution to the tier whose cost is already the process
  spawn, and still reports nothing for a crash.
- **Copy the array from the fuzzer with `process_vm_readv` after the exit.**
  The pages are gone by then. Reading them before the exit needs to know when
  the execution ended, which is the problem being solved.
- **Ask Go for a public counter API.** The right long-term answer and not
  available; the mapping needs nothing from the toolchain beyond the flag that
  already exists.
