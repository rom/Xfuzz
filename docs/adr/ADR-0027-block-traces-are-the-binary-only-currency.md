# ADR-0027: Block traces are the currency of the binary-only tier

- **Status:** Accepted
- **Date:** 2026-08-31
- **Serves:** ASR-0003, ASR-0006, ASR-0007

## Context

[ADR-0002](ADR-0002-pluggable-multi-backend-instrumentation.md) names three
binary-only instrumentation backends — `frida`, `qemu`, `ptrace-bb` — and
[ADR-0009](ADR-0009-tiered-executors.md) puts them at tier T5, "emulation or
dynamic instrumentation", at 10¹–10²/s. Both records fix the *interface* and
leave the realisation open. Building them exposed a decision the interface does
not settle: what, exactly, does a backend at this tier hand back?

The three mechanisms have nothing in common at the level they operate. A
breakpoint backend learns that a trap fired at an address. An emulator prints a
line naming a translation block. A dynamic-instrumentation agent reports a
compiled block as an offset into a module. Their outputs differ in units
(absolute address, guest address, module offset), in ordering (a sequence, or a
set), in completeness (every entry, or the first entry per block), and in
whether the address means anything twice (a position-independent image moves on
every execution).

Two shapes were possible. Each backend could produce a coverage map directly,
which is what the fuzzer ultimately wants; or each could produce something
lower-level that one shared piece of code turns into a map.

## Decision

**A T5 backend returns a block trace: the addresses of the basic blocks the
execution entered, in link-time terms, with an explicit flag saying whether the
order is meaningful. `pkg/executor` folds that into the coverage map.**

Three consequences follow, and each is the point rather than a side effect.

**Link-time addresses, always.** A backend that reports where the code was
loaded reports something unique to one execution: address-space layout
randomisation moves the image every run, so the same input would produce
different coverage every time, every input would look interesting exactly once,
the corpus would fill with duplicates, and no finding would reproduce
(ASR-0008). Each backend recovers the base by whatever means it has — `ptrace-bb`
reads it from the process, `frida` gets module offsets from DRcov and needs no
base, `qemu` recovers it by matching the low twelve bits of traced addresses
against the analysed block list, since page-aligned loading preserves them.

**Ordering is declared, not assumed.** One-shot breakpoints and a DRcov file
both report a *set*: which blocks ran, not what ran after what. Folding a set as
though it were a path keys the map on transitions that never happened, and since
the order is arbitrary the same execution can fold differently twice. An
unordered trace therefore degrades to block coverage rather than manufacturing
edges. Only `qemu`, whose log is a sequence, yields edge coverage.

**The fold is shared and uses the runtime's own scheme.** A block's identity is
its address mixed across the map; the index written is the previous identity
shifted right one, XOR the current — the same arithmetic
`__sanitizer_cov_trace_pc_guard` performs. One implementation means every
backend's coverage is the same kind of thing, and a corpus measured under source
instrumentation describes the same kind of thing as one measured under a tracer.

**`ptrace-bb` is one-shot.** A breakpoint costs two context switches every time
it fires, so one left in a loop body costs a context switch per iteration.
Removing each after its first hit bounds an execution at one stop per *new*
block however long the program runs. What it gives up is hit counts, and
`Granularity` reports blocks rather than edges so that a campaign cannot require
a precision this backend does not have.

**`qemu` uses the stock emulator.** The usual route to coverage from QEMU is a
patched build writing a shared bitmap; requiring one means requiring a
particular fork at a particular version to be built before a campaign can start.
`qemu-user -d exec` already prints a line per translation block, and reading what
a distribution's own package produces costs speed and costs the operator
nothing.

**`frida` is driven out of process.** Linking frida-gum means cgo and a large
native dependency inside the fuzzer's own address space — against
[ADR-0017](ADR-0017-pure-go-core-cgo-behind-build-tags.md) — with a licence
question of its own ([ADR-0018](ADR-0018-proprietary-commercial-license.md)) for
something that runs on an operator's machine. The backend spawns the `frida`
tool with a Stalker agent that writes DRcov, which is also the format every tool
that draws coverage on a disassembly already reads.

## Consequences

**Positive**

- Adding a T5 backend means producing a list of addresses; nothing about
  coverage maps, hashing or edge derivation is duplicated.
- Determinism is a property of one shared rule rather than of three
  implementations remembering it.
- DRcov as the `frida` transport means coverage collected by DynamoRIO, Pin, or
  any other tool that writes it can be brought into a campaign, and coverage
  collected by a campaign opens in a disassembler.
- The pure-Go core is preserved: the only new native dependency is the operator's
  own choice of external tool, spawned through the safety layer like any target.

**Negative**

- A trace is larger than a map, and the fold is per-execution work the
  instrumented tiers do not pay. At 10¹–10²/s this is not the dominant cost, and
  at any higher rate this tier is the wrong choice anyway.
- Block granularity from two of the three backends means the corpus is coarser
  than under source instrumentation, and corpora are not portable between the
  two (already stated in ADR-0002).
- `qemu`'s base recovery is a heuristic. It is high-confidence — a wrong answer
  needs a coincidence to beat the truth across hundreds of addresses — but it can
  decline to answer, and an execution whose base could not be resolved
  contributes no coverage and is counted rather than silently absorbed.

**Verification status**

`ptrace-bb` is verified end to end: a stripped, uninstrumented C target, a
campaign that finds a planted bug, and a comparison against a black-box run of
the same target in the same window. `qemu` and `frida` are verified against stub
tools that emit the real formats — the command built, the process spawned
through the safety layer, the file read back, the addresses rebased, the map
folded, the status classified — because neither tool was installed on the machine
where they were written. What is not verified is the tools' own semantics.

## Alternatives considered

- **Each backend produces a coverage map.** Fewer moving parts per backend.
  Rejected: the folding rules — which mixing function, which masking, whether to
  derive edges — would then live in three places and drift, and directed fuzzing
  needs the addresses themselves, which a map has already hashed away.
- **A patched QEMU with a shared bitmap.** Faster and it is what the ecosystem
  does. Rejected as the *requirement*: it makes "install qemu-user" into "build
  this fork". Nothing prevents adding it later as a second backend for operators
  who have one.
- **frida-gum linked in through cgo.** Lower overhead per execution. Rejected on
  ADR-0017 and ADR-0018 grounds, and because an out-of-process tool can be
  absent without the fuzzer failing to build.
