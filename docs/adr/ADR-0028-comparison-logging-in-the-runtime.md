# ADR-0028: Comparison operands travel in their own region, written by the runtime

- **Status:** Accepted
- **Date:** 2026-08-31
- **Serves:** ASR-0004, ASR-0007, ASR-0014

## Context

[ADR-0007](ADR-0007-composable-feedback-pipeline.md) names `CmpLogStage` and
value profiling as the hybrid tier's native, cheap half, and lists "cmp
operands" among the signals an `Observer` records. It does not say where those
operands come from or how they reach the fuzzer.

The reason they are needed is arithmetic. A four-byte equality against a
constant is one chance in four billion per attempt; a checksum is worse. No
mutation schedule solves either, because there is nothing to climb — every wrong
value is equally wrong, coverage is flat until the exact value appears, and the
campaign has no gradient to follow. Knowing what the comparison wanted turns four
billion guesses into one directed edit, and knowing how *nearly* it passed turns
the cliff into a slope.

`runtime/csrc/xfuzz-rt.c` implemented `__sanitizer_cov_trace_pc_guard` and
nothing else, so neither was available.

## Decision

**The runtime implements the comparison callbacks and writes operands into a
second shared region, separate from the coverage map and separately optional.**

- Integer comparisons (`__sanitizer_cov_trace_cmp1/2/4/8` and the `const_cmp`
  variants), switches (`__sanitizer_cov_trace_switch`, so a case the program
  never took is still in the table), and the memory-comparison weak hooks
  (`memcmp`, `strcmp`, `strncmp`).
- A flat table: a header the fuzzer resets before each execution, then fixed
  records of a site identity, a kind, an operand width, a matching-prefix length,
  and sixteen bytes of each operand.
- Written from the front and truncated when full, never wrapped. The comparisons
  an execution performs first are nearest the input's entry to the program, which
  is where a substitution is most likely to matter; a wrap would discard those in
  favour of whatever a loop did ten thousand iterations later.
- Inert unless the fuzzer attached the region: one predictable branch per
  comparison in a target nobody is fuzzing.

**`trace-cmp` is in the default instrumentation flags, removable by name with
`XFUZZ_NO_CMPLOG`.** Measured back to back on the same machine, a
fork-dominated benchmark ran at 3246 exec/s with the instrumentation compiled in
and 3323 without — within the noise of that measurement. The flag stays
separable because the branch is not free on a target whose hot loop is
comparisons, and because someone auditing what Xfuzz asks their compiler to do
should be able to turn each piece off by name.

**A second region rather than a corner of the first.** The two are written at
different rates and read for different reasons, a campaign that wants coverage
and not comparisons should not map the second, and a campaign that wants both
should not need a different build of the target to get them.

**The memory hooks are defined unconditionally and fire only with a sanitizer.**
They are called by the sanitizer runtime's interceptors, so a target built
without one never reaches them. Defining them costs nothing and means a build
that has one gets string and buffer comparisons for free — which is where a
format's magic bytes usually live, as opposed to its integer fields.

**Substitution tries several encodings and several widths.** A program that
compares an integer did not necessarily read it from the input as one: a length
field is little-endian, a protocol header is big-endian, a text format spells the
number in decimal and a hex dump in hex. And C promotes anything narrower than an
`int` before comparing it, so `uint16_t tail; if (tail != 0xBEEF)` compiles to a
four-byte comparison whose top half is always zero — a four-byte needle is not
where the two-byte field is. Every comparison on a `char` or a `short` is in that
shape, which is most of the comparisons a parser makes.

**Value profiling measures closeness in bits.** A byte-granular measure gives a
four-byte comparison five distinguishable states; a bit-granular one gives it
thirty-three, and the finer measure is what carries a campaign through a checksum
where no byte is ever individually right. Memory comparisons use the matching
prefix instead, which is the better measure there.

## Consequences

**Positive**

- A magic-number ladder becomes climbable. Measured on a target whose three gates
  are 32, 64 and 16 bits wide, from the same seed and a twenty-thousand-execution
  budget: with substitution, 14 coverage entries and the bug found; without, 6
  entries and nothing. The first gate alone is one chance in four billion per
  attempt, so the campaign without it cannot reach the bug at all.
- The same table serves both uses ADR-0007 names, so value profiling costs
  nothing beyond what comparison logging already collects.
- The runtime stays small and auditable, which is the standing constraint on
  anything linked into someone else's software.

**Negative**

- A third piece of shared-memory protocol between the fuzzer and a C runtime,
  with no compiler checking either side. The record layout is therefore asserted
  by a test that builds a real instrumented target, runs it, and requires the
  constants its source compares against to come back out — which is how the two
  defects in the first implementation were found.
- The table is bounded, so a target that compares in a loop loses its later
  comparisons. Counted, not hidden.
- Substitution costs executions on every corpus entry, and on a target with no
  constants to match it admits nothing. It is off unless asked for, and its cost
  and yield are reported separately from the campaign's totals so an operator can
  see the trade and stop paying it.

## Alternatives considered

- **A dictionary instead.** Cheaper and already supported. Rejected as a
  replacement: a dictionary needs someone to know the constants in advance, which
  is exactly what is unavailable for a format nobody documented — and it cannot
  help with a value the program computes, such as a checksum.
- **Reading operands with the binary-only backends.** Would work without an
  instrumented build. Rejected for now: recovering which operands a comparison
  used from a trace means decoding operands as well as lengths, which is the
  disassembler `pkg/binary` deliberately is not.
- **Emitting the operands through the coverage map.** One region, one protocol.
  Rejected: the map is a fixed-size array of counters read by masking, and
  operands are variable-width records read sequentially. Sharing the region would
  mean one of the two using it badly.
