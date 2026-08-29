# Planted-bug targets

Purpose-built targets with known, documented bugs at graded difficulty. They are
the primary end-to-end assertion of the test strategy (docs/TESTS.md § 4), and
the only layer that detects the defining failure of a fuzzer: running beautifully
and finding nothing.

Each bug is reachable only through a specific input shape, and each records what
it is testing about the engine. A campaign that cannot find one within its budget
is a campaign with something broken upstream — a dead coverage map, an inverted
feedback, a mutator producing only invalid inputs.

## Why the bugs are explicit crashes

Each planted bug ends in an unambiguous fault — a null write, an abort, a
division by zero — rather than a subtle out-of-bounds access left for a
sanitizer to notice.

That is deliberate for two reasons. It makes the test a measurement of
*reachability*, which is what the fuzzer is responsible for, rather than of
sanitizer sensitivity, which it is not. And it keeps the suite runnable where
compiler-rt is not installed, which is the case in many container images
including the one this was developed in. Where sanitizers are available, building
these same targets with `XFUZZ_SANITIZE=address` exercises the sanitizer
objective as well; the fuzzer's job of getting there is identical.

## Targets

| Target | Bugs | Difficulty | Exercises |
| --- | --- | --- | --- |
| `simple_parser.c` | 3 | shallow | Basic mutation, crash detection, coverage guidance |
| `magic_parser.c` | 4 | magic values | Dictionaries, and later cmplog and value profile |
| `chunked_format.c` | 5 | checksum-gated | Structured mutation with derived fields; crash bucketing and minimisation |
| `stateful_proto.c` | 4 | sequence-gated | Sessions, protocol state feedback, state-then-message scheduling |
| `hang.c` | 0 | — | Timeout enforcement; a hang is a finding, not a crash |
| `nop.c` | 0 | — | The measurement floor: everything a benchmark reports is protocol, not target |

## Calibration

Difficulty here is a claim about the *fuzzer*, so the targets have to be
calibrated to it or the suite measures the wrong thing.

`simple_parser` is the shallow one. Its comparison ladder uses boundary values —
16, 32, 64, 127 — that a byte-level mutator produces deliberately rather than by
chance, because its job is to check that coverage guidance can climb a ladder at
all.

An earlier version used an arbitrary constant partway up. The campaign reliably
climbed two steps and stalled: reaching the third meant a one-in-fourteen-thousand
guess against a corpus entry mutation had grown to fifty-five bytes. That is a
real limit and worth measuring — but it is what comparison logging (v0.3) and
corpus trimming (M4) exist to solve, and it belongs in `magic_parser` with the
other bugs that are deliberately out of reach until then.

`chunked_format` is calibrated for triage rather than for discovery. Every bug
sits behind a CRC-32 covering its own chunk, so byte-level mutation cannot reach
any of them — changing the payload invalidates the checksum, and changing the
checksum removes the payload that triggers the bug. It is reachable only through
a structured input with a derived field, which is ADR-0005's argument expressed
as a target instead of as a claim. `chunked_format.xfg` is that grammar.

Its five bugs end in three distinct signals: three aborts, one SIGFPE, one
SIGSEGV. That is deliberate. A bucketing strategy that groups on the fatal signal
alone must produce three buckets here and one that groups on the crashing path
must produce five, which makes the difference between them a measurement rather
than an assertion (docs/TESTS.md § 4).

### `stateful_proto`

The stateful counterpart to `chunked_format`. Where that one hides its bugs
behind checksums that only structured mutation can satisfy, this one hides them
behind a *sequence* that only a fuzzer reasoning about protocol state can
assemble. It is a line protocol, so both line framing and status-code state
labelling apply and the target exercises the ordinary configuration rather than
a special one.

The four bugs are graded by how much of the state machine each one needs:

| Bug | Needs | What it measures |
| --- | --- | --- |
| 1 | one message | The session tier works at all: connection, framing, mutation of message zero. Finding it says nothing about state guidance |
| 2 | `HELLO`, then a correct `AUTH` | The exit criterion: a bug reachable only past a valid two-step handshake |
| 3 | two `BULK` transfers on one connection | A counter that is per connection where the array is per transfer — a bug in the *repetition* of a state, not in the state |
| 4 | `AUTH`, `RESET`, `GET`, in that order and no other | A bug in a state *pair* nobody plans for, which is why transitions are counted separately from states |

Each near miss stays alive, and that is the point of the grading: `AUTH` with
the wrong token, a single `BULK` transfer, `RESET` before authenticating, and
re-authenticating after a reset all behave correctly. A campaign that reports
bug 2 has genuinely got through the funnel rather than stumbled past it.

Bug 4 is a null dereference rather than the use-after-free it naturally wants to
be. Leaving the pointer dangling made the fault whatever the allocator happened
to leave behind — on this host glibc's own double-free detector fired at the end
of the session, several messages after the mistake, attributing the crash to the
wrong place. Clearing the pointer keeps the sequence exactly as hard and makes
the fault the target's own, which is what the rest of this file argues for.

The server handles one connection at a time in one process. Serving them
concurrently would make a crash unattributable to the session that caused it,
which is the one thing a fuzzing target must never do.


## Building

    go run ./cmd/xfuzz-cc -O1 -o simple_parser testdata/targets/simple_parser.c

The integration tests build them automatically and skip when clang is absent.
