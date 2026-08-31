# ADR-0030: A TUI's only observable is its screen, so the fuzzer emulates a terminal

- **Status:** Accepted
- **Date:** 2026-08-31
- **Serves:** ASR-0001, ASR-0004, ASR-0008

## Context

[ADR-0013](ADR-0013-gui-tui-driver-adapters.md) chooses
driver adapters with UI-state feedback and names `tui` as the first backend:
"PTY plus an embedded terminal emulator", observing "screen buffer, cursor,
attributes". It does not say why that mechanism rather than a cheaper one, what
the emulator has to implement, or what the campaign gives up by not having one.

Those questions decide whether a TUI campaign is fuzzing the program its users
run. A terminal program has exactly one observable — the screen — and the screen
does not exist in the byte stream: what the program writes is escape sequences,
and a terminal is what turns them into a grid. A fuzzer that reads the byte
stream directly sees a program that emitted `\x1b[2J\x1b[H` and cannot tell
whether that cleared a screen it had already drawn or a screen it had not.

## Decision

**Drive the target through a pseudo-terminal, never through pipes.** Over pipes
`isatty` is false, so a curses application refuses to start or falls back to a
line-oriented mode; the window size is unknown, so nothing that draws a full
screen draws one; there is no controlling terminal, so job control, SIGWINCH and
`/dev/tty` do not work. A campaign run over pipes is a campaign against a
different program, and its findings do not apply to the one anybody runs.

**Interpret the sequences with an emulator in the fuzzer** (`pkg/vt`), covering
what a real TUI needs: cursor movement, erase, insert and delete, the scrolling
region, SGR including 256-colour and 24-bit colour, the alternate screen buffer,
autowrap, UTF-8 with a compact width table, and the modes a driver must consult
before it can encode an event — application cursor keys and mouse tracking.

**The width table is compact and fixed rather than the Unicode database.** The
full tables change with every Unicode revision, so an emulator built against
them would produce a different screen hash on two hosts running the same
campaign — a reproducibility failure (ASR-0008) with no symptom other than a
corpus that does not transfer.

**The emulator is one of the parsers Xfuzz fuzzes itself with**, and this is not
a formality: it reads bytes from a program the fuzzer is actively mutating into
misbehaving, so it is guaranteed adversarial input rather than merely exposed to
it. Every limit in it — parameter counts, string lengths, screen dimensions — is
a bound a fuzzer will push, and a panic there is a crash in the fuzzer reported
as a crash in the target.

**Wait for the interface to go quiet rather than for a fixed interval.** An
interface redraws asynchronously, so reading the screen immediately after a
keystroke reads the screen as it was; a fixed settle is either too slow for the
ordinary redraw or too fast for the one that matters. The executor asks the
backend, through an optional `Settler` interface, and falls back to the interval
for a backend that cannot answer.

**What is not emulated is stated rather than approximated**: scrollback (a
fuzzer looks at the screen, not its history), tab stops beyond the default eight
columns, double-width lines, character sets beyond the default and line-drawing
sets, mouse *reporting* back from the program, and reflow on resize.

## Consequences

**Positive**

- The campaign observes what a user would see, so a finding is reproducible by
  a person running the same program in a terminal.
- The screen is exactly reproducible from the byte stream, which is what makes
  a TUI finding unusually crisp compared with GUI automation.
- The emulator is pure Go with no display server, so a TUI campaign runs
  identically in CI and on a developer's machine.

**Negative**

- The emulator is a few thousand lines that have to be right, and wrong
  emulation is invisible: the campaign runs, states are recorded, and they are
  states of a screen the program never drew.
- Pseudo-terminals are a Unix mechanism. Windows has ConPTY, which is a
  different API with a different lifecycle; until that is written the capability
  is declared absent (ADR-0022) rather than approximated with pipes.
- Waiting for quiet is a wall-clock input to what the campaign observes. It is
  not an input to a fuzzing *decision* (ASR-0008), but it does mean two runs of
  one sequence can observe different screens, which is why the tier declares
  itself non-deterministic and triage verifies a T7 finding by replaying it.

**Neutral**

- The event encoding depends on modes the program sets — application cursor
  keys change the four arrows, mouse tracking decides whether a click is a click
  at all — so the driver consults the emulator before encoding, and a click a
  program never asked for sends nothing.

## Alternatives considered

- **Read the raw byte stream and hash it.** Cheapest by far. Rejected: the
  stream is not the screen, so two programs that drew the same thing by
  different routes are different states, and a program that redraws its whole
  screen every keystroke is a new state every keystroke.
- **Shell out to a terminal multiplexer and screen-scrape it.** Reuses a mature
  emulator. Rejected: it makes the fuzzer's observation depend on a second
  process's version and configuration, costs a spawn per observation at a tier
  where cost is already the binding constraint, and gives no access to the modes
  the driver has to consult.
- **A pixel diff of a rendered terminal.** Universal. Rejected for the reason
  ADR-0013 gives for GUIs: far too noisy, and here it discards the structure
  that is available for free.
