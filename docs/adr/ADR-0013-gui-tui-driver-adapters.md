# ADR-0013: GUI/TUI driver adapters with UI-state feedback

- **Status:** Accepted
- **Date:** 2026-08-28
- **Serves:** ASR-0001, ASR-0002, ASR-0004

## Context

GUI and TUI targets are the most unusual in ASR-0001. They differ from every
other domain on three axes at once: input is a *sequence of interaction events*
rather than data; the interface is inherently *stateful* (screens, focus, modes);
and execution is slow — 10⁻¹ to 10¹ per second, five to six orders of magnitude
below a parser.

Worse, the obvious feedback signal is often unavailable: many GUI applications
are closed-source, and even instrumented ones spend most coverage in the
rendering toolkit rather than in application logic.

## Decision

Implement GUI/TUI as **driver adapters** behind the T7 `Driver` executor
(ADR-0009), with **UI state as a feedback signal** alongside any code coverage:

| Driver | Mechanism | Observable state |
| --- | --- | --- |
| `tui` | PTY plus an embedded terminal emulator | Screen buffer, cursor, attributes |
| `gui-atspi` | AT-SPI accessibility tree, synthetic X11/Wayland input | Widget tree, focus, properties |
| `gui-win` | UI Automation, synthetic input | Control tree, focus |
| `gui-mac` | Accessibility API, synthetic events | Element tree |
| `web` | Chrome DevTools Protocol | DOM, console, network |

**Input** is an IR `Repeat` of event nodes — key presses, text entry, clicks,
gestures, waits — so GUI fuzzing reuses the same mutation and sequence machinery
as protocol fuzzing (ADR-0005), including insert/delete/reorder/duplicate.

**Feedback** is `UIStateFeedback`: a normalised hash of the observed UI state
(screen buffer or widget tree), with normalisation that strips volatile content
— timestamps, counters, cursor blink, animation frames. Novel UI states and novel
transitions are interesting. This composes with code coverage where available
(ADR-0007), giving a useful signal even fully black-box.

The UI state graph is the same object as the protocol state machine (ADR-0006);
GUI fuzzing is stateful fuzzing where states are screens.

**Oracles** extend beyond crashes to the failure modes GUIs actually exhibit:
unhandled exception dialogs, hangs and unresponsiveness, rendering assertions,
accessibility-tree corruption, and unrecoverable states (no path back to a known
screen).

TUI is prioritised over desktop GUI: it is headless, deterministic, fast by GUI
standards, needs no display server, and runs identically in CI.

## Consequences

**Positive**

- GUI/TUI fuzzing reuses the corpus, mutation, scheduling, feedback, and triage
  spine unchanged — the strongest possible validation that the abstractions are
  right.
- UI-state feedback works black-box, which is essential since most GUI targets
  are closed-source.
- Terminal emulation gives an exactly reproducible screen state, making TUI
  findings unusually crisp compared with typical GUI automation.

**Negative**

- Execution rates make coverage growth glacial; the corpus scheduler must be
  configured very differently (deep sequences, aggressive seed reuse) and the
  statistics layer must not assume high rates.
- UI-state normalisation is a tuning problem with two bad failure modes: too
  aggressive and distinct screens merge; too weak and every clock tick is a new
  state. It must be inspectable and per-target tunable.
- Desktop GUI drivers depend on accessibility support that toolkits implement
  unevenly; some applications are effectively opaque.
- Reset is expensive (full application restart), making reset policy the dominant
  performance factor.

**Neutral**

- Phased in ADR-0020 after the v1 domains; interfaces are designed in v1.

## Alternatives considered

- **Accessibility tree as the single universal abstraction.** Elegant. Rejected as
  the sole mechanism: toolkit support is too uneven, and it discards the screen
  buffer, which is the best signal available for TUI.
- **Record and replay of human sessions.** Excellent seed quality. Rejected as the
  primary mechanism — it requires human input before any fuzzing can start — but
  retained as a **seed source**, which is where its value actually lies.
- **Pixel-diff visual feedback.** Universal, needs no accessibility support.
  Rejected as primary: far too noisy (antialiasing, animation, theming), though
  usable as a fallback observer where no structured state is exposed.
