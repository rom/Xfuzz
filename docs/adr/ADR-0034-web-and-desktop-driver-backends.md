# ADR-0034: A browser and an accessibility tree are two more driver backends

- **Status:** Accepted
- **Date:** 2026-08-31
- **Serves:** ASR-0001, ASR-0010, ASR-0013

## Context

[ADR-0013](ADR-0013-gui-tui-driver-adapters.md) put user interfaces behind the
T7 executor tier and named five backends: a terminal program on a pseudo-terminal
(`tui`), accessibility trees on Linux (`gui-atspi`), UI Automation on Windows
(`gui-win`), the accessibility API on macOS (`gui-mac`), and a browser's
debugging protocol (`web`). One existed. The others were the last unmet part of
[ASR-0001](../asr/ASR-0001-multi-domain-target-coverage.md).

The claim ADR-0013 makes about the tier is that a second interface domain costs
one backend and nothing else — the same corpus, the same mutation operators over
an IR Repeat, the same state model, the same triage. That claim had been tested
against exactly one backend, which is not a test of it.

## Decision

**Two more backends, and the two that cannot be tested are not written.**

**`web`: a browser over the Chrome DevTools Protocol.** Every browser worth
fuzzing ships a protocol that can navigate, dispatch a keystroke, click a point
and hand back the document, and none of it needs a display server. What is
different from a terminal campaign is what "the target" means: the browser is a
*harness*, and what is under test is whatever answers `driver.url`. Three
consequences run through it. A web campaign needs no `target.path`. The
browser's exit status is a harness failure and not a finding. And a page fails
while every process involved stays alive and exits zero — an uncaught exception,
a renderer that died, a modal nobody dismissed — so the failures are collected
from the protocol, which is what the `exception` oracle reports.

**`gui-atspi`: a Linux desktop application over AT-SPI.** An application
publishes its interface as a tree of accessible objects over D-Bus, because
assistive technology needs it, and the same bus carries a way to synthesise a
keystroke or a click. The tree is a far better observable than a screenshot: two
screens that differ by an animation frame are different pixels and the same
screen, while the tree changes when the interface changes — and it is the only
observable that says which widget has focus, which is what decides where the
next keystroke goes.

**Clicks are window-relative.** A window does not land in the same place twice,
so a click recorded in screen coordinates is a click that lands somewhere else
the next run, or on somebody else's window. It also puts a mutator's small
numbers inside the application rather than in the corner of the desktop.

**`gui-win` and `gui-mac` are deferred, and the reason is recorded rather than
left as an absence.** UI Automation is a COM API on Windows and the
accessibility API on macOS needs Objective-C — which is C in the fuzzer, and
[ADR-0017](ADR-0017-pure-go-core-cgo-behind-build-tags.md) keeps that out.
Neither can be exercised by this project: there is no macOS or Windows host, and
a driver for an interactive desktop is not something cross-compilation
establishes. Writing several hundred lines that nobody can run is how an
implementation and its documentation start to disagree.

**The event vocabulary is shared across every backend, deliberately.** "key
enter" is a byte sequence on a terminal, a DOM key value in a browser and an X
keysym on a desktop, and it means the same thing in all three, because a corpus
is a corpus (ASR-0013). Where a backend cannot deliver an event it says so and
the tier skips it: AT-SPI presses a keysym and releases it, so it cannot hold
Control across another key, and sending the unmodified key instead would deliver
a keystroke nobody asked for and produce findings that do not reproduce by hand.

**The browser's debugging port is a control channel, not campaign traffic.** It
is dialled through the safety layer and audited, and it must be loopback or it
is refused — but it does not consult the campaign's allowlist. Requiring an
operator to list 127.0.0.1 to let Xfuzz talk to a browser it just launched would
teach them to allow loopback wholesale, which is a far larger hole. What the
scope guard cannot do is constrain the *harness*: a browser runs in the host's
network namespace, because it must reach the page, so where it connects is
beyond the guard's sight. That limit is stated rather than implied by the
presence of a guard.

**A harness gets the session variables it needs and nothing else.** A campaign
builds its target's environment from the campaign file, which is right for a
parser — an inherited environment is a hidden input, and a finding that depends
on one does not reproduce elsewhere. A windowed program is different in a way
that is not negotiable: without a display it does not draw, without a session bus
it publishes no accessibility tree, and the campaign would start, the program
would run, and the driver would wait for something that never appears. So the
driver backends pass a named list through — where to draw, where the bus is,
where the home directory is — and everything that would make a finding
machine-specific stays out.

**The D-Bus wire format is a library's; the WebSocket framing is ours.** Both
carry bytes from a target being driven into undefined behaviour, so the default
is to own the parser. WebSocket framing is a header and a mask, and writing it
was smaller than the risk of a dependency in the fuzzer's own address space.
D-Bus is a general-purpose serialisation format with a type language, alignment
rules and an authentication handshake: a reimplementation would be several times
the size of the thing it serves, with the failure mode that a marshalling bug
looks like an application saying something strange. The library is listed in
NOTICE like every other.

## Consequences

**Positive**

- ASR-0001's last unmet domain is met, and the tier's claim is tested against
  three backends instead of one.
- A web campaign is verifiable end to end in CI wherever a browser is
  installed, which is most places — unlike every other domain-specific backend
  in the tree.
- The desktop backend needs no C: AT-SPI is a D-Bus protocol, so the pure-Go
  core survives it (ADR-0017).

**Negative**

- A browser cannot start under a campaign's ordinary resource caps. A
  JavaScript engine reserves address space by the terabyte and a browser is tens
  of processes and hundreds of threads, so its sandbox drops the address-space
  limit and raises the process floor. It keeps everything else the campaign
  asked for, and the difference is documented rather than silent.
- A desktop campaign needs a display, a session bus, an accessibility bus and a
  toolkit with an accessibility bridge. That is four things a CI image usually
  has none of, so its tests skip rather than fail, and the doctor reports which
  one is missing.
- `gui-win` and `gui-mac` remain unimplemented, so ADR-0013's list is still
  longer than the code. It is now shorter by two, with a reason attached to what
  is left.
- The desktop backend cannot hold a modifier key. A campaign that needs
  Control-C against a GTK application cannot express it, and gets a skipped
  event rather than the wrong keystroke.

**Neutral**

- ADR-0013 is unchanged in substance: the backends it named are the backends
  being written, in the order it put them. What this adds is which two, and why
  the other two are not.

## Alternatives considered

- **Drive a browser through WebDriver instead of the DevTools protocol.**
  Standardised and further from the browser: WebDriver waits for elements,
  retries, and hides exactly the timing a fuzzer is trying to disturb. It also
  needs a second process, and the protocol a browser already speaks needs none.
- **Screenshot the desktop and fingerprint pixels.** Works on any toolkit and
  answers the wrong question: two screens that differ by an animation frame are
  different pixels and the same screen, and no fingerprint of pixels says which
  widget has focus.
- **Drive the desktop with AT-SPI's actions rather than synthesised input** —
  `DoAction` on a button instead of a click at its coordinates. More reliable
  and less honest: it bypasses the input path, which is where the bugs an
  interface campaign is looking for actually live.
- **Write UI Automation and the macOS accessibility API anyway, untested.**
  Rejected for the reason ADR-0026 gives for `gocov`: an ADR that lists
  something the code does not have is indistinguishable from an ADR the code has
  drifted away from, and unrunnable code is the same problem one step later.
