# ASR-0003: Black-, grey-, and white-box operation

- **Status:** Accepted
- **Priority:** Must
- **Date:** 2026-08-28
- **Source:** Product brief — "work well on black-box, grey-box and white-box"

## Requirement

Xfuzz must operate usefully across the full spectrum of target visibility:

| Mode | Available signal | Must still work |
| --- | --- | --- |
| **Black-box** | Exit status, output, timing, responses only | Yes — no instrumentation required |
| **Grey-box** | Edge/block coverage from instrumentation or tracing | Yes — the primary mode |
| **White-box** | Source, CFG, symbols, constraint traces | Yes — enables directed and hybrid modes |

Moving a target up the spectrum must *add* signal without changing the campaign
configuration's shape, the corpus format, or the workflow.

## Rationale

Real engagements span all three: a closed-source appliance binary, a
source-available library, and a first-party service with full build access. A
tool that only works at one point on the spectrum is only usable in one third of
engagements. Critically, the *degradation* must be graceful — losing coverage
signal should reduce effectiveness, never break the run.

## Architectural impact

- Coverage cannot be a required input to the core loop. The scheduler and the
  corpus must function with an empty or absent coverage map, falling back to
  black-box signals (response novelty, timing, output diversity, random
  scheduling).
- Requires several independent instrumentation backends behind one interface,
  selected by target capability rather than by user mode declaration.
- White-box artifacts (CFG, call graph, target-location distances, constraint
  traces) must be *optional metadata* computed by a pre-analysis step, not
  assumed by any core type.
- The campaign configuration must let the user *declare* what is available and
  let the daemon *probe* for the rest, reporting which backend was selected and
  why.

## Acceptance criteria

- The same target, fuzzed black-box and grey-box, produces comparable corpora in
  format and both replay identically; the grey-box run demonstrably achieves
  higher coverage per unit time.
- A campaign against a stripped binary with no source runs without any
  configuration field mentioning instrumentation.
- The daemon reports the active feedback backend, its measured overhead, and any
  requested-but-unavailable signal.

## Satisfied by

ADR-0002, ADR-0007, ADR-0009
