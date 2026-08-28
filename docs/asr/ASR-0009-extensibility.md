# ASR-0009: Extensibility

- **Status:** Accepted
- **Priority:** Must
- **Date:** 2026-08-28
- **Source:** Product brief — grammars, mutations, techniques as user-supplied inputs

## Requirement

Users must be able to extend Xfuzz along every axis without forking it:

- mutators and mutation schedules
- grammars, formats, and codecs
- feedbacks, objectives, and oracles
- executors and target drivers
- protocol state models
- triage, deduplication, and reporting

Three extension levels must exist, with an explicit performance and isolation
trade-off between them:

| Level | Mechanism | Use when |
| --- | --- | --- |
| **Native** | Go interface, compiled in | Hot-path code; maximum speed |
| **External plugin** | Out-of-process, any language | Untrusted, heavyweight, or non-Go logic |
| **Script** | Embedded sandboxed scripting | Rapid iteration, campaign-local logic |

## Rationale

Fuzzing is target-specific in ways no library of built-ins can anticipate: a
proprietary framing, an odd checksum, a custom oracle. Extensibility is the
difference between a tool that works on the examples and one that works on the
engagement. The three levels exist because these needs conflict — a hot-path
mutator cannot afford IPC, and an untrusted community plugin cannot be allowed
in-process.

## Architectural impact

- Every extension point must be a **narrow, documented Go interface** with a
  stable versioned contract; the plugin protocol and the script bindings are both
  generated from and validated against those interfaces.
- Rules out Go's `plugin` package (Linux-only, toolchain-version-locked, no
  isolation) in favour of an out-of-process protocol.
- The script layer must be **hermetic** — no filesystem, network, or clock access
  by default — because campaign files may come from untrusted sources.
- Per-call overhead must be visible: the engine reports time spent inside
  extensions so a slow plugin is diagnosable rather than mysterious.
- Extension failure must be **contained**: a crashing plugin degrades or aborts
  its campaign, never the daemon or sibling campaigns.

## Acceptance criteria

- A custom mutator, feedback, and grammar can each be added at all three levels,
  documented with a working example.
- Killing an external plugin mid-campaign yields a clean, reported error and
  leaves the corpus consistent.
- Scripted extensions cannot perform I/O, verified by test.

## Satisfied by

ADR-0010
