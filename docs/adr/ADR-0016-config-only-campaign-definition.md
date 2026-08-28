# ADR-0016: Config-only campaign definition

- **Status:** Accepted
- **Date:** 2026-08-28
- **Serves:** ASR-0005, ASR-0008, ASR-0010, ASR-0015

## Context

A campaign has a large configuration surface: target and executor, feedback
stack, mutators and schedules, grammars and codecs, seeds, state model, safety
scope, resource limits, worker count and strategies, termination conditions.

This can be expressed through CLI flags, a config file, a scripting language, or
some mixture. The choice determines what the console edits, what CI runs, and
whether a campaign is reproducible six months later.

## Decision

**A campaign is defined by a declarative file. The file is the only interface.**

- Format is **YAML** with a published **JSON Schema**, giving editor completion,
  validation, and machine-checkable structure.
- The CLI **runs, inspects, and validates** campaign files. It does not accept
  ad-hoc flags that alter fuzzing semantics; flags cover runtime concerns only —
  which file, verbosity, output format, worker override, budget override.
- The web console is a **visual editor over the same file**, round-tripping it
  with comments and key order preserved (ADR-0011). Console "launch" is exactly
  "write this file and run it".
- Files support **includes and profiles**, so shared fragments (a house safety
  scope, a standard mutator set) are reused rather than copy-pasted.
- `xfuzz init` scaffolds a campaign file from a target, and `xfuzz explain`
  renders the fully resolved effective configuration — including every default —
  so the file never hides behaviour.

**Termination conditions** are a first-class part of the file (time budget,
execution budget, coverage plateau, finding count), because CI usage requires a
campaign to end deterministically (ASR-0015).

## Consequences

**Positive**

- Campaigns are **reproducible artifacts**: versionable, diffable, reviewable,
  and attachable to a report. Six months later the file explains exactly what ran.
- One configuration path means CLI, console, and CI cannot diverge — parity by
  construction rather than by discipline (ASR-0005).
- Safety scope and authorization live in a reviewable file (ADR-0012), which is
  what makes them auditable.
- A single schema is the natural source for validation, console forms, and
  documentation.

**Negative**

- Loses the one-line ergonomics that AFL and libFuzzer users expect; a quick
  experiment requires a file. `xfuzz init` mitigates this but does not eliminate
  the friction, and this is the real cost of the decision.
- Deeply dynamic strategies (conditional logic, loops over targets) cannot be
  expressed declaratively; those belong in the Starlark tier (ADR-0010) invoked
  *from* a campaign file, keeping the file as the entry point.
- Comment-preserving round-trip requires a comment-aware YAML implementation.

**Neutral**

- Overrides for orthogonal runtime concerns (worker count, budgets, output paths)
  remain available as flags and environment variables, and `xfuzz explain` makes
  their effect visible.

## Alternatives considered

- **CLI-first with optional config.** Familiar to fuzzing veterans. Rejected: two
  configuration paths inevitably diverge, ad-hoc invocations are unreproducible,
  and the console would have to reverse-engineer flags.
- **Declarative file with full CLI parity.** Best of both. Rejected on the same
  divergence grounds — every semantic option would need to exist twice, doubling
  the surface the console and schema must track.
- **Scriptable campaigns (Starlark as the definition language).** Most powerful
  for researchers. Rejected as the primary format: a program cannot be
  round-tripped by a visual editor, and reproducibility becomes a matter of
  reading code. Available as an escape hatch invoked from the file.
