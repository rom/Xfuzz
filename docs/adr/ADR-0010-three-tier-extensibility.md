# ADR-0010: Three-tier extensibility model

- **Status:** Accepted
- **Date:** 2026-08-28
- **Serves:** ASR-0004, ASR-0009, ASR-0014

## Context

ASR-0009 requires extension along every axis — mutators, grammars, feedbacks,
objectives, executors, state models, triage. These needs conflict irreconcilably:

- A per-execution mutator at 100k exec/s cannot afford IPC or an interpreter.
- A community-supplied or heavyweight extension must not run in-process with the
  engine's memory.
- A researcher iterating on a campaign-local oracle should not need a compiler.

Go's built-in `plugin` package fails all three: Linux-only, exact-toolchain-
version-locked, and offering no isolation whatsoever.

## Decision

Provide **three extension tiers over the same interfaces**, and let the user pick
per extension:

| Tier | Mechanism | Isolation | Overhead | Use for |
| --- | --- | --- | --- | --- |
| **Native** | Go interface, compiled in | none | ~ns | Hot-path mutators, codecs, feedbacks |
| **External plugin** | Out-of-process over gRPC/stdio | process | ~10–100 µs | Untrusted, heavyweight, or non-Go logic |
| **Script** | Embedded Starlark, hermetic | sandbox | ~µs | Campaign-local oracles, glue, rapid iteration |

- **Native** is the reference tier. Every extension point is a narrow, documented,
  versioned Go interface; the other two tiers are generated from and validated
  against those same interfaces, so semantics cannot drift between tiers.
- **External plugins** are separate processes speaking a versioned protocol.
  Crashes are contained: a dying plugin fails its campaign with a clear error and
  never touches the daemon or sibling campaigns. Batching amortises IPC — a
  plugin mutator receives a batch of inputs, not one per call.
- **Scripts** use **Starlark**, chosen specifically because it is hermetic by
  construction: no filesystem, network, or clock access, and deterministic
  execution — which matters because campaign files may be untrusted (ASR-0010)
  and because determinism is a hard requirement (ASR-0008). Execution is
  additionally bounded by step and allocation limits.

The engine reports **time spent inside extensions** as a first-class metric, so a
slow plugin is diagnosable rather than mysterious (ASR-0012).

## Consequences

**Positive**

- Users choose their own speed/safety/convenience trade-off per extension rather
  than accepting one global compromise.
- Non-Go users are first-class through the plugin protocol.
- Untrusted extensions are genuinely contained, which is what makes sharing
  grammars and oracles safe.
- Starlark's hermeticity preserves campaign determinism, which an unrestricted
  scripting language would destroy.

**Negative**

- Three delivery mechanisms per extension point to build, document, test, and
  version. Interface changes now ripple across three surfaces.
- The plugin protocol becomes a compatibility commitment with its own versioning
  policy.
- Starlark is unfamiliar to some users and deliberately non-Turing-complete in
  places; some logic will not be expressible and must move to a plugin.

**Neutral**

- v1 ships native tier complete, plugin protocol for feedbacks/mutators/
  objectives, and Starlark for oracles and campaign-local logic (ADR-0020).

## Alternatives considered

- **Go interfaces only.** Fastest and simplest. Rejected: it excludes every
  non-Go user and requires a rebuild for any customisation.
- **Go `plugin` package.** Native speed with dynamic loading. Rejected outright:
  Linux-only, toolchain-lockstep, no isolation — it fails ASR-0006 and ASR-0009
  simultaneously.
- **WASM plugins.** Genuinely attractive — sandboxed, portable, hot-loadable.
  Rejected for v1: per-call overhead in the hottest loop plus a runtime
  dependency, for benefits that Starlark (convenience) and out-of-process plugins
  (isolation) already cover between them. A strong candidate for a future tier.
- **Lua instead of Starlark.** More familiar and faster. Rejected: not hermetic by
  default and not deterministic, conflicting with ASR-0008 and ASR-0010.
