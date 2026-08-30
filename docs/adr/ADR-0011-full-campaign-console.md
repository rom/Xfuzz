# ADR-0011: Full campaign console as an embedded SPA

- **Status:** Accepted
- **Date:** 2026-08-28
- **Serves:** ASR-0005, ASR-0011, ASR-0012, ASR-0015

## Context

ASR-0005 makes the web console a first-class interface with capability parity
against the CLI, and ASR-0015 requires single-artifact, air-gapped deployment.
ASR-0011 puts triage — the real labour of fuzzing — at the centre of the product,
and triage is fundamentally a visual, interactive workflow.

## Decision

Ship a **full campaign console**, not a dashboard, **embedded in the binary**.

Scope:

| View | Purpose |
| --- | --- |
| **Campaigns** | List, launch, pause, resume, stop; health at a glance |
| **Campaign detail** | Live exec rate, coverage-over-time, corpus growth, stability, engine overhead, per-mutator yield, worker table |
| **Coverage** | Coverage map visualisation, plateau detection, per-module breakdown |
| **State machine** | For stateful campaigns: discovered states, transitions, unexplored frontier |
| **Findings** | Bucketed findings, stack traces, sanitizer diagnosis, reproducibility rate, minimised repro download, triage state and notes |
| **Corpus browser** | Inspect entries as IR tree *and* hex, with provenance chain |
| **Config editor** | Schema-driven form over the campaign file, with validation, diff, and raw editing |
| **Grammar workbench** | Author a grammar and sample generated inputs live |
| **Safety** | Scope allowlist, isolation level in force, audit log |

Implementation:

- **TypeScript SPA** built with Vite, compiled to static assets and embedded via
  `embed.FS`. No CDN, no runtime asset fetch, no external fonts — air-gap clean.
- **Live updates over server-sent events**, with server-side **downsampling and
  batching**. High-rate events are lossy by design: a 100k exec/s campaign must
  never be able to back-pressure the engine through a browser (ASR-0012).

  This said WebSocket when it was written. ADR-0024, which is later and decided
  the transport for the whole API, rejected WebSocket for this stream:
  bidirectional framing for traffic that is server-to-client by design, where
  SSE reconnects with no client code at all. Corrected here rather than left to
  contradict it. What would justify revisiting is the console needing to *send*
  on the same channel, which it does not — every action it takes is a POST.
- Pure API client (ADR-0003), with no privileged path of its own.
- Because campaigns are file-defined (ADR-0016), the config editor **round-trips
  the campaign file**, preserving comments and key order, and every console
  "launch" is equivalent to committing that file and running the CLI.

Explicitly **out of scope for v1**: multi-node fleet view (no distributed
fuzzing per ADR-0015), and multi-tenant RBAC.

## Consequences

**Positive**

- Triage, coverage plateaus, and state-machine gaps become visible rather than
  inferred from log scraping — the highest-leverage part of the product.
- Config round-tripping means the console teaches the file format instead of
  hiding it, and campaigns stay reproducible and git-diffable.
- Embedding keeps deployment to one artifact.

**Negative**

- A substantial frontend is a real, ongoing engineering commitment inside a
  systems project, with its own toolchain, dependency, and security surface.
- The build now requires Node for the web assets; the Go build must remain
  possible from pre-built assets so contributors and CI without Node are not
  blocked.
- Comment-preserving config round-trip is genuinely fiddly and needs its own
  tests.
- Visualising a large corpus or coverage map in a browser has hard scaling
  limits, requiring server-side aggregation rather than raw data pushes.

**Neutral**

- Deferring fleet view keeps console scope aligned with ADR-0015.

## Alternatives considered

- **Monitoring and triage only, launch via CLI.** Much smaller surface. Rejected:
  it breaks the parity requirement in ASR-0005 and forces terminal round-trips
  during exactly the workflow the console exists to serve.
- **Dashboard only.** Minimal effort. Rejected: it makes the console decorative,
  and the brief calls for a graphical tool to *specify* campaigns.
