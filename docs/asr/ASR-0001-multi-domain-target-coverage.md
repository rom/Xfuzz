# ASR-0001: Multi-domain target coverage

- **Status:** Accepted
- **Priority:** Must
- **Date:** 2026-08-28
- **Source:** Product brief — "fuzz other tools, protocols, file formats, APIs, GUI and TUI"

## Requirement

Xfuzz must fuzz targets across fundamentally different interaction modes:

1. **File formats / parsers** — target consumes a byte blob (stdin, argv path, memory buffer).
2. **Command-line tools** — target consumes argv, environment, stdin, and files.
3. **Network protocols** — target consumes a *sequence* of framed messages over a socket.
4. **APIs** — REST, GraphQL, and gRPC endpoints, driven from captured traffic.
5. **GUI applications** — desktop apps driven by synthetic input events.
6. **TUI applications** — terminal apps driven through a PTY.

A single installation must handle all six without recompilation, and a user must
be able to move between them without learning a different tool.

## Rationale

These domains are conventionally served by separate, incompatible tools (AFL++
for files, boofuzz for protocols, RESTler for APIs, Sikuli-likes for GUI). The
per-domain differences are real but shallow: they differ in *how an input is
delivered and how a response is observed*, not in how a corpus is scheduled, how
inputs are mutated, or how findings are triaged. Unifying them is the product
thesis.

## Architectural impact

- Forces a hard separation between the **engine core** (corpus, scheduler,
  mutators, feedback, findings) and **domain adapters** (executor + observers +
  input codec).
- Forbids any core type from assuming an input is a flat `[]byte`; the core must
  address a structured input (ASR-0014).
- Forbids the core loop from assuming one execution equals one input; a network
  or GUI execution is a *session* of many deliveries.
- Execution rates differ by five orders of magnitude (10⁵/s for an in-process
  parser vs. 10⁰/s for a GUI). The scheduler, the statistics pipeline, and the
  UI update cadence must all be rate-adaptive rather than tuned for one domain.

## Acceptance criteria

- One `xfuzz` binary runs a campaign in each of the six modes, configured only by
  a campaign file.
- Adding a new domain requires implementing documented interfaces only, with no
  edits to engine-core packages.
- Corpus, findings, triage, replay, and the web console behave identically across
  domains.

## Satisfied by

ADR-0001, ADR-0004, ADR-0005, ADR-0009, ADR-0013, ADR-0014
