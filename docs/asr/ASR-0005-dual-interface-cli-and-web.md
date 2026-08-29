# ASR-0005: Dual interface — CLI and web console

- **Status:** Accepted
- **Priority:** Must
- **Date:** 2026-08-28
- **Source:** Product brief — "both a command line tool and a graphical web based tool"

## Requirement

Xfuzz must offer two first-class interfaces over identical capability:

- A **CLI** suitable for scripting, CI, and remote shells.
- A **web console** for configuring, launching, monitoring, and triaging
  campaigns, including live coverage growth, corpus inspection, state-machine
  visualisation, and finding triage.

Neither interface may possess a capability the other lacks, and neither may hold
authoritative state.

## Rationale

Fuzzing is long-running and visual: coverage plateaus, state-machine gaps, and
crash clusters are far easier to reason about graphically, while campaign launch
and CI integration demand a CLI. Tools that bolt a read-only dashboard onto a CLI
force operators back to the terminal for every real action; tools that are
GUI-first are unusable in CI.

## Architectural impact

- Both interfaces must be **clients of one API**; the API is the only place
  campaign state lives.
- Campaign state must survive client disconnection — launching from the CLI and
  observing from the browser is a required workflow.
- Requires a **live event stream** with backpressure and downsampling: a
  100k exec/s campaign cannot push per-execution events to a browser.
- The web console must be **shippable inside the single binary** (no separate
  web server, no CDN dependency) to keep deployment honest on air-gapped hosts.
- Because the campaign definition is file-only (ADR-0016), the console's editor
  must round-trip to that exact file format, preserving comments and ordering.

## Acceptance criteria

- Every action available in the console has a documented CLI equivalent and vice
  versa, verified by a parity test over the API surface.
- A campaign launched by the CLI is fully controllable from the console, and one
  configured in the console is reproducible by committing the emitted file and
  running the CLI.
- The console operates against a 100k exec/s campaign without unbounded memory
  growth in either the browser or the daemon.

## Satisfied by

ADR-0003, ADR-0011, ADR-0016, ADR-0024
