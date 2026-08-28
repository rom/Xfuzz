# ADR-0003: Daemon core with thin clients

- **Status:** Accepted
- **Date:** 2026-08-28
- **Serves:** ASR-0005, ASR-0010, ASR-0012, ASR-0015

## Context

ASR-0005 requires a CLI and a web console with equal capability and no
authoritative state in either. ASR-0012 requires campaigns to survive client
disconnection and daemon restart. Campaigns run for days; a design where the
campaign is a child of the CLI process makes "launch from the terminal, watch
from a browser, triage tomorrow" impossible.

## Decision

Adopt a **control-plane daemon with thin clients**:

```
xfuzz (CLI) ─┐
             ├─► xfuzzd (daemon) ─► worker processes ─► targets
browser  ────┘        │
                      └─► store (corpus, coverage, findings, audit)
```

- **`xfuzzd`** owns campaign lifecycle, configuration validation, worker
  supervision, the store, the safety layer, and the event bus.
- **`xfuzz`** (CLI) and the **web console** are both API clients with no
  privileged path and no local state beyond caches and credentials.
- The API is **gRPC** with a **REST/JSON gateway** for the browser and for
  scripting; live updates stream over **WebSocket/SSE**.
- **Default transport is a Unix domain socket** with filesystem permissions;
  TCP/TLS with token authentication is opt-in and never the default (ASR-0010).
- `xfuzz run` transparently **auto-starts a private daemon** when none is
  running, so the common single-user case needs no service management. The
  daemon is still the engine — there is no in-process bypass path.

Every capability is defined once as an API method; CLI commands and console views
are generated from or tested against that surface, enforcing parity by
construction (ASR-0005).

## Consequences

**Positive**

- Campaigns are decoupled from client lifetime: disconnect, reconnect, resume.
- One authorisation, audit, and scope-enforcement chokepoint (ASR-0010) rather
  than one per interface.
- Multi-user and remote operation become configuration, not redesign; the same
  boundary is where distributed coordination would attach in v2 (ADR-0015).
- Worker supervision, restart, and health live in one place.

**Negative**

- Meaningfully more machinery than a single-process tool: IPC, serialisation,
  versioning, lifecycle, and a new class of failure ("daemon not running",
  "version mismatch").
- API/CLI/console version skew is now possible and must be handled explicitly.
- A daemon holding findings and able to spawn processes is a security-relevant
  service in its own right — hence local-socket-by-default and the threat model
  in `docs/SECURITY.md`.

**Neutral**

- Auto-start keeps the single-user experience close to a plain CLI while
  preserving one execution path.

## Alternatives considered

- **Single binary with embedded web UI, no daemon.** Simplest deployment.
  Rejected: the campaign dies with the process, which breaks ASR-0012's
  resumability and the launch-here-watch-there workflow that motivates the
  console.
- **Library-first with thin wrappers, no persistent server.** Excellent for
  embedding and CI. Rejected as the primary topology for the same reason;
  retained as a *secondary* property — the engine remains a usable Go library
  and the daemon is a thin shell over it.
