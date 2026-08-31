# ASR-0010: Safety, isolation, and authorization

- **Status:** Accepted
- **Priority:** Must
- **Date:** 2026-08-28
- **Source:** Design decision — sandbox by default plus scope guard

## Requirement

1. **Target isolation by default.** Fuzz targets execute confined — filesystem,
   network, process, and resource limits — without the operator opting in.
2. **Scope guard.** Any campaign that emits traffic off-host requires an explicit
   allowlist of hosts, networks, and ports. Out-of-scope destinations are refused
   at the point of transmission, not merely warned about.
3. **Authorization record.** Remote-target campaigns require a recorded
   operator identity, timestamp, and authorization reference before the first
   packet is sent.
4. **Audit trail.** Campaign lifecycle, scope decisions, scope violations, and
   findings access are recorded in a tamper-evident log.
5. **Daemon security.** The control plane authenticates clients, is local-only by
   default, and never exposes an unauthenticated remote-code-execution surface.
6. **Sensitive data handling.** Corpora derived from captured traffic may contain
   credentials and personal data; storage, redaction, and export must account for
   this.

## Rationale

A fuzzer is, mechanically, an automated attack tool that runs hostile code and
emits malicious traffic at high volume. The two catastrophic failure modes are
concrete and common: a target escaping to damage the host or the fuzzer's own
corpus, and traffic reaching a system the operator was never authorised to test.
Both are architectural problems — a documentation warning does not prevent
either. Safety is therefore a subsystem with interfaces, tests, and failure
semantics, not a chapter in the manual.

## Architectural impact

- Introduces a mandatory **safety layer** between the engine and every executor;
  no executor may spawn a process or open a socket except through it.
- Isolation strength varies by platform (ASR-0006), so the layer must report a
  declared strength level and the campaign must be able to *require* a minimum
  level and refuse to start below it.
- The scope guard must sit at the lowest practical layer — a network namespace
  with default-deny egress on Linux, plus an in-process dialer check everywhere —
  so that a buggy or malicious adapter cannot bypass it.
- Audit logging must be append-only and hash-chained, and must not be disableable
  from within a campaign configuration.
- Findings and corpora require an at-rest handling policy and redaction hooks on
  export.

## Acceptance criteria

- Default configuration confines a target that attempts to write outside its
  workdir, spawn children beyond its limit, or connect to an unlisted host.
- A network campaign without a scope allowlist refuses to start, with an
  actionable error.
- Scope-violation attempts are blocked and recorded; the audit log detects
  tampering.
- Threat model, controls, and residual risks are documented in `docs/SECURITY.md`.

## Satisfied by

ADR-0003, ADR-0012, ADR-0014, ADR-0016, ADR-0022, ADR-0033
