# ADR-0012: Sandbox by default and scope guard

- **Status:** Accepted
- **Date:** 2026-08-28
- **Serves:** ASR-0006, ASR-0010

## Context

A fuzzer is an automated system for running hostile code and emitting malicious
traffic at high volume. Two failure modes are catastrophic and common:

1. **Target escape** — a fuzzed target writes outside its workdir, exhausts host
   resources, forks without bound, or corrupts the fuzzer's own corpus.
2. **Out-of-scope traffic** — a network campaign reaches a host the operator was
   never authorised to test. In a professional context this is the difference
   between an engagement and an incident.

Neither is preventable by documentation. Opt-in safety is not safety: the default
is what people run.

## Decision

Make safety a **mandatory subsystem** sitting between the engine and every
executor. No executor may spawn a process or open a socket except through it.

**Isolation by default.** Targets run confined without the operator opting in,
at the strongest level the platform supports:

| Platform | Mechanism | Declared strength |
| --- | --- | --- |
| Linux | User/mount/PID/network namespaces, seccomp-bpf allowlist, cgroups v2 (CPU, memory, PIDs), `no_new_privs`, read-only root with a writable workdir | `strong` |
| macOS | Sandbox profile, `rlimit`s, restricted environment | `moderate` |
| Windows | Job Objects, restricted tokens, AppContainer where available | `moderate` |
| any | Resource limits and workdir confinement only | `minimal` |

The level in force is **reported**, and a campaign may **require a minimum level
and refuse to start below it** — so "supported on macOS" never silently means
"unprotected on macOS".

**Scope guard.** Any campaign emitting off-host traffic requires an explicit
allowlist of hosts, CIDRs, and ports. Enforcement is layered deliberately:

1. A **network namespace with default-deny egress** on Linux — enforcement below
   the code, so a buggy or malicious adapter cannot bypass it.
2. An **in-process dialer check** on every platform, as the portable layer.
3. **Validation at campaign start**, so misconfiguration fails immediately rather
   than after the first packet.

A campaign targeting a non-loopback address without an allowlist **refuses to
start**. Widening scope to public address space requires an explicit,
separately recorded acknowledgement.

**Authorization record.** Remote-target campaigns require operator identity, a
timestamp, and an authorization reference recorded before the first packet.

**Audit trail.** Campaign lifecycle, scope decisions, scope violations, and
findings access are written to an append-only, hash-chained log that cannot be
disabled from within a campaign configuration.

## Consequences

**Positive**

- The two catastrophic failure modes are structurally prevented, not warned about.
- Professional engagement requirements (scope, authorization, audit) are met by
  the tool rather than by operator discipline.
- Isolation also protects *the fuzzer* — corpus corruption by a runaway target is
  a real and under-appreciated failure mode.

**Negative**

- Sandboxing adds per-execution setup cost, directly taxing ASR-0007. Mitigation:
  the sandbox is established once per worker or per pooled process, not per
  execution; the cost must be measured and reported.
- Some legitimate targets need capabilities the default denies (raw sockets,
  privileged ports, device access), so escape hatches must exist — each explicit,
  narrow, and audited.
- Platform isolation differences make this the least portable subsystem in the
  project, and the honest strength levels above are less comfortable than a claim
  of uniform protection.
- Scope guard adds friction to quick local experiments; loopback is exempted to
  keep that path fast.

**Neutral**

- Safety configuration lives in the campaign file (ADR-0016), so it is reviewable
  and version-controlled like everything else.

## Alternatives considered

- **Sandbox optional, scope guard always on.** Lower friction. Rejected: target
  escape and corpus corruption are frequent enough in practice that opt-in
  protection means most runs are unprotected.
- **Documented guardrails only.** Simplest, engine stays neutral. Rejected: this
  is the status quo across existing fuzzers and it demonstrably does not prevent
  either failure mode.
