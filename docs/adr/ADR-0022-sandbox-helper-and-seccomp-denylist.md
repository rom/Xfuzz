# ADR-0022: Sandbox helper process, seccomp denylist, and honest isolation levels

- **Status:** Accepted
- **Date:** 2026-08-28
- **Serves:** ASR-0006, ASR-0010

## Context

[ADR-0012](ADR-0012-sandbox-by-default-and-scope-guard.md) decided that
confinement is mandatory and named the mechanisms: namespaces, a **seccomp-bpf
allowlist**, **cgroups v2**, `no_new_privs`, and a read-only root. Implementing
it surfaced three things that decision could not have known.

This record **refines** ADR-0012 rather than superseding it. The decision that
confinement is mandatory, default-on, reported honestly, and refusable by a
campaign is unchanged and remains binding; what changes is how three of its
mechanisms are realised.

**Two mechanisms cannot be applied from the parent.** Resource limits and a
seccomp filter apply to the calling process and are inherited across `exec`, so
the only way to impose them on a target is to set them in the process that
*becomes* it — between `fork` and `exec`. Go offers no hook there: `os/exec`
forks and execs in one step, and running arbitrary Go between the two is not safe
in a runtime with a garbage collector and threads. Every sandbox launcher of this
shape — `bwrap`, `runc`'s init, AFL's own fork-server child — solves it the same
way, with a small process that confines itself and then becomes the target.

**An allowlist is unusable against arbitrary targets.** ADR-0012 said allowlist
because an allowlist is stronger, which is true. But the targets are arbitrary
programs in arbitrary languages, and a list one syscall short does not weaken
confinement — it kills every execution of a target that happens to use that call,
which the campaign then reports as a finding. Chasing that list is a permanent
maintenance cost paid in false crashes.

**The named mechanisms are frequently unavailable.** cgroups v2 is not mounted on
many hosts, including hybrid-mode systems that mount v1 alongside a controllerless
v2 hierarchy. A mount namespace created alongside a user namespace inherits its
mounts *locked* on many kernels, so the read-only root cannot be built in that
combination at all. Neither is detectable from a version number.

## Decision

**A helper binary, `xfuzz-sandbox`.** It applies what only the child can apply —
the filesystem confinement, the identity drop, the resource limits, `no_new_privs`
and the seccomp filter, in that order — and then `execve`s the target. It exits
with a distinct status (125) rather than continuing when any step fails, so the
spawner can tell "the sandbox refused" from "the target crashed". Where the
helper is absent the isolation level reported drops accordingly; it is never
skipped silently.

**A seccomp denylist, not an allowlist.** It names the calls that a namespace
does not already deny and that have a history of kernel escapes — `io_uring`,
`perf_event_open`, `bpf`, `ptrace`, the module and kexec calls, the mount family,
the keyring family, the time-setting family. Denied calls return `EPERM` rather
than killing the process, so a target that handles the error keeps running. The
filter pins the architecture in its first instruction, because a filter that
compares syscall numbers without doing so denies one call and permits another on
any kernel with a second ABI.

**cgroups v1 is supported and reported as weaker.** Under v2 the kernel places
the child in its group at clone time; under v1 the only interface is writing a
pid after the process exists, which leaves a window in which a target that forks
immediately escapes the limit. v1 therefore does not count towards `strong`.

**Availability is probed, not inferred.** The read-only root is established once
against `/bin/true` at startup and the result recorded. Where the fuzzer runs as
root the user namespace is left out entirely, because root does not need it and
including it is what locks the mounts.

**The level explains itself.** Every mechanism that is missing, weaker than it
looks, or disabled by configuration contributes a sentence to the isolation
report, and that report is what a campaign refused for insufficient isolation is
told.

## Consequences

**Positive**

- Confinement is real rather than partial: limits and a syscall filter are
  actually in force, which without the helper they could not be.
- The denylist never turns a working target into a stream of false findings.
- A campaign that requires `strong` gets a refusal naming what is missing, which
  is usually one line of host configuration away.
- Hosts with cgroups v1 get memory and process limits rather than none.

**Negative**

- A second binary must be installed beside `xfuzz` and kept at the same version.
  Where it is missing the tool still runs, with less confinement, and says so.
- A denylist is weaker than an allowlist and cannot be complete. Recorded as a
  residual risk in SECURITY.md rather than left implicit.
- The read-only-root probe costs one process at startup.
- `strong` will be rare in practice. That is the honest report, and the
  alternative — reporting the level the code could achieve rather than the one it
  achieved — is the failure ADR-0012 exists to prevent.

**Neutral**

- The identity drop is a real `setuid` performed by the helper, not a user
  namespace mapping. A mapping translates identities; it does not deprivilege.

## Alternatives considered

- **Re-exec the running binary with an environment marker**, the classic Go
  `reexec` pattern, instead of a separate helper. Rejected: it requires every
  Xfuzz binary — including test binaries — to check for the marker in `main`,
  which puts sandbox behaviour in places that have nothing to do with sandboxing
  and fails in any embedding that does not.
- **`libseccomp` via cgo.** Rejected: ADR-0017 makes the pure-Go build the
  default, and the filter is a few dozen BPF instructions that can be emitted
  directly.
- **Require cgroups v2 and refuse to run without it.** Rejected: it would make
  the tool unusable on common hosts to gain a level that most campaigns do not
  require. Reporting the difference achieves the same protection for campaigns
  that do.
- **A full container runtime** — `pivot_root` onto a constructed root with bind
  mounts. Rejected for v1 as disproportionate: it is a container runtime's worth
  of code and failure modes for a confinement the identity drop already provides
  most of. Revisit if a campaign needs to run a target that must not *read* the
  host either.
