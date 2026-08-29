# Xfuzz — Security

> Threat model, controls, and residual risks. Implements [ASR-0010](asr/ASR-0010-safety-isolation-and-authorization.md)
> and [ADR-0012](adr/ADR-0012-sandbox-by-default-and-scope-guard.md).

## 1. Why this document is load-bearing

Xfuzz is, mechanically, an automated system for **running hostile code** and
**emitting malicious traffic at high volume**. Its normal operation is
indistinguishable from an attack, and its failure modes damage the host it runs
on or systems it was never authorised to touch.

Safety is therefore implemented as a **subsystem with interfaces, tests, and
failure semantics** — not as advice in a manual. Opt-in safety is not safety: the
default is what people run.

## 2. Threat model

### 2.1 Assets

| Asset | Why it matters |
| --- | --- |
| Host running Xfuzz | Compromise via an escaping target |
| Corpus and findings | Represent the campaign's entire value; corruption is silent and costly |
| Captured traffic | Routinely contains credentials, tokens, session material, personal data |
| Target systems | Must only be touched within authorised scope |
| The daemon | Spawns processes and holds findings — a privileged service |
| Audit log | Evidence of what was done, to whom, under what authorization |

### 2.2 Actors

| Actor | Trust | Notes |
| --- | --- | --- |
| Operator | Trusted | Authenticated to the daemon |
| Fuzz target | **Untrusted** | Assumed hostile and actively malicious |
| Campaign file | **Untrusted by default** | May be shared, downloaded, or attacker-supplied |
| Grammars, corpora, dictionaries | **Untrusted** | Community-shared artifacts are attacker-influenced |
| External plugins | **Untrusted** | Arbitrary third-party code |
| Captured traffic | **Untrusted, sensitive** | Attacker-influenced *and* confidential |
| Network peers | Untrusted | Including out-of-scope hosts reached by mistake |

### 2.3 Threats

| ID | Threat | Impact |
| --- | --- | --- |
| **T1** | Target escapes confinement — writes outside its workdir, forks without bound, exhausts memory/disk, or execs a shell | Host compromise, corpus corruption |
| **T2** | Target attacks the fuzzer — corrupts the coverage map, forges the fork-server handshake, poisons the corpus | Silent campaign compromise; findings become untrustworthy |
| **T3** | Traffic reaches an out-of-scope host | Unauthorised access; in a professional context, an incident |
| **T4** | Malicious campaign file achieves code execution on the operator's host | Full compromise via a shared "config" |
| **T5** | Malicious grammar, corpus, or capture exploits an Xfuzz parser | Compromise of the fuzzer itself |
| **T6** | Plugin abuses its position to read findings or reach the network | Data exfiltration |
| **T7** | Unauthenticated or over-exposed daemon | Remote code execution as the operator |
| **T8** | Captured credentials leak via corpus, findings, exports, or logs | Credential disclosure |
| **T9** | Audit log tampering | Loss of accountability |
| **T10** | Uncontrolled resource growth fills disk or OOMs the host | Denial of service against the operator |

## 3. Controls

### 3.1 Target isolation — T1, T2

Targets run confined **by default**, at the strongest level the platform offers.

| Platform | Mechanism | Level |
| --- | --- | --- |
| Linux | User/mount/PID/network namespaces; seccomp-bpf allowlist; cgroups v2 (CPU, memory, PIDs); `no_new_privs`; read-only root with a writable workdir | `strong` |
| macOS | Sandbox profile, `rlimit`s, restricted environment | `moderate` |
| Windows | Job Objects, restricted tokens, AppContainer where available | `moderate` |
| any | Resource limits and workdir confinement only | `minimal` |

The level in force is **reported**, and a campaign may declare
`safety.isolation: strong` and **refuse to start** below it. "Supported on macOS"
must never silently mean "unprotected on macOS".

The level is computed from the mechanisms the host actually provides, probed at
startup, never from what was configured. In practice that means a well-equipped
Linux host frequently reports `moderate` rather than `strong`, and it should:

- **cgroups v1 instead of v2.** Only v2 can place a process in its group at
  clone time. Under v1 the pid is written after the process exists, so a target
  that forks immediately can escape the limit. The window is microseconds and
  the alternative is no limit at all, but it is a real gap.
- **No read-only root.** A mount namespace created alongside a user namespace
  inherits its mounts *locked* on many configurations, so they cannot be
  remounted read-only. The sandbox probes this once rather than guessing from
  kernel versions, and where it fails, confinement rests on the target's host
  identity instead.
- **No sandbox helper.** Resource limits and the seccomp filter can only be
  installed by the process that will become the target (§ 3.1a), so without
  `xfuzz-sandbox` on the path neither is in force.
- **No PID namespace for a one-shot target.** A PID namespace changes the
  behaviour of the program inside it (§ 3.1b), so it is applied only where it
  does not: to a fork server, whose executions are its children.

Each of these appears in `xfuzz`'s isolation report with the sentence explaining
it, because a campaign refused for insufficient isolation has to be told what is
missing — the remedy is usually one line of host configuration.

### 3.1a How the Linux sandbox is applied

Three mechanisms are applied by the parent at clone time: the namespaces, the
cgroup (under v2), and the process group. Three more can only be applied by the
process that will *become* the target, between fork and exec — resource limits,
`no_new_privs` with the seccomp filter, and the identity drop — and Go offers no
hook there. `cmd/xfuzz-sandbox` is that process: it applies them to itself and
then execs the target, which inherits all three. It exits 125 rather than
continuing when any of them fails, because a sandbox that quietly did not happen
is worse than no sandbox: the campaign would still report itself as confined.

Two details of that ordering are load-bearing:

- **A user-namespace uid mapping is not a privilege drop.** A child cloned by
  root with a mapping that omits uid 0 is still host root; it merely *reports*
  the kernel's overflow id, which is indistinguishable from an unprivileged uid
  in `getuid()` and in every log line. The drop is a real `setuid`, performed
  after the steps that need privilege and verified afterwards.
- **The target must not run as the overflow id.** A process mapped to it sees
  every file owned by anyone outside its namespace — the corpus included — as
  owned by itself, and may write all of it. Targets run as 65533, checked
  against the kernel's own `overflowuid` rather than assumed.

### 3.1b Why a one-shot target gets no PID namespace

A PID namespace makes the first process in it PID 1, and the kernel treats PID 1
specially: it discards signals sent to it from inside its own namespace unless a
handler is installed. `abort(3)` is implemented by raising SIGABRT at oneself, so
a target that *is* PID 1 cannot abort. glibc's fallback is to dereference a null
pointer, and the campaign records a segmentation fault where an assertion failed.

That is not a cosmetic difference. Bucketing separates findings by their failure
class and minimisation preserves it, so every `assert()`, every Rust panic under
`panic=abort`, and every sanitizer report would be filed under the wrong bug —
with nothing anywhere reporting an error. A sandbox that changes what the program
under test *does* is not a sandbox, it is a second bug.

A fork server is unaffected: the process it forks for each execution is PID 2 and
upwards, with ordinary signal semantics. So the namespace is used for fork-server
targets and left out for one-shot ones, and the isolation report says so. The
remaining gap is a fork server whose target aborts during startup, before its
first fork; that surfaces as a handshake failure rather than as a finding.

Making it work for one-shot targets too would need the helper to fork rather than
exec and to carry the child's wait status back out of band, because PID 1 cannot
re-raise the signal its child died from either. That is a worthwhile change and
it is not this one.

The seccomp policy is a **denylist**, not an allowlist, and that is a deliberate
weakening. The targets are arbitrary programs in arbitrary languages; an
allowlist one syscall short kills every execution of a target that happens to use
it, which the campaign would report as a finding. A denylist one syscall short
still blocks everything it names. It is also not the primary control — the user
namespace already denies most of it by removing the capabilities those calls need
— it is the layer covering what a namespace does not, `io_uring` and
`perf_event_open` foremost. Denied calls return `EPERM` rather than killing the
process, so a target that handles the error keeps running and the campaign does
not fill with crashes of the sandbox's own making.

Against T2 specifically: the coverage map is validated for structural sanity, the
fork-server handshake is versioned and length-checked, and executors treat all
target output as untrusted input to their own parsers.

Escape hatches exist for legitimate needs (raw sockets, privileged ports, device
access). Each is explicit, narrow, and recorded in the audit log.

### 3.2 Scope guard — T3

Any campaign emitting off-host traffic requires an explicit allowlist of hosts,
CIDRs, and ports. Enforcement is layered so no single bug defeats it:

1. **Network namespace with default-deny egress** (Linux) — enforcement *below*
   the code, so a buggy or malicious adapter cannot bypass it.
2. **In-process dialer check** on every platform — the portable layer.
3. **Validation at campaign start** — misconfiguration fails immediately, not
   after the first packet.

Rules:

- A campaign targeting a non-loopback address **without** an allowlist refuses to
  start.
- Loopback is exempt, so local experimentation stays frictionless.
- Widening scope to public address space requires an explicit, separately
  recorded acknowledgement.
- Every scope decision and every violation attempt is audited.

### 3.3 Authorization record — T3, T9

Remote-target campaigns require, before the first packet:

- operator identity
- timestamp
- an authorization reference (engagement ID, ticket, or written approval
  reference)
- an attestation that the operator is authorised to test the declared scope

This is recorded in the audit log and attached to every finding exported from the
campaign.

### 3.4 Untrusted campaign files — T4

A campaign file names a binary to execute, so an attacker-supplied file is an
attacker-supplied command. Controls:

- Campaign files are **data, not code** — YAML with a JSON Schema, no
  general-purpose execution during parsing.
- Dynamic logic is confined to the Starlark tier, which is **hermetic**: no
  filesystem, network, or clock access, with step and allocation limits
  (ADR-0010).
- The daemon executes campaigns only from operator-designated directories.
- `xfuzz explain` renders the fully resolved configuration — every binary,
  argument, environment variable, and scope entry — so a file can be reviewed
  before it is run.
- Targets are sandboxed regardless of what the file requests; a campaign file
  cannot lower isolation below the daemon's configured floor.

### 3.5 Xfuzz's own attack surface — T5

Xfuzz parses untrusted input in the ordinary course of its work: corpora,
grammars, dictionaries, campaign files, HAR/pcap captures, sanitizer output,
target responses, and the plugin protocol.

Controls:

- **Self-fuzzing.** Every parser listed above is continuously fuzzed with Go
  native fuzzing in CI ([TESTS.md](TESTS.md) § Self-fuzzing). A fuzzing tool with
  an unfuzzed parser has no credibility.
- Memory-safe implementation language throughout the parsing surface.
- Explicit size, depth, and recursion limits on every parser — decompression
  bombs and deeply nested grammars are anticipated inputs.
- No dynamic code loading in-process (Go's `plugin` package is rejected outright,
  ADR-0010).

### 3.6 Plugin containment — T6

External plugins run **out of process** with:

- no inherited credentials and no store access — they receive only the data their
  interface defines
- their own sandbox profile and resource limits
- a versioned protocol with strict message validation
- contained failure: a dying plugin fails its campaign with a clear error and
  never affects the daemon or sibling campaigns

Scripted extensions run in hermetic Starlark and cannot perform I/O at all — an
assertion covered by test.

### 3.7 Daemon security — T7

- **Unix domain socket by default**, protected by filesystem permissions.
- TCP/TLS is **opt-in**, never the default, and requires token authentication.
- No unauthenticated endpoint, including metrics.
- The console is served by the daemon with standard web protections: CSP, no
  external asset loading, CSRF protection on state-changing requests, and
  same-origin enforcement for the WebSocket.
- API inputs are schema-validated before reaching any subsystem.

### 3.8 Sensitive data — T8

Captured traffic is treated as confidential by default:

- Authentication material (bearer tokens, cookies, API keys, `Authorization`
  headers) is **recognised, held fixed during mutation, and redacted at rest**.
  Fixing it is also correct fuzzing practice — mutating a token yields only 401s.
- Findings and corpora derived from captures are marked sensitive; export applies
  redaction and warns explicitly.
- Redaction rules are configurable and extensible for domain-specific secrets.
- Logs never contain input payloads at default verbosity.

### 3.9 Audit integrity — T9

The audit log is **append-only and hash-chained**: each entry commits to its
predecessor, so removal or modification is detectable. Every field is
length-prefixed before hashing, so moving a character across a field boundary is
not an undetectable edit, and the chain head is mirrored outside the table, so
truncation at the end is detectable as well as modification in the middle — a
prefix of a valid chain is otherwise a valid chain. It **cannot be disabled from
within a campaign configuration**. Verification is a supported operation
(`xfuzz audit verify`) and reports how many entries verified before the first
divergence.

This is tamper **evidence**, not tamper **proofing**, and the distinction is
stated rather than glossed: anyone who can write the database can rewrite the
chain and the head together. What it buys is that accidental corruption, a
partial restore, and a careless edit are all caught, and that a deliberate
rewrite has to be deliberate. Anything stronger needs a signature or an off-box
copy, which is a v1.0 concern.

### 3.10 Resource control — T10

- Per-campaign disk budgets for corpus and findings, with a defined culling
  policy and reported (never silent) culling.
- Per-target memory, CPU, PID, file-descriptor, and wall-clock limits enforced by
  the sandbox.
- Daemon-level caps on concurrent campaigns and workers.
- Termination conditions are a first-class part of every campaign file, so an
  unattended run ends deterministically.

## 4. Residual risks

Stated plainly, because unstated residual risk is the dangerous kind:

| Risk | Status |
| --- | --- |
| Kernel vulnerability defeating namespace/seccomp isolation | Not mitigable by Xfuzz. Run high-risk targets in a disposable VM. |
| A seccomp denylist cannot be complete | Accepted, and explained in § 3.1a. An allowlist would be stronger and unusable against arbitrary targets. |
| cgroups v1 admits a process to its group after it starts | Reported as part of the isolation level; a fork in that window escapes the limit. Mount cgroup v2 for `strong`. |
| An unprivileged Xfuzz cannot give the target a separate identity | Reported. The target is then, on the host, the same user as the fuzzer, with the same access to the corpus. |
| macOS and Windows isolation is weaker than Linux | Reported honestly as `moderate`; require `strong` for hostile targets. |
| An operator with an escape hatch enabled | Audited, not prevented. |
| Scope guard cannot prevent an authorised-but-wrong target | Scope is only as correct as the allowlist the operator writes. |
| A malicious plugin exfiltrating data it is legitimately given | Contained but not eliminated; only run trusted plugins. |
| Physical or hypervisor-level attacks | Out of scope. |

## 5. Responsible use

Xfuzz is built for authorised security testing: your own software, systems you
have written permission to test, and CTF or research environments where testing
is sanctioned.

Using it against systems you are not authorised to test is unlawful in most
jurisdictions. The scope guard and authorization record exist to make the
boundary explicit and auditable — they are not a substitute for having
authorization, and they must not be treated as one.

## 6. Reporting a vulnerability in Xfuzz

Report security issues in Xfuzz itself privately to the maintainer. Please
include a description, affected version, reproduction steps, and impact
assessment.

- Acknowledgement target: 3 business days
- Assessment target: 10 business days
- Fix and disclosure: coordinated with the reporter

Do not open a public issue for a security vulnerability.

## 7. Security testing

Security properties are tested, not asserted. See [TESTS.md](TESTS.md):

- Sandbox escape attempts (write outside workdir, fork bomb, memory exhaustion,
  unlisted network connection) are integration tests that must fail to escape.
- Scope-guard bypass attempts are tests.
- Audit-log tamper detection is a test.
- Starlark I/O attempts are tests.
- Every untrusted parser is continuously self-fuzzed.
- Dependency licence and vulnerability scanning gate the build.
