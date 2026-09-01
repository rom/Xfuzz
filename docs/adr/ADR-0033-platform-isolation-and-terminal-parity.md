# ADR-0033: Each platform gets its own confinement mechanism, not one with gaps

- **Status:** Accepted
- **Date:** 2026-08-31
- **Serves:** ASR-0006, ASR-0010, ASR-0011

> **Amendment.** Two things this record decided in the abstract were wrong in
> the specific, and CI found both on the platforms nobody develops on.
>
> **The profile must keep the fuzzer's own mechanisms writable, not only the
> target's working directory.** The coverage map, the comparison map and the
> block map are files under the shared-memory directory that the *target* maps
> for writing, and macOS has no `/dev/shm` — they live under the temporary
> directory, which the profile denied. The macOS job then reported every
> coverage test failing with "the target is not instrumented", which is the
> wrong diagnosis of a correct sandbox. This is not a relaxation of the Linux
> policy but parity with it: there a read-only root is a bind remount of `/`,
> and `/dev/shm` is a separate mount the remount does not reach, so the maps
> stay writable without anyone having decided they should. The writable set is
> now assembled by `platform.ConfineWritable`, which is untagged and tested on
> every platform, because a denied write does not stop a campaign — it makes it
> find nothing.
>
> Two smaller corrections, both about a rule the kernel reads differently from
> the person writing it: a `subpath` rule is matched against the *real* path, so
> a temporary directory under `/var` — a link to `/private/var` — was allowed
> under a name the kernel never sees; and a relative `subpath` makes
> `sandbox-exec` reject the entire profile, which leaves the target unrunnable
> rather than unconfined.
>
> **A control protocol is not a descriptor number.** The daemon speaks to its
> workers, and a fork server to its target, on the two descriptors after the
> standard three. Windows has none: a child receives handles, only the three
> standard ones are placed for it, and naming a fourth file makes the process
> start fail outright — which is why `xfuzz doctor` could not start a daemon
> there at all. So the streams are requested rather than always created
> (`ProcSpec.Protocol`), they are placed where the platform has room — standard
> input and output where descriptors cannot be inherited — and the child is
> *told* the numbers rather than assuming them. A child on that path gives up
> its own standard input and output, which is why asking is part of it: a
> browser and a terminal program must keep theirs.
>
> **On Windows the symbol-less executable is not the hard case, it is every
> case.** `pkg/binary` treated a missing symbol table as the exception a
> stripped ELF represents. Microsoft's linker writes every name into a separate
> PDB file, so an ordinary Windows build — not stripped, not hardened — arrives
> with no symbol table at all, and the tests that asked the fixture for a
> function by name were asking for something the platform does not put in the
> image. What stands in for it is the exception directory: unwinding an x64
> stack is table-driven with no frame-pointer fallback, so the ABI requires a
> `.pdata` entry for every non-leaf function, the table is needed at run time,
> and unlike a DWARF call-frame entry it states where each function *ends* as
> well as where it starts. Reading it needs the image base, which is in the
> optional header and which this package had been guessing at by rounding the
> first executable section's address down — right for the usual layout, and a
> whole section short for any image whose code starts past the first 64K, where
> every function address it produced pointed at nothing. Recovery on such an
> image is now measured directly rather than inferred from the ELF case: the
> fixture is a freestanding program built for the Microsoft target, which any
> clang can compile and any COFF linker can link without a Windows SDK, so the
> platform's normal shape is exercised on every host rather than only on the one
> where it ships.
>
> The same fixture exposed a second fault that is not a Windows fault at all.
> Blocks were attributed to whichever entry point the walk reached them from
> first, so descent from one address owned everything that address called. On
> Linux that is invisible, because the C runtime reaches `main` through an
> indirect call and every function therefore becomes its own root by accident of
> the platform; on Windows the runtime calls `main` directly and one function
> came back holding the whole image. Ownership is now decided by address — a
> function runs to the next entry point, the end of its declared extent, or the
> end of the section, whichever comes first — which is what the field always
> claimed to mean.
>
> **Two more things this platform does not have, now stated rather than
> assumed.** The daemon's socket lock took no lock: the non-Unix implementation
> opened the lock file with `os.OpenFile` while its comment claimed Windows
> "takes the lock by opening the file without sharing", which is not what Go
> does — it opens shared, so every daemon took the lock and two would have
> served one store. That is `LockFileEx` now, and the exclusion has a test that
> runs on every platform rather than on the one it was assumed on. The socket's
> *permissions* are the one still missing: `os.Chmod` here sets the read-only
> attribute and nothing else, so the owner-only mode the Unix path relies on is
> not enforced, and what stands between the socket and another user is whatever
> permissions the containing directory inherits. Windows stays at `minimal`
> isolation and this is part of why.

## Context

[ADR-0012](ADR-0012-sandbox-by-default-and-scope-guard.md) makes confinement
mandatory and [ADR-0022](ADR-0022-sandbox-helper-and-seccomp-denylist.md)
realises it — entirely in Linux mechanisms: namespaces, seccomp-bpf, cgroups, a
helper that confines itself between `fork` and `exec`. Everything else in
`internal/platform` was one file, `sandbox_other.go`, whose every function did
nothing and said so.

Saying so was the right call at the time: a stub that silently succeeded would
let a campaign requiring isolation start on a host that provides none, which is
the failure ADR-0012 exists to prevent. But "this platform has no confinement"
was never true. It meant "nobody has written this platform's confinement", and
the two are indistinguishable from the outside, which is how macOS and Windows
stayed at the `minimal` level for six releases.

Three further gaps were found in the same place, each invisible in the same way.

**A Windows crash read as a clean exit.** Everything above the platform layer
classifies an execution by its signal — `ProcResult.ExitKind` calls it a crash
when the signal is non-zero, triage buckets by it, the crash oracles read it.
Windows has no signals: a target that dereferences a null pointer exits with the
code `0xC0000005`. `SignalOf` returned 0 for it. So a Windows campaign that was
finding bugs reported that it found none, and a fuzzer that finds nothing looks
exactly like a target with no bugs.

**The terminal driver refused to start on Windows.** T7 needs a pseudo-terminal,
`PTYSupported` returned false, and the doctor said ConPTY was not implemented.

**`UsableCgroupMode` existed only on Linux** while a test named it
unconditionally, so `GOOS=darwin go vet ./...` did not pass and nobody knew.

## Decision

**Each platform gets the mechanism it actually has, reported for what it is.**

**macOS: a Seatbelt profile, applied by wrapping the command in
`sandbox-exec`.** The profile allows by default, denies `file-write*` and
`network*`, and re-allows writes under the target's working directory and
whatever the campaign added. Allow-by-default is a choice about which failure is
acceptable: a deny-by-default profile has to enumerate every mach service,
sysctl and dyld path a target needs, and getting one wrong produces a target
that will not start — which a campaign reports as a broken target rather than as
a broken profile. `sandbox-exec` is deprecated and is still what confines a
process on macOS without entitlements; the alternative, `libsandbox` through
cgo, is refused by [ADR-0017](ADR-0017-pure-go-core-cgo-behind-build-tags.md).

**That reaches `moderate`.** Denying writes outside the working directory and
denying the network is the same separation a mount namespace and a syscall
filter provide, arrived at differently. A level that could never rise above
`minimal` on a whole operating system is not a conservative report, it is an
uninformative one.

**Windows: a job object, wearing the `Cgroup` interface the tree already has.**
It caps memory and process count and kills everything in the job when the last
handle closes, so a fuzzer that dies takes its targets with it instead of
leaving a machine full of orphans. It does **not** separate the target from the
filesystem — that needs a restricted or low-integrity token, which is a larger
change with a larger blast radius — so Windows stays at `minimal` and the doctor
says exactly which half is present. It is attached after the process exists, the
same race cgroups v1 has, and is treated identically for that reason.

**Windows exception codes are translated to the signal the same fault raises on
Unix.** An access violation and a segmentation fault are the same bug, and
filing them in the same bucket is what lets a corpus and its findings move
between platforms (ASR-0011, ASR-0008). An unlisted code in the NTSTATUS error
range is a crash of unknown kind rather than a clean exit, because that list is
never complete and a lost finding is worse than a coarse one.

**Windows gets a pseudo-console, so T7 runs there.** ConPTY is a console object
around two pipes, handed to a child in a `STARTUPINFOEX` attribute list, which
`os/exec` cannot carry. This is therefore the one place in Xfuzz that calls
`CreateProcess` itself, and it does so from the `*exec.Cmd` the safety layer
prepared — same path, argv, directory, environment and creation flags — so every
decision the sandbox made still applies. The pseudo-terminal becomes a
`platform.TTY` both platforms implement, so `internal/safety` no longer knows
whether it holds a master descriptor or a console handle.

**What a platform cannot do is still said out loud.** A ConPTY resize sends no
signal, because Windows has none, so a program that redraws only on `SIGWINCH`
does not redraw there; the doctor says so. `sandbox-exec` missing is reported as
a finding on macOS and as the normal state on Linux, because the action differs.

**Anything that is pure logic is written without a build tag and tested.** The
Seatbelt profile builder and the exception-to-signal mapping are the two places
where a mistake is silent — a working directory whose name carries a quote could
close the profile's string and have the rest of the name read as policy; an exit
code of 1 mistaken for a fault would turn every campaign into false findings —
and behind a `//go:build` line they would be exercised on no machine in CI.

## Consequences

**Positive**

- macOS campaigns can require `moderate` isolation and get it.
- An unattended Windows campaign no longer leaks target processes when the
  fuzzer is killed.
- Windows campaigns report the crashes they find. This is a correctness fix, not
  a feature: the platform was silently losing every finding.
- The terminal driver runs on all three platforms.
- `go vet` passes for `linux`, `darwin` and `windows`, so a cross-platform break
  is a build failure rather than a discovery.

**Negative**

- Applying a Seatbelt profile and creating a job object are unverified: no macOS
  or Windows host is available to this project. Everything is cross-built,
  cross-vetted and unit-tested in its pure-logic parts, and the parts that need
  the operating system are marked unverified in MVP_PLAN § 7.1 alongside the
  qemu and frida backends, rather than being claimed.
- `sandbox-exec` is deprecated. If a macOS release removes it, macOS returns to
  `minimal` and says so, which is the same behaviour as a host that never had
  it.
- The exception-to-signal mapping is a deliberate lie about the mechanism in
  service of the truth about the failure. A Windows user reading "signal 11"
  should understand it as "the fault a segmentation fault would have been".

**Neutral**

- ADR-0022 is unchanged and remains the Linux story. This record sits beside it
  rather than over it: nothing about the helper, the denylist or the level
  policy moves, and the level policy gains one clause.
- Naming a job object `Cgroup` is a small lie about the kernel and a large truth
  about the code: the call sites are identical — create one per campaign, add
  each target, close it at the end — and the alternative was a second lifecycle
  in the spawner with a build tag around it.

## Alternatives considered

- **Leave the stub and document the gap.** What was already happening. It is
  honest about the level and silent about the reason, and the reason was that
  nobody had written it.
- **A restricted or low-integrity token on Windows, for filesystem
  confinement.** The right eventual answer and a much larger change: a target
  that cannot read its own DLLs does not start, and the campaign reports a
  broken target. Deferred, with the job object landing now and the level
  reporting the difference.
- **Deny-by-default Seatbelt profile.** Stronger and unusable: the enumeration
  is per-target and a miss looks like a broken program.
- **A `sandbox_init` call from inside the target, matching the Linux helper's
  shape.** Needs cgo, which ADR-0017 forbids for exactly the portability reason
  that makes this file necessary.
- **Classify Windows crashes by exit code at the executor layer instead of
  mapping to signals.** Rejected: it would put Windows exception codes into
  `pkg/executor`, and every consumer of `ProcResult` — triage, bucketing,
  oracles, the store — would need a second code path. One translation at the
  platform boundary keeps a finding the same object on every platform, which is
  what ASR-0008 asks for.
- **Start the Windows terminal target through `os/exec` anyway, with pipes.**
  That is the failure ADR-0030 exists to prevent: over pipes `isatty` is false
  and the program under test is a different program.
