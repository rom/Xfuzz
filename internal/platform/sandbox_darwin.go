//go:build darwin

package platform

import "syscall"

// Confinement on macOS.
//
// There are no namespaces and no seccomp, but there is a real kernel-enforced
// policy engine — Seatbelt, reached through sandbox-exec — and there are
// rlimits. Together they are enough to deny a target the two things a fuzzer
// most needs it denied: writing outside its working directory, and reaching the
// network. That is what takes macOS off the minimal level, where it sat for
// want of anyone writing the profile rather than for want of a mechanism.
//
// sandbox-exec is deprecated and has been for years, and it is still what every
// tool that confines a process on macOS without entitlements uses. The
// alternative — linking libsandbox through cgo — would put C into the fuzzer,
// which ADR-0017 forbids for exactly the portability reason that makes this
// file necessary.

// ApplyLimits installs the resource caps in the calling process.
//
// The same mechanism Linux uses, minus the limits macOS does not have. A target
// can raise a soft limit it was given, which is why these do not count as
// kernel-enforced accounting the way a cgroup does — they are a guard against a
// target that misbehaves, not against one that is hostile.
func ApplyLimits(l Limits) error {
	set := func(res int, v uint64) error {
		if v == 0 {
			return nil
		}
		return syscall.Setrlimit(res, &syscall.Rlimit{Cur: v, Max: v})
	}
	if err := set(syscall.RLIMIT_AS, l.AddressSpaceBytes); err != nil {
		return err
	}
	if err := set(syscall.RLIMIT_FSIZE, l.FileSizeBytes); err != nil {
		return err
	}
	if err := set(syscall.RLIMIT_CPU, l.CPUSeconds); err != nil {
		return err
	}
	// No RLIMIT_NPROC here: macOS spells the process cap RLIMIT_NPROC in its
	// headers and Go's syscall package does not export it, and a target that
	// forks without bound is caught by the process group instead.
	if err := set(syscall.RLIMIT_NOFILE, l.OpenFiles); err != nil {
		return err
	}
	if l.DisableCore {
		return syscall.Setrlimit(syscall.RLIMIT_CORE, &syscall.Rlimit{})
	}
	return set(syscall.RLIMIT_CORE, l.CoreBytes)
}

// DropPrivileges becomes another user, groups first.
//
// The order is not stylistic: setuid drops the privilege that setgid needs, so
// doing it the other way round leaves the target in the fuzzer's groups while
// looking as though it had been deprivileged.
func DropPrivileges(uid, gid int) error {
	if gid > 0 {
		if err := syscall.Setgid(gid); err != nil {
			return err
		}
	}
	if uid > 0 {
		if err := syscall.Setuid(uid); err != nil {
			return err
		}
	}
	return nil
}

// DetectSandbox reports what this host can enforce.
func DetectSandbox() SandboxCapabilities {
	c := SandboxCapabilities{Cgroups: CgroupNone, Rlimits: true}
	if SeatbeltAvailable() {
		c.Confined = true
	} else {
		c.Notes = append(c.Notes, SandboxExecPath+" is not present, so a target cannot be "+
			"denied file writes or the network; confinement is the working directory and "+
			"the process group only")
	}
	c.Notes = append(c.Notes,
		"namespaces, seccomp and cgroups are Linux mechanisms; on macOS the equivalent "+
			"is a Seatbelt profile, which denies writes outside the working directory and "+
			"denies the network, and rlimits, which a target can raise",
		"a target cannot be given a separate identity unless Xfuzz runs as root, so on "+
			"an ordinary developer machine it shares the fuzzer's access to the corpus")
	return c
}
