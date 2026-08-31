package platform

import "strings"

// SeccompDenyErrno is what a filtered syscall returns.
//
// EPERM, which is 1 on every Linux ABI. It is named here rather than taken from
// syscall.EPERM because that constant is the host platform's, and a cross-build
// for Windows would put a Windows error number into a Linux BPF program — which
// compiles, and denies nothing recognisable.
//
// EPERM rather than killing the process: a target that is refused a syscall
// usually handles the error, and a campaign whose targets are killed outright by
// the sandbox reports a stream of crashes that are the fuzzer's doing.
const SeccompDenyErrno uint16 = 1

// The cgroup modes, and the one thing that stands in for a cgroup off Linux.
//
// Declared in the portable file rather than per platform because callers switch
// on them: internal/safety decides how to place a process from the mode, and
// putting the names behind a build tag would mean either a tag in the caller or
// a constant that exists in one build and not another. That second failure is
// the one this file already caused once — CgroupJob lived in the non-Linux file
// and the Linux build stopped compiling the moment the safety layer named it.
const (
	CgroupV2   = "v2"
	CgroupV1   = "v1"
	CgroupNone = "none"

	// CgroupJob is a Windows job object standing in for a cgroup. It caps
	// memory and process count and kills the whole tree when the handle closes,
	// which is two of the three things a cgroup does; what it does not do is
	// account a process from its first instruction, because it is attached
	// after the process exists. That is the same window cgroup v1 leaves, which
	// is why the safety layer treats the two the same way.
	CgroupJob = "job"
)

// SandboxCapabilities is what a host can actually enforce.
//
// It is a report of mechanisms, not a verdict. Deciding whether a set of
// mechanisms adds up to a given isolation level is policy and belongs to
// internal/safety; if it were decided here it would be decided in two places,
// and the two would eventually disagree.
type SandboxCapabilities struct {
	UserNS  bool
	MountNS bool
	PIDNS   bool
	NetNS   bool
	Seccomp bool
	Rlimits bool

	// Confined reports that the platform applies a kernel-enforced confinement
	// policy that is not a namespace: a seatbelt profile on macOS, a
	// low-integrity or restricted token on Windows.
	//
	// A separate field rather than folding it into Seccomp or MountNS, because
	// what it grants differs and the difference is what an operator has to
	// judge. A seatbelt profile denies file writes and network by pattern, and
	// a Linux mount namespace denies them by construction; calling both
	// "MountNS" would let a campaign that requires one accept the other.
	Confined bool

	// JobLimits reports that resource limits are enforced by an object the
	// kernel attaches at creation — a Windows job object — rather than by an
	// rlimit the target can raise. It is the Windows counterpart of a cgroup,
	// and like a cgroup it also kills the whole tree when the fuzzer lets go.
	JobLimits bool

	// Cgroups is CgroupV2, CgroupV1, or CgroupNone.
	Cgroups string

	// Notes explain, in a sentence a person can act on, why a mechanism is
	// missing or weaker than it looks. They are shown when a campaign is
	// refused for insufficient isolation, because "isolation is too weak" with
	// no reason is a message nobody can do anything about.
	Notes []string
}

// String renders the capabilities on one line.
func (c SandboxCapabilities) String() string {
	var on []string
	for name, ok := range map[string]bool{
		"userns": c.UserNS, "mountns": c.MountNS, "pidns": c.PIDNS,
		"netns": c.NetNS, "seccomp": c.Seccomp, "rlimits": c.Rlimits,
		"confined": c.Confined, "joblimits": c.JobLimits,
	} {
		if ok {
			on = append(on, name)
		}
	}
	// Sorted so two hosts with the same capabilities produce the same string,
	// which is what makes the line comparable across machines.
	sortStrings(on)
	if c.Cgroups != "" && c.Cgroups != CgroupNone {
		on = append(on, "cgroups-"+c.Cgroups)
	}
	if len(on) == 0 {
		return "none"
	}
	return strings.Join(on, ",")
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}
