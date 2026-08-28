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
