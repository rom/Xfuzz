//go:build !linux && !darwin && !windows

package platform

import "errors"

// The sandbox mechanism on a platform Xfuzz has no confinement story for.
//
// Every function here does nothing and says so. That is the honest shape: the
// alternative — silently succeeding — would let a campaign that requires
// isolation start on a host that cannot provide it, which is the failure
// ADR-0012 exists to prevent.

// ApplyLimits reports that resource limits are not settable this way here.
func ApplyLimits(l Limits) error { return nil }

// DropPrivileges reports that this platform has no equivalent here.
func DropPrivileges(uid, gid int) error {
	return errors.New("platform: dropping to another user is a Unix mechanism")
}

// DetectSandbox reports what this host can enforce, which is nothing beyond
// what the operating system applies to any process.
func DetectSandbox() SandboxCapabilities {
	return SandboxCapabilities{
		Cgroups: CgroupNone,
		Notes: []string{
			"namespaces, seccomp, and cgroups are Linux mechanisms, and this platform " +
				"has no confinement mechanism Xfuzz knows how to use; confinement here " +
				"is workdir and process-group containment only",
		},
	}
}
