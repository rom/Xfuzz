//go:build !linux

package platform

import (
	"errors"
	"os/exec"
)

// Sandbox mechanism for platforms without Linux namespaces.
//
// Every function here is a stub that does nothing and says so. That is the
// honest shape: the alternative — silently succeeding — would let a campaign
// that requires strong isolation start on a platform that cannot provide it,
// which is the exact failure ADR-0012 exists to prevent. The level a caller
// computes from DetectSandbox is what refuses that campaign.

// Cgroup modes, defined on every platform so callers need no build tags.
const (
	CgroupV2   = "v2"
	CgroupV1   = "v1"
	CgroupNone = "none"
)

// ErrSeccompUnsupported is returned where seccomp does not exist.
var ErrSeccompUnsupported = errors.New("platform: seccomp filters are a Linux mechanism")

// SandboxOptions selects which namespaces a target is launched into. No field
// has any effect off Linux.
type SandboxOptions struct {
	UserNS, MountNS, PIDNS, NetNS, IPCNS, UTSNS bool
	UID, GID                                    int
}

// Limits are the per-target resource caps.
type Limits struct {
	AddressSpaceBytes uint64
	FileSizeBytes     uint64
	CPUSeconds        uint64
	Processes         uint64
	OpenFiles         uint64
	CoreBytes         uint64
	DisableCore       bool
}

// UserNamespacesAvailable reports false: there are none.
func UserNamespacesAvailable() bool { return false }

// SeccompAvailable reports false.
func SeccompAvailable() bool { return false }

// CgroupMode reports that no cgroup hierarchy exists.
func CgroupMode() string { return CgroupNone }

// ConfigureSandbox does nothing. Process-group setup is the platform's
// ConfigureProcess, which is applied separately.
func ConfigureSandbox(cmd *exec.Cmd, o SandboxOptions) {}

// ApplyLimits reports that resource limits are not settable this way here.
func ApplyLimits(l Limits) error { return nil }

// SetNoNewPrivs does nothing.
func SetNoNewPrivs() error { return nil }

// BuildSeccompFilter reports that seccomp does not exist.
func BuildSeccompFilter(deny []int, errno uint16) ([]SockFilter, error) {
	return nil, ErrSeccompUnsupported
}

// SockFilter stands in for the Linux type so that signatures match.
type SockFilter struct {
	Code uint16
	Jt   uint8
	Jf   uint8
	K    uint32
}

// ApplySeccomp reports that seccomp does not exist.
func ApplySeccomp(prog []SockFilter) error { return ErrSeccompUnsupported }

// DefaultSeccompNumbers returns nothing to deny.
func DefaultSeccompNumbers() []int { return nil }

// Cgroup is a no-op resource group.
type Cgroup struct{}

// NewCgroup returns no cgroup, without failing: the caller reports a lower
// isolation level rather than refusing to run.
func NewCgroup(name string, l Limits) (*Cgroup, error) { return nil, nil }

// Mode reports that no hierarchy backs this cgroup.
func (c *Cgroup) Mode() string { return CgroupNone }

// Attach reports that the kernel cannot place the child for us.
func (c *Cgroup) Attach(cmd *exec.Cmd) bool { return false }

// Add does nothing.
func (c *Cgroup) Add(pid int) error { return nil }

// Close does nothing.
func (c *Cgroup) Close() error { return nil }

// DetectSandbox reports what this host can enforce, which is the resource
// limits the operating system applies to any process and nothing more.
func DetectSandbox() SandboxCapabilities {
	return SandboxCapabilities{
		Cgroups: CgroupNone,
		Notes: []string{
			"namespaces, seccomp, and cgroups are Linux mechanisms; " +
				"confinement here is workdir and process-group containment only",
		},
	}
}

// ConfineFilesystem reports that mount-based confinement is a Linux mechanism.
func ConfineFilesystem(writable []string) error {
	return errors.New("platform: read-only root confinement needs a Linux mount namespace")
}

// DropPrivileges reports that this platform has no equivalent here.
func DropPrivileges(uid, gid int) error {
	return errors.New("platform: dropping to another user is a Unix mechanism")
}

// OverflowID returns the conventional "nobody" ids.
func OverflowID() (uid, gid int) { return 65534, 65534 }

// UnprivilegedID returns the id targets would run as, where that is possible.
func UnprivilegedID() (uid, gid int) { return 65533, 65533 }
