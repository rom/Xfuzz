//go:build !linux

package platform

import (
	"errors"
	"os/exec"
)

// The parts of the sandbox mechanism that are the same on every platform
// without Linux namespaces.
//
// What is here is either a type the rest of the tree needs to compile against
// everywhere, or a mechanism that genuinely does not exist outside Linux and
// says so. What a particular platform *can* do instead lives beside this file,
// in sandbox_darwin.go and sandbox_windows.go — because the honest answer for
// macOS and Windows is not "nothing", it is "something different", and
// collapsing the two into one stub is what left both at the minimal level for
// six releases.

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

// CgroupMode reports which resource-group mechanism this host provides.
//
// It is answered from DetectSandbox rather than hard-coded to CgroupNone, so
// that a platform with something cgroup-shaped — a Windows job object — reports
// it here too. A second, quieter answer would have meant the doctor and the
// spawner disagreeing about whether a campaign has a memory cap.
func CgroupMode() string { return DetectSandbox().Cgroups }

// UsableCgroupMode reports the mechanism this process can actually create a
// group in.
//
// The same answer as CgroupMode off Linux, and deliberately so: the distinction
// exists on Linux because the hierarchy can be mounted and still refuse a mkdir
// under delegation. Every non-Linux mechanism here is probed by creating one,
// so "present" and "usable" are the same question already.
func UsableCgroupMode() string { return CgroupMode() }

// ConfigureSandbox does nothing. Process-group setup is the platform's
// ConfigureProcess, which is applied separately.
func ConfigureSandbox(cmd *exec.Cmd, o SandboxOptions) {}

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

// ConfineFilesystem reports that mount-based confinement is a Linux mechanism.
func ConfineFilesystem(writable []string) error {
	return errors.New("platform: read-only root confinement needs a Linux mount namespace")
}

// OverflowID returns the conventional "nobody" ids.
func OverflowID() (uid, gid int) { return 65534, 65534 }

// UnprivilegedID returns the id targets would run as, where that is possible.
func UnprivilegedID() (uid, gid int) { return 65533, 65533 }
