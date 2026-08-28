//go:build linux

package platform

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Linux confinement mechanism. The policy — what to confine, how strongly, and
// what to do when a mechanism is unavailable — belongs to internal/safety; what
// belongs here is only how Linux expresses it.

// UserNamespacesAvailable reports whether unprivileged user namespaces can be
// created.
//
// Several distributions disable them outright, and a kernel that refuses the
// clone flag is indistinguishable from one that does not have the feature. The
// probe is a read of the sysctl rather than an attempted clone, because a
// failed clone in a Go process is expensive and this is asked at startup.
func UserNamespacesAvailable() bool {
	// A kernel without the file has user namespaces compiled in and unrestricted
	// (the sysctl only exists where the restriction does).
	b, err := os.ReadFile("/proc/sys/user/max_user_namespaces")
	if err == nil {
		n, convErr := strconv.Atoi(strings.TrimSpace(string(b)))
		if convErr == nil && n <= 0 {
			return false
		}
	}
	if b, err := os.ReadFile("/proc/sys/kernel/unprivileged_userns_clone"); err == nil {
		if strings.TrimSpace(string(b)) == "0" && os.Geteuid() != 0 {
			return false
		}
	}
	_, err = os.Stat("/proc/self/ns/user")
	return err == nil
}

// SeccompAvailable reports whether seccomp-bpf filters can be installed.
func SeccompAvailable() bool {
	b, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return false
	}
	return strings.Contains(string(b), "Seccomp:")
}

// Cgroup modes.
const (
	CgroupV2   = "v2"
	CgroupV1   = "v1"
	CgroupNone = "none"
)

// CgroupMode reports which cgroup hierarchy the host provides.
//
// The difference matters and is not cosmetic. Under v2 a child can be placed in
// its cgroup by the kernel at clone time, so it is accounted from its first
// instruction. Under v1 the only interface is writing a pid into a file after
// the process exists, which leaves a window — small, but real — in which a
// target that forks immediately escapes the limit. Reporting which is in force
// is what lets the safety layer declare an honest isolation level instead of
// implying the stronger one.
func CgroupMode() string {
	if _, err := os.Stat("/sys/fs/cgroup/cgroup.controllers"); err == nil {
		return CgroupV2
	}
	if fi, err := os.Stat("/sys/fs/cgroup/memory"); err == nil && fi.IsDir() {
		return CgroupV1
	}
	if fi, err := os.Stat("/sys/fs/cgroup/pids"); err == nil && fi.IsDir() {
		return CgroupV1
	}
	return CgroupNone
}

// OverflowID returns the uid and gid the kernel shows for a file whose owner is
// not mapped into the current user namespace.
//
// This is load-bearing, not trivia. A target mapped to the overflow id sees
// every unmapped file — which is every file owned by anyone outside its
// namespace, the fuzzer's corpus included — as owned by *itself*, and can write
// all of it. The confinement looks correct in every log line, the target reports
// an unprivileged uid, and it can still destroy the corpus. Picking an id that
// is not this one is the difference.
func OverflowID() (uid, gid int) {
	uid, gid = 65534, 65534
	if b, err := os.ReadFile("/proc/sys/kernel/overflowuid"); err == nil {
		if n, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil {
			uid = n
		}
	}
	if b, err := os.ReadFile("/proc/sys/kernel/overflowgid"); err == nil {
		if n, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil {
			gid = n
		}
	}
	return uid, gid
}

// UnprivilegedID returns an id to run targets as: unprivileged, and distinct
// from the overflow id for the reason OverflowID gives.
func UnprivilegedID() (uid, gid int) {
	ouid, ogid := OverflowID()
	uid, gid = defaultTargetID, defaultTargetID
	if uid == ouid {
		uid--
	}
	if gid == ogid {
		gid--
	}
	return uid, gid
}

// defaultTargetID is the identity targets run as. It is high enough to be
// outside any real account range and is adjusted away from the overflow id.
const defaultTargetID = 65533

// SandboxOptions selects which namespaces a target is launched into.
type SandboxOptions struct {
	UserNS  bool
	MountNS bool
	PIDNS   bool
	NetNS   bool
	IPCNS   bool
	UTSNS   bool

	// UID and GID are what the caller's identity maps to inside the user
	// namespace. Mapping to a non-zero id is what makes the target unprivileged
	// with respect to everything outside the namespace.
	UID, GID int
}

// ConfigureSandbox applies namespace options to a command.
//
// It does not change the child's credentials. That is deliberate and it is the
// subtle part: a user-namespace uid *mapping* translates identities, it does not
// deprivilege. A child cloned by root with a mapping that does not include uid 0
// is still host root — it merely reports the kernel's overflow id, which happens
// to look exactly like an unprivileged uid in every log and every getuid(). The
// identity drop is a real setuid, done by the sandbox helper after it has
// finished the steps that need privilege.
func ConfigureSandbox(cmd *exec.Cmd, o SandboxOptions) {
	attr := cmd.SysProcAttr
	if attr == nil {
		attr = &syscall.SysProcAttr{}
		cmd.SysProcAttr = attr
	}
	attr.Setpgid = true

	var flags uintptr
	if o.UserNS {
		// A user namespace is how an unprivileged caller gets the other
		// namespaces at all. Where the caller is already root it is left out:
		// root can create the others directly, and a mount namespace created
		// alongside a user namespace inherits its mounts *locked*, which is
		// what makes a read-only root impossible in that combination.
		flags |= syscall.CLONE_NEWUSER
		attr.UidMappings = []syscall.SysProcIDMap{
			{ContainerID: o.UID, HostID: os.Getuid(), Size: 1},
		}
		attr.GidMappings = []syscall.SysProcIDMap{
			{ContainerID: o.GID, HostID: os.Getgid(), Size: 1},
		}
		attr.GidMappingsEnableSetgroups = false
	}
	if o.MountNS {
		flags |= syscall.CLONE_NEWNS
	}
	if o.PIDNS {
		flags |= syscall.CLONE_NEWPID
	}
	if o.NetNS {
		flags |= syscall.CLONE_NEWNET
	}
	if o.IPCNS {
		flags |= syscall.CLONE_NEWIPC
	}
	if o.UTSNS {
		flags |= syscall.CLONE_NEWUTS
	}
	attr.Cloneflags |= flags
}

// DropPrivileges becomes an unprivileged user, irreversibly.
//
// Order matters and is not stylistic: supplementary groups first, then the
// group, then the user. Dropping the user first would lose the privilege needed
// to drop the groups, and a process that kept a supplementary group is a process
// that kept whatever that group could reach.
func DropPrivileges(uid, gid int) error {
	if uid <= 0 || gid <= 0 {
		return fmt.Errorf("platform: refusing to drop privileges to uid %d gid %d", uid, gid)
	}
	if err := unix.Setgroups(nil); err != nil {
		return fmt.Errorf("platform: clearing supplementary groups: %w", err)
	}
	if err := unix.Setgid(gid); err != nil {
		return fmt.Errorf("platform: setting gid %d: %w", gid, err)
	}
	if err := unix.Setuid(uid); err != nil {
		return fmt.Errorf("platform: setting uid %d: %w", uid, err)
	}
	// Verified rather than assumed. A drop that silently did not happen is the
	// failure this whole layer exists to prevent, and it costs two syscalls to
	// be sure.
	if got := os.Getuid(); got != uid {
		return fmt.Errorf("platform: still running as uid %d after dropping to %d", got, uid)
	}
	if got := os.Getgid(); got != gid {
		return fmt.Errorf("platform: still running as gid %d after dropping to %d", got, gid)
	}
	return nil
}

// Limits are the per-target resource caps. Zero means unlimited.
type Limits struct {
	// AddressSpaceBytes caps the virtual address space, which is what contains
	// a target that allocates without bound.
	AddressSpaceBytes uint64

	// FileSizeBytes caps how large a file the target may write, which is what
	// contains one that fills the disk.
	FileSizeBytes uint64

	// CPUSeconds caps CPU time. It is a backstop behind the wall-clock timeout,
	// for a target that spins without making syscalls.
	CPUSeconds uint64

	// Processes caps how many processes the user may have, which is what
	// contains a fork bomb where no PID cgroup is available.
	Processes uint64

	// OpenFiles caps descriptors.
	OpenFiles uint64

	// CoreBytes caps core dumps. It defaults to zero meaning "no core", which
	// is the opposite of the convention elsewhere in this struct and is stated
	// explicitly by DisableCore.
	CoreBytes uint64

	// DisableCore suppresses core dumps. A fuzzer produces crashes by design,
	// and a campaign that writes a core file per crash fills a disk in minutes.
	DisableCore bool
}

// ApplyLimits sets the calling process's resource limits.
//
// It applies to the caller, not to another process, because that is what
// setrlimit does: limits are inherited across exec, so the way to limit a target
// is to set them in the process that will become it. That is what the sandbox
// helper is for.
func ApplyLimits(l Limits) error {
	set := func(res int, name string, v uint64) error {
		if v == 0 {
			return nil
		}
		rl := unix.Rlimit{Cur: v, Max: v}
		if err := unix.Setrlimit(res, &rl); err != nil {
			return fmt.Errorf("platform: setting %s to %d: %w", name, v, err)
		}
		return nil
	}
	if err := set(unix.RLIMIT_AS, "RLIMIT_AS", l.AddressSpaceBytes); err != nil {
		return err
	}
	if err := set(unix.RLIMIT_FSIZE, "RLIMIT_FSIZE", l.FileSizeBytes); err != nil {
		return err
	}
	if err := set(unix.RLIMIT_CPU, "RLIMIT_CPU", l.CPUSeconds); err != nil {
		return err
	}
	if err := set(unix.RLIMIT_NPROC, "RLIMIT_NPROC", l.Processes); err != nil {
		return err
	}
	if err := set(unix.RLIMIT_NOFILE, "RLIMIT_NOFILE", l.OpenFiles); err != nil {
		return err
	}
	if l.DisableCore {
		rl := unix.Rlimit{Cur: l.CoreBytes, Max: l.CoreBytes}
		if err := unix.Setrlimit(unix.RLIMIT_CORE, &rl); err != nil {
			return fmt.Errorf("platform: disabling core dumps: %w", err)
		}
	}
	return nil
}

// SetNoNewPrivs makes the calling process unable to gain privileges through
// exec, which is also the precondition for installing a seccomp filter without
// CAP_SYS_ADMIN.
func SetNoNewPrivs() error {
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("platform: setting no_new_privs: %w", err)
	}
	return nil
}

// DeniedSyscalls is the seccomp denylist.
//
// A denylist, not an allowlist, and the choice is deliberate. An allowlist is
// stronger in principle and unusable here in practice: the targets are arbitrary
// programs in arbitrary languages, and a list that is one syscall short kills
// every execution of a target that happens to use it — which a fuzzer would
// report as a finding. A denylist that is one syscall short still blocks
// everything it names.
//
// It is also not the primary control. The user namespace already denies most of
// this by removing the capabilities these calls require; the filter is the
// second layer, and it covers what a namespace does not — io_uring, which has
// been a reliable source of kernel escapes, and perf_event_open, which has been
// another.
var DeniedSyscalls = []struct {
	Name string
	Nr   int
}{
	{"mount", unix.SYS_MOUNT},
	{"umount2", unix.SYS_UMOUNT2},
	{"pivot_root", unix.SYS_PIVOT_ROOT},
	{"swapon", unix.SYS_SWAPON},
	{"swapoff", unix.SYS_SWAPOFF},
	{"init_module", unix.SYS_INIT_MODULE},
	{"finit_module", unix.SYS_FINIT_MODULE},
	{"delete_module", unix.SYS_DELETE_MODULE},
	{"kexec_load", unix.SYS_KEXEC_LOAD},
	{"kexec_file_load", unix.SYS_KEXEC_FILE_LOAD},
	{"reboot", unix.SYS_REBOOT},
	{"ptrace", unix.SYS_PTRACE},
	{"setns", unix.SYS_SETNS},
	{"unshare", unix.SYS_UNSHARE},
	{"bpf", unix.SYS_BPF},
	{"perf_event_open", unix.SYS_PERF_EVENT_OPEN},
	{"process_vm_readv", unix.SYS_PROCESS_VM_READV},
	{"process_vm_writev", unix.SYS_PROCESS_VM_WRITEV},
	{"open_by_handle_at", unix.SYS_OPEN_BY_HANDLE_AT},
	{"name_to_handle_at", unix.SYS_NAME_TO_HANDLE_AT},
	{"add_key", unix.SYS_ADD_KEY},
	{"keyctl", unix.SYS_KEYCTL},
	{"request_key", unix.SYS_REQUEST_KEY},
	{"syslog", unix.SYS_SYSLOG},
	{"acct", unix.SYS_ACCT},
	{"quotactl", unix.SYS_QUOTACTL},
	{"settimeofday", unix.SYS_SETTIMEOFDAY},
	{"clock_settime", unix.SYS_CLOCK_SETTIME},
	{"clock_adjtime", unix.SYS_CLOCK_ADJTIME},
	{"adjtimex", unix.SYS_ADJTIMEX},
	{"sethostname", unix.SYS_SETHOSTNAME},
	{"setdomainname", unix.SYS_SETDOMAINNAME},
	{"userfaultfd", unix.SYS_USERFAULTFD},
	{"io_uring_setup", unix.SYS_IO_URING_SETUP},
	{"io_uring_enter", unix.SYS_IO_URING_ENTER},
	{"io_uring_register", unix.SYS_IO_URING_REGISTER},
}

// auditArch returns the AUDIT_ARCH value the filter must check.
//
// Checking it is not optional. A filter that matches syscall numbers without
// pinning the architecture is bypassable on any kernel with a second ABI: the
// same number means a different call under x32 or i386, so an unchecked filter
// denies one syscall and permits another.
func auditArch() (uint32, error) {
	switch runtime.GOARCH {
	case "amd64":
		return uint32(unix.AUDIT_ARCH_X86_64), nil
	case "arm64":
		return uint32(unix.AUDIT_ARCH_AARCH64), nil
	default:
		return 0, fmt.Errorf("platform: no seccomp architecture known for %s", runtime.GOARCH)
	}
}

// ErrSeccompUnsupported is returned where a filter cannot be built or installed.
var ErrSeccompUnsupported = errors.New("platform: seccomp filters are unavailable")

// seccomp_data field offsets.
const (
	seccompOffNr   = 0
	seccompOffArch = 4
)

// BuildSeccompFilter returns the BPF program denying the listed syscalls.
//
// It is separated from installation so the program can be inspected and tested
// without a process to install it in — a filter is a small program, and a small
// program that is only ever exercised by its own side effects is one nobody can
// check.
func BuildSeccompFilter(deny []int, errno uint16) ([]unix.SockFilter, error) {
	arch, err := auditArch()
	if err != nil {
		return nil, err
	}

	// Layout: check the architecture, then compare the syscall number against
	// each denied value, then allow. Jump offsets are counted from the
	// instruction after the jump, so they are computed from the tail backwards.
	prog := make([]unix.SockFilter, 0, len(deny)+6)

	// load arch; if it does not match, refuse everything rather than fall
	// through to a comparison that means something else.
	prog = append(prog,
		unix.SockFilter{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: seccompOffArch},
		unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: arch, Jt: 1, Jf: 0},
		unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K,
			K: uint32(unix.SECCOMP_RET_ERRNO) | uint32(errno)},
		unix.SockFilter{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: seccompOffNr},
	)

	// One equality test per denied call. Each jumps forward to the deny return,
	// whose distance shrinks as the list is consumed.
	for i, nr := range deny {
		remaining := len(deny) - i - 1
		prog = append(prog, unix.SockFilter{
			Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K,
			K:    uint32(nr),
			// jt skips the remaining comparisons and the allow return.
			Jt: uint8(remaining + 1),
			Jf: 0,
		})
		if remaining+1 > 255 {
			return nil, fmt.Errorf("platform: seccomp denylist of %d is too long for a flat filter", len(deny))
		}
	}
	prog = append(prog,
		unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K, K: uint32(unix.SECCOMP_RET_ALLOW)},
		unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K,
			K: uint32(unix.SECCOMP_RET_ERRNO) | uint32(errno)},
	)
	return prog, nil
}

// ApplySeccomp installs a filter on the calling process.
//
// Like the resource limits, this applies to the caller: a seccomp filter is
// inherited across exec, so the way to filter a target is to install the filter
// in the process that becomes it.
func ApplySeccomp(prog []unix.SockFilter) error {
	if len(prog) == 0 {
		return nil
	}
	if err := SetNoNewPrivs(); err != nil {
		return err
	}
	fprog := unix.SockFprog{Len: uint16(len(prog)), Filter: &prog[0]}
	if err := unix.Prctl(unix.PR_SET_SECCOMP, unix.SECCOMP_MODE_FILTER,
		uintptr(unsafe.Pointer(&fprog)), 0, 0); err != nil {
		return fmt.Errorf("%w: %v", ErrSeccompUnsupported, err)
	}
	// prog is referenced by the kernel only for the duration of the prctl; the
	// KeepAlive makes that explicit rather than relying on the escape analysis
	// of an unsafe.Pointer conversion.
	runtime.KeepAlive(prog)
	runtime.KeepAlive(fprog)
	return nil
}

// DefaultSeccompNumbers returns the syscall numbers of DeniedSyscalls.
func DefaultSeccompNumbers() []int {
	out := make([]int, 0, len(DeniedSyscalls))
	for _, s := range DeniedSyscalls {
		out = append(out, s.Nr)
	}
	return out
}

// --- cgroups ---------------------------------------------------------------

// Cgroup is a resource-limited group a target runs in.
type Cgroup struct {
	mode string
	path string
	dir  *os.File
}

// NewCgroup creates a cgroup with the given limits.
//
// It returns a nil Cgroup and no error where cgroups are unavailable: the
// caller's job is to report a lower isolation level, not to fail. A campaign
// that requires strong isolation refuses to start on that report, which is the
// designed behaviour; a campaign that does not require it should still run.
func NewCgroup(name string, l Limits) (*Cgroup, error) {
	switch CgroupMode() {
	case CgroupV2:
		return newCgroupV2(name, l)
	case CgroupV1:
		return newCgroupV1(name, l)
	default:
		return nil, nil
	}
}

func newCgroupV2(name string, l Limits) (*Cgroup, error) {
	path := filepath.Join("/sys/fs/cgroup", "xfuzz", name)
	if err := os.MkdirAll(path, 0o755); err != nil {
		return nil, fmt.Errorf("platform: creating cgroup %s: %w", path, err)
	}
	c := &Cgroup{mode: CgroupV2, path: path}
	if l.AddressSpaceBytes > 0 {
		if err := c.write("memory.max", strconv.FormatUint(l.AddressSpaceBytes, 10)); err != nil {
			c.Close()
			return nil, err
		}
	}
	if l.Processes > 0 {
		if err := c.write("pids.max", strconv.FormatUint(l.Processes, 10)); err != nil {
			c.Close()
			return nil, err
		}
	}
	dir, err := os.Open(path)
	if err != nil {
		c.Close()
		return nil, err
	}
	c.dir = dir
	return c, nil
}

func newCgroupV1(name string, l Limits) (*Cgroup, error) {
	c := &Cgroup{mode: CgroupV1, path: filepath.Join("xfuzz", name)}
	if l.AddressSpaceBytes > 0 {
		p := filepath.Join("/sys/fs/cgroup/memory", c.path)
		if err := os.MkdirAll(p, 0o755); err != nil {
			return nil, fmt.Errorf("platform: creating cgroup %s: %w", p, err)
		}
		if err := os.WriteFile(filepath.Join(p, "memory.limit_in_bytes"),
			[]byte(strconv.FormatUint(l.AddressSpaceBytes, 10)), 0o644); err != nil {
			return nil, fmt.Errorf("platform: setting the memory limit: %w", err)
		}
	}
	if l.Processes > 0 {
		p := filepath.Join("/sys/fs/cgroup/pids", c.path)
		if err := os.MkdirAll(p, 0o755); err != nil {
			return nil, fmt.Errorf("platform: creating cgroup %s: %w", p, err)
		}
		if err := os.WriteFile(filepath.Join(p, "pids.max"),
			[]byte(strconv.FormatUint(l.Processes, 10)), 0o644); err != nil {
			return nil, fmt.Errorf("platform: setting the process limit: %w", err)
		}
	}
	return c, nil
}

func (c *Cgroup) write(file, value string) error {
	p := filepath.Join(c.path, file)
	if err := os.WriteFile(p, []byte(value), 0o644); err != nil {
		return fmt.Errorf("platform: writing %s: %w", p, err)
	}
	return nil
}

// Mode reports which hierarchy backs this cgroup.
func (c *Cgroup) Mode() string {
	if c == nil {
		return CgroupNone
	}
	return c.mode
}

// Attach places a command in the cgroup.
//
// Under v2 the kernel does it at clone time, so the target is accounted from its
// first instruction. Under v1 there is no such interface and the caller must
// call Add after the process exists.
func (c *Cgroup) Attach(cmd *exec.Cmd) bool {
	if c == nil || c.mode != CgroupV2 || c.dir == nil {
		return false
	}
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.UseCgroupFD = true
	cmd.SysProcAttr.CgroupFD = int(c.dir.Fd())
	return true
}

// Add places an existing process in the cgroup. It is the v1 path, and it races:
// a process that forks between exec and this write leaves children outside the
// limit.
func (c *Cgroup) Add(pid int) error {
	if c == nil {
		return nil
	}
	pidStr := strconv.Itoa(pid)
	switch c.mode {
	case CgroupV2:
		return c.write("cgroup.procs", pidStr)
	case CgroupV1:
		var firstErr error
		for _, controller := range []string{"memory", "pids"} {
			p := filepath.Join("/sys/fs/cgroup", controller, c.path, "cgroup.procs")
			if _, err := os.Stat(filepath.Dir(p)); err != nil {
				continue
			}
			if err := os.WriteFile(p, []byte(pidStr), 0o644); err != nil && firstErr == nil {
				firstErr = fmt.Errorf("platform: adding pid %d to %s: %w", pid, p, err)
			}
		}
		return firstErr
	}
	return nil
}

// Close removes the cgroup. A cgroup with live processes cannot be removed, so
// this is best effort: the caller has already killed the target, and a directory
// left behind is tidied by the next run of the same name.
func (c *Cgroup) Close() error {
	if c == nil {
		return nil
	}
	if c.dir != nil {
		c.dir.Close()
		c.dir = nil
	}
	switch c.mode {
	case CgroupV2:
		return os.Remove(c.path)
	case CgroupV1:
		for _, controller := range []string{"memory", "pids"} {
			os.Remove(filepath.Join("/sys/fs/cgroup", controller, c.path))
		}
	}
	return nil
}

// DetectSandbox reports what this host can actually enforce.
//
// It reports facts, not a verdict. Whether those facts add up to "strong" is a
// policy question and belongs to internal/safety; keeping the two apart is what
// stops the level from being computed differently in two places.
func DetectSandbox() SandboxCapabilities {
	caps := SandboxCapabilities{
		Rlimits: true,
		Cgroups: CgroupMode(),
		Seccomp: SeccompAvailable(),
	}
	if UserNamespacesAvailable() {
		caps.UserNS, caps.MountNS, caps.PIDNS, caps.NetNS = true, true, true, true
	} else if os.Geteuid() == 0 {
		// Without user namespaces a privileged process can still create the
		// others directly. It is a worse position — the target is confined but
		// not deprivileged — and saying so is the point of reporting mechanisms
		// rather than a single flag.
		caps.MountNS, caps.PIDNS, caps.NetNS = true, true, true
		caps.Notes = append(caps.Notes,
			"user namespaces are unavailable; namespaces are created with host privilege instead")
	} else {
		caps.Notes = append(caps.Notes, "user namespaces are unavailable to this user")
	}
	switch caps.Cgroups {
	case CgroupNone:
		caps.Notes = append(caps.Notes,
			"no cgroup hierarchy is mounted; memory and process limits fall back to rlimits")
	case CgroupV1:
		caps.Notes = append(caps.Notes,
			"cgroups v1: a target is placed in its group after it starts, so a process that "+
				"forks immediately can escape the limit; v2 places it at clone time")
	}
	if !caps.Seccomp {
		caps.Notes = append(caps.Notes, "seccomp is unavailable; the syscall denylist is not enforced")
	}
	return caps
}

// ConfineFilesystem makes the mount namespace read-only except for the paths
// given.
//
// This is the mechanism behind "read-only root with a writable workdir", and it
// is needed even when the target has been mapped to an unprivileged id. A user
// namespace maps the caller's uid into the namespace, so every file the caller
// owns still appears to belong to the target and is still writable by it — which
// includes the corpus. Deprivileging alone does not confine the filesystem;
// this does.
//
// It must run inside the target's mount namespace, which is why it lives in the
// sandbox helper: the namespace is created at clone time and the helper is the
// first process in it.
func ConfineFilesystem(writable []string) error {
	// Private first, so nothing done here propagates back to the host's mount
	// table. Without it a shared mount would carry the read-only remount out of
	// the namespace and make the host's root read-only, which is a spectacular
	// way to take a machine down.
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		return fmt.Errorf("platform: making the mount namespace private: %w", err)
	}
	// A read-only remount applies to a mount, not to a superblock, so the root
	// has to be bound onto itself to have a mount of its own to change.
	if err := unix.Mount("/", "/", "", unix.MS_BIND|unix.MS_REC, ""); err != nil {
		return fmt.Errorf("platform: binding the root: %w", err)
	}
	if err := unix.Mount("", "/", "",
		unix.MS_REMOUNT|unix.MS_BIND|unix.MS_RDONLY, ""); err != nil {
		return fmt.Errorf("platform: making the root read-only: %w", err)
	}

	// The writable paths are restored afterwards, each as its own bind mount.
	// Doing it in this order means a path that fails to become writable leaves
	// the target confined rather than leaving the root writable.
	for _, p := range writable {
		if p == "" {
			continue
		}
		abs, err := filepath.Abs(p)
		if err != nil {
			return fmt.Errorf("platform: resolving the writable path %s: %w", p, err)
		}
		if err := unix.Mount(abs, abs, "", unix.MS_BIND, ""); err != nil {
			return fmt.Errorf("platform: binding the writable path %s: %w", abs, err)
		}
		if err := unix.Mount("", abs, "", unix.MS_REMOUNT|unix.MS_BIND, ""); err != nil {
			return fmt.Errorf("platform: making %s writable: %w", abs, err)
		}
	}
	return nil
}
