package safety

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/rom/Xfuzz/internal/platform"
)

// Level is how strongly a target is confined.
//
// The levels are the ones ADR-0012 declares, and the point of naming them is
// that a campaign can require a minimum and refuse to start below it. That only
// works if the level reported is the level in force, so nothing here reports a
// mechanism that was requested rather than applied.
type Level int

// The isolation levels, weakest first.
const (
	// LevelNone is no confinement at all. It exists so that a campaign can ask
	// for it explicitly — some targets genuinely need the host — and so that
	// "unconfined" is a value in the same vocabulary rather than an absence.
	LevelNone Level = iota

	// LevelMinimal is workdir confinement, a process group that can be killed
	// as a unit, a wall-clock timeout, and whatever resource caps the host
	// offers.
	LevelMinimal

	// LevelModerate adds real separation — namespaces, or a syscall filter —
	// but is missing one of the mechanisms that makes the strong level strong.
	LevelModerate

	// LevelStrong is user, mount, and PID namespaces, a seccomp filter, and a
	// cgroup that accounts the target from its first instruction.
	LevelStrong
)

var levelNames = [...]string{
	LevelNone: "none", LevelMinimal: "minimal",
	LevelModerate: "moderate", LevelStrong: "strong",
}

func (l Level) String() string {
	if int(l) < len(levelNames) && levelNames[l] != "" {
		return levelNames[l]
	}
	return "Level(" + strconv.Itoa(int(l)) + ")"
}

// ParseLevel resolves a level name.
func ParseLevel(s string) (Level, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "none", "off":
		return LevelNone, nil
	case "", "minimal":
		return LevelMinimal, nil
	case "moderate":
		return LevelModerate, nil
	case "strong":
		return LevelStrong, nil
	}
	return LevelNone, fmt.Errorf("safety: unknown isolation level %q (want none, minimal, moderate, or strong)", s)
}

// ErrIsolationTooWeak is returned when a campaign requires more confinement than
// the host provides.
var ErrIsolationTooWeak = errors.New("safety: the host cannot provide the required isolation level")

// HelperName is the sandbox helper binary.
const HelperName = "xfuzz-sandbox"

// Sandbox is the confinement policy for a campaign's targets.
//
// The zero value is usable and confines: no field has to be set for a target to
// run in a namespace with a syscall filter, because opt-in safety is not safety
// (ADR-0012). What the fields do is relax it — a campaign whose target needs the
// network, or the host's PID space, says so.
type Sandbox struct {
	// Require is the minimum level the campaign will accept. A host that cannot
	// reach it refuses to start the campaign rather than running it less
	// confined than it asked for.
	Require Level

	// Workdir is the directory the target runs in. Empty means the caller's.
	Workdir string

	// Network keeps the target in the host's network namespace, for a campaign
	// whose target is a network client or server. It is the single largest
	// relaxation available and is audited as an escape hatch.
	Network bool

	// HostPIDs keeps the target in the host's PID namespace. Needed only for a
	// target that inspects other processes.
	HostPIDs bool

	// Writable lists paths that stay writable under the read-only root, beyond
	// the workdir. A target that needs a scratch directory or a socket path
	// names it here rather than the sandbox being turned off for it.
	Writable []string

	// WritableRoot disables the read-only root, leaving the target able to
	// modify anything its identity permits. It is an escape hatch and is
	// audited as one.
	WritableRoot bool

	// NoSeccomp disables the syscall denylist.
	NoSeccomp bool

	// Unconfined skips confinement entirely.
	//
	// It exists for one case: Xfuzz spawning *its own* processes. A worker is
	// this binary, not a target, and confining it would nest a namespace inside
	// a namespace and take away the privilege it needs to confine the target
	// itself. The target inside a worker is still confined, by that worker's own
	// sandbox — the exemption covers the process, not what it runs.
	//
	// It is a field rather than a separate constructor so that it appears in
	// the configuration a reviewer reads, and Level reports "none" when it is
	// set, so nothing can claim confinement it does not have.
	Unconfined bool

	// Limits are the per-target resource caps.
	Limits platform.Limits

	// HelperPath locates xfuzz-sandbox. Empty searches beside the running
	// binary and then PATH.
	HelperPath string

	// Auditor records the level in force and every escape hatch taken.
	Auditor Auditor

	// Name distinguishes this campaign's cgroup from another's.
	Name string

	// probeOnce guards the detection below. A spawner is shared by every worker
	// in a campaign (ADR-0015), so this is read concurrently; detecting once
	// under a sync.Once also means the read-only-root probe runs once rather
	// than once per worker.
	probeOnce sync.Once
	mu        sync.Mutex

	caps   platform.SandboxCapabilities
	helper string
	roRoot bool
	cgroup *platform.Cgroup
}

// Probe determines what this host can do and what level that adds up to.
//
// It is separate from applying the sandbox so that a campaign can be refused
// before anything is started, and so that the level can be reported in a status
// view without spawning anything.
func (s *Sandbox) Probe() (Level, platform.SandboxCapabilities) {
	s.probeOnce.Do(func() {
		s.caps = platform.DetectSandbox()
		s.helper, _ = s.findHelper()
		s.roRoot = s.probeReadOnlyRoot()
		if !s.roRoot && s.caps.MountNS {
			s.caps.Notes = append(s.caps.Notes,
				"a read-only root could not be established: the mounts a new mount namespace "+
					"inherits are locked when it is created alongside a user namespace on this "+
					"kernel, so confinement rests on the target's host identity instead")
		}
	})
	return s.level(), s.caps
}

// level computes the isolation level from the mechanisms actually available.
func (s *Sandbox) level() Level {
	if s.Unconfined {
		return LevelNone
	}
	c := s.caps
	// The filter and the resource limits both need the helper, because both can
	// only be installed by the process that becomes the target.
	seccomp := c.Seccomp && s.helper != "" && !s.NoSeccomp
	// A separate identity is what actually keeps a target out of the corpus,
	// and only a privileged fuzzer can give the target one.
	deprivileged := s.helper != "" && s.privileged()

	switch {
	case deprivileged && c.MountNS && c.PIDNS && seccomp && s.roRoot &&
		c.Cgroups == platform.CgroupV2:
		return LevelStrong
	case (deprivileged && c.MountNS && c.PIDNS) || (c.UserNS && c.MountNS) || seccomp:
		return LevelModerate
	default:
		return LevelMinimal
	}
}

// Explain returns the level, and why it is not higher.
//
// A campaign refused for insufficient isolation must be told what is missing.
// "Isolation is too weak" with no reason is a message nobody can act on, and the
// action — enable user namespaces, mount cgroup v2, install the helper — is
// usually one line of configuration.
func (s *Sandbox) Explain() string {
	level, caps := s.Probe()
	var b strings.Builder
	fmt.Fprintf(&b, "isolation %s (%s)", level, caps)
	notes := append([]string(nil), caps.Notes...)
	if s.Unconfined {
		notes = append(notes,
			"confinement is switched off for this process: it is one of Xfuzz's own, "+
				"and the target it runs is confined by its own sandbox")
	}
	if s.helper == "" {
		notes = append(notes,
			HelperName+" was not found beside the running binary or on PATH; "+
				"resource limits and the syscall denylist cannot be installed without it")
	}
	if s.NoSeccomp {
		notes = append(notes, "the syscall denylist is disabled by configuration")
	}
	if s.Network {
		notes = append(notes, "the target shares the host network namespace by configuration")
	}
	if s.HostPIDs {
		notes = append(notes, "the target shares the host PID namespace by configuration")
	}
	if s.WritableRoot {
		notes = append(notes, "the root filesystem is writable by configuration")
	}
	if !caps.MountNS {
		notes = append(notes,
			"no mount namespace: the target can write anywhere its identity permits, "+
				"including the corpus")
	}
	if !s.privileged() {
		uid, _ := platform.UnprivilegedID()
		notes = append(notes,
			fmt.Sprintf("Xfuzz is not running as root, so the target cannot be given a "+
				"separate identity (uid %d): on the host it remains the same user as the "+
				"fuzzer, with the same access to the corpus", uid))
	}
	for _, n := range notes {
		b.WriteString("\n  - " + n)
	}
	return b.String()
}

// Check refuses a campaign whose required level the host cannot reach.
func (s *Sandbox) Check(ctx context.Context) error {
	if s.Unconfined && s.Require != LevelNone {
		return fmt.Errorf("%w: the sandbox is explicitly unconfined but %s is required",
			ErrIsolationTooWeak, s.Require)
	}
	level, _ := s.Probe()
	if level < s.Require {
		return fmt.Errorf("%w: %s is required, %s is available\n%s",
			ErrIsolationTooWeak, s.Require, level, s.Explain())
	}
	if err := s.checkWorkdir(); err != nil {
		return err
	}
	if s.Auditor != nil {
		if err := s.Auditor.Audit(ctx, "", AuditSandboxLevel, s.Explain()); err != nil {
			return err
		}
		for _, hatch := range s.hatches() {
			if err := s.Auditor.Audit(ctx, "", AuditEscapeHatch, hatch); err != nil {
				return err
			}
		}
	}
	return nil
}

// ErrWorkdirUnreachable is returned when the target's identity cannot reach its
// own working directory.
var ErrWorkdirUnreachable = errors.New("safety: the target cannot reach its working directory")

// checkWorkdir verifies the target will be able to use the directory it is
// given.
//
// Running the target as a different user is what keeps it out of the corpus, and
// the same change is what makes a workdir the fuzzer created with default
// permissions unusable to it. Left undetected this appears as every execution
// failing for an unrelated-looking reason; caught here it is one sentence naming
// the directory component that blocks it.
func (s *Sandbox) checkWorkdir() error {
	uid, gid := s.dropTo()
	if uid == 0 || s.Workdir == "" {
		return nil
	}
	abs, err := filepath.Abs(s.Workdir)
	if err != nil {
		return err
	}

	// Every component from the root down has to be traversable, and the
	// directory itself writable, by the identity the target will have.
	var walked string
	for _, part := range strings.Split(abs, string(filepath.Separator)) {
		walked = filepath.Join(walked, string(filepath.Separator), part)
		fi, err := os.Stat(walked)
		if err != nil {
			return fmt.Errorf("%w: %s: %w", ErrWorkdirUnreachable, walked, err)
		}
		if !permitted(fi, uid, gid, 0o1) {
			return fmt.Errorf("%w: %s is mode %v and owned by %s, so uid %d cannot enter it",
				ErrWorkdirUnreachable, walked, fi.Mode().Perm(), ownerOf(fi), uid)
		}
	}
	fi, err := os.Stat(abs)
	if err != nil {
		return err
	}
	if !permitted(fi, uid, gid, 0o2) {
		return fmt.Errorf("%w: %s is mode %v and owned by %s, so uid %d cannot write in it",
			ErrWorkdirUnreachable, abs, fi.Mode().Perm(), ownerOf(fi), uid)
	}
	return nil
}

// permitted reports whether uid/gid has the given permission bits on a file.
func permitted(fi os.FileInfo, uid, gid int, bits uint32) bool {
	mode := uint32(fi.Mode().Perm())
	fuid, fgid, ok := platform.OwnerOf(fi)
	if !ok {
		// Without ownership information the only safe answer is the one that
		// does not claim access the target may not have.
		return mode&bits != 0
	}
	switch {
	case fuid == uid:
		return mode&(bits<<6) != 0
	case fgid == gid:
		return mode&(bits<<3) != 0
	default:
		return mode&bits != 0
	}
}

func ownerOf(fi os.FileInfo) string {
	uid, gid, ok := platform.OwnerOf(fi)
	if !ok {
		return "an unknown user"
	}
	return fmt.Sprintf("uid %d gid %d", uid, gid)
}

// hatches lists the relaxations this configuration takes.
func (s *Sandbox) hatches() []string {
	var out []string
	if s.Network {
		out = append(out, "network: the target shares the host network namespace")
	}
	if s.HostPIDs {
		out = append(out, "pids: the target shares the host PID namespace")
	}
	if s.NoSeccomp {
		out = append(out, "seccomp: the syscall denylist is disabled")
	}
	if s.Unconfined {
		out = append(out, "unconfined: this process is one of Xfuzz's own and is not sandboxed")
	}
	if s.WritableRoot {
		out = append(out, "filesystem: the root is writable rather than read-only")
	}
	for _, p := range s.Writable {
		out = append(out, "filesystem: "+p+" is writable in addition to the workdir")
	}
	return out
}

// Level returns the level in force.
func (s *Sandbox) Level() Level {
	l, _ := s.Probe()
	return l
}

// findHelper locates xfuzz-sandbox.
//
// Beside the running binary first, because that is where a released tarball
// puts it and because it is the copy whose version matches. PATH second, for a
// development tree where the binaries are installed. Nothing else: searching
// the working directory would let a target that can write there choose its own
// sandbox.
func (s *Sandbox) findHelper() (string, error) {
	if s.HelperPath != "" {
		if _, err := os.Stat(s.HelperPath); err != nil {
			return "", fmt.Errorf("safety: the configured sandbox helper %s: %w", s.HelperPath, err)
		}
		return s.HelperPath, nil
	}
	return FindTool(HelperName)
}

// FindTool locates one of Xfuzz's own binaries.
//
// Beside the running binary first, because that is where a released tarball
// puts it and because it is the copy whose version matches; then PATH, for a
// development tree where the binaries are installed. Nothing else: searching
// the working directory would let whatever can write there choose which binary
// Xfuzz runs, which for a tool that spawns processes is a straightforward way
// to hand it a different program.
//
// It lives in this package because looking a program up on PATH is part of
// deciding what to execute, and deciding what to execute is what the spawn
// boundary is for (ARCHITECTURE section 2).
func FindTool(name string) (string, error) {
	if self, err := os.Executable(); err == nil {
		candidate := filepath.Join(filepath.Dir(self), name)
		if fi, err := os.Stat(candidate); err == nil && !fi.IsDir() {
			return candidate, nil
		}
	}
	if p, err := exec.LookPath(name); err == nil {
		return p, nil
	}
	return "", fmt.Errorf("safety: %s was not found beside the running binary or on PATH", name)
}

// privileged reports whether the fuzzer itself runs as root.
//
// It changes the shape of the sandbox rather than just its strength. A root
// fuzzer can hand the target a genuinely different, unprivileged identity and
// can build a read-only root; an unprivileged one can only put the target in a
// namespace where it is still, on the host, the same user as the fuzzer — with
// the same access to the corpus. Both are worth having and they are not the
// same thing, so the level reported distinguishes them.
func (s *Sandbox) privileged() bool { return os.Geteuid() == 0 }

// dropTo returns the identity the target should run as, or zero when the
// fuzzer cannot give it one.
func (s *Sandbox) dropTo() (uid, gid int) {
	if s.Unconfined || !s.privileged() {
		return 0, 0
	}
	return platform.UnprivilegedID()
}

// wantRORoot reports whether the helper should build a read-only root.
func (s *Sandbox) wantRORoot() bool { return s.roRoot && !s.WritableRoot }

// probeReadOnlyRoot finds out whether a read-only root can actually be
// established here.
//
// It is a probe rather than a check of kernel version or capability bits
// because the answer depends on how the host's mounts were set up: a mount
// namespace created alongside a user namespace inherits its mounts *locked* on
// many configurations, and a locked mount cannot be remounted read-only. The
// only reliable way to know is to try it once, which is what this does — with
// /bin/true as the target, so the probe costs one process.
//
// Asking the helper for a read-only root that cannot be built would fail every
// execution of the campaign. Not asking for one that could be built would give
// up real confinement. Probing is what avoids having to guess.
func (s *Sandbox) probeReadOnlyRoot() bool {
	if s.Unconfined || s.helper == "" || !s.caps.MountNS || s.WritableRoot {
		return false
	}
	probe, err := exec.LookPath("true")
	if err != nil {
		return false
	}
	dir, err := os.MkdirTemp("", "xfuzz-roprobe-")
	if err != nil {
		return false
	}
	defer os.RemoveAll(dir)
	if err := os.Chmod(dir, 0o777); err != nil {
		return false
	}

	args := []string{"-ro-root", "-rw", dir, "-seccomp=false"}
	if uid, gid := s.dropTo(); uid > 0 {
		args = append(args, "-uid", strconv.Itoa(uid), "-gid", strconv.Itoa(gid))
	}
	args = append(args, "--", probe)
	cmd := exec.Command(s.helper, args...)
	platform.ConfigureProcess(cmd, false)
	platform.ConfigureSandbox(cmd, s.namespaces())
	return cmd.Run() == nil
}

// namespaces returns the namespace options for this policy.
func (s *Sandbox) namespaces() platform.SandboxOptions {
	if s.Unconfined {
		return platform.SandboxOptions{}
	}
	c := s.caps
	uid, gid := platform.UnprivilegedID()
	o := platform.SandboxOptions{
		// A user namespace is what an unprivileged caller needs to get the
		// other namespaces at all. A privileged one does not need it, and is
		// better off without: a mount namespace created alongside a user
		// namespace inherits its mounts locked, so the read-only root — the
		// stronger of the two mechanisms — becomes impossible in that
		// combination.
		UserNS:  c.UserNS && !s.privileged(),
		MountNS: c.MountNS,
		IPCNS:   c.MountNS,
		UTSNS:   c.MountNS,
		// Map to an unprivileged id inside the namespace. Mapping to 0 would
		// give the target root inside its namespace, which is convenient and is
		// the setting most container escapes have started from — and mapping to
		// the kernel's overflow id would be worse still, for the reason
		// platform.OverflowID explains.
		UID: uid,
		GID: gid,
	}
	if c.PIDNS && !s.HostPIDs {
		o.PIDNS = true
	}
	if c.NetNS && !s.Network {
		o.NetNS = true
	}
	return o
}

// wrap rewrites a process spec to run under the sandbox helper.
//
// It returns the spec unchanged when there is no helper, because a spec that
// silently lost its resource limits is worse than one that never had them: the
// campaign would still report itself as limited.
func (s *Sandbox) wrap(path string, argv []string, dir string) (string, []string) {
	if s.Unconfined || s.helper == "" {
		return path, argv
	}
	args := []string{s.helper}
	if s.wantRORoot() {
		args = append(args, "-ro-root")
		// The workdir has to stay writable or the target cannot write its own
		// output, which would make the sandbox indistinguishable from a broken
		// target.
		for _, p := range append([]string{dir}, s.Writable...) {
			if p != "" {
				args = append(args, "-rw", p)
			}
		}
	}
	if dir != "" {
		args = append(args, "-chdir", dir)
	}
	if s.Limits.FileSizeBytes > 0 {
		args = append(args, "-limit-fsize", strconv.FormatUint(s.Limits.FileSizeBytes, 10))
	}
	if s.Limits.CPUSeconds > 0 {
		args = append(args, "-limit-cpu", strconv.FormatUint(s.Limits.CPUSeconds, 10))
	}
	if s.Limits.Processes > 0 {
		args = append(args, "-limit-nproc", strconv.FormatUint(s.Limits.Processes, 10))
	}
	if s.Limits.OpenFiles > 0 {
		args = append(args, "-limit-nofile", strconv.FormatUint(s.Limits.OpenFiles, 10))
	}
	if uid, gid := s.dropTo(); uid > 0 {
		args = append(args, "-uid", strconv.Itoa(uid), "-gid", strconv.Itoa(gid))
	}
	if s.NoSeccomp || !s.caps.Seccomp {
		args = append(args, "-seccomp=false")
	}
	args = append(args, "--", path)
	if len(argv) > 1 {
		args = append(args, argv[1:]...)
	}
	return s.helper, args
}

// ensureCgroup creates the campaign's cgroup on first use.
func (s *Sandbox) ensureCgroup() *platform.Cgroup {
	if s.Unconfined {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cgroup != nil {
		return s.cgroup
	}
	name := s.Name
	if name == "" {
		name = "campaign-" + strconv.Itoa(os.Getpid())
	}
	cg, err := platform.NewCgroup(name, s.Limits)
	if err != nil {
		// A cgroup that could not be created is a mechanism that is not in
		// force. The level was computed from what the host reported, so this is
		// a race or a permission problem rather than a surprise; returning nil
		// means the target simply runs without it, which the level already
		// says.
		return nil
	}
	s.cgroup = cg
	return cg
}

// Close releases the sandbox's resources.
func (s *Sandbox) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cgroup != nil {
		err := s.cgroup.Close()
		s.cgroup = nil
		return err
	}
	return nil
}
