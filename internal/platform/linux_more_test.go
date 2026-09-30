//go:build linux

package platform

import (
	"bytes"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// The seccomp filter is a small program, and a small program only ever
// exercised by its side effects is one nobody can check. So it is read back
// as a program: the architecture guard first, one comparison per denied
// call, and the two returns last.
func TestSeccompFilterHasTheShapeItClaims(t *testing.T) {
	deny := []int{unix.SYS_MOUNT, unix.SYS_REBOOT, unix.SYS_KEXEC_LOAD}
	prog, err := BuildSeccompFilter(deny, uint16(unix.EPERM))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := len(prog), 4+len(deny)+2; got != want {
		t.Fatalf("program is %d instructions, want %d", got, want)
	}

	arch, _ := auditArch()
	if prog[0].Code != unix.BPF_LD|unix.BPF_W|unix.BPF_ABS || prog[0].K != seccompOffArch {
		t.Errorf("the first instruction does not load the architecture: %+v", prog[0])
	}
	if prog[1].K != arch || prog[1].Jt != 1 {
		t.Errorf("the architecture check is wrong: %+v", prog[1])
	}
	if prog[2].K != uint32(unix.SECCOMP_RET_ERRNO)|uint32(unix.EPERM) {
		t.Errorf("a foreign architecture is not refused with EPERM: %+v", prog[2])
	}
	if prog[3].K != seccompOffNr {
		t.Errorf("the syscall number is not loaded next: %+v", prog[3])
	}
	// Each denied number is compared, and each jump lands on the deny return
	// — the last instruction — from wherever it is.
	for i, nr := range deny {
		ins := prog[4+i]
		if ins.K != uint32(nr) {
			t.Errorf("comparison %d checks %d, want %d", i, ins.K, nr)
		}
		if target := 4 + i + 1 + int(ins.Jt); target != len(prog)-1 {
			t.Errorf("comparison %d jumps to %d, want the deny return at %d", i, target, len(prog)-1)
		}
	}
	if prog[len(prog)-2].K != uint32(unix.SECCOMP_RET_ALLOW) {
		t.Error("the fall-through is not allow")
	}
	if prog[len(prog)-1].K != uint32(unix.SECCOMP_RET_ERRNO)|uint32(unix.EPERM) {
		t.Error("the deny return does not carry the errno")
	}
}

func TestSeccompRefusesADenylistItCannotJumpOver(t *testing.T) {
	// A BPF jump offset is one byte. A list long enough to need more would
	// silently wrap into a filter that denies the wrong things.
	deny := make([]int, 300)
	if _, err := BuildSeccompFilter(deny, 1); err == nil {
		t.Error("a 300-entry denylist was accepted")
	}
}

func TestDefaultDenylistNamesRealSyscalls(t *testing.T) {
	nrs := DefaultSeccompNumbers()
	if len(nrs) != len(DeniedSyscalls) {
		t.Fatalf("%d numbers for %d entries", len(nrs), len(DeniedSyscalls))
	}
	seen := map[int]string{}
	for _, d := range DeniedSyscalls {
		if prev, dup := seen[d.Nr]; dup {
			t.Errorf("%s and %s are the same syscall", prev, d.Name)
		}
		seen[d.Nr] = d.Name
		if d.Nr < 0 {
			t.Errorf("%s has number %d", d.Name, d.Nr)
		}
	}
	// The whole list fits the flat filter, or ApplySeccomp could never run.
	if _, err := BuildSeccompFilter(nrs, uint16(unix.EPERM)); err != nil {
		t.Errorf("the default denylist does not build: %v", err)
	}
}

func TestCapabilitiesRenderSortedAndStable(t *testing.T) {
	c := SandboxCapabilities{UserNS: true, Seccomp: true, MountNS: true, Cgroups: CgroupV2}
	if got := c.String(); got != "mountns,seccomp,userns,cgroups-v2" {
		t.Errorf("String() = %q", got)
	}
	if got := (SandboxCapabilities{}).String(); got != "none" {
		t.Errorf("no capabilities render as %q", got)
	}
	if got := (SandboxCapabilities{Cgroups: CgroupNone, Rlimits: true}).String(); got != "rlimits" {
		t.Errorf("cgroups-none must not be named: %q", got)
	}
	s := []string{"c", "a", "b"}
	sortStrings(s)
	if strings.Join(s, "") != "abc" {
		t.Errorf("sortStrings = %v", s)
	}
}

func TestProbesAgreeWithEachOther(t *testing.T) {
	// The individual probes and the summary must not disagree: the doctor
	// prints the former and the level ladder reads the latter.
	caps := DetectSandbox()
	if caps.Seccomp != SeccompAvailable() {
		t.Errorf("DetectSandbox says seccomp=%v, SeccompAvailable says %v", caps.Seccomp, SeccompAvailable())
	}
	if caps.UserNS != UserNamespacesAvailable() {
		t.Errorf("DetectSandbox says userns=%v, UserNamespacesAvailable says %v", caps.UserNS, UserNamespacesAvailable())
	}
	if !caps.Rlimits {
		t.Error("Linux always has rlimits")
	}
	if mode := CgroupMode(); mode != CgroupNone && mode != CgroupV1 && mode != CgroupV2 {
		t.Errorf("CgroupMode = %q", mode)
	}
	if usable := UsableCgroupMode(); usable != CgroupNone && usable != CgroupMode() {
		t.Errorf("UsableCgroupMode %q is not a restriction of CgroupMode %q", usable, CgroupMode())
	}
	if caps.Cgroups != UsableCgroupMode() {
		t.Errorf("DetectSandbox reports cgroups %q, UsableCgroupMode %q", caps.Cgroups, UsableCgroupMode())
	}

	uid, gid := UnprivilegedID()
	ouid, ogid := OverflowID()
	if uid <= 0 || gid <= 0 || ouid <= 0 || ogid <= 0 {
		t.Errorf("ids: target %d:%d overflow %d:%d", uid, gid, ouid, ogid)
	}
	if uid == ouid {
		t.Error("the target identity is the overflow identity, which every unmapped file belongs to")
	}
	if UnenforceableLimits(Limits{AddressSpaceBytes: 1, Processes: 1, FileSizeBytes: 1, CPUSeconds: 1}) != nil {
		t.Error("Linux reported a limit it cannot enforce")
	}
	if !strings.Contains(LimitsDetail(), "rlimits") {
		t.Errorf("LimitsDetail = %q", LimitsDetail())
	}
}

func TestACgroupIsOptionalAndSaysSo(t *testing.T) {
	// Unavailable is not an error: the caller reports a lower level. Where one
	// can be made, it carries the mode it was made in and can be released.
	cg, err := NewCgroup("xfuzz-test", Limits{AddressSpaceBytes: 64 << 20, Processes: 8})
	if err != nil {
		t.Skipf("a cgroup could not be created here: %v", err)
	}
	if cg == nil {
		if UsableCgroupMode() != CgroupNone {
			t.Errorf("no cgroup was made although %s is usable", UsableCgroupMode())
		}
		if cg.Mode() != CgroupNone {
			t.Errorf("a nil cgroup reports mode %q", cg.Mode())
		}
		return
	}
	defer cg.Close()
	if cg.Mode() != UsableCgroupMode() {
		t.Errorf("mode = %q, usable = %q", cg.Mode(), UsableCgroupMode())
	}
}

func TestSharedMemoryIsARegionTheOwnerCanWrite(t *testing.T) {
	p := NewSharedMemoryProvider()
	if !p.Available() {
		t.Fatal("shared memory is not available on Linux")
	}
	if _, err := p.Create(0); err == nil {
		t.Error("a zero-sized region was created")
	}
	shm, err := p.Create(4096)
	if err != nil {
		t.Fatal(err)
	}
	if len(shm.Bytes()) != 4096 {
		t.Errorf("region is %d bytes", len(shm.Bytes()))
	}
	if shm.ID() == "" {
		t.Error("the region has no identifier for a target to open")
	}
	fi, err := os.Stat(shm.ID())
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("the region is mode %o, want owner-only", fi.Mode().Perm())
	}
	// A write through the mapping is a write to the file: that is what a
	// target's coverage map arrives through.
	copy(shm.Bytes(), []byte("edges"))
	b, _ := os.ReadFile(shm.ID())
	if !bytes.HasPrefix(b, []byte("edges")) {
		t.Errorf("the file does not see the mapped write: %q", b[:8])
	}
	id := shm.ID()
	if err := shm.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(id); err == nil {
		t.Error("the region outlived Close")
	}
	if _, err := CleanupStaleShm(0); err != nil {
		t.Errorf("CleanupStaleShm: %v", err)
	}
}

func TestSharedMemoryForAnotherIdentityIsRefusedWithoutPrivilege(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root can chown")
	}
	p := NewSharedMemoryProviderFor(12345, 12345)
	if _, err := p.Create(64); err == nil {
		t.Error("an unprivileged process gave a region to another user")
	}
}

func TestAProcessGroupDiesTogether(t *testing.T) {
	// A target that forks leaves orphans on every timeout unless it is in its
	// own group and the group is what gets killed.
	cmd := exec.Command("sh", "-c", "sleep 30 & sleep 30")
	ConfigureProcess(cmd, false)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	if err := KillGroup(cmd.Process.Pid); err != nil {
		t.Fatal(err)
	}
	err := cmd.Wait()
	if err == nil {
		t.Fatal("the shell exited cleanly after a SIGKILL to its group")
	}
	if got := SignalOf(cmd.ProcessState); got != int(syscall.SIGKILL) {
		t.Errorf("SignalOf = %d, want SIGKILL", got)
	}
	// TerminateGroup is the polite form.
	cmd = exec.Command("sleep", "30")
	ConfigureProcess(cmd, true)
	cmd.Start()
	if err := TerminateGroup(cmd.Process.Pid); err != nil {
		t.Fatal(err)
	}
	cmd.Wait()
	if got := SignalOf(cmd.ProcessState); got != int(syscall.SIGTERM) {
		t.Errorf("SignalOf after TerminateGroup = %d", got)
	}
	// A clean exit has no signal.
	cmd = exec.Command("true")
	cmd.Run()
	if SignalOf(cmd.ProcessState) != 0 {
		t.Error("a clean exit reports a signal")
	}
	if !ProcessGroupsSupported() || !ExtraFilesSupported() {
		t.Error("Linux supports process groups and extra files")
	}
	if len(TerminationSignals()) == 0 {
		t.Error("no termination signals")
	}
}

func TestOwnerOfReadsTheStat(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "o")
	if err != nil {
		t.Fatal(err)
	}
	fi, _ := f.Stat()
	uid, gid, ok := OwnerOf(fi)
	if !ok || uid != os.Getuid() || gid != os.Getgid() {
		t.Errorf("OwnerOf = %d:%d ok=%v, want %d:%d", uid, gid, ok, os.Getuid(), os.Getgid())
	}
}

func TestTTYSizesAreClampedAndEIOIsEOF(t *testing.T) {
	for _, c := range []struct{ inC, inR, wantC, wantR int }{
		{0, 0, 1, 1}, {80, 24, 80, 24}, {5000, -3, MaxPTYCols, 1},
	} {
		if gc, gr := clampTTYSize(c.inC, c.inR); gc != c.wantC || gr != c.wantR {
			t.Errorf("clampTTYSize(%d,%d) = %d,%d", c.inC, c.inR, gc, gr)
		}
	}
	if !IsTerminalEOF(syscall.EIO) || !IsTerminalEOF(&os.PathError{Err: syscall.EIO}) {
		t.Error("EIO from a pty master is end-of-file and was not recognised")
	}
	if IsTerminalEOF(syscall.EAGAIN) || IsTerminalEOF(nil) {
		t.Error("something other than EIO was called end-of-file")
	}
}

func TestATargetRunsOnARealTerminal(t *testing.T) {
	if !PTYSupported() {
		t.Skip("no pseudo-terminal here")
	}
	tty, err := OpenTTY(40, 10)
	if err != nil {
		t.Fatal(err)
	}
	defer tty.Close()

	// A program that only behaves this way on a terminal: `tty` prints the
	// device and exits 0 when it has one, "not a tty" and 1 when it does not.
	cmd := exec.Command("sh", "-c", "tty && stty size && exit 3")
	proc, err := tty.Start(cmd)
	if err != nil {
		t.Fatal(err)
	}
	if proc.Pid() == 0 {
		t.Error("no pid")
	}
	if _, err := tty.Start(exec.Command("true")); err == nil {
		t.Error("a terminal started two targets")
	}
	exit, err := proc.Wait()
	if err != nil {
		t.Fatal(err)
	}
	if exit.ExitCode != 3 || exit.Signal != 0 {
		t.Errorf("exit = %+v", exit)
	}
	var drawn []byte
	buf := make([]byte, 4096)
	for {
		n, rerr := tty.Read(buf)
		drawn = append(drawn, buf[:n]...)
		if rerr != nil {
			if !IsTerminalEOF(rerr) {
				t.Fatalf("read: %v", rerr)
			}
			break
		}
	}
	out := string(drawn)
	if !strings.Contains(out, "/dev/pts/") {
		t.Errorf("the target did not see a terminal: %q", out)
	}
	if !strings.Contains(out, "10 40") {
		t.Errorf("the target did not see the size it was given: %q", out)
	}
	if err := tty.Resize(50, 12); err != nil {
		t.Errorf("Resize: %v", err)
	}
}
