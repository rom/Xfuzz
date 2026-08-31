package safety

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/rom/Xfuzz/internal/platform"
)

func TestLevelOrdering(t *testing.T) {
	if !(LevelNone < LevelMinimal && LevelMinimal < LevelModerate && LevelModerate < LevelStrong) {
		t.Fatal("the levels do not order weakest to strongest, so a minimum cannot be required")
	}
}

func TestParseLevel(t *testing.T) {
	for in, want := range map[string]Level{
		"none": LevelNone, "off": LevelNone, "": LevelMinimal, "minimal": LevelMinimal,
		"Moderate": LevelModerate, " STRONG ": LevelStrong,
	} {
		got, err := ParseLevel(in)
		if err != nil || got != want {
			t.Errorf("ParseLevel(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	if _, err := ParseLevel("paranoid"); err == nil {
		t.Fatal("an unknown level was accepted")
	}
}

func TestLevelRoundTripsThroughItsName(t *testing.T) {
	for _, l := range []Level{LevelNone, LevelMinimal, LevelModerate, LevelStrong} {
		back, err := ParseLevel(l.String())
		if err != nil || back != l {
			t.Errorf("%v round-tripped to %v, %v", l, back, err)
		}
	}
}

func TestSandboxReportsWhatIsAvailableNotWhatIsWanted(t *testing.T) {
	// A helper that does not exist means resource limits and the syscall filter
	// cannot be installed. The reported level must fall accordingly; reporting
	// the configured intent would let a campaign that requires strong isolation
	// run without it, which is the exact failure ADR-0012 exists to prevent.
	absent := &Sandbox{HelperPath: filepath.Join(t.TempDir(), "no-such-helper")}
	level, _ := absent.Probe()
	if level == LevelStrong {
		t.Fatal("a sandbox with no helper reported the strong level")
	}
	if !strings.Contains(absent.Explain(), HelperName) {
		t.Fatalf("Explain does not mention the missing helper:\n%s", absent.Explain())
	}
}

func TestSandboxRefusesACampaignItCannotConfine(t *testing.T) {
	sb := &Sandbox{Require: LevelStrong, HelperPath: filepath.Join(t.TempDir(), "absent")}
	err := sb.Check(context.Background())
	if err == nil {
		t.Skip("this host provides strong isolation, so the refusal cannot be exercised here")
	}
	if !errors.Is(err, ErrIsolationTooWeak) {
		t.Fatalf("err = %v, want ErrIsolationTooWeak", err)
	}
	if !strings.Contains(err.Error(), "strong is required") {
		t.Fatalf("the error does not say what was required: %v", err)
	}
	if !strings.Contains(err.Error(), "-") {
		t.Fatalf("the error does not explain what is missing: %v", err)
	}
}

func TestSandboxAcceptsALevelItCanMeet(t *testing.T) {
	sb := &Sandbox{Require: LevelMinimal, Auditor: &recordingAuditor{}}
	if err := sb.Check(context.Background()); err != nil {
		t.Fatalf("the minimal level was refused on a host that can run processes: %v", err)
	}
}

func TestSandboxAuditsItsLevelAndEveryEscapeHatch(t *testing.T) {
	a := &recordingAuditor{}
	sb := &Sandbox{Auditor: a, Network: true, NoSeccomp: true, HostPIDs: true}
	if err := sb.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	if a.count(AuditSandboxLevel) != 1 {
		t.Fatalf("the isolation level was not audited: %v", a.entries)
	}
	if got := a.count(AuditEscapeHatch); got != 3 {
		t.Fatalf("%d escape hatches audited, want 3: %v", got, a.entries)
	}
}

func TestSandboxFindsTheHelperBesideTheRunningBinary(t *testing.T) {
	// The lookup must prefer the copy shipped alongside the binary over
	// anything on PATH: that is the copy whose version matches, and a PATH
	// entry a target could influence must never win.
	self, err := os.Executable()
	if err != nil {
		t.Skip("the running binary's path is unknown here")
	}
	beside := filepath.Join(filepath.Dir(self), HelperName)
	if _, err := os.Stat(beside); err != nil {
		t.Skipf("no helper beside %s to find", self)
	}
	sb := &Sandbox{}
	got, err := sb.findHelper()
	if err != nil || got != beside {
		t.Fatalf("findHelper = %q, %v; want %q", got, err, beside)
	}
}

func TestSandboxNamespaceOptionsFollowConfiguration(t *testing.T) {
	sb := &Sandbox{}
	sb.Probe()
	caps := platform.DetectSandbox()

	full := sb.namespaces(true)
	if caps.NetNS && !full.NetNS {
		t.Error("the default policy left the target in the host network namespace")
	}
	if caps.PIDNS && !full.PIDNS {
		t.Error("the default policy left the target in the host PID namespace")
	}
	// And not for a target that is executed directly: it would be PID 1 in that
	// namespace, and PID 1 cannot abort() itself. See Sandbox.namespaces.
	if sb.namespaces(false).PIDNS {
		t.Error("a one-shot target was put in a PID namespace, where its abort() " +
			"would be discarded and reported as a segmentation fault")
	}
	if caps.UserNS && full.UID == 0 {
		t.Error("the target is mapped to root inside its user namespace")
	}

	relaxed := &Sandbox{Network: true, HostPIDs: true}
	relaxed.Probe()
	o := relaxed.namespaces(true)
	if o.NetNS || o.PIDNS {
		t.Error("the relaxations were configured but not applied")
	}
}

func TestSandboxWrapPassesLimitsToTheHelper(t *testing.T) {
	sb := &Sandbox{
		HelperPath: helperForTest(t),
		Limits: platform.Limits{
			FileSizeBytes: 1 << 20, CPUSeconds: 7, Processes: 32, OpenFiles: 64,
		},
	}
	sb.Probe()
	path, argv := sb.wrap("/bin/true", []string{"/bin/true", "-x"}, "/tmp")
	if path != sb.HelperPath {
		t.Fatalf("wrap ran %s directly rather than through the helper", path)
	}
	joined := strings.Join(argv, " ")
	for _, want := range []string{
		"-chdir /tmp", "-limit-fsize 1048576", "-limit-cpu 7",
		"-limit-nproc 32", "-limit-nofile 64", "-- /bin/true -x",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("the helper was not told %q: %s", want, joined)
		}
	}
}

func TestSandboxWrapIsATransparentPassThroughWithNoHelper(t *testing.T) {
	// Silently dropping the limits would be worse than not having them: the
	// campaign would still report itself as limited.
	sb := &Sandbox{HelperPath: filepath.Join(t.TempDir(), "absent")}
	sb.Probe()
	path, argv := sb.wrap("/bin/true", []string{"/bin/true"}, "/tmp")
	if path != "/bin/true" || len(argv) != 1 {
		t.Fatalf("wrap = %q, %v", path, argv)
	}
	if sb.Level() >= LevelStrong {
		t.Fatal("a sandbox that cannot install limits reported the strong level")
	}
}

// helperForTest builds xfuzz-sandbox once per test binary.
func helperForTest(t testing.TB) string {
	t.Helper()
	helperOnce.Do(func() {
		dir, err := os.MkdirTemp("", "xfuzz-helper-")
		if err != nil {
			helperErr = err
			return
		}
		helperDir = dir
		out := filepath.Join(dir, HelperName)
		cmd := exec.Command("go", "build", "-o", out, "./cmd/xfuzz-sandbox")
		cmd.Dir = repoRoot(t)
		if b, err := cmd.CombinedOutput(); err != nil {
			helperErr = errors.New(string(b))
			return
		}
		helperPath = out
	})
	if helperErr != nil {
		t.Fatalf("building %s: %v", HelperName, helperErr)
	}
	return helperPath
}

func TestSandboxProbesOnceUnderConcurrentUse(t *testing.T) {
	// A spawner is shared by every worker in a campaign, so the lazy detection
	// is read concurrently. Two workers installing a default simultaneously
	// would give half of them a different sandbox — and a different cgroup —
	// from the other half.
	sp := NewSpawner()

	var wg sync.WaitGroup
	levels := make([]string, 16)
	for i := range levels {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			levels[i] = sp.IsolationLevel()
			_ = sp.Explain()
		}(i)
	}
	wg.Wait()

	for i, l := range levels {
		if l != levels[0] {
			t.Fatalf("worker %d saw isolation %q, worker 0 saw %q", i, l, levels[0])
		}
	}
}

func TestSandboxCloseIsSafeToRepeat(t *testing.T) {
	sb := &Sandbox{Name: "close-twice"}
	sb.Probe()
	if err := sb.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := sb.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

func TestUnconfinedIsHonestAboutItself(t *testing.T) {
	sb := &Sandbox{Unconfined: true}
	if got := sb.Level(); got != LevelNone {
		t.Fatalf("an unconfined sandbox reports %v", got)
	}
	if !strings.Contains(sb.Explain(), "not sandboxed") &&
		!strings.Contains(sb.Explain(), "switched off") {
		t.Fatalf("Explain does not say the process is unconfined:\n%s", sb.Explain())
	}
	// It applies no namespaces and asks the helper for nothing.
	if o := sb.namespaces(true); o.UserNS || o.MountNS || o.PIDNS || o.NetNS {
		t.Fatalf("an unconfined sandbox still requested namespaces: %+v", o)
	}
	sb.HelperPath = helperForTest(t)
	sb.Probe()
	path, argv := sb.wrap("/bin/true", []string{"/bin/true"}, "")
	if path != "/bin/true" || len(argv) != 1 {
		t.Fatalf("an unconfined spawn went through the helper: %q %v", path, argv)
	}
}

func TestUnconfinedCannotSatisfyARequiredLevel(t *testing.T) {
	// The exemption is for Xfuzz's own processes. It must never be a way to
	// run a campaign that asked for confinement without it.
	sb := &Sandbox{Unconfined: true, Require: LevelMinimal}
	err := sb.Check(context.Background())
	if !errors.Is(err, ErrIsolationTooWeak) {
		t.Fatalf("err = %v, want ErrIsolationTooWeak", err)
	}
}

func TestTrustedSpawnerIsUnconfinedAndSaysSo(t *testing.T) {
	sp := NewTrustedSpawner()
	if sp.IsolationLevel() != LevelNone.String() {
		t.Fatalf("the trusted spawner reports %q", sp.IsolationLevel())
	}
	if NewSpawner().IsolationLevel() == LevelNone.String() {
		t.Fatal("the ordinary spawner is also unconfined; the default must confine")
	}
}

// injectedCaps returns a sandbox whose capabilities are the given ones, with
// detection burned so Probe does not replace them with the host's.
//
// Every non-Linux mechanism has to be testable from Linux, or the policy that
// decides what macOS and Windows are worth is exercised on no machine anyone
// runs the tests on.
func injectedCaps(c platform.SandboxCapabilities) *Sandbox {
	s := &Sandbox{}
	s.probeOnce.Do(func() {})
	s.caps = c
	return s
}

func TestPlatformConfinementReachesTheModerateLevel(t *testing.T) {
	// A Seatbelt profile denies the target file writes outside its working
	// directory and denies it the network. That is the same separation a mount
	// namespace and a syscall filter provide, reached differently, so it earns
	// the same level — otherwise a macOS host reports minimal for ever and a
	// campaign that requires moderate can never run on one.
	s := injectedCaps(platform.SandboxCapabilities{
		Confined: true, Rlimits: true, Cgroups: platform.CgroupNone,
	})
	if level, _ := s.Probe(); level != LevelModerate {
		t.Fatalf("a confined host reported %v, want %v", level, LevelModerate)
	}
}

func TestAJobObjectAloneStaysMinimal(t *testing.T) {
	// A job object caps memory and process count and kills the tree. None of
	// that keeps a target out of the corpus, and calling it moderate would let a
	// campaign that requires isolation run on a host that gives it none.
	s := injectedCaps(platform.SandboxCapabilities{
		JobLimits: true, Rlimits: true, Cgroups: platform.CgroupJob,
	})
	level, _ := s.Probe()
	if level != LevelMinimal {
		t.Fatalf("a host with only a job object reported %v, want %v", level, LevelMinimal)
	}
	if !strings.Contains(s.Explain(), "job object") {
		t.Fatalf("Explain does not say what the job object does:\n%s", s.Explain())
	}
	if !strings.Contains(s.Explain(), "write anywhere") {
		t.Fatalf("Explain does not say the target can still write anywhere:\n%s", s.Explain())
	}
}

func TestConfinementSuppressesTheMountNamespaceWarning(t *testing.T) {
	// "no mount namespace: the target can write anywhere" is false on a host
	// whose profile denies exactly that, and a warning that is not true is one
	// an operator learns to ignore.
	s := injectedCaps(platform.SandboxCapabilities{Confined: true, Rlimits: true})
	if strings.Contains(s.Explain(), "write anywhere") {
		t.Fatalf("a confined host was warned it can write anywhere:\n%s", s.Explain())
	}
}

func TestCapabilityStringNamesTheNonLinuxMechanisms(t *testing.T) {
	// The line is what a doctor report and an audit record carry, so a mechanism
	// missing from it is a mechanism nobody can see was in force.
	got := platform.SandboxCapabilities{
		Confined: true, JobLimits: true, Rlimits: true, Cgroups: platform.CgroupJob,
	}.String()
	for _, want := range []string{"confined", "joblimits", "rlimits", "cgroups-job"} {
		if !strings.Contains(got, want) {
			t.Errorf("%q does not name %s", got, want)
		}
	}
}
