package safety

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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

	full := sb.namespaces()
	if caps.NetNS && !full.NetNS {
		t.Error("the default policy left the target in the host network namespace")
	}
	if caps.PIDNS && !full.PIDNS {
		t.Error("the default policy left the target in the host PID namespace")
	}
	if caps.UserNS && full.UID == 0 {
		t.Error("the target is mapped to root inside its user namespace")
	}

	relaxed := &Sandbox{Network: true, HostPIDs: true}
	relaxed.Probe()
	o := relaxed.namespaces()
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
