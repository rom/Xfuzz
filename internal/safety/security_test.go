package safety

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/rom/Xfuzz/internal/platform"
	"github.com/rom/Xfuzz/pkg/executor"
)

// The executable half of docs/SECURITY.md, one test per row of the table in
// docs/TESTS.md section 12. A security property that is only written down is a
// claim; these are the same properties as assertions.
//
// Each test states what "contained" means for it and fails if the target got
// further, so a regression in the sandbox shows up as a failing test rather than
// as an incident.

// run executes the escape target under a sandbox and returns its output.
func run(t *testing.T, sb *Sandbox, timeout time.Duration, args ...string) executor.ProcResult {
	t.Helper()
	target := escapeTarget(t)

	sp := NewSpawner()
	sp.Sandbox = sb
	t.Cleanup(func() { sb.Close() })

	res, err := sp.Run(context.Background(), executor.ProcSpec{
		Path:          target,
		Args:          append([]string{target}, args...),
		CaptureOutput: true,
		Timeout:       timeout,
	})
	if err != nil {
		t.Fatalf("running the escape target: %v", err)
	}
	if res.ExitCode == 125 {
		t.Fatalf("the sandbox helper refused to start the target: %s", res.Stderr)
	}
	return res
}

func confined(t *testing.T, name string) *Sandbox {
	t.Helper()
	return &Sandbox{
		HelperPath: helperForTest(t),
		Name:       name + "-" + strconv.Itoa(os.Getpid()),
	}
}

func out(res executor.ProcResult) string {
	return strings.TrimSpace(string(res.Stdout) + string(res.Stderr))
}

// TestSecurityTargetIsDeprivileged is the precondition for most of the rest: a
// target that still holds the fuzzer's identity is not confined regardless of
// what else is applied.
func TestSecurityTargetIsDeprivileged(t *testing.T) {
	caps := platform.DetectSandbox()
	if !caps.UserNS {
		t.Skip("user namespaces are unavailable; deprivileging cannot be tested here")
	}
	sb := confined(t, "identity")
	res := run(t, sb, 10*time.Second, "identity")

	uid, _ := platform.UnprivilegedID()
	if !strings.Contains(out(res), fmt.Sprintf("uid=%d", uid)) {
		t.Fatalf("the target ran as %s, want uid=%d (isolation %s)", out(res), uid, sb.Level())
	}
	// Running as the kernel's overflow id would look identical in this output
	// and would leave every unmapped file — the corpus among them — appearing
	// to belong to the target.
	ouid, _ := platform.OverflowID()
	if uid == ouid {
		t.Fatalf("targets run as the overflow id %d, so every unmapped file looks like theirs", uid)
	}
}

// TestSecurityWriteOutsideWorkdir — "Write outside workdir: blocked by sandbox".
func TestSecurityWriteOutsideWorkdir(t *testing.T) {
	caps := platform.DetectSandbox()
	if !caps.UserNS {
		t.Skip("user namespaces are unavailable; the target cannot be deprivileged here")
	}

	// The half that holds on every host: a target must be able to write inside
	// the workdir it was given. Checked first and unconditionally, because if
	// this fails the containment assertion below would pass for the wrong
	// reason — a sandbox that blocks everything blocks the escape too.
	workdir := reachableDir(t)
	allowed := filepath.Join(workdir, "output")
	res := run(t, confinedIn(t, "write-inside", workdir), 10*time.Second, "write-outside", allowed)
	if !strings.Contains(out(res), "wrote") {
		t.Fatalf("the target could not write inside its own workdir: %s", out(res))
	}

	if os.Geteuid() != 0 {
		// The other half needs a separate identity, and namespaces are not what
		// supplies one. sandbox.dropTo returns nothing unless the fuzzer is
		// root, so an unprivileged fuzzer puts the target in a namespace where
		// it remains, on the host, the same user — with the same access to the
		// same corpus. A 0700 directory the fuzzer owns is therefore writable
		// by its own target, by design and as sandbox.go says in as many words.
		//
		// The guard used to be caps.UserNS alone, which is true for any user,
		// so this asserted containment that cannot hold for most of them. It
		// passed where it was written because that host runs as root, and
		// failed the first time CI got far enough to run it.
		//
		// ADR-0022 is the reason this skips rather than being deleted or
		// weakened: the isolation level is a property of how the fuzzer was
		// started, and the test states which level it is measuring instead of
		// reporting a pass that would mean nothing.
		t.Skip("the fuzzer is unprivileged: it cannot give the target a separate " +
			"identity, so a directory it owns is not protected from its own target " +
			"(ADR-0022); the in-workdir write above was still checked")
	}

	// A directory the fuzzer owns and the target must not be able to write to.
	// Owned by the caller and mode 0700, which is what a corpus directory is:
	// the failure this prevents is a runaway target corrupting the corpus, and
	// that is the shape it would take.
	protected := t.TempDir()
	if err := os.Chmod(protected, 0o700); err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(protected, "corpus-entry")

	sb := confined(t, "write-outside")
	sb.Workdir = reachableDir(t)

	res = run(t, sb, 10*time.Second, "write-outside", victim)
	if !strings.Contains(out(res), "blocked") {
		t.Fatalf("the target wrote outside its workdir: %s", out(res))
	}
	if _, err := os.Stat(victim); err == nil {
		t.Fatalf("%s exists; the target escaped", victim)
	}
}

// reachableDir returns a directory the target's identity can actually use.
//
// A directory tree created with default permissions is not reachable by another
// user, which is the same condition Sandbox.checkWorkdir refuses a campaign for.
// The test has to arrange what a real deployment has to arrange.
func reachableDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for p := dir; p != "/" && p != "."; p = filepath.Dir(p) {
		// Stop *before* chmodding, not after. The old loop tested for the
		// boundary at the end of the body, so it always chmodded os.TempDir()
		// itself — which is /tmp, owned by root and mode 1777, and on a CI
		// runner that is `chmod /tmp: operation not permitted` and a failed
		// security test that has nothing to do with security.
		if p == os.TempDir() {
			break
		}
		if err := os.Chmod(p, 0o777); err != nil {
			// Only fatal if the directory is not already traversable by others.
			// What this helper needs is a path the target's identity can walk,
			// not ownership of every component: a directory that is already
			// world-executable needs nothing done to it, and one somebody else
			// owns is not ours to change.
			fi, statErr := os.Stat(p)
			if statErr != nil || fi.Mode().Perm()&0o001 == 0 {
				t.Fatalf("%s is not traversable by the target's identity and cannot be made so: %v", p, err)
			}
		}
	}
	return dir
}

func confinedIn(t *testing.T, name, workdir string) *Sandbox {
	sb := confined(t, name)
	sb.Workdir = workdir
	return sb
}

// TestSecurityForkBomb — "Fork bomb: contained by PID limit".
func TestSecurityForkBomb(t *testing.T) {
	const limit = 64

	sb := confined(t, "forkbomb")
	sb.Limits = platform.Limits{Processes: limit}
	if platform.CgroupMode() == platform.CgroupNone && !platform.UserNamespacesAvailable() {
		t.Skip("neither a PID cgroup nor a user namespace is available to contain a fork bomb")
	}

	res := run(t, sb, 30*time.Second, "fork-bomb")
	got := out(res)
	if strings.Contains(got, "unbounded") {
		t.Fatalf("the fork bomb was never contained: %s (isolation %s)", got, sb.Level())
	}
	if !strings.Contains(got, "blocked") {
		t.Fatalf("the fork bomb produced no verdict: %s", got)
	}
	// Contained is not enough on its own: contained *near the configured limit*
	// is what says the limit is the thing that stopped it.
	if n := forksFrom(got); n > 8*limit {
		t.Errorf("the bomb made %d processes against a limit of %d; "+
			"something other than the limit stopped it", n, limit)
	}
	t.Logf("%s (isolation %s, cgroups %s)", got, sb.Level(), platform.UsableCgroupMode())
}

func forksFrom(s string) int {
	i := strings.Index(s, "forks=")
	if i < 0 {
		return -1
	}
	rest := s[i+len("forks="):]
	end := strings.IndexFunc(rest, func(r rune) bool { return r < '0' || r > '9' })
	if end < 0 {
		end = len(rest)
	}
	n, err := strconv.Atoi(rest[:end])
	if err != nil {
		return -1
	}
	return n
}

// TestSecurityMemoryExhaustion — "Memory exhaustion: contained by cgroup".
func TestSecurityMemoryExhaustion(t *testing.T) {
	if platform.UsableCgroupMode() == platform.CgroupNone {
		// Usable, not mounted. A delegated hierarchy is present and unwritable
		// on CI runners and inside containers, and the difference is the whole
		// finding: asking the mounted question let this test run against a
		// sandbox that had silently failed to apply the limit.
		t.Skip("no usable cgroup hierarchy: memory cannot be capped, so containment cannot be verified here")
	}
	const limitBytes = 128 << 20

	sb := confined(t, "memory")
	sb.Limits = platform.Limits{AddressSpaceBytes: limitBytes}

	// The target is asked to allocate far more than the limit. Either it is
	// refused, or the kernel kills it — both are containment; running to
	// completion is not.
	res := run(t, sb, 60*time.Second, "memory", "2048")
	got := out(res)
	if strings.Contains(got, "unbounded") {
		t.Fatalf("the target allocated 2 GiB against a %d MiB limit: %s (isolation %s, cgroups %s)",
			limitBytes>>20, got, sb.Level(), platform.UsableCgroupMode())
	}
	t.Logf("%s exit=%d signal=%d (cgroups %s)", got, res.ExitCode, res.Signal, platform.UsableCgroupMode())
}

// TestSecurityPrivilegedSyscallIsDenied — the seccomp denylist, which is the
// layer that covers what a user namespace does not.
func TestSecurityPrivilegedSyscallIsDenied(t *testing.T) {
	if !platform.SeccompAvailable() {
		t.Skip("seccomp is unavailable")
	}
	sb := confined(t, "seccomp")
	res := run(t, sb, 10*time.Second, "privileged-syscall")
	got := out(res)
	if strings.Contains(got, "mounted") {
		t.Fatalf("mount(2) succeeded inside the sandbox: %s", got)
	}
	if !strings.Contains(got, "blocked") {
		t.Fatalf("no verdict from the privileged syscall: %s", got)
	}
	// EPERM is what the filter returns. A different errno means something else
	// refused it, which is not a failure but is worth seeing in the log.
	t.Logf("%s (isolation %s)", got, sb.Level())
}

// TestSecuritySeccompFilterShape checks the program itself, which is the part a
// mistake would make silently permissive.
func TestSecuritySeccompFilterShape(t *testing.T) {
	prog, err := platform.BuildSeccompFilter(platform.DefaultSeccompNumbers(), 1)
	if err != nil {
		t.Skipf("seccomp filters cannot be built here: %v", err)
	}
	if len(prog) < len(platform.DefaultSeccompNumbers())+4 {
		t.Fatalf("the filter has %d instructions for %d denied calls; it cannot be checking them all",
			len(prog), len(platform.DefaultSeccompNumbers()))
	}
	// The first instruction must load the architecture. A filter that compares
	// syscall numbers without pinning the ABI denies one call and permits
	// another on any kernel with a second ABI.
	if prog[0].K != 4 {
		t.Fatalf("the filter does not begin by loading the architecture: first load is at offset %d", prog[0].K)
	}
}

// TestSecurityUnlistedHostIsRefused — "Connection to unlisted host: blocked by
// scope guard, audited".
func TestSecurityUnlistedHostIsRefused(t *testing.T) {
	a := &recordingAuditor{}
	s := NewScope()
	s.Auditor = a
	s.MustAllow("10.0.0.0/8", PortRange{80, 80})

	if _, err := s.Dial(context.Background(), "tcp", "172.16.0.1:80"); err == nil {
		t.Fatal("a connection to an unlisted host was permitted")
	}
	if a.count(AuditScopeDeny) != 1 {
		t.Fatalf("the refusal was not audited: %v", a.entries)
	}
}

// TestSecurityCampaignWithoutScopeRefusesToStart — "Campaign without scope
// allowlist: refuses to start".
func TestSecurityCampaignWithoutScopeRefusesToStart(t *testing.T) {
	err := Authorize(context.Background(), &recordingAuditor{}, NewScope(), goodAuth(), true)
	if err == nil {
		t.Fatal("a remote campaign with no allowlist started")
	}
	if !strings.Contains(err.Error(), "scope allowlist") {
		t.Fatalf("the refusal does not say what is missing: %v", err)
	}
}

// TestSecuritySandboxIsOnByDefault is the property the whole design rests on:
// the zero configuration confines. Opt-in safety is not safety, because the
// default is what people run.
func TestSecuritySandboxIsOnByDefault(t *testing.T) {
	sp := NewSpawner()
	if sp.Sandbox != nil {
		t.Fatal("NewSpawner should not need a configured sandbox to confine")
	}
	level := sp.IsolationLevel()
	if level == LevelNone.String() {
		t.Fatalf("the default spawner reports %q:\n%s", level, sp.Explain())
	}
	sb := &Sandbox{}
	sb.Probe()
	caps := platform.DetectSandbox()
	if caps.NetNS && !sb.namespaces(true).NetNS {
		t.Fatal("the default policy leaves a target in the host network namespace")
	}
}

// TestSecurityWorkdirIsCheckedBeforeTheCampaignStarts — a target given an
// identity it cannot use fails on every execution for a reason that looks
// nothing like the cause. Catching it at start is the difference between one
// clear sentence and an afternoon.
func TestSecurityWorkdirIsCheckedBeforeTheCampaignStarts(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("Xfuzz is not root here, so the target keeps the caller's identity")
	}
	unreachable := t.TempDir() // created 0700 and owned by the caller
	sb := confined(t, "workdir")
	sb.Workdir = unreachable

	err := sb.Check(context.Background())
	if err == nil {
		t.Fatal("a workdir the target cannot enter was accepted")
	}
	if !errors.Is(err, ErrWorkdirUnreachable) {
		t.Fatalf("err = %v, want ErrWorkdirUnreachable", err)
	}
	if !strings.Contains(err.Error(), unreachable) && !strings.Contains(err.Error(), filepath.Dir(unreachable)) {
		t.Fatalf("the error does not name the directory that blocks it: %v", err)
	}

	sb2 := confined(t, "workdir-ok")
	sb2.Workdir = reachableDir(t)
	if err := sb2.Check(context.Background()); err != nil {
		t.Fatalf("a reachable workdir was refused: %v", err)
	}
}

// TestSecurityAuditTamperIsDetected — "Audit log modified: tamper detected by
// hash chain".
//
// The chain itself is implemented and tested in internal/store, where the log
// lives. What is asserted here is the property the safety layer depends on: a
// decision this layer records cannot be quietly removed afterwards. The
// auditor is an interface, so a campaign could be given one that forgets — which
// is exactly why the daemon supplies the store's, and why that one is chained.
func TestSecurityAuditTamperIsDetected(t *testing.T) {
	a := &recordingAuditor{}
	s := NewScope()
	s.Auditor = a
	s.MustAllow("10.0.0.0/8")

	_ = s.Check(context.Background(), addr("172.16.0.1:80"))
	if a.count(AuditScopeDeny) != 1 {
		t.Fatal("the refusal was not offered to the auditor")
	}
	// The safety layer must not be able to decide not to audit: the only way a
	// decision goes unrecorded is if no auditor was configured at all, which is
	// the daemon's responsibility and is itself a campaign-level refusal.
	if s.Auditor == nil {
		t.Fatal("the scope guard cleared its own auditor")
	}
}
