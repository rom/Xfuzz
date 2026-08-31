//go:build integration

// The cross-platform criterion: a subprocess campaign, end to end, on every
// platform Xfuzz supports.
//
// Linux gets the fast paths — a fork server, sancov coverage through shared
// memory, namespaces. macOS and Windows get T3/T4 and black-box feedback
// (ADR-0020), and this file is what makes that a measured claim rather than a
// hope. Every other end-to-end test here compiles a C target through xfuzz-cc
// and skips without clang, which on a Windows runner is every time; the target
// here is Go, so the only toolchain it needs is the one already running the
// test.
//
// Black-box on purpose, and not only for portability. Shared memory is a Unix
// mechanism, so a Windows campaign has no coverage map at all: what it has is
// the exit status and what the target said. ASR-0003 requires that to be a
// supported mode rather than a failure state, and the only way to know it is is
// to run one.

package e2e

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/rom/Xfuzz/internal/testenv"
)

// newPortableEnv builds the binaries and a Go planted-bug target.
func newPortableEnv(t *testing.T) *env {
	t.Helper()
	bin := testenv.ReachableDir(t)
	for _, cmd := range portableCommands() {
		testenv.BuildBinary(t, bin, cmd)
	}
	e := &env{
		t:       t,
		binDir:  bin,
		dataDir: testenv.ReachableDir(t),
		target: testenv.BuildAt(t,
			filepath.Join(bin, testenv.ExeName("portable")),
			"./testdata/targets/go/portable"),
	}
	t.Cleanup(e.reapTargets)
	t.Cleanup(e.stopDaemon)
	return e
}

// portableCommands is the binary set a black-box campaign needs.
//
// Not xfuzz-sandbox: it is the Linux confinement helper (ADR-0022), and a
// platform with no namespaces to enter has nothing for it to do. Requiring it
// everywhere would make the criterion depend on a component the criterion is
// explicitly not about.
func portableCommands() []string {
	cmds := []string{"xfuzz", "xfuzzd", "xfuzz-worker"}
	if runtime.GOOS == "linux" {
		cmds = append(cmds, "xfuzz-sandbox")
	}
	return cmds
}

// writeBlackBoxCampaign writes a campaign with no coverage and no isolation,
// which is what every platform can provide.
func writeBlackBoxCampaign(t *testing.T, e *env, name string, after time.Duration) string {
	t.Helper()
	body := fmt.Sprintf(`
name: %s
target:
  path: %s
  input: stdin
  # auto, so the test exercises the tier a user actually gets. With no
  # coverage map to pollute, that is the pool.
  timeout: 5s
seeds:
  inline: ["A", "AB", "B", "BC", "C", "hello"]
feedback:
  coverage: none
  novelty: true
  objectives: [crash, hang, oom, sanitizer]
safety:
  isolation: none
workers:
  count: 1
storage:
  checkpoint_interval: 5s
stop:
  after: %s
`, name, filepath.ToSlash(e.target), after)

	path := filepath.Join(e.dataDir, name+".yaml")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// A whole campaign against a real target, with no coverage instrumentation and
// no isolation: the path macOS and Windows take.
func TestASubprocessCampaignRunsEndToEndOnEveryPlatform(t *testing.T) {
	e := newPortableEnv(t)
	path := writeBlackBoxCampaign(t, e, "portable", 60*time.Second)

	out, err := e.xfuzz(240*time.Second, "run", path)
	if err != nil {
		t.Fatalf("running a black-box campaign on %s/%s: %v\n%s",
			runtime.GOOS, runtime.GOARCH, err, out)
	}

	final := e.status("portable")
	t.Logf("%s/%s: %d execs (%.0f/s), %d corpus entries, %d finding(s) in %d bucket(s), state %s",
		runtime.GOOS, runtime.GOARCH, final.Metrics.Execs, final.Metrics.ExecsPerS,
		final.Metrics.CorpusSize, final.Metrics.Findings, final.Metrics.Buckets, final.State)

	if final.State != "finished" {
		t.Fatalf("the campaign ended in state %q, not finished:\n%s", final.State, out)
	}

	// The criterion says "a subprocess campaign", meaning one that gives every
	// input its own process, and the tier that does that on a platform without
	// a fork server is the pool (ADR-0009's T3). Asserting which one ran is
	// what stops this quietly measuring a fallback.
	if tier := executorOf(t, e, "portable"); tier != "pool" {
		t.Errorf("the campaign ran on the %q tier; with no coverage configured, "+
			"auto should have chosen the pool", tier)
	}

	if final.Metrics.Execs < 500 {
		t.Errorf("only %d executions in a minute; the subprocess tier is not delivering inputs",
			final.Metrics.Execs)
	}

	// Novelty is the black-box substitute for coverage, and a campaign that
	// keeps nothing is a campaign that learns nothing. The seeds are six, so
	// anything above that is the feedback working.
	if final.Metrics.CorpusSize <= 6 {
		t.Errorf("the corpus is %d entries against 6 seeds; novelty feedback admitted nothing",
			final.Metrics.CorpusSize)
	}

	// And the point of all of it: the planted bugs are found. Both are Go
	// panics, which carry no fatal signal — they are exit status 2 and a line
	// on standard error — so this also checks that a target which fails the way
	// a managed language fails is not invisible to a black-box campaign.
	if final.Metrics.Findings == 0 {
		t.Fatalf("nothing was found in a target with two planted bugs, both reachable "+
			"from the seeds by a byte or two:\n%s", out)
	}

	kinds := findingKinds(t, e, "portable")
	t.Logf("finding kinds: %v", kinds)
	if kinds["panic"] == 0 && kinds["crash"] == 0 && kinds["sanitizer"] == 0 {
		t.Errorf("findings were reported but none is a crash or a runtime fault: %v", kinds)
	}

	// Two planted bugs, two buckets. This is the ASR-0011 claim, and on this
	// path it is not free: a Go panic carries no sanitizer frames, so before
	// the traceback parser understood one, bucketing fell through to the
	// message — and "slice bounds out of range [:255] with capacity 8" carries
	// the values, so every crash was its own bug. Measured then: 78 buckets.
	if final.Metrics.Buckets > 4 {
		t.Errorf("%d buckets for two planted bugs; crashes at the same place are "+
			"not being recognised as the same bug", final.Metrics.Buckets)
	}
}

// The same campaign, resumed: a store written on this platform must be
// readable by the next run on it.
//
// Resume is where the platform differences bite — file locking, path handling,
// and whether a process that died released what it held — and none of that is
// exercised by a campaign that only ever runs once.
func TestABlackBoxCampaignResumesOnEveryPlatform(t *testing.T) {
	e := newPortableEnv(t)
	path := writeBlackBoxCampaign(t, e, "portable-resume", 20*time.Second)

	if out, err := e.xfuzz(180*time.Second, "run", path); err != nil {
		t.Fatalf("the first run failed: %v\n%s", err, out)
	}
	first := e.status("portable-resume")
	t.Logf("first run: %d execs, %d corpus entries", first.Metrics.Execs, first.Metrics.CorpusSize)
	if first.Metrics.CorpusSize == 0 {
		t.Fatal("the first run stored nothing, so there is nothing for a resume to keep")
	}

	// The daemon holds a finished campaign in memory, so a second run against
	// the same one is refused. Stopping it first is what makes this a resume
	// rather than a re-run: everything the second campaign knows has to come
	// off the disk, which is the part that differs between platforms.
	e.stopDaemon()

	if out, err := e.xfuzz(180*time.Second, "run", path); err != nil {
		t.Fatalf("the second run failed: %v\n%s", err, out)
	}
	second := e.status("portable-resume")
	t.Logf("after the resume: %d execs, %d corpus entries", second.Metrics.Execs, second.Metrics.CorpusSize)

	if second.Metrics.CorpusSize < first.Metrics.CorpusSize {
		t.Errorf("the corpus shrank from %d to %d across a resume on %s; "+
			"the store written by the first run was not fully readable by the second",
			first.Metrics.CorpusSize, second.Metrics.CorpusSize, runtime.GOOS)
	}
	if second.State != "finished" {
		t.Errorf("the resumed campaign ended in state %q, not finished", second.State)
	}
}

// What `xfuzz doctor` says about this host must match what the host can
// actually do, on every platform.
//
// A diagnostic that is right only on Linux is worse than none: somebody on
// Windows reads "isolation: strong" and believes it.
func TestDoctorTellsTheTruthAboutThisPlatform(t *testing.T) {
	e := newPortableEnv(t)
	out := e.mustRun(60*time.Second, "doctor", "--json")

	var report struct {
		Platform     string `json:"platform"`
		Isolation    string `json:"isolation"`
		Capabilities []struct {
			Name      string `json:"name"`
			Available bool   `json:"available"`
			Detail    string `json:"detail"`
		} `json:"capabilities"`
	}
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatalf("decoding the doctor report: %v\n%s", err, out)
	}
	if !strings.Contains(report.Platform, runtime.GOOS) {
		t.Errorf("doctor reports platform %q on %s", report.Platform, runtime.GOOS)
	}
	if len(report.Capabilities) == 0 {
		t.Fatalf("doctor reported no capabilities:\n%s", out)
	}

	have := map[string]bool{}
	named := map[string]bool{}
	for _, c := range report.Capabilities {
		have[c.Name] = c.Available
		named[c.Name] = true
		t.Logf("%-20s %-5t %s", c.Name, c.Available, c.Detail)
		if c.Detail == "" {
			t.Errorf("capability %q says nothing about what it is for", c.Name)
		}
	}

	// The claims that must not be made where they are not true. Somebody on
	// Windows who reads "isolation: strong" believes it, and a diagnostic that
	// is only right on Linux is worse than none at all.
	if runtime.GOOS != "linux" {
		for _, mechanism := range []string{
			"user-namespace", "mount-namespace", "pid-namespace",
			"network-namespace", "seccomp", "cgroups",
		} {
			if have[mechanism] {
				t.Errorf("doctor claims %s on %s, where it does not exist", mechanism, runtime.GOOS)
			}
		}
		if report.Isolation == "strong" {
			t.Errorf("doctor reports strong isolation on %s", runtime.GOOS)
		}
	}
	// And the other half of the same duty: the report must name what the host
	// *has*, not only decline to claim what it has not. Windows confines with a
	// job object, which does a cgroup's work and is not one, so it appears under
	// its own name (ADR-0033) — and an operator who finds neither name there has
	// been told nothing about whether a target's children are contained.
	if runtime.GOOS == "windows" && !named["job-object"] {
		t.Error("doctor names no job object on Windows, so it says nothing about " +
			"the mechanism that actually contains a target there")
	}
	if runtime.GOOS == "windows" && have["shared-memory"] {
		t.Error("doctor claims shared memory on Windows, where the campaign " +
			"that relied on it would fail at startup")
	}
}
