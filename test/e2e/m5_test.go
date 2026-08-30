//go:build integration

// M5's exit criteria, measured against the binaries that ship rather than
// against the packages behind them.
//
// The criteria are about the system: how a campaign scales across worker
// processes, and what survives losing the daemon. Neither can be answered from
// inside one package, and answering them in-process would skip exactly the
// parts — process launch, the descriptor protocol, the store on disk — that the
// criteria are about.
//
// Behind the integration tag because everything here compiles a target and runs
// real processes.

package e2e

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/rom/Xfuzz/internal/testenv"
)

// env is a built tree of Xfuzz binaries and a data directory to run against.
type env struct {
	t       *testing.T
	binDir  string
	dataDir string
	target  string
}

func newEnv(t *testing.T) *env { return newEnvFor(t, "simple_parser") }

// newEnvFor builds the binaries, a data directory, and one planted-bug target.
func newEnvFor(t *testing.T, target string) *env {
	t.Helper()
	// One reachable directory for everything: the binaries are found through
	// PATH, and the target has to be enterable by the unprivileged identity the
	// sandbox gives it.
	bin := testenv.ReachableDir(t)
	for _, cmd := range []string{"xfuzz", "xfuzzd", "xfuzz-worker", "xfuzz-sandbox"} {
		testenv.BuildBinary(t, bin, cmd)
	}
	e := &env{
		t:       t,
		binDir:  bin,
		dataDir: testenv.ReachableDir(t),
		target:  testenv.BuildTarget(t, target),
	}
	// Registered so that the daemon goes first: cleanups run last-registered
	// first, and reaping targets while the daemon still supervises workers only
	// gives the workers something to restart.
	t.Cleanup(e.reapTargets)
	t.Cleanup(e.stopDaemon)
	return e
}

// reapTargets kills anything still running this test's target binary.
//
// A test that leaves processes behind poisons the one after it. On the session
// tier that is not hypothetical: a managed server outlives its worker (see the
// changelog's known issues), and the next test's campaign then spends its
// budget on a host busy with the last one's targets — measured as a
// forty-five-second campaign reaching its time budget having executed nothing.
//
// By the target's own path, so this reaps what this test started and nothing
// else: each test builds its target into a directory of its own.
func (e *env) reapTargets() {
	if runtime.GOOS == "windows" {
		return
	}
	out, err := exec.Command("ps", "-eo", "pid,args").Output()
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(out), "\n") {
		if !strings.Contains(line, e.target) {
			continue
		}
		var pid int
		if _, err := fmt.Sscan(strings.TrimSpace(line), &pid); err != nil || pid <= 0 {
			continue
		}
		_ = kill(pid)
	}
}

// xfuzz runs a client command and returns its combined output.
func (e *env) xfuzz(timeout time.Duration, args ...string) (string, error) {
	e.t.Helper()
	cmd := exec.Command(filepath.Join(e.binDir, "xfuzz"), args...)
	cmd.Env = append(os.Environ(),
		"PATH="+e.binDir+string(os.PathListSeparator)+os.Getenv("PATH"),
		"XFUZZ_DATA_DIR="+e.dataDir)
	cmd.Dir = e.dataDir

	done := make(chan struct{})
	timer := time.AfterFunc(timeout, func() {
		if cmd.Process != nil {
			cmd.Process.Kill()
		}
		close(done)
	})
	out, err := cmd.CombinedOutput()
	if !timer.Stop() {
		<-done
		return string(out), fmt.Errorf("xfuzz %s did not finish within %s", args[0], timeout)
	}
	return string(out), err
}

// mustRun fails the test if the command does not succeed.
func (e *env) mustRun(timeout time.Duration, args ...string) string {
	e.t.Helper()
	out, err := e.xfuzz(timeout, args...)
	if err != nil {
		e.t.Fatalf("xfuzz %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return out
}

// status returns one campaign's status as the API reports it.
func (e *env) status(name string) campaignStatus {
	e.t.Helper()
	out := e.mustRun(30*time.Second, "status", name, "--json")
	var s campaignStatus
	if err := json.Unmarshal([]byte(out), &s); err != nil {
		e.t.Fatalf("decoding status: %v\n%s", err, out)
	}
	return s
}

// campaignStatus is the part of the status document these criteria need.
type campaignStatus struct {
	Name    string `json:"name"`
	State   string `json:"state"`
	Seed    uint64 `json:"seed,string"`
	Metrics struct {
		Execs       uint64  `json:"execs"`
		ExecsPerS   float64 `json:"execs_per_second"`
		Coverage    int     `json:"coverage"`
		CorpusSize  int     `json:"corpus_size"`
		Findings    int     `json:"findings"`
		Buckets     int     `json:"buckets"`
		States      int     `json:"states"`
		Transitions int     `json:"transitions"`
	} `json:"metrics"`
}

// info is the part of the daemon report these criteria need.
type info struct {
	Daemon struct {
		Pid       int    `json:"pid"`
		Campaigns int    `json:"campaigns"`
		DataDir   string `json:"data_dir"`
	} `json:"daemon"`
}

// daemonPid reads the pid of the daemon serving this data directory.
func (e *env) daemonPid() int {
	e.t.Helper()
	out := e.mustRun(30*time.Second, "info", "--json")
	var got info
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		e.t.Fatalf("decoding the daemon report: %v\n%s", err, out)
	}
	if got.Daemon.Pid == 0 {
		e.t.Fatalf("the daemon reported no pid:\n%s", out)
	}
	return got.Daemon.Pid
}

// stopDaemon kills whatever daemon is serving this environment.
func (e *env) stopDaemon() {
	out, err := e.xfuzz(15*time.Second, "info", "--json")
	if err != nil {
		return
	}
	var got info
	if json.Unmarshal([]byte(out), &got) != nil || got.Daemon.Pid == 0 {
		return
	}
	kill(got.Daemon.Pid)
	os.Remove(filepath.Join(e.dataDir, "xfuzzd.sock"))
}

// writeCampaign writes a campaign file and returns its path.
func (e *env) writeCampaign(name string, workers int, after time.Duration, extra string) string {
	e.t.Helper()
	body := fmt.Sprintf(`
name: %s
target:
  path: %s
  input: stdin
  timeout: 2s
seeds:
  inline: ["Z", "Axx", "B", "CCCC"]
feedback:
  coverage: sancov
workers:
  count: %d
  sync_interval: 2s
stop:
  after: %s
%s`, name, e.target, workers, after, extra)
	path := filepath.Join(e.dataDir, name+".yaml")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		e.t.Fatal(err)
	}
	return path
}

// M5's scaling criterion: a campaign on N workers does at least 0.85 × N times
// the work of the same campaign on one.
//
// Measured as executions completed in a fixed wall-clock window rather than as
// a reported rate, because the reported rate is the thing under test: if the
// campaign aggregates its workers' counters wrongly, a rate check passes on a
// campaign that is doing nothing of the sort. Executions in a window is the
// number a user would count by hand.
func TestMultiWorkerCampaignsScale(t *testing.T) {
	// At most half the cores go to workers. The daemon, the client and the test
	// itself all run on this machine, and a measurement that put a worker on
	// every core would be measuring the scheduler dividing the last one between
	// the fuzzer and the thing timing it.
	workers := min(4, runtime.NumCPU()/2)
	if workers < 2 {
		t.Skipf("scaling needs at least four cores; this host has %d", runtime.NumCPU())
	}
	e := newEnv(t)

	// Best of two runs each, interleaved. Throughput is bounded above by the
	// machine and dragged below it by whatever else the machine is doing, so
	// repeated trials scatter downwards from a ceiling and the maximum is the
	// least noisy estimate of where that ceiling is. Interleaving keeps a burst
	// of unrelated load from landing entirely on one of the two configurations.
	const window = 20 * time.Second
	var one, many uint64
	for trial := 1; trial <= 2; trial++ {
		one = max(one, e.runFor(fmt.Sprintf("scale-1-%d", trial), 1, window))
		many = max(many, e.runFor(fmt.Sprintf("scale-n-%d", trial), workers, window))
	}

	if one == 0 {
		t.Fatal("the single-worker campaign completed no executions")
	}
	speedup := float64(many) / float64(one)
	efficiency := speedup / float64(workers)
	t.Logf("1 worker: %d execs; %d workers: %d execs; speedup %.2fx (%.0f%% efficiency)",
		one, workers, many, speedup, 100*efficiency)

	if speedup < 0.85*float64(workers) {
		t.Errorf("%d workers gave a %.2fx speedup, below the 0.85 x N = %.2fx criterion "+
			"(%d execs against %d in %s)",
			workers, speedup, 0.85*float64(workers), many, one, window)
	}
}

// runFor runs a campaign for a fixed window and returns the executions it
// completed.
func (e *env) runFor(name string, workers int, window time.Duration) uint64 {
	e.t.Helper()
	// A store of its own for each measurement. Sharing one would let the first
	// campaign hand the second a corpus it did not have to find, and the second
	// would look faster for a reason that has nothing to do with workers.
	store := testenv.ReachableDir(e.t)
	path := e.writeCampaign(name, workers, window, "storage:\n  dir: "+store+"\n")

	// Detached, and polled rather than followed. A client following the event
	// stream prints a line several times a second, and on a host with as many
	// cores as this has workers that is the measurement competing with itself.
	e.mustRun(60*time.Second, "run", path, "--detach")
	s := e.waitFor(name, window+90*time.Second,
		func(s campaignStatus) bool { return s.State == "finished" },
		"the campaign did not finish within its own budget")
	return s.Metrics.Execs
}

// M5's explain criterion: the client renders the configuration a campaign will
// actually run, defaults included.
//
// The point is reviewability (ADR-0016). A campaign file states a fraction of
// what a run is; the rest comes from defaults, profiles and includes, and a
// reviewer who cannot see the rest is reviewing the fraction. So this checks
// that settings the file never mentions are shown, that they are marked as
// defaults, and that the rendered file is one the daemon accepts — which is
// what makes it usable as the artefact a run is pinned to.
func TestExplainRendersTheFullyResolvedConfiguration(t *testing.T) {
	e := newEnv(t)
	path := e.writeCampaign("explained", 2, time.Minute, "")

	text := e.mustRun(60*time.Second, "explain", path)
	for _, want := range []string{
		"target.path",       // stated in the file
		"workers.count",     // stated in the file
		"feedback.map_size", // never mentioned in it
		"triage.trials",     // never mentioned in it
		"safety.isolation",  // never mentioned in it, and the one that matters most
		"(default)",         // and the defaults say so
	} {
		if !strings.Contains(text, want) {
			t.Errorf("the resolved configuration does not mention %s:\n%s", want, text)
		}
	}

	// The YAML form is the same configuration as a file, so it has to be one
	// the daemon will accept.
	asYAML := e.mustRun(60*time.Second, "explain", path, "--yaml")
	round := filepath.Join(e.dataDir, "round-trip.yaml")
	if err := os.WriteFile(round, []byte(asYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	if out, err := e.xfuzz(60*time.Second, "validate", round); err != nil {
		t.Fatalf("the rendered configuration does not validate: %v\n%s\n---\n%s", err, out, asYAML)
	}
}

// A campaign file names its target relative to itself, and the client is not
// the process that runs it.
//
// Three working directories are in play — the user's shell, the daemon's, and
// each worker's — and only the first knows what "./target" in a file invoked as
// "xfuzz run campaign.yaml" was supposed to mean. Getting this wrong does not
// produce an error: the campaign starts, reports two live workers, and
// completes no executions, because every worker died looking for a file in a
// directory nobody named. So it is checked with the relative forms a person
// actually types, from a directory that is not the daemon's.
func TestRelativePathsResolveAgainstTheCampaignFile(t *testing.T) {
	e := newEnv(t)

	// A directory of its own, holding the campaign and the target beside it,
	// and referring to both the way a person would.
	dir := testenv.ReachableDir(t)
	target := filepath.Join(dir, "target")
	if err := copyFile(e.target, target); err != nil {
		t.Fatal(err)
	}
	body := `
name: relative
target:
  path: ./target
  input: stdin
  timeout: 2s
seeds:
  inline: ["Z", "Axx"]
workers:
  count: 1
stop:
  after: 8s
`
	if err := os.WriteFile(filepath.Join(dir, "campaign.yaml"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	// Run it by its bare name, from its own directory. The daemon's working
	// directory is elsewhere, which is the whole point.
	cmd := exec.Command(filepath.Join(e.binDir, "xfuzz"), "run", "campaign.yaml")
	cmd.Env = append(os.Environ(),
		"PATH="+e.binDir+string(os.PathListSeparator)+os.Getenv("PATH"),
		"XFUZZ_DATA_DIR="+e.dataDir)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("xfuzz run campaign.yaml: %v\n%s", err, out)
	}

	s := e.status("relative")
	t.Logf("%d execs, %d edges", s.Metrics.Execs, s.Metrics.Coverage)
	if s.Metrics.Execs == 0 {
		t.Fatalf("the campaign completed no executions, which is what a target "+
			"resolved against the wrong directory looks like:\n%s", out)
	}
}

// copyFile duplicates an executable.
func copyFile(from, to string) error {
	b, err := os.ReadFile(from)
	if err != nil {
		return err
	}
	return os.WriteFile(to, b, 0o755)
}

// M5's resume criterion: losing the daemon outright does not lose the campaign.
//
// SIGKILL rather than a stop: a daemon that is asked politely gets to flush,
// and flushing is not what the criterion is about. What has to survive is
// whatever reached the store before the process disappeared — which is what a
// power cut leaves behind too.
func TestKillingTheDaemonMidCampaignResumesCleanly(t *testing.T) {
	e := newEnv(t)
	path := e.writeCampaign("resume", 2, 30*time.Second, "storage:\n  checkpoint_interval: 2s\n")

	e.mustRun(60*time.Second, "run", path, "--detach")

	// Wait until the campaign has learned something worth losing.
	before := e.waitFor("resume", 60*time.Second, func(s campaignStatus) bool {
		return s.Metrics.CorpusSize > 4 && s.Metrics.Coverage > 0
	}, "the campaign never grew its corpus beyond its seeds")
	t.Logf("before the kill: %d execs, %d edges, %d corpus entries",
		before.Metrics.Execs, before.Metrics.Coverage, before.Metrics.CorpusSize)

	pid := e.daemonPid()
	if err := kill(pid); err != nil {
		t.Fatalf("killing daemon %d: %v", pid, err)
	}

	// The socket file outlives the process it belonged to, so a client will
	// find it and fail to connect through it. Recovering from that is the
	// criterion, and the proof is a daemon with a different pid answering on
	// the same data directory.
	deadline := time.Now().Add(30 * time.Second)
	revived := pid
	for time.Now().Before(deadline) && revived == pid {
		time.Sleep(500 * time.Millisecond)
		revived = e.daemonPid()
	}
	if revived == 0 || revived == pid {
		t.Fatalf("no new daemon took over from the killed one (pid %d)", pid)
	}
	t.Logf("daemon %d was killed; %d took over", pid, revived)

	// A fresh client on the same data directory is what a user retyping the
	// command gets.
	after := e.mustRun(120*time.Second, "run", path)
	if strings.Contains(after, "no such file") || strings.Contains(after, "nothing to fuzz") {
		t.Fatalf("the resumed campaign could not find what the first one stored:\n%s", after)
	}

	final := e.status("resume")
	t.Logf("after the resume: %d execs, %d edges, %d corpus entries, %d finding(s)",
		final.Metrics.Execs, final.Metrics.Coverage, final.Metrics.CorpusSize, final.Metrics.Findings)

	// The corpus is the thing a campaign spends its time earning, and it is
	// what a resume is for. It must not start from the seeds again.
	if final.Metrics.CorpusSize < before.Metrics.CorpusSize {
		t.Errorf("the resumed campaign has %d corpus entries, fewer than the %d stored before the kill",
			final.Metrics.CorpusSize, before.Metrics.CorpusSize)
	}
	if final.Metrics.Coverage < before.Metrics.Coverage {
		t.Errorf("the resumed campaign reached %d edges, fewer than the %d before the kill",
			final.Metrics.Coverage, before.Metrics.Coverage)
	}
	if final.State != "finished" {
		t.Errorf("the resumed campaign ended in state %q, not finished", final.State)
	}

	// And nothing was left running. A daemon that dies without reaping its
	// workers leaves processes fuzzing a campaign nobody is watching, which is
	// worse than losing the campaign.
	if n := strayWorkers(t, e.dataDir); n > 0 {
		t.Errorf("%d worker process(es) survived the daemon that started them", n)
	}
}

// waitFor polls a campaign's status until a condition holds.
func (e *env) waitFor(name string, limit time.Duration, cond func(campaignStatus) bool, msg string) campaignStatus {
	e.t.Helper()
	deadline := time.Now().Add(limit)
	var last campaignStatus
	for time.Now().Before(deadline) {
		last = e.status(name)
		if cond(last) {
			return last
		}
		time.Sleep(500 * time.Millisecond)
	}
	e.t.Fatalf("%s (last status: %+v)", msg, last)
	return last
}

// kill ends a process outright.
func kill(pid int) error {
	p, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	return p.Kill()
}

// strayWorkers counts worker processes still running against a data directory.
func strayWorkers(t *testing.T, dataDir string) int {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("counting stray processes here needs ps(1)")
	}
	out, err := exec.Command("ps", "-eo", "args").Output()
	if err != nil {
		t.Skipf("ps is not usable here, so stray workers cannot be counted: %v", err)
	}
	n := 0
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, "xfuzz-worker") && strings.Contains(line, dataDir) {
			t.Logf("stray: %s", line)
			n++
		}
	}
	return n
}
