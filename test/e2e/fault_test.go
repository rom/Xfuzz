//go:build integration

// The system's half of the fault-injection suite (docs/TESTS.md section 9).
//
// Nine faults are required; four of them are the store's and are injected at a
// byte, so they live in internal/store/fault_test.go where the fault can be
// made precisely. Two more are already proven where the behaviour lives: a
// dying plugin in internal/worker (a campaign fails cleanly, naming it) and a
// killed daemon in m5_test.go (a resume loses at most the checkpoint window).
//
// What is left is the three that are only true of the whole running system: a
// worker that dies under a supervisor, a target that will not stop, and a
// target that tries to take the machine with it. Each is injected against the
// binaries that ship.
//
//	Injected fault                  Required behaviour                       Where
//	------------------------------  ---------------------------------------  -----
//	Worker killed mid-execution     restarted; corpus stays consistent       here
//	Daemon killed mid-campaign      resume loses at most the checkpoint      m5_test.go
//	Plugin process dies             campaign fails cleanly, clear error      internal/worker
//	Disk full during corpus write   degrades, reported, no corruption        internal/store
//	Corrupted blob                  detected, quarantined, campaign runs on  internal/store
//	Corrupted database              detected on open, explicit error         internal/store
//	Target hangs indefinitely       timeout enforced, recorded as a hang     here
//	Target fork-bombs               PID limit holds; campaign continues      here
//	Store opened by a newer version explicit version error                   internal/store

package e2e

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

// workerPids returns the worker processes running against a data directory.
func workerPids(t *testing.T, dataDir string) []int {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("finding worker processes here needs ps(1)")
	}
	out, err := exec.Command("ps", "-eo", "pid,args").Output()
	if err != nil {
		t.Skipf("ps is not usable here: %v", err)
	}
	var pids []int
	for _, line := range strings.Split(string(out), "\n") {
		if !strings.Contains(line, "xfuzz-worker") || !strings.Contains(line, dataDir) {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if pid, err := strconv.Atoi(fields[0]); err == nil {
			pids = append(pids, pid)
		}
	}
	return pids
}

// A worker killed mid-execution is restarted, and the corpus it had earned is
// still there afterwards.
//
// Restart is routine rather than exceptional (ADR-0015): running targets in
// separate processes is *for* this, and a worker that dies because its target
// corrupted memory has done its job. What must not happen is the campaign
// losing what that worker found, or the supervisor giving up on it.
func TestFaultAKilledWorkerIsRestartedAndTheCampaignKeepsItsCorpus(t *testing.T) {
	e := newEnv(t)
	path := e.writeCampaign("workerkill", 2, 60*time.Second, "storage:\n  checkpoint_interval: 2s\n")
	e.mustRun(60*time.Second, "run", path, "--detach")

	before := e.waitFor("workerkill", 90*time.Second, func(s campaignStatus) bool {
		return s.Metrics.CorpusSize > 4 && s.Metrics.Coverage > 0
	}, "the campaign never grew its corpus beyond its seeds")
	t.Logf("before the kill: %d execs, %d edges, %d corpus entries",
		before.Metrics.Execs, before.Metrics.Coverage, before.Metrics.CorpusSize)

	pids := workerPids(t, e.dataDir)
	if len(pids) == 0 {
		t.Fatal("no worker processes are running, so none can be killed")
	}
	victim := pids[0]
	if err := kill(victim); err != nil {
		t.Fatalf("killing worker %d: %v", victim, err)
	}
	t.Logf("killed worker %d of %v", victim, pids)

	// A replacement, not merely a survivor: the supervisor has to notice and
	// start another. Waiting for a pid that was not in the original set is the
	// only proof that does not also pass when nothing happened.
	original := map[int]bool{}
	for _, p := range pids {
		original[p] = true
	}
	deadline := time.Now().Add(60 * time.Second)
	var replaced bool
	for time.Now().Before(deadline) && !replaced {
		time.Sleep(500 * time.Millisecond)
		for _, p := range workerPids(t, e.dataDir) {
			if !original[p] {
				t.Logf("worker %d took over from %d", p, victim)
				replaced = true
				break
			}
		}
	}
	if !replaced {
		t.Fatal("no replacement worker was started; the supervisor did not notice the death")
	}

	final := e.waitFor("workerkill", 180*time.Second, func(s campaignStatus) bool {
		return s.State == "finished"
	}, "the campaign never finished after losing a worker")
	t.Logf("after the restart: %d execs, %d edges, %d corpus entries",
		final.Metrics.Execs, final.Metrics.Coverage, final.Metrics.CorpusSize)

	// Consistent: the corpus is the thing a campaign spends its time earning,
	// and losing a worker must not cost any of it.
	if final.Metrics.CorpusSize < before.Metrics.CorpusSize {
		t.Errorf("the corpus shrank from %d entries to %d after a worker was killed",
			before.Metrics.CorpusSize, final.Metrics.CorpusSize)
	}
	if final.Metrics.Coverage < before.Metrics.Coverage {
		t.Errorf("coverage fell from %d edges to %d after a worker was killed",
			before.Metrics.Coverage, final.Metrics.Coverage)
	}
	if final.Metrics.Execs <= before.Metrics.Execs {
		t.Errorf("the campaign executed nothing after the kill: %d then %d",
			before.Metrics.Execs, final.Metrics.Execs)
	}

	// And the killed worker's corpus is readable, not merely counted: a
	// consistent corpus is one whose payloads are still there.
	out := e.mustRun(60*time.Second, "corpus", "workerkill", "--json")
	var listed struct {
		Count int `json:"count"`
	}
	if err := json.Unmarshal([]byte(out), &listed); err != nil {
		t.Fatalf("decoding the corpus listing: %v\n%s", err, out)
	}
	if listed.Count == 0 {
		t.Error("the corpus lists no entries after a worker was killed")
	}
}

// A target that loops forever is stopped by its timeout and recorded as a hang.
//
// A fuzzer that cannot stop a looping target stops with it, and this is the
// difference between a timeout that is configured and one that is enforced.
func TestFaultATargetThatHangsIsTimedOutAndRecordedAsAHang(t *testing.T) {
	e := newEnvFor(t, "hang")
	path := e.writeCampaign("hangs", 1, 45*time.Second,
		"triage:\n  enabled: true\n  trials: 3\n")
	e.mustRun(60*time.Second, "run", path)

	final := e.status("hangs")
	t.Logf("%d execs, %d finding(s), %d bucket(s), state %s",
		final.Metrics.Execs, final.Metrics.Findings, final.Metrics.Buckets, final.State)

	// Enforced, and the proof is that this line was reached at all: the target
	// loops forever on any input starting with H, so a campaign that could not
	// stop one would still be running now. Finishing inside its wall-clock
	// budget is the whole claim.
	if final.State != "finished" {
		t.Fatalf("the campaign ended in state %q, not finished; a hang was not stopped", final.State)
	}
	// And it kept going past the first one rather than spending the campaign on
	// it. The rate is low by design — every hang costs the full timeout — so
	// this is a floor, not a throughput measurement.
	if final.Metrics.Execs < 20 {
		t.Fatalf("only %d executions; the campaign did not get past its first hang", final.Metrics.Execs)
	}

	kinds := findingKinds(t, e, "hangs")
	t.Logf("finding kinds: %v", kinds)
	if kinds["hang"] == 0 {
		t.Errorf("no finding of kind hang, although the target loops forever on any input "+
			"starting with H; kinds seen: %v", kinds)
	}
}

// A target that fork-bombs is contained by the sandbox's process limit, and the
// campaign carries on.
//
// Containment alone is tested in internal/safety against the sandbox directly.
// What is only true of the whole system is the second half: the machine is
// still usable and the campaign still finishes.
func TestFaultAForkBombingTargetIsContainedAndTheCampaignFinishes(t *testing.T) {
	e := newEnvFor(t, "escape")
	// The target takes its mode as an argument, so every execution fork-bombs.
	path := writeCampaignWithArgs(t, e, "forkbomb", []string{"fork-bomb"}, 30*time.Second,
		"safety:\n  isolation: moderate\n  process_limit: 32\n")

	out, err := e.xfuzz(180*time.Second, "run", path)
	if err != nil && !strings.Contains(out, "finished") {
		t.Fatalf("the campaign did not survive a fork-bombing target: %v\n%s", err, out)
	}

	final := e.status("forkbomb")
	t.Logf("%d execs, state %s, %d finding(s)", final.Metrics.Execs, final.State, final.Metrics.Findings)
	if final.State != "finished" {
		t.Fatalf("the campaign ended in state %q, not finished, against a fork-bombing target", final.State)
	}
	if final.Metrics.Execs == 0 {
		t.Error("the campaign executed nothing; the target was not merely contained, it was unusable")
	}

	// Nothing left behind. A fork bomb that outlived its campaign is a machine
	// that the next test — and the next campaign — inherits.
	if n := strayWorkers(t, e.dataDir); n > 0 {
		t.Errorf("%d worker process(es) survived a campaign against a fork bomb", n)
	}
}

// findingKinds counts a campaign's findings by kind.
func findingKinds(t *testing.T, e *env, name string) map[string]int {
	t.Helper()
	out := e.mustRun(60*time.Second, "findings", name, "--json")
	var resp struct {
		Findings []struct {
			Kind string `json:"kind"`
		} `json:"findings"`
	}
	if err := json.Unmarshal([]byte(out), &resp); err != nil {
		t.Fatalf("decoding findings: %v\n%s", err, out)
	}
	kinds := map[string]int{}
	for _, f := range resp.Findings {
		kinds[f.Kind]++
	}
	return kinds
}

// writeCampaignWithArgs writes a campaign whose target takes arguments, which
// writeCampaign has no room for: its extra block is appended at the top level,
// and args belong inside the target.
func writeCampaignWithArgs(t *testing.T, e *env, name string, args []string, after time.Duration, extra string) string {
	t.Helper()
	quoted := make([]string, len(args))
	for i, a := range args {
		quoted[i] = strconv.Quote(a)
	}
	body := fmt.Sprintf(`
name: %s
target:
  path: %s
  args: [%s]
  input: stdin
  timeout: 5s
seeds:
  inline: ["Z", "Axx", "B", "CCCC"]
feedback:
  coverage: sancov
workers:
  count: 1
stop:
  after: %s
%s`, name, e.target, strings.Join(quoted, ", "), after, extra)

	path := filepath.Join(e.dataDir, name+".yaml")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}
