//go:build integration

// Clause 4 of the v0.1 definition of done: determinism and cross-host replay.
//
// ASR-0008 states two acceptance criteria and this file is both of them,
// measured through the shipped binaries rather than asserted about the engine:
//
//   - two single-worker runs of the same campaign file and seed produce the
//     same executions;
//   - `xfuzz replay <finding>` reproduces the outcome on a different host.
//
// "A different host" is approximated as honestly as one machine allows: a
// second data directory, a second daemon, a second copy of the binaries, a
// campaign file that never mentions the first, and a store that travelled as
// bytes. What is deliberately *not* carried over is the seed — a finding whose
// replay needed the seed that produced it would not be a finding anyone else
// could act on.

package e2e

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/rom/Xfuzz/internal/testenv"
)

// seededCampaign writes a single-worker campaign with a pinned seed and an
// execution budget.
//
// Both halves matter. One worker because ASR-0008 promises determinism for one:
// with several, the corpus each of them sees depends on when the others
// published, and that is wall-clock. An execution budget rather than a
// wall-clock one because two runs that stop after five seconds stop at
// different places on any machine that is doing anything else, and the
// difference would look exactly like non-determinism.
func seededCampaign(t *testing.T, e *env, name string, seed uint64, execs int) string {
	t.Helper()
	body := fmt.Sprintf(`
name: %s
seed: %d
target:
  path: %s
  input: stdin
  timeout: 2s
seeds:
  inline: ["Z", "Axx", "B", "CCCC"]
feedback:
  coverage: sancov
workers:
  count: 1
storage:
  dir: %s
triage:
  enabled: true
  trials: 3
stop:
  execs: %d
`, name, seed, e.target, filepath.Join(e.dataDir, "store-"+name), execs)

	path := filepath.Join(e.dataDir, name+".yaml")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// corpusDigests returns the campaign's corpus as digest → provenance.
//
// The provenance is half the point. Two runs agreeing on which inputs they
// found but disagreeing on how they got there would mean the mutation sequence
// diverged and converged again, which is not determinism — it is a coincidence
// that will not survive the next change to a mutator.
func corpusDigests(t *testing.T, e *env, name string) map[string]string {
	t.Helper()
	out := e.mustRun(60*time.Second, "corpus", "list", name, "--limit", "5000", "--json")
	var resp struct {
		Entries []struct {
			Digest string   `json:"digest"`
			Ops    []string `json:"ops"`
			Origin string   `json:"origin"`
		} `json:"entries"`
	}
	if err := json.Unmarshal([]byte(out), &resp); err != nil {
		t.Fatalf("decoding the corpus listing: %v\n%s", err, out)
	}
	got := map[string]string{}
	for _, en := range resp.Entries {
		got[en.Digest] = en.Origin + " " + strings.Join(en.Ops, ",")
	}
	return got
}

func TestTheSameSeedAndFileGiveTheSameCampaign(t *testing.T) {
	if testing.Short() {
		t.Skip("determinism is measured over two full campaigns")
	}

	const (
		seed  = 0x5EED0F1CE5EED01 // pinned, and larger than 2^53 on purpose
		other = 0x5EED0F1CE5EED02
		execs = 20000
	)

	// Each run gets a data directory, a daemon and a store of its own, so what
	// is being compared is the campaign file and the seed and nothing else.
	run := func(name string, seed uint64) map[string]string {
		e := newEnv(t)
		file := seededCampaign(t, e, name, seed, execs)
		e.mustRun(6*time.Minute, "run", file)
		st := e.status(name)
		if st.Seed != seed {
			t.Fatalf("campaign %s ran with seed %d, not the %d its file pinned",
				name, st.Seed, seed)
		}
		return corpusDigests(t, e, name)
	}

	first := run("det-a", seed)
	second := run("det-b", seed)

	if len(first) == 0 {
		t.Fatal("the first run produced no corpus at all")
	}
	t.Logf("seed %#x: %d corpus entries, twice", seed, len(first))

	// Reported as the symmetric difference rather than as "they differ",
	// because the useful question when this fails is *which* input one run
	// found and the other did not.
	var onlyFirst, onlySecond, differentOps []string
	for d, ops := range first {
		switch other, ok := second[d]; {
		case !ok:
			onlyFirst = append(onlyFirst, d)
		case other != ops:
			differentOps = append(differentOps,
				fmt.Sprintf("%s: %q against %q", d[:12], ops, other))
		}
	}
	for d := range second {
		if _, ok := first[d]; !ok {
			onlySecond = append(onlySecond, d)
		}
	}
	sort.Strings(onlyFirst)
	sort.Strings(onlySecond)
	sort.Strings(differentOps)

	if len(onlyFirst) > 0 || len(onlySecond) > 0 {
		t.Errorf("two runs of the same file and seed found different corpora: "+
			"%d entries only in the first, %d only in the second\n first only: %s\nsecond only: %s",
			len(onlyFirst), len(onlySecond),
			strings.Join(trunc(onlyFirst, 5), " "), strings.Join(trunc(onlySecond, 5), " "))
	}
	if len(differentOps) > 0 {
		t.Errorf("%d entries were reached by a different route in each run:\n  %s",
			len(differentOps), strings.Join(trunc(differentOps, 5), "\n  "))
	}

	// And the seed has to be doing the work. Without this the whole test passes
	// on a fuzzer that ignores its seed entirely and explores the same sequence
	// every time — which is determinism of a kind, and useless.
	third := run("det-c", other)
	same := 0
	for d := range third {
		if _, ok := first[d]; ok {
			same++
		}
	}
	t.Logf("a different seed: %d entries, %d shared with the first", len(third), same)
	if len(third) == len(first) && same == len(first) {
		t.Error("a different seed produced exactly the same corpus, so the seed is not reaching the engine")
	}
}

func TestAFindingReplaysOnAnotherHost(t *testing.T) {
	if testing.Short() {
		t.Skip("this runs a campaign to a finding and then replays it")
	}

	// Host A: find something.
	a := newEnv(t)
	const name = "travelling"
	file := seededCampaign(t, a, name, 0xA1DE57, 300000)
	a.mustRun(6*time.Minute, "run", file)

	found := findingsOf(t, a, name)
	if len(found) == 0 {
		t.Skip("host A found nothing to replay; the campaign's budget was too small")
	}
	t.Logf("host A: %d finding(s)", len(found))

	// Host B: a second set of binaries, a second data directory, a second
	// daemon, and the store copied across as bytes — which is what "another
	// machine" means for a store that is a directory (ADR-0008).
	bin := testenv.ReachableDir(t)
	for _, cmd := range []string{"xfuzz", "xfuzzd", "xfuzz-worker", "xfuzz-sandbox"} {
		testenv.BuildBinary(t, bin, cmd)
	}
	b := &env{
		t:      t,
		binDir: bin,
		// The target is rebuilt at a path of its own, so nothing on host B
		// resolves through a path host A created. A replay that only worked
		// because both stores pointed at one binary would prove nothing.
		dataDir: testenv.ReachableDir(t),
		target:  testenv.BuildTarget(t, "simple_parser"),
	}
	t.Cleanup(b.reapTargets)
	t.Cleanup(b.stopDaemon)

	storeB := filepath.Join(b.dataDir, "arrived")
	copyTree(t, filepath.Join(a.dataDir, "store-"+name), storeB)

	// The campaign file that travels with it names host B's target, because a
	// reproducer is bytes plus an invocation and the invocation is local. The
	// seed is deliberately absent: replay must not need it.
	loaded := b.mustRun(60*time.Second, "load", name, "--store", storeB)
	t.Logf("host B: %s", strings.TrimSpace(loaded))

	arrived := findingsOf(t, b, name)
	if len(arrived) != len(found) {
		t.Errorf("host A recorded %d findings, host B reads %d from the same store",
			len(found), len(arrived))
	}

	// The reproducer's bytes must survive the journey exactly. A store that
	// carried the metadata but not the blob would still list the finding, and
	// the difference would only appear when somebody tried to act on it.
	for _, f := range arrived {
		here := filepath.Join(b.dataDir, fmt.Sprintf("repro-%d", f.ID))
		there := filepath.Join(a.dataDir, fmt.Sprintf("repro-%d", f.ID))
		b.mustRun(60*time.Second, "findings", "get", name, fmt.Sprintf("%d", f.ID), "-o", here)
		a.mustRun(60*time.Second, "findings", "get", name, fmt.Sprintf("%d", f.ID), "-o", there)
		x, err := os.ReadFile(here)
		if err != nil {
			t.Fatalf("reading the reproducer on host B: %v", err)
		}
		y, err := os.ReadFile(there)
		if err != nil {
			t.Fatalf("reading the reproducer on host A: %v", err)
		}
		if string(x) != string(y) {
			t.Errorf("finding %d's reproducer differs between hosts: %d bytes against %d",
				f.ID, len(x), len(y))
		}
	}

	// The criterion itself: it still fails, on the other host, against a binary
	// the other host built.
	replayed := 0
	for _, f := range arrived {
		out, err := b.xfuzz(120*time.Second, "replay", name, fmt.Sprintf("%d", f.ID),
			"--trials", "3", "--json")
		if err != nil {
			t.Errorf("replaying finding %d on host B: %v\n%s", f.ID, err, out)
			continue
		}
		var resp struct {
			Kind       string  `json:"kind"`
			Rate       float64 `json:"rate"`
			Trials     int     `json:"trials"`
			Reproduced int     `json:"reproduced"`
			Divergent  bool    `json:"divergent"`
		}
		if err := json.Unmarshal([]byte(out), &resp); err != nil {
			t.Fatalf("decoding the replay of finding %d: %v\n%s", f.ID, err, out)
		}
		t.Logf("host B replayed finding %d (%s): %d of %d trials, divergent=%v",
			f.ID, resp.Kind, resp.Reproduced, resp.Trials, resp.Divergent)
		if resp.Trials == 0 {
			t.Errorf("finding %d was replayed zero times on host B", f.ID)
			continue
		}
		if resp.Rate < 1 {
			t.Errorf("finding %d reproduced %.0f%% of the time on host B; "+
				"a finding that does not travel is not one anybody else can act on",
				f.ID, 100*resp.Rate)
			continue
		}
		if resp.Kind != f.Kind {
			t.Errorf("finding %d was %q on host A and %q on host B", f.ID, f.Kind, resp.Kind)
		}
		replayed++
	}
	if replayed == 0 {
		t.Error("nothing replayed on host B")
	}
}

// findingsOf lists a campaign's findings with the fields replay is judged on.
func findingsOf(t *testing.T, e *env, name string) []struct {
	ID   int64  `json:"id"`
	Kind string `json:"kind"`
} {
	t.Helper()
	out := e.mustRun(60*time.Second, "findings", name, "--json")
	var resp struct {
		Findings []struct {
			ID   int64  `json:"id"`
			Kind string `json:"kind"`
		} `json:"findings"`
	}
	if err := json.Unmarshal([]byte(out), &resp); err != nil {
		t.Fatalf("decoding findings: %v\n%s", err, out)
	}
	return resp.Findings
}

// copyTree copies a directory, which is how a store travels.
func copyTree(t *testing.T, from, to string) {
	t.Helper()
	if err := os.MkdirAll(to, 0o755); err != nil {
		t.Fatal(err)
	}
	// Through the shell's own copy rather than a walk of our own: what is being
	// tested is that a store survives being moved by whatever the operator
	// happens to use, not that our copy function is faithful.
	cmd := exec.Command("cp", "-a", from+"/.", to)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("copying the store: %v\n%s", err, out)
	}
}

func trunc(s []string, n int) []string {
	if len(s) <= n {
		return s
	}
	return append(s[:n:n], fmt.Sprintf("... and %d more", len(s)-n))
}
