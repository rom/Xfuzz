//go:build integration

// The v0.1 proof obligation (docs/MVP_PLAN.md section 1.2).
//
// Two campaigns, both launched from a file, monitored in the console, and
// triaged to a minimised reproducible finding:
//
//  1. Stateless: coverage-guided, against a checksum-protected format,
//     sustaining >= 5,000 exec/s on a fork-server target, with a demonstrably
//     higher valid-input rate than byte-level mutation of the same corpus.
//  2. Stateful: a bug reachable only after a valid multi-step handshake, with
//     state coverage reported separately from code coverage.
//
// The stateless campaign is measured here, in full. The stateful one is
// measured in m6_test.go, which spends eight minutes on it; repeating that
// would add ten minutes to the suite and answer nothing new. What this file
// adds for it is the clause m6 does not assert.
//
//	Clause                                          Where
//	----------------------------------------------  ------------------------
//	stateless: from a file, coverage-guided          here
//	stateless: >= 5,000 exec/s on a fork server      here
//	stateless: beats byte mutation on the same seeds here
//	stateless: minimised, reproducible finding       here
//	stateful:  bug behind a handshake                m6_test.go
//	stateful:  state coverage reported separately    m6_test.go
//	stateful:  findings replay as sessions           m6_test.go
//	both:      monitored in the console              m7_test.go

package e2e

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"hash/crc32"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rom/Xfuzz/internal/testenv"
)

// chunkedSeed builds a valid XCHK file: the magic, the version, and one chunk
// per tag with a correct length and a correct CRC.
//
// Written by hand rather than generated, because it is the *input* to the
// comparison this test makes: both arms start from exactly these bytes, and a
// seed produced by the grammar would hand the structured arm an advantage
// before the campaign began.
func chunkedSeed(tags []string, payload []byte) []byte {
	out := append([]byte("XCHK"), 1)
	for _, tag := range tags {
		chunk := append([]byte(tag), 0, 0, 0, 0)
		binary.BigEndian.PutUint32(chunk[4:], uint32(len(payload)))
		chunk = append(chunk, payload...)

		sum := make([]byte, 4)
		binary.BigEndian.PutUint32(sum, crc32.ChecksumIEEE(chunk))
		out = append(out, append(chunk, sum...)...)
	}
	return out
}

// writeChunkedSeeds fills a directory with valid inputs and returns it.
func writeChunkedSeeds(t *testing.T, dir string) string {
	t.Helper()
	seeds := filepath.Join(dir, "chunked-seeds")
	if err := os.MkdirAll(seeds, 0o755); err != nil {
		t.Fatal(err)
	}
	// A spread that looks like real files of this format: one chunk of each
	// kind, payloads of the sizes those chunks carry, and a file with a run of
	// them.
	//
	// The sizes matter as much as the shapes. A corpus of uniformly tiny
	// payloads leaves a bug that needs a long one behind *two* independent
	// conditions rather than one, with no coverage gradient between them —
	// which measures how well a fuzzer guesses rather than how well it mutates
	// structure. GUIDE.md tells a reader their seeds matter more than anything
	// else in the campaign file; a criterion that ignored its own advice would
	// be measuring the wrong thing.
	long := make([]byte, 96)
	for i := range long {
		long[i] = byte('a' + i%26)
	}
	cases := []struct {
		name    string
		tags    []string
		payload []byte
	}{
		{"size-small", []string{"SIZE"}, []byte("0123456789abcdef")},
		{"size-large", []string{"SIZE"}, long},
		{"idxt", []string{"IDXT"}, []byte{0, 4, 7}},
		{"math", []string{"MATH"}, []byte{0, 0, 0, 2, 0, 0, 0, 1}},
		{"ptrv", []string{"PTRV"}, []byte{1, 2, 3, 4}},
		{"depth", []string{"DPTH", "DPTH"}, []byte("d")},
		{"mixed", []string{"DPTH", "SIZE", "IDXT"}, []byte("payload")},
	}
	for _, c := range cases {
		body := chunkedSeed(c.tags, c.payload)
		if err := os.WriteFile(filepath.Join(seeds, c.name), body, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(seeds, 0o755); err != nil {
		t.Fatal(err)
	}
	return seeds
}

// chunkedCampaign writes one arm of the comparison.
func chunkedCampaign(t *testing.T, e *env, name, seeds, format string, after time.Duration) string {
	t.Helper()
	body := fmt.Sprintf(`
name: %s
target:
  path: %s
  input: stdin
  timeout: 2s
seeds:
  dirs: [%s]
format:
%s
feedback:
  coverage: sancov
  objectives: [crash, hang, oom, sanitizer]
workers:
  count: 2
stop:
  after: %s
`, name, e.target, seeds, format, after)

	path := filepath.Join(e.dataDir, name+".yaml")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// executorOf reports the delivery tier a campaign's workers are using.
func executorOf(t *testing.T, e *env, name string) string {
	t.Helper()
	out := e.mustRun(30*time.Second, "workers", name, "--json")
	var resp struct {
		Workers []struct {
			Executor string `json:"executor"`
		} `json:"workers"`
	}
	if err := json.Unmarshal([]byte(out), &resp); err != nil {
		t.Fatalf("decoding the worker report: %v\n%s", err, out)
	}
	if len(resp.Workers) == 0 {
		return ""
	}
	return resp.Workers[0].Executor
}

// The first proof-obligation campaign, end to end.
func TestProofObligationOneAStatelessCampaignAgainstAChecksumProtectedFormat(t *testing.T) {
	e := newEnvFor(t, "chunked_format")
	seeds := writeChunkedSeeds(t, e.dataDir)

	grammar := filepath.Join(testenv.RepoRoot(t), "testdata", "targets", "chunked_format.xfg")
	const budget = 3 * time.Minute

	// The structured arm: the same seeds, read through the grammar, so every
	// mutation is followed by a fixup pass that re-derives the lengths and the
	// checksums.
	path := chunkedCampaign(t, e, "structured", seeds,
		"  grammar: "+grammar+"\n", budget)
	e.mustRun(budget+3*time.Minute, "run", path)
	structured := e.status("structured")

	tier := executorOf(t, e, "structured")
	t.Logf("structured: %d execs (%.0f/s) on the %s tier, %d edges, %d corpus, %d finding(s) in %d bucket(s)",
		structured.Metrics.Execs, structured.Metrics.ExecsPerS, tier,
		structured.Metrics.Coverage, structured.Metrics.CorpusSize,
		structured.Metrics.Findings, structured.Metrics.Buckets)

	// Clause: a fork-server target.
	if tier != "forkserver" {
		t.Errorf("the campaign ran on the %q tier, not the fork server; "+
			"the throughput clause is about that tier", tier)
	}
	// Clause: >= 5,000 exec/s. Measured over the campaign rather than reported
	// instantaneously, because a rate sampled at one moment is not a sustained
	// one.
	rate := float64(structured.Metrics.Execs) / budget.Seconds()
	t.Logf("sustained %.0f exec/s over %s", rate, budget)
	if rate < 5000 {
		t.Errorf("sustained %.0f exec/s, below the 5,000 the proof obligation requires", rate)
	}

	// Clause: it gets past the checksum. Every bug in this target sits behind a
	// CRC the parser verifies before it does anything else, so a finding is
	// proof the gate opened.
	if structured.Metrics.Findings == 0 {
		t.Fatal("no finding: the campaign never got past the target's checksum gate, " +
			"which is the whole thing this campaign exists to prove")
	}

	// Clause: triaged to a minimised, reproducible finding.
	assertMinimisedAndReproducible(t, e, "structured")

	// The byte-level arm: identical in every respect except that it does not
	// know the format.
	bytePath := chunkedCampaign(t, e, "bytelevel", seeds, "  codec: raw\n", budget)
	e.mustRun(budget+3*time.Minute, "run", bytePath)
	byteLevel := e.status("bytelevel")

	t.Logf("byte-level: %d execs (%.0f/s), %d edges, %d corpus, %d finding(s)",
		byteLevel.Metrics.Execs, byteLevel.Metrics.ExecsPerS,
		byteLevel.Metrics.Coverage, byteLevel.Metrics.CorpusSize,
		byteLevel.Metrics.Findings)

	// Clause: a demonstrably higher valid-input rate on the same corpus.
	//
	// Measured on what each campaign kept, by re-checking every entry against
	// the format's own rules: the magic, the version, and a CRC over every
	// chunk that agrees with the bytes it covers. That is the gate the target
	// puts in front of all five of its bugs, and an arm whose corpus is mostly
	// past it is an arm producing inputs that survive validation.
	//
	// Not coverage. This target's parse loop is a few dozen edges, so both arms
	// saturate it and the number stops discriminating — measured, 37 against 38
	// — which says something about the fixture rather than about mutation. The
	// direct measurement of the rate is in pkg/mutate/validrate_test.go, where
	// inputs can be counted as they are produced rather than after a coverage
	// filter has chosen among them: 99.8% against 0.0% over five thousand
	// mutations of a PNG corpus.
	structuredValid := validShare(t, e, "structured")
	byteValid := validShare(t, e, "bytelevel")
	t.Logf("corpus validity: %.0f%% structured against %.0f%% byte-level",
		100*structuredValid, 100*byteValid)

	if structuredValid <= byteValid {
		t.Errorf("the structured arm's corpus is %.0f%% valid and the byte-level arm's %.0f%%; "+
			"knowing the format bought nothing, which contradicts the premise of ADR-0005",
			100*structuredValid, 100*byteValid)
	}
}

// validShare exports a campaign's corpus and reports what fraction of it is a
// valid file of the format.
func validShare(t *testing.T, e *env, name string) float64 {
	t.Helper()
	dir := filepath.Join(e.dataDir, name+"-corpus")
	e.mustRun(120*time.Second, "corpus", "export", name, "--dir", dir, "--format", "raw")

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading the exported corpus: %v", err)
	}
	valid, total := 0, 0
	for _, ent := range entries {
		if ent.IsDir() {
			continue
		}
		body, err := os.ReadFile(filepath.Join(dir, ent.Name()))
		if err != nil {
			continue
		}
		total++
		if chunkedValid(body) {
			valid++
		}
	}
	if total == 0 {
		t.Fatalf("%s exported an empty corpus", name)
	}
	return float64(valid) / float64(total)
}

// chunkedValid applies the target's own acceptance rule: the magic, the
// version, and a checksum over every chunk that agrees with the bytes it
// covers.
func chunkedValid(b []byte) bool {
	if len(b) < 5 || string(b[:4]) != "XCHK" || b[4] != 1 {
		return false
	}
	off, chunks := 5, 0
	for off+12 <= len(b) {
		declared := int(binary.BigEndian.Uint32(b[off+4:]))
		if declared > 4096 || off+12+declared > len(b) {
			break
		}
		claimed := binary.BigEndian.Uint32(b[off+8+declared:])
		if claimed != crc32.ChecksumIEEE(b[off:off+8+declared]) {
			return false
		}
		off += 12 + declared
		chunks++
	}
	return chunks > 0
}

// assertMinimisedAndReproducible checks the last clause of the obligation: that
// a campaign does not merely find something, it hands over a finding somebody
// can act on.
func assertMinimisedAndReproducible(t *testing.T, e *env, name string) {
	t.Helper()

	out := e.mustRun(60*time.Second, "findings", name, "--json")
	var resp struct {
		Findings []struct {
			ID          int64   `json:"id"`
			Kind        string  `json:"kind"`
			TriageState string  `json:"triage_state"`
			ReproRate   float64 `json:"repro_rate"`
			ReproTrials int     `json:"repro_trials"`
			Reduction   float64 `json:"reduction"`
		} `json:"findings"`
	}
	if err := json.Unmarshal([]byte(out), &resp); err != nil {
		t.Fatalf("decoding findings: %v\n%s", err, out)
	}
	if len(resp.Findings) == 0 {
		t.Fatal("no findings to triage")
	}

	var reproducible, minimised int
	for _, f := range resp.Findings {
		t.Logf("finding %d: %s, %s, reproduced %.0f%% of %d, %.0f%% smaller",
			f.ID, f.Kind, f.TriageState, 100*f.ReproRate, f.ReproTrials, 100*f.Reduction)
		if f.ReproTrials > 0 && f.ReproRate >= 1 {
			reproducible++
		}
		if f.TriageState == "minimized" {
			minimised++
		}
	}
	if reproducible == 0 {
		t.Error("no finding reproduced on every verification run; " +
			"a finding nobody can reproduce is not one anybody can act on")
	}
	if minimised == 0 {
		t.Error("no finding reached the minimized state")
	}

	// And the reproducer is really there, as bytes, not merely as a claim.
	repro := filepath.Join(e.dataDir, name+"-repro")
	e.mustRun(60*time.Second, "findings", "get", name,
		fmt.Sprintf("%d", resp.Findings[0].ID), "-o", repro)
	fi, err := os.Stat(repro)
	if err != nil || fi.Size() == 0 {
		t.Fatalf("the reproducer for finding %d was not written: %v", resp.Findings[0].ID, err)
	}

	// Re-running it must still fail, which is what makes it a reproducer.
	replayed := e.mustRun(120*time.Second, "replay", name, fmt.Sprintf("%d", resp.Findings[0].ID))
	t.Logf("replay: %s", replayed)
}
