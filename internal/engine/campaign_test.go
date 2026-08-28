//go:build integration

// Campaign tests are layer 3 of docs/TESTS.md: planted-bug targets run through
// a whole coverage-guided worker. They take minutes rather than seconds, so
// they sit behind the integration tag and run in their own CI job — `make test`
// stays fast enough to run before every commit, which is the only way a
// pre-commit suite actually gets run.

package engine

import (
	"bytes"
	"context"
	"fmt"
	"path/filepath"
	"regexp"
	"strconv"
	"testing"
	"time"

	"github.com/rom/Xfuzz/internal/platform"
	"github.com/rom/Xfuzz/internal/safety"
	"github.com/rom/Xfuzz/pkg/codec"
	"github.com/rom/Xfuzz/pkg/corpus"
	"github.com/rom/Xfuzz/pkg/executor"
	"github.com/rom/Xfuzz/pkg/feedback"
	"github.com/rom/Xfuzz/pkg/mutate"
)

// This file is M3's exit criterion. It is the layer of the test strategy that
// detects the defining failure of a fuzzer — running beautifully and finding
// nothing — and it is the only one that can (docs/TESTS.md section 4).

// bugMarker is what the planted targets print when a bug is reached. Using the
// target's own report rather than inferring the bug from a stack keeps the test
// measuring what the fuzzer is responsible for: reaching the code.
var bugMarker = regexp.MustCompile(`XFUZZ-BUG-(\d+)`)

// plantedBugObjective reports a crash and names which planted bug it is, so
// distinct bugs land in distinct buckets.
func plantedBugObjective(out *feedback.OutputObserver) feedback.Objective {
	return feedback.NewOracleObjective("planted-bug", "crash",
		func(_ []feedback.Observer, ek feedback.ExitKind) (bool, string) {
			if ek != feedback.ExitCrash {
				return false, ""
			}
			if m := bugMarker.FindSubmatch(out.Stderr()); m != nil {
				return true, "XFUZZ-BUG-" + string(m[1])
			}
			// A crash the target did not announce is still a crash, and
			// reporting it as one is what would surface an unplanted bug.
			return true, "unidentified crash"
		})
}

// campaign assembles a full coverage-guided worker: shared memory, an
// instrumented fork server, a coverage feedback, a corpus, a power schedule,
// and the mutation stack.
type campaign struct {
	engine   *Engine
	executor *executor.ForkServer
	coverage *feedback.MapFeedback
	cleanup  func()
}

func newCampaign(t testing.TB, target string, seeds [][]byte, dictPath string, seed uint64, trace *bytes.Buffer) *campaign {
	t.Helper()

	provider := platform.NewSharedMemoryProvider()
	if !provider.Available() {
		t.Skip("shared memory is unavailable; coverage-guided fuzzing needs it")
	}
	shm, err := provider.Create(feedback.DefaultMapSize)
	if err != nil {
		t.Fatalf("creating the coverage region: %v", err)
	}

	covMap := feedback.NewCoverageMap("coverage", feedback.DefaultMapSize)
	covMap.SetBuffer(shm.Bytes())
	covMap.SetBackend("sancov")
	out := feedback.NewOutputObserver("output")

	fs := executor.NewForkServer("forkserver", safety.NewSpawner(), executor.ProcSpec{
		Path: target, Args: []string{target},
	})
	fs.Coverage, fs.Shm, fs.Output = covMap, shm, out
	fs.Timeout = 1 * time.Second

	if err := fs.Start(context.Background()); err != nil {
		shm.Close()
		t.Fatalf("starting the fork server: %v", err)
	}

	mapFB := feedback.NewMapFeedback("coverage", covMap)

	var dict *mutate.Dictionary
	if dictPath != "" {
		d, err := mutate.LoadDictionary(dictPath)
		if err != nil {
			t.Fatalf("loading the dictionary: %v", err)
		}
		dict = d
	}

	cfg := Config{
		CampaignSeed:  seed,
		WorkerID:      0,
		Executor:      fs,
		Observers:     []feedback.Observer{covMap, out},
		Feedback:      mapFB,
		Objective:     plantedBugObjective(out),
		Corpus:        corpus.New(),
		Schedule:      corpus.NewFastScheduler(),
		Mutators:      mutate.Default(),
		Codec:         codec.Raw{},
		Dict:          dict,
		MaxInputBytes: 4096,
		MaxChildren:   64,
	}
	if trace != nil {
		cfg.Trace = trace
	}

	eng, err := New(cfg)
	if err != nil {
		fs.Close()
		shm.Close()
		t.Fatalf("building the engine: %v", err)
	}
	for i, s := range seeds {
		if err := eng.AddSeed(context.Background(), s, fmt.Sprintf("seed-%d", i)); err != nil {
			t.Fatalf("adding seed %d: %v", i, err)
		}
	}

	c := &campaign{engine: eng, executor: fs, coverage: mapFB}
	c.cleanup = func() { fs.Close(); shm.Close() }
	t.Cleanup(c.cleanup)
	return c
}

// foundBugs returns the planted bug numbers a campaign reached.
func foundBugs(e *Engine) map[int]bool {
	found := map[int]bool{}
	for bucket := range e.Buckets() {
		if m := bugMarker.FindStringSubmatch(bucket); m != nil {
			n, _ := strconv.Atoi(m[1])
			found[n] = true
		}
	}
	return found
}

// TestCampaignFindsAllPlantedBugs is M3's headline exit criterion.
func TestCampaignFindsAllPlantedBugs(t *testing.T) {
	cases := []struct {
		target string
		bugs   int
		dict   string
		seeds  [][]byte
		budget Budget
	}{
		{
			target: "simple_parser",
			bugs:   3,
			// One seed per opcode, none matching any guarded byte. A corpus
			// that never reaches a branch does not test whether coverage
			// guidance can explore it — it tests whether the fuzzer can guess
			// an opcode, which is a weaker and different claim. Real corpora
			// exercise a format's variants; these do the same.
			seeds: [][]byte{
				[]byte("Z\x00"),
				[]byte("A\x01xx"),
				[]byte("B\x01\x02"),
				[]byte("C\x00\x00\x00\x00\x00"),
			},
			budget: Budget{MaxExecs: 500_000, MaxTime: 90 * time.Second},
		},
		{
			target: "magic_parser",
			bugs:   4,
			dict:   "magic_parser.dict",
			// Section 3's bug needs a length field that agrees with the payload.
			// A seed carrying a valid one is not a shortcut: it is what a real
			// corpus is — valid files the target accepts — and it is the corpus
			// that gives byte-level mutation something to preserve.
			seeds: [][]byte{
				[]byte("XFZ!\x01\x00"),
				[]byte("XFZ!\x02\x00\x00\x00\x00"),
				[]byte("XFZ!\x03\x00\x08AAAAAAAA"),
				[]byte("XFZ!\x04\x00\x00\x00\x00BBBBBBBB"),
				[]byte("hello world"),
			},
			budget: Budget{MaxExecs: 600_000, MaxTime: 90 * time.Second},
		},
	}

	for _, tc := range cases {
		t.Run(tc.target, func(t *testing.T) {
			target := buildTarget(t, tc.target)
			dict := ""
			if tc.dict != "" {
				dict = filepath.Join(repoRoot(t), "testdata", "targets", tc.dict)
			}

			c := newCampaign(t, target, tc.seeds, dict, 0x58465A33, nil)
			stats, err := c.engine.Run(context.Background(), tc.budget)
			if err != nil {
				t.Fatalf("campaign failed: %v", err)
			}

			found := foundBugs(c.engine)
			t.Logf("%s: %d execs in %v (%.0f/s), overhead %.1f%%, coverage %d, corpus %d, "+
				"found %d/%d bugs, stopped: %s",
				tc.target, stats.Execs, stats.Elapsed.Round(time.Millisecond),
				stats.ExecsPerSecond(), 100*stats.Overhead(),
				stats.Coverage, stats.CorpusSize, len(found), tc.bugs, stats.StopReason)
			for _, b := range c.engine.SortedBuckets() {
				t.Logf("  bucket %-24s x%d", b, c.engine.Buckets()[b])
			}

			var missing []int
			for i := 1; i <= tc.bugs; i++ {
				if !found[i] {
					missing = append(missing, i)
				}
			}
			if len(missing) > 0 {
				t.Errorf("did not find planted bug(s) %v in %d executions.\n"+
					"A planted bug that is not found means something upstream is broken — "+
					"a dead coverage map, an inverted feedback, a mutator producing only "+
					"invalid inputs — not that the fuzzer was unlucky.", missing, stats.Execs)
			}
			if stats.Coverage == 0 {
				t.Error("the campaign recorded no coverage at all; it was fuzzing blind")
			}
			if stats.CorpusSize <= len(tc.seeds) {
				t.Errorf("the corpus never grew past its %d seeds; coverage feedback is "+
					"admitting nothing", len(tc.seeds))
			}
		})
	}
}

// TestCampaignIsDeterministic enforces ASR-0008 at the campaign level: the same
// seed must produce the same sequence of executions, or a finding recorded today
// cannot be reproduced tomorrow.
func TestCampaignIsDeterministic(t *testing.T) {
	target := buildTarget(t, "simple_parser")
	seeds := [][]byte{[]byte("Z\x00"), []byte("A\x01xx")}
	budget := Budget{MaxExecs: 3000}

	run := func() string {
		var trace bytes.Buffer
		c := newCampaign(t, target, seeds, "", 0xDE7E4111, &trace)
		if _, err := c.engine.Run(context.Background(), budget); err != nil {
			t.Fatalf("campaign failed: %v", err)
		}
		return trace.String()
	}

	first, second := run(), run()
	if first != second {
		firstLines, secondLines := splitN(first, 40), splitN(second, 40)
		for i := range firstLines {
			if i < len(secondLines) && firstLines[i] != secondLines[i] {
				t.Fatalf("the two runs diverged at execution %d:\n first: %s\nsecond: %s",
					i, firstLines[i], secondLines[i])
			}
		}
		t.Fatalf("traces differ in length: %d against %d bytes", len(first), len(second))
	}
	if len(first) == 0 {
		t.Fatal("no trace was produced")
	}
}

func splitN(s string, n int) []string {
	var out []string
	start := 0
	for i := 0; i < len(s) && len(out) < n; i++ {
		if s[i] == '\n' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return out
}

// TestForkServerThroughput checks the ASR-0007 floor for the T2 tier and the
// 10% cap on the engine's own bookkeeping.
//
// The absolute floor of 5,000 exec/s is stated for a commodity 8-core Linux
// host. A machine that cannot reach it with a target that does nothing at all
// cannot reach it with a real one either, and failing there would be measuring
// the host rather than the fuzzer. So the floor is asserted only where the host
// can support it, and the ratio against a do-nothing target — which is what
// says whether the fork server is efficient — is asserted everywhere.
func TestForkServerThroughput(t *testing.T) {
	if testing.Short() {
		t.Skip("throughput measurement is slow")
	}

	floorRate := forkRate(t, "nop", false)
	realRate := forkRate(t, "simple_parser", true)
	t.Logf("protocol floor (nop target): %.0f exec/s", floorRate)
	t.Logf("realistic target with coverage: %.0f exec/s", realRate)

	// The fork server has to spend most of its time in the target, not in the
	// protocol around it. This holds on any host.
	if ratio := realRate / floorRate; ratio < 0.55 {
		t.Errorf("a realistic target ran at %.0f%% of the do-nothing floor; the fork "+
			"server protocol is costing more than the target it is measuring", 100*ratio)
	}

	const floor = 5000
	switch {
	case floorRate < floor:
		t.Logf("SKIPPING the %d exec/s floor from ASR-0007: this host tops out at "+
			"%.0f exec/s with a target that does nothing, so the floor measures the "+
			"host rather than the fuzzer. It applies to the reference 8-core host.",
			floor, floorRate)
	case realRate < floor:
		t.Errorf("the fork server sustained %.0f exec/s, below the %d exec/s floor in "+
			"ASR-0007, on a host whose own floor is %.0f exec/s. A tier that misses its "+
			"floor is not a slower fuzzer, it is one that never reaches the bug.",
			realRate, floor, floorRate)
	}

	// Engine overhead is measured over a real campaign, not the bare executor.
	c := newCampaign(t, buildTarget(t, "simple_parser"),
		[][]byte{[]byte("Z\x00"), []byte("B\x01\x02")}, "", 0x7A1B2C3D, nil)
	stats, err := c.engine.Run(context.Background(), Budget{MaxTime: 5 * time.Second})
	if err != nil {
		t.Fatalf("campaign failed: %v", err)
	}
	t.Logf("campaign: %.0f exec/s over %d executions, engine overhead %.1f%%",
		stats.ExecsPerSecond(), stats.Execs, 100*stats.Overhead())
	if stats.Overhead() > 0.10 {
		t.Errorf("engine overhead was %.1f%%, above the 10%% budget in ASR-0007: the "+
			"fuzzer's own bookkeeping is costing more than the target", 100*stats.Overhead())
	}
}

// TestTimeoutIsEnforced checks that a looping target is actually stopped. A
// fuzzer that cannot stop one stops with it.
func TestTimeoutIsEnforced(t *testing.T) {
	target := buildTarget(t, "hang")
	fs := executor.NewForkServer("fs", safety.NewSpawner(), executor.ProcSpec{
		Path: target, Args: []string{target},
	})
	fs.Timeout = 300 * time.Millisecond
	if err := fs.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer fs.Close()

	start := time.Now()
	ek, err := fs.Run(context.Background(), executor.Input{Bytes: []byte("H")}, nil)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("a timeout must be an outcome, not an error: %v", err)
	}
	if ek != feedback.ExitTimeout {
		t.Errorf("a looping target produced %s, want timeout", ek)
	}
	if elapsed > 3*time.Second {
		t.Errorf("the timeout took %v to fire", elapsed)
	}

	// And the server must survive it, or one slow input ends the campaign.
	ek, err = fs.Run(context.Background(), executor.Input{Bytes: []byte("Z")}, nil)
	if err != nil {
		t.Fatalf("the fork server did not survive a timeout: %v", err)
	}
	if ek != feedback.ExitOK {
		t.Errorf("after a timeout, a benign input produced %s", ek)
	}
}

// TestCoverageGuidanceBeatsBlindFuzzing isolates the value of the feedback
// pipeline. With coverage guidance removed and everything else identical, the
// campaign should reach visibly less of the target — otherwise the feedback is
// not actually steering anything.
func TestCoverageGuidanceBeatsBlindFuzzing(t *testing.T) {
	if testing.Short() {
		t.Skip("comparative run is slow")
	}
	target := buildTarget(t, "simple_parser")
	seeds := [][]byte{[]byte("Z\x00")}
	budget := Budget{MaxExecs: 60_000, MaxTime: 30 * time.Second}

	guided := newCampaign(t, target, seeds, "", 0x6D1DED01, nil)
	gStats, err := guided.engine.Run(context.Background(), budget)
	if err != nil {
		t.Fatal(err)
	}

	// The blind arm keeps only its seeds: nothing a mutation discovers is ever
	// admitted, so every input is a mutation of the original seed.
	blind := newCampaign(t, target, seeds, "", 0x6D1DED01, nil)
	blind.engine.cfg.Feedback = feedback.Never()
	bStats, err := blind.engine.Run(context.Background(), budget)
	if err != nil {
		t.Fatal(err)
	}

	gFound, bFound := len(foundBugs(guided.engine)), len(foundBugs(blind.engine))
	t.Logf("guided: corpus %d, coverage %d, bugs %d, %d execs",
		gStats.CorpusSize, gStats.Coverage, gFound, gStats.Execs)
	t.Logf("blind:  corpus %d, coverage %d, bugs %d, %d execs",
		bStats.CorpusSize, bStats.Coverage, bFound, bStats.Execs)

	if gStats.CorpusSize <= bStats.CorpusSize {
		t.Errorf("the guided corpus (%d) did not grow past the blind one (%d); "+
			"the feedback pipeline is not steering", gStats.CorpusSize, bStats.CorpusSize)
	}
	if gFound < bFound {
		t.Errorf("guided fuzzing found %d bugs against blind fuzzing's %d", gFound, bFound)
	}
}

func TestEngineRejectsIncompleteConfiguration(t *testing.T) {
	full := func() Config {
		return Config{
			Executor:  executor.NewInProc("x", func([]byte) error { return nil }),
			Feedback:  feedback.Never(),
			Objective: feedback.NewHangObjective("hang"),
			Corpus:    corpus.New(),
			Schedule:  corpus.NewRandScheduler(),
			Mutators:  mutate.Default(),
			Codec:     codec.Raw{},
		}
	}
	cases := map[string]func(*Config){
		"no executor":  func(c *Config) { c.Executor = nil },
		"no feedback":  func(c *Config) { c.Feedback = nil },
		"no objective": func(c *Config) { c.Objective = nil },
		"no corpus":    func(c *Config) { c.Corpus = nil },
		"no schedule":  func(c *Config) { c.Schedule = nil },
		"no mutators":  func(c *Config) { c.Mutators = nil },
		"no codec":     func(c *Config) { c.Codec = nil },
	}
	for name, break_ := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := full()
			break_(&cfg)
			if _, err := New(cfg); err == nil {
				t.Error("expected the engine to refuse this configuration")
			}
		})
	}
	if _, err := New(full()); err != nil {
		t.Errorf("a complete configuration was rejected: %v", err)
	}
}

func TestEngineRefusesAnEmptyCorpus(t *testing.T) {
	e, err := New(Config{
		Executor:  executor.NewInProc("x", func([]byte) error { return nil }),
		Feedback:  feedback.Never(),
		Objective: feedback.NewHangObjective("hang"),
		Corpus:    corpus.New(),
		Schedule:  corpus.NewRandScheduler(),
		Mutators:  mutate.Default(),
		Codec:     codec.Raw{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.Run(context.Background(), Budget{MaxExecs: 10}); err == nil {
		t.Error("a campaign with no seeds must refuse to run rather than spin")
	}
}
