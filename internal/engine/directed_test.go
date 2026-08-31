package engine

import (
	"testing"
	"time"

	"github.com/rom/Xfuzz/internal/platform"
	"github.com/rom/Xfuzz/internal/safety"
	"github.com/rom/Xfuzz/pkg/binary"
	"github.com/rom/Xfuzz/pkg/codec"
	"github.com/rom/Xfuzz/pkg/corpus"
	"github.com/rom/Xfuzz/pkg/executor"
	"github.com/rom/Xfuzz/pkg/feedback"
	"github.com/rom/Xfuzz/pkg/mutate"
)

// Directed fuzzing is a claim about where a campaign spends its budget, so it
// can only be tested by comparison, and the comparison has to isolate the one
// thing that differs.
//
// Both campaigns here are instrumented identically and both are measured against
// the same distance map. What differs is only the guidance: one puts the
// distance feedback in its stack and weights its schedule by closeness, and the
// other does not. Comparing "did it find the bug" would measure luck — a bug a
// coverage-guided campaign can also reach says nothing, and one it cannot says
// only that this seed did not. Comparing how close each campaign *got* measures
// the claim itself, with far less variance.
//
// The target's shape is what makes it meaningful: a bug four calls down one
// branch, and twelve sibling branches full of code that produces new coverage
// and leads nowhere.

type directedResult struct {
	stats   Stats
	closest float64
	reached bool
}

func TestDirectionSpendsTheBudgetWhereItWasAimed(t *testing.T) {
	if testing.Short() {
		t.Skip("this runs two campaigns")
	}
	directed := runDeepCampaign(t, true)
	undirected := runDeepCampaign(t, false)

	t.Logf("directed:   %d execs, %d coverage, %d corpus, %d findings, closest %.2f blocks",
		directed.stats.Execs, directed.stats.Coverage, directed.stats.CorpusSize,
		directed.stats.Findings, directed.closest)
	t.Logf("undirected: %d execs, %d coverage, %d corpus, %d findings, closest %.2f blocks",
		undirected.stats.Execs, undirected.stats.Coverage, undirected.stats.CorpusSize,
		undirected.stats.Findings, undirected.closest)

	if !directed.reached {
		t.Fatal("the directed campaign never executed a block with a distance to the " +
			"target, so the distance map and the block trace are not meeting: either " +
			"the target is not reporting its blocks or their addresses are not being " +
			"related back to the binary")
	}
	if !undirected.reached {
		t.Fatal("the undirected campaign produced no distance measurement, so there is " +
			"nothing to compare against")
	}
	if directed.closest > undirected.closest {
		t.Errorf("the directed campaign got no closer than %.2f blocks from its target and "+
			"the undirected one reached %.2f, with the same seed, the same budget and the "+
			"same instrumentation. Direction is only worth its cost if it arrives somewhere "+
			"coverage alone does not", directed.closest, undirected.closest)
	}
}

// runDeepCampaign fuzzes deep_target for a fixed budget, aimed at the bug's
// function or not aimed at all.
func runDeepCampaign(t *testing.T, directed bool) directedResult {
	t.Helper()
	target := buildTarget(t, "deep_target")

	provider := platform.NewSharedMemoryProvider()
	if !provider.Available() {
		t.Skip("shared memory is unavailable; this needs the fork server")
	}
	shm, err := provider.Create(feedback.DefaultMapSize)
	if err != nil {
		t.Fatalf("creating the coverage region: %v", err)
	}
	defer shm.Close()

	cov := feedback.NewCoverageMap("coverage", feedback.DefaultMapSize)
	cov.SetBuffer(shm.Bytes())
	cov.SetBackend("sancov")
	out := feedback.NewOutputObserver("output")

	fs := executor.NewForkServer("forkserver", safety.NewSpawner(), executor.ProcSpec{
		Path: target, Args: []string{target},
	})
	fs.Coverage, fs.Shm, fs.Output = cov, shm, out
	fs.Timeout = time.Second

	// The measurement, on both campaigns. The undirected one is instrumented and
	// scored identically and simply does not act on the score, so the comparison
	// isolates the guidance rather than the instrumentation's cost.
	im, oerr := binary.Open(target)
	if oerr != nil {
		t.Fatal(oerr)
	}
	defer im.Close()
	if im.Arch != binary.ArchAMD64 {
		t.Skipf("this host is %v; the distance map is amd64 only", im.Arch)
	}
	addrs, rerr := binary.Resolve(im, []binary.TargetSpec{"level4"})
	if rerr != nil {
		t.Skipf("the fixture's target function is not in the symbol table: %v", rerr)
	}
	analysis, aerr := binary.Analyze(im)
	if aerr != nil {
		t.Fatal(aerr)
	}
	dist, derr := binary.BuildDistanceMap(analysis, addrs)
	if derr != nil {
		t.Fatal(derr)
	}
	anchor, ok := im.Lookup(blockAnchor)
	if !ok {
		t.Skipf("the target carries no %s symbol to recover its load base from", blockAnchor)
	}
	bbShm, berr := provider.Create(feedback.BlockRegionSize)
	if berr != nil {
		t.Fatalf("creating the block-trace region: %v", berr)
	}
	defer bbShm.Close()
	fs.BlockShm = bbShm

	blocks := feedback.NewBlockObserver("blocks", bbShm.Bytes())
	blocks.SetAnchor(anchor)

	observers := []feedback.Observer{cov, out, blocks}
	dfb := feedback.NewDistanceFeedback("distance", blocks, dist)
	fb := feedback.Feedback(feedback.NewMapFeedback("coverage", cov))
	schedule := corpus.NewFastScheduler()

	if directed {
		t.Logf("distance map: %d of %d blocks reach the target (%.0f%%), furthest %d",
			dist.Reachable, len(analysis.Blocks), 100*dist.Coverage(analysis), dist.Max)
		fb = feedback.Any(fb, dfb)
		schedule.Directed = corpus.DefaultDirectedWeight
	} else {
		// Measured but not acted on: the feedback is asked how close every
		// execution came, and its answer changes nothing about what is kept or
		// what is fuzzed next.
		fb = feedback.Any(fb, observeOnly{dfb})
	}

	if err := fs.Start(t.Context()); err != nil {
		t.Skipf("the fork server would not start: %v", err)
	}
	defer fs.Close()

	e, err := New(Config{
		CampaignSeed:  0xD1EC,
		Executor:      fs,
		Observers:     observers,
		Feedback:      fb,
		Objective:     feedback.NewCrashObjective("crash", out),
		Corpus:        corpus.New(),
		Schedule:      schedule,
		Mutators:      mutate.Default(),
		Codec:         codec.Raw{},
		MaxInputBytes: 4096,
		MaxChildren:   64,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, seed := range [][]byte{{'A'}, {'Z', 'z', 'z', 'z'}, {'Q', 'q'}} {
		if err := e.AddSeed(t.Context(), seed, "seed"); err != nil {
			t.Fatal(err)
		}
	}

	stats, err := e.Run(t.Context(), Budget{MaxExecs: 40000})
	if err != nil {
		t.Fatalf("running the campaign: %v", err)
	}
	res := directedResult{stats: stats}
	if dfb != nil {
		res.closest, res.reached = dfb.Closest()
	}
	return res
}

// blockAnchor is the symbol the runtime publishes the runtime address of, so a
// position-independent target's load base can be recovered. It matches
// internal/worker's constant, and is duplicated rather than exported because it
// is a property of the C runtime rather than of either package.
const blockAnchor = "xfuzz_map"

// observeOnly wraps a feedback so that its measurement is taken and its verdict
// ignored.
//
// It is what makes the comparison fair. The undirected campaign has to run the
// same instrumentation and take the same measurement — otherwise the two
// campaigns differ in throughput as well as in guidance, and the result would
// confound the two. What it must not do is let the measurement change which
// inputs are kept.
type observeOnly struct{ f feedback.Feedback }

func (o observeOnly) Name() string { return "observed(" + o.f.Name() + ")" }

func (o observeOnly) IsInteresting(obs []feedback.Observer, ek feedback.ExitKind) (bool, feedback.Score, error) {
	interesting, score, err := o.f.IsInteresting(obs, ek)
	if err != nil {
		return false, feedback.Score{}, err
	}
	if interesting {
		// Committed so the wrapped feedback keeps tracking its own best, which
		// is the number being compared; discarded from the caller's point of
		// view so nothing is admitted for it.
		o.f.Append()
	} else {
		o.f.Discard()
	}
	return false, feedback.Score{Distance: score.Distance}, nil
}

func (o observeOnly) Append()  {}
func (o observeOnly) Discard() {}
