//go:build integration

// M4's resume criterion: a campaign killed and resumed loses at most the
// checkpoint window.
//
// "Loses" is measured, not asserted. Two campaigns run from the same seed for
// the same total number of executions; one is interrupted and resumed. What the
// interruption cost is the difference between them, and the criterion is that it
// is bounded by how long ago the last checkpoint was — not by how long the
// campaign had been running.

package engine

import (
	"context"
	"testing"
	"time"

	"github.com/rom/Xfuzz/internal/store"
	"github.com/rom/Xfuzz/pkg/corpus"
)

func seedsForResume() [][]byte {
	return [][]byte{
		[]byte("Z\x00"),
		[]byte("A\x01xx"),
		[]byte("B\x01\x02"),
		[]byte("C\x00\x00\x00\x00\x00"),
	}
}

// persist writes a campaign's corpus and a checkpoint, as a daemon would.
func persist(t *testing.T, s *store.Store, campaignID int64, e *Engine) {
	t.Helper()
	ctx := context.Background()
	if err := s.SaveTestcases(ctx, campaignID, e.cfg.Corpus.Entries()); err != nil {
		t.Fatalf("saving the corpus: %v", err)
	}
	snap := e.Snapshot()
	if err := s.SaveCheckpoint(ctx, campaignID, &store.Checkpoint{
		Coverage:     snap.Coverage,
		Execs:        snap.Execs,
		CorpusSize:   snap.CorpusSize,
		RNGPositions: snap.RNG,
	}); err != nil {
		t.Fatalf("saving the checkpoint: %v", err)
	}
}

// reload restores a fresh engine from the store.
func reload(t *testing.T, s *store.Store, campaignID int64, e *Engine, stats Stats) {
	t.Helper()
	ctx := context.Background()

	entries, err := s.Testcases(ctx, campaignID, store.TestcaseQuery{WithPayload: true, Order: "discovered"})
	if err != nil {
		t.Fatalf("loading the corpus: %v", err)
	}
	loaded, skipped, err := e.LoadCorpus(entries)
	if err != nil {
		t.Fatalf("restoring the corpus: %v", err)
	}
	if skipped != 0 {
		t.Fatalf("%d of %d stored entries could not be decoded", skipped, len(entries))
	}
	if loaded != len(entries) {
		t.Fatalf("loaded %d of %d entries", loaded, len(entries))
	}

	cp, err := s.Checkpoint(ctx, campaignID)
	if err != nil {
		t.Fatalf("loading the checkpoint: %v", err)
	}
	stats.Execs = cp.Execs
	if err := e.Restore(Snapshot{
		Coverage:   cp.Coverage,
		Execs:      cp.Execs,
		CorpusSize: cp.CorpusSize,
		RNG:        cp.RNGPositions,
		Stats:      stats,
	}); err != nil {
		t.Fatalf("restoring the checkpoint: %v", err)
	}
}

func openStoreFor(t *testing.T) (*store.Store, int64) {
	t.Helper()
	s, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatalf("opening the store: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	c, err := s.CreateCampaign(context.Background(), "resume", "", "", 0x5EED)
	if err != nil {
		t.Fatal(err)
	}
	return s, c.ID
}

// TestResumeLosesNothingWhenTheCheckpointIsCurrent is the baseline: with a
// checkpoint taken at the moment of the kill, an interrupted campaign must end
// up where an uninterrupted one did.
func TestResumeLosesNothingWhenTheCheckpointIsCurrent(t *testing.T) {
	const half = 40_000
	budget := func(n uint64) Budget {
		return Budget{MaxExecs: n, MaxTime: 90 * time.Second}
	}

	// The control: one uninterrupted campaign of 2 x half executions.
	control := newCampaign(t, buildTarget(t, "simple_parser"), seedsForResume(), "", 0x5EED, nil)
	if _, err := control.engine.Run(context.Background(), budget(2*half)); err != nil {
		t.Fatalf("the control campaign: %v", err)
	}
	want := control.engine.Stats()

	// The interrupted one: half, checkpoint, kill, resume, half again.
	s, campaignID := openStoreFor(t)

	first := newCampaign(t, buildTarget(t, "simple_parser"), seedsForResume(), "", 0x5EED, nil)
	if _, err := first.engine.Run(context.Background(), budget(half)); err != nil {
		t.Fatalf("the first half: %v", err)
	}
	atKill := first.engine.Stats()
	persist(t, s, campaignID, first.engine)
	first.cleanup()

	second := newCampaign(t, buildTarget(t, "simple_parser"), nil, "", 0x5EED, nil)
	reload(t, s, campaignID, second.engine, atKill)

	resumedStart := second.engine.Stats()
	if resumedStart.Execs != atKill.Execs {
		t.Fatalf("the resumed campaign restarted its clock at %d, not %d",
			resumedStart.Execs, atKill.Execs)
	}
	if resumedStart.Coverage != atKill.Coverage {
		t.Fatalf("coverage after resume is %d, was %d at the kill: %d edges were lost",
			resumedStart.Coverage, atKill.Coverage, atKill.Coverage-resumedStart.Coverage)
	}
	if resumedStart.CorpusSize != atKill.CorpusSize {
		t.Fatalf("the corpus came back with %d entries, had %d",
			resumedStart.CorpusSize, atKill.CorpusSize)
	}

	if _, err := second.engine.Run(context.Background(), budget(2*half)); err != nil {
		t.Fatalf("the resumed half: %v", err)
	}
	got := second.engine.Stats()

	if got.Execs != want.Execs {
		t.Errorf("the resumed campaign ran %d executions, the control %d", got.Execs, want.Execs)
	}

	// The two campaigns are compared, not equated. A resumed worker does not
	// replay the executions that admitted the seeds — the coverage those
	// produced is in the checkpoint — so from the resume onwards the two runs
	// are offset by a handful of executions and explore differently from there.
	// Claiming byte-identity would be claiming something that is not true and
	// would fail on a different seed.
	//
	// What must hold is that the interruption did not cost the campaign its
	// accumulated work, which the checks above establish exactly. The
	// comparison here catches the failure that would matter: a resume that
	// leaves the campaign substantially behind an uninterrupted one.
	const tolerance = 0.8
	if float64(got.Coverage) < tolerance*float64(want.Coverage) {
		t.Errorf("the resumed campaign reached %d edges against the control's %d; "+
			"the interruption cost more than the %.0f%% tolerance",
			got.Coverage, want.Coverage, 100*(1-tolerance))
	}
	t.Logf("control: %d execs, %d edges, %d corpus, %d buckets",
		want.Execs, want.Coverage, want.CorpusSize, want.Buckets)
	t.Logf("resumed: %d execs, %d edges, %d corpus, %d buckets",
		got.Execs, got.Coverage, got.CorpusSize, got.Buckets)
}

// TestResumeLosesAtMostTheCheckpointWindow is the criterion itself: work done
// after the last checkpoint is lost, and nothing before it is.
func TestResumeLosesAtMostTheCheckpointWindow(t *testing.T) {
	const (
		checkpointAt = 30_000
		killAt       = 45_000 // 15,000 executions past the checkpoint
	)
	budget := func(n uint64) Budget { return Budget{MaxExecs: n, MaxTime: 90 * time.Second} }

	s, campaignID := openStoreFor(t)
	first := newCampaign(t, buildTarget(t, "simple_parser"), seedsForResume(), "", 0x5EED, nil)

	if _, err := first.engine.Run(context.Background(), budget(checkpointAt)); err != nil {
		t.Fatalf("running to the checkpoint: %v", err)
	}
	atCheckpoint := first.engine.Stats()
	persist(t, s, campaignID, first.engine)

	// The campaign keeps working past the checkpoint, and is then killed. The
	// corpus entries it found in that window are durable — they are written as
	// they are discovered — but the coverage map and the RNG positions are not.
	if _, err := first.engine.Run(context.Background(), budget(killAt)); err != nil {
		t.Fatalf("running past the checkpoint: %v", err)
	}
	atKill := first.engine.Stats()
	if err := s.SaveTestcases(context.Background(), campaignID, first.engine.cfg.Corpus.Entries()); err != nil {
		t.Fatal(err)
	}
	first.cleanup()

	second := newCampaign(t, buildTarget(t, "simple_parser"), nil, "", 0x5EED, nil)
	reload(t, s, campaignID, second.engine, atCheckpoint)
	resumed := second.engine.Stats()

	lost := atKill.Execs - resumed.Execs
	window := atKill.Execs - atCheckpoint.Execs
	if lost > window {
		t.Fatalf("the resume lost %d executions but the checkpoint window was only %d",
			lost, window)
	}
	if resumed.Execs != atCheckpoint.Execs {
		t.Fatalf("the resumed clock is %d, the checkpoint was at %d",
			resumed.Execs, atCheckpoint.Execs)
	}

	// Coverage found before the checkpoint must survive it. Coverage found in
	// the window is re-derivable from the corpus, which is durable — so the
	// entries survive even though the map does not.
	if resumed.Coverage < atCheckpoint.Coverage {
		t.Errorf("coverage fell from %d at the checkpoint to %d after resume",
			atCheckpoint.Coverage, resumed.Coverage)
	}
	if resumed.CorpusSize < atKill.CorpusSize {
		t.Errorf("the corpus came back with %d entries; %d were live at the kill, "+
			"and every one of those was written when it was found",
			resumed.CorpusSize, atKill.CorpusSize)
	}
	t.Logf("checkpoint at %d execs / %d edges; killed at %d execs / %d edges; "+
		"resumed at %d execs / %d edges / %d corpus (window %d, lost %d)",
		atCheckpoint.Execs, atCheckpoint.Coverage, atKill.Execs, atKill.Coverage,
		resumed.Execs, resumed.Coverage, resumed.CorpusSize, window, lost)
}

// TestResumeContinuesTheRNGRatherThanRestartingIt is what makes a resume a
// continuation. Without it the streams restart from zero and the worker spends
// its next hour replaying mutations it has already tried.
func TestResumeContinuesTheRNGRatherThanRestartingIt(t *testing.T) {
	s, campaignID := openStoreFor(t)
	c := newCampaign(t, buildTarget(t, "simple_parser"), seedsForResume(), "", 0x5EED, nil)
	if _, err := c.engine.Run(context.Background(), Budget{MaxExecs: 5000, MaxTime: 60 * time.Second}); err != nil {
		t.Fatal(err)
	}
	snap := c.engine.Snapshot()
	persist(t, s, campaignID, c.engine)
	c.cleanup()

	for name, pos := range snap.RNG {
		if pos == 0 {
			t.Errorf("stream %s is still at position 0 after 5000 executions", name)
		}
	}
	if len(snap.RNG) < 5 {
		t.Fatalf("the snapshot records %d streams; a worker has five", len(snap.RNG))
	}

	fresh := newCampaign(t, buildTarget(t, "simple_parser"), nil, "", 0x5EED, nil)
	before := fresh.engine.Snapshot()
	for name, pos := range before.RNG {
		if pos != 0 {
			t.Fatalf("a fresh engine's stream %s starts at %d", name, pos)
		}
	}
	reload(t, s, campaignID, fresh.engine, c.engine.Stats())
	after := fresh.engine.Snapshot()
	for name, want := range snap.RNG {
		if after.RNG[name] != want {
			t.Errorf("stream %s resumed at %d, was at %d", name, after.RNG[name], want)
		}
	}
}

// TestLoadCorpusSkipsUnreadableEntriesWithoutLosingTheRest — one corrupt entry
// must not cost a campaign its corpus.
func TestLoadCorpusSkipsUnreadableEntriesWithoutLosingTheRest(t *testing.T) {
	c := newCampaign(t, buildTarget(t, "simple_parser"), nil, "", 1, nil)
	entries := []*corpus.Testcase{
		corpus.NewTestcase(nil, []byte("A\x01xx")),
		{ID: corpus.DigestOf([]byte("gone"))}, // payload never loaded
		corpus.NewTestcase(nil, []byte("B\x01\x02")),
	}
	loaded, skipped, err := c.engine.LoadCorpus(entries)
	if err != nil {
		t.Fatal(err)
	}
	if loaded != 2 || skipped != 1 {
		t.Fatalf("loaded %d, skipped %d; want 2 and 1", loaded, skipped)
	}
	if _, _, err := c.engine.LoadCorpus([]*corpus.Testcase{{}}); err == nil {
		t.Fatal("a corpus where nothing could be loaded was accepted as a resume")
	}
}
