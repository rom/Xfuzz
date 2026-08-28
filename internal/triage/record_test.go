package triage

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/rom/Xfuzz/internal/store"
	"github.com/rom/Xfuzz/pkg/corpus"
	"github.com/rom/Xfuzz/pkg/feedback"
)

func openStore(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatalf("opening the store: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// The store satisfies Recorder without either package knowing about the other's
// concrete types. This is a compile-time assertion of that.
var _ Recorder = (*store.Store)(nil)

func TestRecordPersistsATriageResult(t *testing.T) {
	s := openStore(t)
	ctx := context.Background()
	c, err := s.CreateCampaign(ctx, "c", "", 1)
	if err != nil {
		t.Fatal(err)
	}

	original := []byte(strings.Repeat("x", 400) + "BOOM")
	f := &store.Finding{
		CampaignID:   c.ID,
		Digest:       corpus.DigestOf(original),
		OriginalSize: len(original),
		Finding:      feedback.Finding{Kind: "crash", Summary: "SIGSEGV", Signal: 11},
	}
	f.SetBucket("signal", "crash/sig11")
	if err := s.SaveFinding(ctx, f, original); err != nil {
		t.Fatal(err)
	}

	r := &fakeRunner{fn: func(in []byte) Outcome {
		if bytes.Contains(in, []byte("BOOM")) {
			return crash(11, "")
		}
		return ok()
	}}
	w := NewWorker(Config{Runner: r, Trials: 3, Strategy: SignalStrategy{}})
	res := w.Triage(ctx, Job{ID: f.ID, Input: original})
	if err := Record(ctx, s, res); err != nil {
		t.Fatalf("Record: %v", err)
	}

	got, err := s.Finding(ctx, f.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.TriageState != store.TriageMinimized {
		t.Fatalf("state = %q", got.TriageState)
	}
	if got.ReproTrials != 3 || got.ReproRate != 1 {
		t.Fatalf("verification not recorded: trials=%d rate=%v", got.ReproTrials, got.ReproRate)
	}
	if got.Minimized.IsZero() {
		t.Fatal("no minimised reproducer was stored")
	}
	if got.Reduction() < 0.8 {
		t.Fatalf("recorded reduction = %.2f", got.Reduction())
	}
	if !strings.Contains(got.Notes, "reproduced") {
		t.Fatalf("notes = %q", got.Notes)
	}

	payload, err := s.Blobs().Get(got.Minimized)
	if err != nil {
		t.Fatalf("the minimised payload is not in the blob store: %v", err)
	}
	if !bytes.Contains(payload, []byte("BOOM")) {
		t.Fatalf("stored payload = %q", payload)
	}
}

func TestRecordMovesTheFindingToItsTriagedBucket(t *testing.T) {
	s := openStore(t)
	ctx := context.Background()
	c, _ := s.CreateCampaign(ctx, "c", "", 1)

	// Two findings the engine could only file by signal, which merges them.
	// Triage, with coverage to work from, separates them — and the bucket count
	// has to follow.
	inputs := map[string][]byte{"first": []byte("BOOM-A"), "second": []byte("BOOM-B")}
	ids := map[string]int64{}
	for name, in := range inputs {
		f := &store.Finding{
			CampaignID: c.ID, Digest: corpus.DigestOf(in), OriginalSize: len(in),
			Finding: feedback.Finding{Kind: "crash", Signal: 11},
		}
		f.SetBucket("signal", "crash/sig11")
		if err := s.SaveFinding(ctx, f, in); err != nil {
			t.Fatal(err)
		}
		ids[name] = f.ID
	}
	if n, _ := s.CountBuckets(ctx, c.ID, "signal"); n != 1 {
		t.Fatalf("the engine filed %d signal buckets, want 1", n)
	}

	r := &fakeRunner{fn: func(in []byte) Outcome {
		m := make([]byte, 16)
		if bytes.Contains(in, []byte("A")) {
			m[1] = 1
		} else {
			m[2] = 1
		}
		return Outcome{Exit: feedback.ExitCrash, Signal: 11, Coverage: m}
	}}
	w := NewWorker(Config{Runner: r, Trials: 1, SkipMinimize: true, Strategy: CoverageStrategy{}})
	for name, in := range inputs {
		res := w.Triage(ctx, Job{ID: ids[name], Input: in})
		if err := Record(ctx, s, res); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}

	n, err := s.CountBuckets(ctx, c.ID, "coverage")
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("triage produced %d coverage buckets, want 2", n)
	}
	// The provisional bucket had both findings and now has none, so it must be
	// gone: an empty bucket left behind inflates every count taken from the
	// table.
	if n, _ := s.CountBuckets(ctx, c.ID, "signal"); n != 0 {
		t.Fatalf("%d empty signal buckets survived", n)
	}
}

func TestRecordLeavesTheFindingAloneWhenTriageFailed(t *testing.T) {
	s := openStore(t)
	ctx := context.Background()
	c, _ := s.CreateCampaign(ctx, "c", "", 1)

	in := []byte("input")
	f := &store.Finding{CampaignID: c.ID, Digest: corpus.DigestOf(in),
		Finding: feedback.Finding{Kind: "crash"}}
	f.SetBucket("signal", "crash")
	if err := s.SaveFinding(ctx, f, in); err != nil {
		t.Fatal(err)
	}

	err := Record(ctx, s, Result{ID: f.ID, Err: context.Canceled})
	if err == nil {
		t.Fatal("Record swallowed the triage error")
	}
	got, _ := s.Finding(ctx, f.ID)
	if got.TriageState != store.TriageNew {
		t.Fatalf("state = %q; a failed triage must not be recorded as a result", got.TriageState)
	}
}

func TestRecordDistinguishesUnverifiedFromUnexamined(t *testing.T) {
	s := openStore(t)
	ctx := context.Background()
	c, _ := s.CreateCampaign(ctx, "c", "", 1)

	in := []byte("was a crash, once")
	f := &store.Finding{CampaignID: c.ID, Digest: corpus.DigestOf(in),
		Finding: feedback.Finding{Kind: "crash"}}
	f.SetBucket("signal", "crash")
	if err := s.SaveFinding(ctx, f, in); err != nil {
		t.Fatal(err)
	}

	r := &fakeRunner{fn: func([]byte) Outcome { return ok() }}
	w := NewWorker(Config{Runner: r, Trials: 4, Strategy: SignalStrategy{}})
	if err := Record(ctx, s, w.Triage(ctx, Job{ID: f.ID, Input: in})); err != nil {
		t.Fatal(err)
	}

	got, _ := s.Finding(ctx, f.ID)
	if got.TriageState != store.TriageUnverified {
		t.Fatalf("state = %q", got.TriageState)
	}
	if got.ReproTrials != 4 {
		t.Fatalf("trials = %d; the record must show it was examined", got.ReproTrials)
	}
	if got.ReproRate != 0 {
		t.Fatalf("rate = %v", got.ReproRate)
	}
}
