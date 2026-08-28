package engine

import (
	"fmt"

	"github.com/rom/Xfuzz/pkg/corpus"

	"github.com/rom/Xfuzz/pkg/feedback"
	"github.com/rom/Xfuzz/pkg/rng"
)

// Snapshot is a worker's resumable state.
//
// It is deliberately not the whole engine. The corpus is already durable —
// every admitted entry is written when it is found — and the findings are
// already recorded. What only exists in memory is the accumulated coverage, the
// counters, and where each RNG stream stands, and that is exactly what this
// holds.
//
// The RNG positions are what make a resumed campaign a continuation rather than
// a fresh one that happens to share a corpus. Without them the streams restart
// from zero and the worker replays the same mutations it already tried; with
// them the sequence continues, which is the same property that makes a campaign
// reproducible in the first place (ASR-0008).
type Snapshot struct {
	// Coverage is the accumulated bucket map.
	Coverage []byte

	// Execs is the campaign's own clock — the number a resumed campaign
	// continues from, and the one that decides how much a kill cost.
	Execs uint64

	// CorpusSize is how many entries were live when the snapshot was taken, so
	// a resume can tell whether the corpus it loaded is the one this snapshot
	// describes.
	CorpusSize int

	// RNG holds each stream's position, keyed by "worker:stream".
	RNG map[string]uint64

	// Stats is the counter set at the moment of the snapshot. It is restored so
	// that a resumed campaign's totals are the campaign's, not the session's:
	// a report that resets its crash count on every restart is a report nobody
	// can use.
	Stats Stats
}

// streamNames are the streams a worker owns, in the order they are recorded.
//
// Named rather than numbered in the snapshot, because a snapshot outlives the
// build that wrote it and adding a stream must not silently shift the meaning
// of the ones already there.
var streamNames = map[rng.Stream]string{
	rng.StreamSeedSelect:    "seed-select",
	rng.StreamMutatorSelect: "mutator-select",
	rng.StreamMutatorParam:  "mutator-param",
	rng.StreamStructure:     "structure",
	rng.StreamSplice:        "splice",
}

// Snapshot captures the worker's resumable state.
func (e *Engine) Snapshot() Snapshot {
	s := Snapshot{
		Execs:      e.stats.Execs,
		CorpusSize: e.cfg.Corpus.Len(),
		RNG:        make(map[string]uint64, len(streamNames)),
		Stats:      e.Stats(),
	}
	if mf, ok := e.cfg.Feedback.(*feedback.MapFeedback); ok {
		s.Coverage = append([]byte(nil), mf.Virgin()...)
	}
	for stream, r := range e.streams() {
		s.RNG[e.streamKey(stream)] = r.Position()
	}
	return s
}

// Restore returns the worker to a snapshot's state.
//
// The corpus is not restored here: it is loaded separately, because a corpus is
// large and durable while a snapshot is small and volatile, and conflating them
// would mean rewriting the whole corpus on every checkpoint.
func (e *Engine) Restore(s Snapshot) error {
	if len(s.Coverage) > 0 {
		mf, ok := e.cfg.Feedback.(*feedback.MapFeedback)
		if !ok {
			return fmt.Errorf("engine: the snapshot carries a coverage map but this campaign " +
				"has no coverage feedback; resuming would discard it silently")
		}
		if err := mf.LoadVirgin(s.Coverage); err != nil {
			return fmt.Errorf("engine: restoring coverage: %w", err)
		}
	}
	for stream, r := range e.streams() {
		if pos, ok := s.RNG[e.streamKey(stream)]; ok {
			r.Seek(pos)
		}
	}
	e.stats = s.Stats
	e.stats.Elapsed = 0
	e.stats.StopReason = ""
	return nil
}

// streams returns the worker's RNG streams by name.
func (e *Engine) streams() map[rng.Stream]*rng.Rand {
	return map[rng.Stream]*rng.Rand{
		rng.StreamSeedSelect:    e.seedRand,
		rng.StreamSplice:        e.spliceR,
		rng.StreamMutatorParam:  e.mctx.Rand,
		rng.StreamMutatorSelect: e.mctx.Select,
		rng.StreamStructure:     e.mctx.Nodes,
	}
}

func (e *Engine) streamKey(s rng.Stream) string {
	return fmt.Sprintf("%d:%s", e.cfg.WorkerID, streamNames[s])
}

// LoadCorpus admits stored entries without executing them.
//
// A resume must not re-run the corpus. On a large corpus that is minutes of
// execution before the campaign does anything new, and it is unnecessary: the
// coverage those entries produced is in the checkpoint, and their measured
// timing and scores are in their own records. Re-running would replace real
// recorded measurements with fresh ones taken under different load, which is
// worse data as well as slower.
//
// Entries whose payload no longer decodes are skipped and counted rather than
// failing the resume: one unreadable entry must not cost a campaign its whole
// corpus.
func (e *Engine) LoadCorpus(entries []*corpus.Testcase) (loaded, skipped int, err error) {
	for _, tc := range entries {
		if len(tc.Bytes) == 0 {
			skipped++
			continue
		}
		node, decodeErr := e.cfg.Codec.Decode(nil, tc.Bytes)
		if decodeErr != nil {
			skipped++
			continue
		}
		entry := &corpus.Testcase{
			ID:    tc.ID,
			Input: node,
			Bytes: append([]byte(nil), tc.Bytes...),
			Meta:  tc.Meta,
			Prov:  tc.Prov,
		}
		if e.cfg.Corpus.Add(entry) {
			loaded++
		}
	}
	if loaded == 0 && len(entries) > 0 {
		return loaded, skipped, fmt.Errorf(
			"engine: none of the %d stored entries could be loaded; the campaign has no corpus to resume from",
			len(entries))
	}
	return loaded, skipped, nil
}
