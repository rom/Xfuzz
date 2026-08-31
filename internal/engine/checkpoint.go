package engine

import (
	"context"
	"fmt"

	"github.com/rom/Xfuzz/pkg/corpus"

	"github.com/rom/Xfuzz/pkg/executor"
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

	// A stateful campaign needs each entry's trace, and a trace only exists
	// once the entry has run.
	//
	// LoadCorpus deliberately admits without executing: on a resumed campaign
	// with a large corpus, running every entry costs minutes before any fuzzing
	// starts. But the state scheduler decides which message of a session to
	// mutate by looking up where that session got to, and an entry with no
	// trace gets the fallback — a uniformly random message. With the whole
	// corpus loaded this way that is every entry, so the state-then-message
	// split never engages at all and the campaign spends its budget on the
	// handshake. Measured: a campaign whose seeds contained a valid handshake
	// never reached the authenticated state.
	if loaded == 0 && len(entries) > 0 {
		return loaded, skipped, fmt.Errorf(
			"engine: none of the %d stored entries could be loaded; the campaign has no corpus to resume from",
			len(entries))
	}
	if e.cfg.State != nil {
		e.traceCorpus(context.Background())
	}
	return loaded, skipped, nil
}

// traceCorpus runs the entries that have no trace, so that they have one to be
// scheduled by.
//
// Only the ones that need it. LoadCorpus is also how a worker takes in the
// entries its siblings found, which arrives every few seconds for the length of
// a campaign — re-running the whole corpus each time would cost more executions
// than the campaign spends fuzzing, and would grow with the corpus rather than
// with what arrived.
//
// Best effort: an entry that fails to run keeps no trace and is scheduled
// without one, which is the same position it was in before. A failure here must
// not stop a campaign from starting, because the corpus is the thing it was
// going to fuzz.
func (e *Engine) traceCorpus(ctx context.Context) {
	for i := 0; i < e.cfg.Corpus.Len(); i++ {
		tc := e.cfg.Corpus.At(i)
		if e.cfg.State.HasTrace(tc.ID) {
			continue
		}
		ek, err := e.cfg.Executor.Run(ctx,
			executor.Input{Bytes: tc.Bytes, Node: tc.Input}, e.cfg.Observers)
		if err != nil {
			return
		}
		e.stats.Execs++
		e.cfg.State.Record(tc.ID)

		// An execution is an execution: if this entry is a finding, it is one
		// now rather than whenever a mutation happens to rediscover it.
		//
		// This pass exists to give each entry a state trace, and it ran the
		// entry without judging it — so a seed that already reproduced a bug was
		// admitted to the corpus in silence. On a fast tier that costs a few
		// thousand executions; on the driver tier, where an operator's seed is
		// usually the reproducer they are trying to minimise, the campaign can
		// run for its whole budget without ever saying what its first input
		// already showed.
		if found, f, oerr := e.cfg.Objective.IsFinding(e.cfg.Observers, ek); oerr == nil && found {
			e.record(f, tc.Bytes)
		}
	}
}
