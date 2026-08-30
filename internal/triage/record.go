package triage

import (
	"context"
	"fmt"

	"github.com/rom/Xfuzz/pkg/corpus"
)

// Recorder is what triage needs from a store.
//
// It is stated as an interface here rather than taking *store.Store so that
// this package does not depend on how findings are persisted — and so a test
// can watch what triage decided without a database in the way.
type Recorder interface {
	// PutBlob stores a minimised reproducer.
	PutBlob(ctx context.Context, data []byte) (corpus.Digest, error)

	// UpdateTriage records the verification and minimisation outcome, and
	// triage's own account of it. Never a person's notes: those are theirs.
	UpdateTriage(ctx context.Context, id int64, state string, trials int, rate float64,
		minimized corpus.Digest, minimizedSize int, diagnosis string) error

	// Rebucket files the finding under the bucket triage computed.
	Rebucket(ctx context.Context, findingID int64, strategy, signature string) error
}

// Record persists a triage result.
//
// A result carrying an error is not written. The finding stays in the state it
// was in, because "triage could not run" and "triage found nothing" must not
// look the same to whoever reads the campaign afterwards.
func Record(ctx context.Context, rec Recorder, res Result) error {
	if res.Err != nil {
		return res.Err
	}

	var digest corpus.Digest
	size := 0
	if len(res.Minimized) > 0 {
		d, err := rec.PutBlob(ctx, res.Minimized)
		if err != nil {
			return err
		}
		digest, size = d, len(res.Minimized)
	}

	diagnosis := res.Verify.String()
	if res.Minimize.OriginalSize > 0 {
		diagnosis += "; " + res.Minimize.String()
	}
	if err := rec.UpdateTriage(ctx, res.ID, res.State, res.Verify.Trials, res.Verify.Rate(),
		digest, size, diagnosis); err != nil {
		return err
	}
	if res.Signature == "" {
		return nil
	}
	if err := rec.Rebucket(ctx, res.ID, res.Strategy, res.Signature); err != nil {
		return fmt.Errorf("triage: filing finding %d under %s:%s: %w",
			res.ID, res.Strategy, res.Signature, err)
	}
	return nil
}
