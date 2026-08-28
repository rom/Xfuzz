package store

import (
	"bytes"
	"compress/flate"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"
)

// Checkpoint is everything needed to resume a campaign where it stopped.
//
// It is deliberately small. A checkpoint does not contain the corpus — that is
// already durable, entry by entry, as it is discovered — only the state that
// lives in the worker's memory and would otherwise be lost: which edges have
// been seen, how far the campaign has got, and where each RNG stream stands.
//
// What resume costs is bounded by the checkpoint interval, and what it costs is
// re-discovery of coverage, not loss of it: a resumed campaign that has
// forgotten a few edges re-finds them from a corpus it still has.
type Checkpoint struct {
	// Coverage is the accumulated map. Its length is part of the checkpoint:
	// resuming into a differently sized map is refused rather than truncated,
	// because a map of a different size is a different edge encoding and the
	// coverage would silently mean something else.
	Coverage []byte

	// Execs is the campaign's own clock.
	Execs uint64

	// CorpusSize is how many entries were live, so a resume can tell whether
	// the metadata it loaded matches the checkpoint it is resuming from.
	CorpusSize int

	// RNGPositions records each stream's counter, keyed by "worker:stream".
	// With the campaign seed this is what makes a resumed run continue the same
	// sequence rather than start a correlated one (ASR-0008).
	RNGPositions map[string]uint64

	SavedAt time.Time
}

// ErrNoCheckpoint is returned when a campaign has never been checkpointed.
var ErrNoCheckpoint = errors.New("store: no checkpoint")

// SaveCheckpoint writes a campaign's resume state.
//
// The write is a single-row upsert inside a transaction, which is what makes it
// atomic: a checkpoint is either wholly the old one or wholly the new one. A
// half-written checkpoint would be worse than none, because resume would trust
// it.
func (s *Store) SaveCheckpoint(ctx context.Context, campaignID int64, cp *Checkpoint) error {
	blob, err := packCoverage(cp.Coverage)
	if err != nil {
		return err
	}
	positions, err := json.Marshal(cp.RNGPositions)
	if err != nil {
		return fmt.Errorf("store: encoding RNG positions: %w", err)
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO checkpoint (campaign_id, coverage, execs, corpus_size, rng_positions, saved_at)
		 VALUES (?, ?, ?, ?, ?, ?)
		 ON CONFLICT(campaign_id) DO UPDATE SET
		   coverage      = excluded.coverage,
		   execs         = excluded.execs,
		   corpus_size   = excluded.corpus_size,
		   rng_positions = excluded.rng_positions,
		   saved_at      = excluded.saved_at`,
		campaignID, blob, int64(cp.Execs), cp.CorpusSize, string(positions),
		s.now().UTC().UnixNano())
	if err != nil {
		return fmt.Errorf("store: saving checkpoint: %w", err)
	}
	return nil
}

// Checkpoint loads a campaign's resume state.
func (s *Store) Checkpoint(ctx context.Context, campaignID int64) (*Checkpoint, error) {
	var (
		blob      []byte
		execs     int64
		size      int
		positions string
		saved     int64
	)
	err := s.db.QueryRowContext(ctx,
		`SELECT coverage, execs, corpus_size, rng_positions, saved_at
		 FROM checkpoint WHERE campaign_id = ?`, campaignID).
		Scan(&blob, &execs, &size, &positions, &saved)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%w for campaign %d", ErrNoCheckpoint, campaignID)
	}
	if err != nil {
		return nil, err
	}
	cov, err := unpackCoverage(blob)
	if err != nil {
		return nil, err
	}
	cp := &Checkpoint{
		Coverage:   cov,
		Execs:      uint64(execs),
		CorpusSize: size,
		SavedAt:    time.Unix(0, saved).UTC(),
	}
	if positions != "" {
		if err := json.Unmarshal([]byte(positions), &cp.RNGPositions); err != nil {
			return nil, fmt.Errorf("store: decoding RNG positions: %w", err)
		}
	}
	return cp, nil
}

// packCoverage compresses a coverage map.
//
// Coverage maps are mostly zero — a campaign that has covered ten thousand
// edges of a 64 KiB map leaves most of it untouched — so this is close to free
// on the write and turns a checkpoint from tens of kilobytes into hundreds of
// bytes. The length is stored so unpacking can restore exactly the original
// size rather than whatever the decompressor happened to produce.
func packCoverage(cov []byte) ([]byte, error) {
	if len(cov) == 0 {
		return nil, nil
	}
	var buf bytes.Buffer
	var hdr [8]byte
	putUint64(hdr[:], uint64(len(cov)))
	buf.Write(hdr[:])

	w, err := flate.NewWriter(&buf, flate.BestSpeed)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(cov); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func unpackCoverage(b []byte) ([]byte, error) {
	if len(b) == 0 {
		return nil, nil
	}
	if len(b) < 8 {
		return nil, fmt.Errorf("store: checkpoint coverage is truncated (%d bytes)", len(b))
	}
	n := getUint64(b[:8])
	if n > 1<<30 {
		return nil, fmt.Errorf("store: checkpoint claims a %d-byte coverage map", n)
	}
	out := make([]byte, n)
	r := flate.NewReader(bytes.NewReader(b[8:]))
	defer r.Close()
	if _, err := io.ReadFull(r, out); err != nil {
		return nil, fmt.Errorf("store: decompressing checkpoint coverage: %w", err)
	}
	return out, nil
}

func putUint64(b []byte, v uint64) {
	for i := 0; i < 8; i++ {
		b[i] = byte(v >> (8 * i))
	}
}

func getUint64(b []byte) uint64 {
	var v uint64
	for i := 0; i < 8; i++ {
		v |= uint64(b[i]) << (8 * i)
	}
	return v
}
