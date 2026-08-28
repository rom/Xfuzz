package store

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/rom/Xfuzz/pkg/corpus"
	"github.com/rom/Xfuzz/pkg/feedback"
)

// SaveTestcase persists a corpus entry: the payload as a blob, the metadata as
// a row.
//
// The order matters and is not an implementation detail. The blob is written
// first, so the only state a crash can leave behind is a blob nothing points at
// — which the collector reclaims. The reverse order would leave a row promising
// a payload that does not exist, which no amount of collection can repair.
//
// Re-saving a known entry updates its counters rather than failing. Two workers
// finding the same input is normal, and so is a scheduler flushing an entry
// whose fuzz count has moved on.
func (s *Store) SaveTestcase(ctx context.Context, campaignID int64, tc *corpus.Testcase) error {
	if _, err := s.blobs.Put(tc.Bytes); err != nil {
		return err
	}
	ops, err := encodeOps(tc.Prov.Ops)
	if err != nil {
		return err
	}
	discovered := tc.Meta.Discovered
	if discovered.IsZero() {
		discovered = s.now()
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO testcase
		   (campaign_id, digest, size, coverage, new_signal, exec_time_ns, depth,
		    fuzzed, children, favoured, discovered_at, parent, origin, worker, ops)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(campaign_id, digest) DO UPDATE SET
		   coverage   = excluded.coverage,
		   new_signal = excluded.new_signal,
		   fuzzed     = excluded.fuzzed,
		   children   = excluded.children,
		   favoured   = excluded.favoured`,
		campaignID, tc.ID.String(), tc.Meta.Size, tc.Meta.Coverage, tc.Meta.Score.NewSignal,
		int64(tc.Meta.ExecTime), tc.Meta.Depth, int64(tc.Meta.Fuzzed), int64(tc.Meta.Children),
		boolToInt(tc.Meta.Favoured), discovered.UTC().UnixNano(),
		digestOrEmpty(tc.Prov.Parent), tc.Prov.Origin, int64(tc.Prov.Worker), ops)
	if err != nil {
		return fmt.Errorf("store: saving testcase %s: %w", tc.ID.Short(), err)
	}
	return nil
}

// SaveTestcases persists a batch in one transaction.
//
// Batching is why the store stays off the hot path (ADR-0008): a campaign that
// admitted forty entries in a burst pays one commit, not forty. Blobs are
// written outside the transaction because they are idempotent and a failed
// commit leaving them behind is exactly the orphan case the collector handles.
func (s *Store) SaveTestcases(ctx context.Context, campaignID int64, tcs []*corpus.Testcase) error {
	if len(tcs) == 0 {
		return nil
	}
	for _, tc := range tcs {
		if _, err := s.blobs.Put(tc.Bytes); err != nil {
			return err
		}
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx,
		`INSERT INTO testcase
		   (campaign_id, digest, size, coverage, new_signal, exec_time_ns, depth,
		    fuzzed, children, favoured, discovered_at, parent, origin, worker, ops)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(campaign_id, digest) DO UPDATE SET
		   coverage   = excluded.coverage,
		   new_signal = excluded.new_signal,
		   fuzzed     = excluded.fuzzed,
		   children   = excluded.children,
		   favoured   = excluded.favoured`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, tc := range tcs {
		ops, err := encodeOps(tc.Prov.Ops)
		if err != nil {
			return err
		}
		discovered := tc.Meta.Discovered
		if discovered.IsZero() {
			discovered = s.now()
		}
		if _, err := stmt.ExecContext(ctx,
			campaignID, tc.ID.String(), tc.Meta.Size, tc.Meta.Coverage, tc.Meta.Score.NewSignal,
			int64(tc.Meta.ExecTime), tc.Meta.Depth, int64(tc.Meta.Fuzzed), int64(tc.Meta.Children),
			boolToInt(tc.Meta.Favoured), discovered.UTC().UnixNano(),
			digestOrEmpty(tc.Prov.Parent), tc.Prov.Origin, int64(tc.Prov.Worker), ops); err != nil {
			return fmt.Errorf("store: saving testcase %s: %w", tc.ID.Short(), err)
		}
	}
	return tx.Commit()
}

// Testcase loads one entry, payload included.
//
// The returned entry has no IR: the store keeps encoded bytes, and turning them
// back into a tree is the codec's job, which the store must not know about
// (ADR-0005 keeps the IR independent of any one format).
func (s *Store) Testcase(ctx context.Context, campaignID int64, d corpus.Digest) (*corpus.Testcase, error) {
	row := s.db.QueryRowContext(ctx, testcaseSelect+` WHERE campaign_id = ? AND digest = ?`,
		campaignID, d.String())
	tc, err := scanTestcase(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%w: testcase %s", ErrNotFound, d.Short())
	}
	if err != nil {
		return nil, err
	}
	tc.Bytes, err = s.blobs.Get(d)
	if err != nil {
		return nil, err
	}
	return tc, nil
}

// TestcaseQuery selects and orders a listing.
type TestcaseQuery struct {
	// FavouredOnly restricts the listing to the minimal covering set, which is
	// what a corpus export should carry.
	FavouredOnly bool

	// Order is "coverage", "size", or "discovered". Anything else is treated as
	// insertion order.
	Order string

	// Limit caps the result. Zero means no cap.
	Limit int

	// WithPayload loads each entry's bytes. Off by default: a listing for the
	// console wants metadata, and reading ten thousand payloads to render a
	// table would be absurd.
	WithPayload bool
}

// Testcases lists a campaign's corpus.
func (s *Store) Testcases(ctx context.Context, campaignID int64, q TestcaseQuery) ([]*corpus.Testcase, error) {
	var b strings.Builder
	b.WriteString(testcaseSelect)
	b.WriteString(` WHERE campaign_id = ?`)
	if q.FavouredOnly {
		b.WriteString(` AND favoured = 1`)
	}
	switch q.Order {
	case "coverage":
		b.WriteString(` ORDER BY coverage DESC, size ASC`)
	case "size":
		b.WriteString(` ORDER BY size ASC, coverage DESC`)
	case "discovered":
		b.WriteString(` ORDER BY discovered_at ASC`)
	default:
		b.WriteString(` ORDER BY id ASC`)
	}
	args := []any{campaignID}
	if q.Limit > 0 {
		b.WriteString(` LIMIT ?`)
		args = append(args, q.Limit)
	}

	rows, err := s.db.QueryContext(ctx, b.String(), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*corpus.Testcase
	for rows.Next() {
		tc, err := scanTestcase(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, tc)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if q.WithPayload {
		for _, tc := range out {
			if tc.Bytes, err = s.blobs.Get(tc.ID); err != nil {
				return nil, err
			}
		}
	}
	return out, nil
}

// CountTestcases returns how many entries and how many payload bytes a campaign
// holds.
func (s *Store) CountTestcases(ctx context.Context, campaignID int64) (count int64, bytes int64, err error) {
	err = s.db.QueryRowContext(ctx,
		`SELECT COUNT(*), COALESCE(SUM(size), 0) FROM testcase WHERE campaign_id = ?`,
		campaignID).Scan(&count, &bytes)
	return count, bytes, err
}

// DeleteTestcase removes an entry's row. The blob survives until collection,
// because another campaign may reference the same content.
func (s *Store) DeleteTestcase(ctx context.Context, campaignID int64, d corpus.Digest) error {
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM testcase WHERE campaign_id = ? AND digest = ?`, campaignID, d.String())
	return err
}

const testcaseSelect = `SELECT digest, size, coverage, new_signal, exec_time_ns, depth,
	fuzzed, children, favoured, discovered_at, parent, origin, worker, ops FROM testcase`

func scanTestcase(sc scanner) (*corpus.Testcase, error) {
	var (
		digest, parent, origin, ops string
		size, coverage, newSignal   int64
		execNS, depth               int64
		fuzzed, children, favoured  int64
		discovered, worker          int64
	)
	if err := sc.Scan(&digest, &size, &coverage, &newSignal, &execNS, &depth,
		&fuzzed, &children, &favoured, &discovered, &parent, &origin, &worker, &ops); err != nil {
		return nil, err
	}
	id, err := parseDigestHex(digest)
	if err != nil {
		return nil, err
	}
	decoded, err := decodeOps(ops)
	if err != nil {
		return nil, err
	}
	tc := &corpus.Testcase{
		ID: id,
		Meta: corpus.Metadata{
			Score:      feedback.Score{NewSignal: int(newSignal)},
			ExecTime:   time.Duration(execNS),
			Size:       int(size),
			Coverage:   int(coverage),
			Fuzzed:     uint64(fuzzed),
			Children:   uint64(children),
			Depth:      int(depth),
			Discovered: time.Unix(0, discovered).UTC(),
			Favoured:   favoured != 0,
		},
		Prov: corpus.Provenance{Ops: decoded, Worker: uint32(worker), Origin: origin},
	}
	if parent != "" {
		if tc.Prov.Parent, err = parseDigestHex(parent); err != nil {
			return nil, err
		}
	}
	return tc, nil
}

// encodeOps renders a provenance chain as JSON.
//
// JSON rather than a packed binary form because provenance is what a person
// reads when they want to know how an input came to exist, and a column they
// can read with sqlite3 is worth more than the bytes it costs. The column is
// written once per admitted entry, not per execution.
func encodeOps(ops []corpus.Op) (string, error) {
	if len(ops) == 0 {
		return "", nil
	}
	b, err := json.Marshal(ops)
	if err != nil {
		return "", fmt.Errorf("store: encoding provenance: %w", err)
	}
	return string(b), nil
}

func decodeOps(s string) ([]corpus.Op, error) {
	if s == "" {
		return nil, nil
	}
	var ops []corpus.Op
	if err := json.Unmarshal([]byte(s), &ops); err != nil {
		return nil, fmt.Errorf("store: decoding provenance: %w", err)
	}
	return ops, nil
}

func parseDigestHex(s string) (corpus.Digest, error) {
	var d corpus.Digest
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != len(d) {
		return d, fmt.Errorf("store: %q is not a digest", s)
	}
	copy(d[:], b)
	return d, nil
}

func digestOrEmpty(d corpus.Digest) string {
	if d.IsZero() {
		return ""
	}
	return d.String()
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
