package store

import (
	"context"
	"fmt"
	"time"

	"github.com/rom/Xfuzz/pkg/corpus"
)

// Budget caps what a campaign may occupy on disk.
//
// A fuzzing campaign left running is an unbounded producer: every new edge is a
// new corpus entry and nothing ever expires. Without a cap the failure mode is
// a full filesystem, which does not fail politely — it takes the campaign, the
// store, and often whatever else shares the disk.
type Budget struct {
	// MaxBytes caps total payload size for the campaign. Zero means unlimited.
	MaxBytes int64

	// MaxEntries caps the corpus entry count. Zero means unlimited.
	MaxEntries int64
}

// CullReport says what enforcement removed.
type CullReport struct {
	Removed    int
	BytesFreed int64
	Kept       int
	KeptBytes  int64
	Protected  int
	OverBudget bool
}

// Enforce brings a campaign back inside its budget by culling corpus entries.
//
// Two classes of entry are never culled. Favoured entries are the minimal set
// that covers everything the campaign has found: dropping one loses coverage
// outright, which is the one thing a corpus exists to hold. Entries that a
// finding references are the reproducers, and a bug report whose input has been
// garbage-collected is not a bug report.
//
// Among the rest, entries are ranked by coverage per byte and the cheapest are
// dropped first. That is the same quantity the scheduler favours, so culling
// removes what the campaign was already paying least attention to. Ties break on
// the digest, so two runs of the same campaign cull the same entries — a
// culling policy that depended on map iteration order would quietly break
// reproducibility (ASR-0008).
func (s *Store) Enforce(ctx context.Context, campaignID int64, b Budget) (CullReport, error) {
	var rep CullReport
	if b.MaxBytes <= 0 && b.MaxEntries <= 0 {
		count, bytes, err := s.CountTestcases(ctx, campaignID)
		rep.Kept, rep.KeptBytes = int(count), bytes
		return rep, err
	}

	protected, err := s.protectedDigests(ctx, campaignID)
	if err != nil {
		return rep, err
	}

	// Ordered worst-first: least coverage per byte at the front, so the loop can
	// stop as soon as the campaign is inside its budget.
	rows, err := s.db.QueryContext(ctx,
		`SELECT digest, size, coverage, favoured
		 FROM testcase WHERE campaign_id = ?
		 ORDER BY (CAST(coverage AS REAL) / MAX(size, 1)) ASC, digest ASC`, campaignID)
	if err != nil {
		return rep, err
	}
	type entry struct {
		digest string
		size   int64
	}
	var candidates []entry
	var totalBytes, totalCount int64
	for rows.Next() {
		var (
			digest   string
			size     int64
			coverage int64
			favoured int
		)
		if err := rows.Scan(&digest, &size, &coverage, &favoured); err != nil {
			rows.Close()
			return rep, err
		}
		totalBytes += size
		totalCount++
		if favoured != 0 || protected[digest] {
			rep.Protected++
			continue
		}
		candidates = append(candidates, entry{digest, size})
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return rep, err
	}

	over := func() bool {
		return (b.MaxBytes > 0 && totalBytes > b.MaxBytes) ||
			(b.MaxEntries > 0 && totalCount > b.MaxEntries)
	}
	if !over() {
		rep.Kept, rep.KeptBytes = int(totalCount), totalBytes
		return rep, nil
	}
	rep.OverBudget = true

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return rep, err
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx,
		`DELETE FROM testcase WHERE campaign_id = ? AND digest = ?`)
	if err != nil {
		return rep, err
	}
	defer stmt.Close()

	for _, c := range candidates {
		if !over() {
			break
		}
		if _, err := stmt.ExecContext(ctx, campaignID, c.digest); err != nil {
			return rep, fmt.Errorf("store: culling %s: %w", c.digest[:8], err)
		}
		totalBytes -= c.size
		totalCount--
		rep.Removed++
		rep.BytesFreed += c.size
	}
	if err := tx.Commit(); err != nil {
		return rep, err
	}

	rep.Kept, rep.KeptBytes = int(totalCount), totalBytes
	if over() {
		// Everything culllable is gone and the campaign is still over. Saying so
		// is the point: silently continuing would let the disk fill anyway, and
		// the operator needs to know the budget cannot be met without dropping
		// coverage or reproducers.
		return rep, fmt.Errorf(
			"store: campaign %d is over budget at %d entries / %d bytes after culling; "+
				"the remainder is %d protected entries (favoured or referenced by findings)",
			campaignID, totalCount, totalBytes, rep.Protected)
	}
	return rep, nil
}

// protectedDigests returns every payload a finding depends on.
func (s *Store) protectedDigests(ctx context.Context, campaignID int64) (map[string]bool, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT digest FROM finding WHERE campaign_id = ?
		 UNION
		 SELECT minimized_digest FROM finding WHERE campaign_id = ? AND minimized_digest != ''`,
		campaignID, campaignID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := map[string]bool{}
	for rows.Next() {
		var d string
		if err := rows.Scan(&d); err != nil {
			return nil, err
		}
		out[d] = true
	}
	return out, rows.Err()
}

// GCReport says what blob collection removed.
type GCReport struct {
	Scanned    int
	Removed    int
	BytesFreed int64
	Retained   int
}

// CollectBlobs removes payloads no row refers to.
//
// Blobs outlive their rows on purpose: a culled corpus entry, a deleted
// campaign, and an interrupted write all leave a blob behind, and content
// addressing means the same blob may be reachable from several campaigns at
// once. Deciding reachability is therefore a whole-store question, answered
// here rather than at each deletion.
//
// Blobs younger than grace are kept regardless. A blob is written before the row
// that points at it, so there is always a window in which a live payload is
// unreferenced; collecting inside that window would delete a corpus entry the
// instant before it was recorded.
func (s *Store) CollectBlobs(ctx context.Context, grace time.Duration) (GCReport, error) {
	var rep GCReport

	live, err := s.liveDigests(ctx)
	if err != nil {
		return rep, err
	}
	cutoff := s.now().Add(-grace)

	var doomed []corpus.Digest
	err = s.blobs.Walk(func(d corpus.Digest, size int64) error {
		rep.Scanned++
		if live[d.String()] {
			rep.Retained++
			return nil
		}
		fi, err := s.blobs.stat(d)
		if err != nil {
			return err
		}
		if fi.ModTime().After(cutoff) {
			rep.Retained++
			return nil
		}
		doomed = append(doomed, d)
		rep.BytesFreed += size
		return nil
	})
	if err != nil {
		return rep, err
	}
	for _, d := range doomed {
		if err := s.blobs.Delete(d); err != nil {
			return rep, err
		}
		rep.Removed++
	}
	return rep, nil
}

// liveDigests collects every digest any row refers to, across all campaigns.
func (s *Store) liveDigests(ctx context.Context) (map[string]bool, error) {
	out := map[string]bool{}
	for _, q := range []string{
		`SELECT digest FROM testcase`,
		`SELECT digest FROM finding`,
		`SELECT minimized_digest FROM finding WHERE minimized_digest != ''`,
	} {
		rows, err := s.db.QueryContext(ctx, q)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var d string
			if err := rows.Scan(&d); err != nil {
				rows.Close()
				return nil, err
			}
			out[d] = true
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}
