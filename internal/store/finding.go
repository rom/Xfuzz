package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/rom/Xfuzz/pkg/corpus"
	"github.com/rom/Xfuzz/pkg/feedback"
)

// Triage states. A finding moves through these as the triage worker gets to it;
// the fuzz loop never waits on the transition (ARCHITECTURE section 4).
const (
	TriageNew        = "new"        // recorded, not yet examined
	TriageVerified   = "verified"   // reproduces
	TriageFlaky      = "flaky"      // reproduces sometimes
	TriageMinimized  = "minimized"  // reduced, still reproduces, same bucket
	TriageUnverified = "unverified" // did not reproduce at all
)

// Bucket is a group of findings believed to share a root cause.
//
// Bucketing is a judgement, not a fact, which is why the strategy that produced
// a signature is stored alongside it. Two strategies disagreeing about whether
// two crashes are the same bug is information; silently overwriting one with
// the other is not.
type Bucket struct {
	ID          int64
	CampaignID  int64
	Strategy    string
	Signature   string
	Kind        string
	Summary     string
	Count       int64
	FirstSeenAt time.Time
}

// Finding is a crash, hang, or oracle violation with its reproducer.
type Finding struct {
	ID         int64
	CampaignID int64
	BucketID   int64

	// Digest addresses the input that produced it; Minimized addresses the
	// reduced input, once triage has produced one.
	Digest    corpus.Digest
	Minimized corpus.Digest

	// strategy and signature are the bucket this finding was classified into.
	// They are unexported because a finding must not be filed under a
	// half-assigned bucket: SetBucket takes both at once.
	strategy  string
	signature string

	OriginalSize  int
	MinimizedSize int

	feedback.Finding

	// ReproTrials is how many times verification ran the reproducer, and
	// ReproRate the fraction of those that reproduced. Trials is what separates
	// "we have not looked" from "it never reproduces": with a rate alone, zero
	// would have to mean both, and a finding nobody had examined would read as
	// one that had been examined and dismissed.
	ReproTrials int
	ReproRate   float64

	TriageState string
	Notes       string

	// FoundAtExec is the execution count when it was found — the campaign's own
	// clock, which unlike wall time is the same on a replay (ASR-0008).
	FoundAtExec uint64

	CreatedAt time.Time
	UpdatedAt time.Time
}

// Reduction reports how much minimisation shrank the reproducer.
func (f *Finding) Reduction() float64 {
	if f.OriginalSize <= 0 || f.MinimizedSize <= 0 {
		return 0
	}
	return 1 - float64(f.MinimizedSize)/float64(f.OriginalSize)
}

// SaveFinding records a finding and the bucket it belongs to.
//
// Bucket and finding are written in one transaction: a bucket whose count
// includes a finding that was not recorded would make the headline number a
// lie, and the headline number is what a person judges a campaign by.
func (s *Store) SaveFinding(ctx context.Context, f *Finding, payload []byte) error {
	if len(payload) > 0 {
		if _, err := s.blobs.Put(payload); err != nil {
			return err
		}
	}
	now := s.now().UTC()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	strategy := f.bucketStrategy()
	signature := f.bucketSignature()

	if _, err := tx.ExecContext(ctx,
		`INSERT INTO bucket (campaign_id, strategy, signature, kind, summary, count, first_seen_at)
		 VALUES (?, ?, ?, ?, ?, 0, ?)
		 ON CONFLICT(campaign_id, strategy, signature) DO NOTHING`,
		f.CampaignID, strategy, signature, f.Kind, f.Summary, now.UnixNano()); err != nil {
		return fmt.Errorf("store: recording bucket: %w", err)
	}
	var bucketID int64
	if err := tx.QueryRowContext(ctx,
		`SELECT id FROM bucket WHERE campaign_id = ? AND strategy = ? AND signature = ?`,
		f.CampaignID, strategy, signature).Scan(&bucketID); err != nil {
		return fmt.Errorf("store: reading bucket: %w", err)
	}
	f.BucketID = bucketID

	res, err := tx.ExecContext(ctx,
		`INSERT INTO finding
		   (campaign_id, bucket_id, digest, minimized_digest, original_size, minimized_size,
		    kind, summary, signal, detail, frames, repro_trials, repro_rate,
		    triage_state, notes, found_at_exec, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(campaign_id, digest) DO NOTHING`,
		f.CampaignID, bucketID, f.Digest.String(), digestOrEmpty(f.Minimized),
		f.OriginalSize, f.MinimizedSize, f.Kind, f.Summary, f.Signal, f.Detail,
		strings.Join(f.Frames, "\n"), f.ReproTrials, f.ReproRate,
		stateOrNew(f.TriageState), f.Notes, int64(f.FoundAtExec),
		now.UnixNano(), now.UnixNano())
	if err != nil {
		return fmt.Errorf("store: recording finding: %w", err)
	}
	inserted, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if inserted == 0 {
		// A duplicate reproducer. The bucket count already includes it; not
		// incrementing again is what keeps "how many times have we seen this"
		// meaningful.
		return tx.Commit()
	}
	if f.ID, err = res.LastInsertId(); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE bucket SET count = count + 1 WHERE id = ?`, bucketID); err != nil {
		return err
	}
	return tx.Commit()
}

// UpdateTriage records the outcome of triaging a finding.
func (s *Store) UpdateTriage(ctx context.Context, id int64, state string, trials int, reproRate float64,
	minimized corpus.Digest, minimizedSize int, notes string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE finding SET triage_state = ?, repro_trials = ?, repro_rate = ?,
		        minimized_digest = ?, minimized_size = ?, notes = ?, updated_at = ?
		 WHERE id = ?`,
		state, trials, reproRate, digestOrEmpty(minimized), minimizedSize, notes,
		s.now().UTC().UnixNano(), id)
	if err != nil {
		return fmt.Errorf("store: updating triage for finding %d: %w", id, err)
	}
	return nil
}

// Findings lists a campaign's findings, oldest first.
func (s *Store) Findings(ctx context.Context, campaignID int64) ([]*Finding, error) {
	rows, err := s.db.QueryContext(ctx, findingSelect+` WHERE campaign_id = ? ORDER BY id`, campaignID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*Finding
	for rows.Next() {
		f, err := scanFinding(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// FindingsInState lists findings awaiting or having reached a triage state.
// The triage worker uses it to pick up where it left off after a restart.
func (s *Store) FindingsInState(ctx context.Context, campaignID int64, state string) ([]*Finding, error) {
	rows, err := s.db.QueryContext(ctx,
		findingSelect+` WHERE campaign_id = ? AND triage_state = ? ORDER BY id`, campaignID, state)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*Finding
	for rows.Next() {
		f, err := scanFinding(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// Finding loads one finding by id.
func (s *Store) Finding(ctx context.Context, id int64) (*Finding, error) {
	row := s.db.QueryRowContext(ctx, findingSelect+` WHERE id = ?`, id)
	f, err := scanFinding(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%w: finding %d", ErrNotFound, id)
	}
	return f, err
}

// Buckets lists a campaign's buckets under one strategy, most frequent first.
func (s *Store) Buckets(ctx context.Context, campaignID int64, strategy string) ([]*Bucket, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, campaign_id, strategy, signature, kind, summary, count, first_seen_at
		 FROM bucket WHERE campaign_id = ? AND strategy = ? ORDER BY count DESC, id`,
		campaignID, strategy)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*Bucket
	for rows.Next() {
		var (
			b     Bucket
			first int64
		)
		if err := rows.Scan(&b.ID, &b.CampaignID, &b.Strategy, &b.Signature,
			&b.Kind, &b.Summary, &b.Count, &first); err != nil {
			return nil, err
		}
		b.FirstSeenAt = time.Unix(0, first).UTC()
		out = append(out, &b)
	}
	return out, rows.Err()
}

// CountBuckets returns how many distinct buckets a strategy produced. This is
// the number the planted-bug suites are graded against: a bucket count far above
// the number of planted bugs means the strategy is splitting one bug across many
// buckets, and far below means it is merging distinct ones.
func (s *Store) CountBuckets(ctx context.Context, campaignID int64, strategy string) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM bucket WHERE campaign_id = ? AND strategy = ?`,
		campaignID, strategy).Scan(&n)
	return n, err
}

const findingSelect = `SELECT id, campaign_id, bucket_id, digest, minimized_digest,
	original_size, minimized_size, kind, summary, signal, detail, frames,
	repro_trials, repro_rate, triage_state, notes, found_at_exec, created_at, updated_at FROM finding`

func scanFinding(sc scanner) (*Finding, error) {
	var (
		f                 Finding
		digest, minimized string
		frames            string
		foundAt           int64
		created, updated  int64
	)
	if err := sc.Scan(&f.ID, &f.CampaignID, &f.BucketID, &digest, &minimized,
		&f.OriginalSize, &f.MinimizedSize, &f.Kind, &f.Summary, &f.Signal, &f.Detail,
		&frames, &f.ReproTrials, &f.ReproRate, &f.TriageState, &f.Notes, &foundAt, &created, &updated); err != nil {
		return nil, err
	}
	var err error
	if f.Digest, err = parseDigestHex(digest); err != nil {
		return nil, err
	}
	if minimized != "" {
		if f.Minimized, err = parseDigestHex(minimized); err != nil {
			return nil, err
		}
	}
	if frames != "" {
		f.Frames = strings.Split(frames, "\n")
	}
	f.FoundAtExec = uint64(foundAt)
	f.CreatedAt = time.Unix(0, created).UTC()
	f.UpdatedAt = time.Unix(0, updated).UTC()
	return &f, nil
}

// bucketStrategy and bucketSignature let a caller pre-compute a bucket and pass
// it in Notes-free form. When a caller has not classified the finding, the store
// falls back to the crudest possible grouping — kind and summary — rather than
// inventing a signature it has no evidence for.
func (f *Finding) bucketStrategy() string {
	if f.strategy != "" {
		return f.strategy
	}
	return "kind"
}

func (f *Finding) bucketSignature() string {
	if f.signature != "" {
		return f.signature
	}
	return f.Kind + "|" + f.Summary
}

// SetBucket attaches a pre-computed bucket to a finding before it is saved.
func (f *Finding) SetBucket(strategy, signature string) {
	f.strategy, f.signature = strategy, signature
}

// Bucket returns the strategy and signature a finding will be filed under.
func (f *Finding) Bucket() (strategy, signature string) {
	return f.bucketStrategy(), f.bucketSignature()
}

func stateOrNew(s string) string {
	if s == "" {
		return TriageNew
	}
	return s
}
