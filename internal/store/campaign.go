package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// Campaign statuses. A campaign's status is a fact about the store, not about a
// running process: a daemon that dies leaves a campaign at "running", and
// resume is what reconciles that.
const (
	StatusCreated  = "created"
	StatusRunning  = "running"
	StatusPaused   = "paused"
	StatusFinished = "finished"
	StatusFailed   = "failed"
)

// ErrNoCampaign is returned when a named campaign does not exist.
var ErrNoCampaign = errors.New("store: no such campaign")

// Campaign is a persisted fuzzing run.
type Campaign struct {
	ID   int64
	Name string

	// ConfigDigest pins the resolved configuration this campaign ran under.
	// Resuming with a different configuration is a different campaign, and
	// recording the digest is what makes that detectable rather than a silent
	// change of meaning halfway through a corpus.
	ConfigDigest string

	// Seed is the campaign's root RNG seed. With the configuration digest it is
	// half of what a byte-identical replay needs (ASR-0008).
	Seed uint64

	// ConfigDocument is the resolved campaign file this ran under.
	//
	// Kept beside the digest because the digest pins what ran and cannot say
	// what ran. Without it, triaging a finished campaign means finding the file
	// that produced it — and a store whose findings cannot be read without a
	// file kept somewhere else is not the durable record it is meant to be.
	// Empty on a campaign written before this was recorded.
	ConfigDocument string

	Status    string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// CreateCampaign records a new campaign. Names are unique: a campaign is
// addressed by name from the CLI, and two runs sharing one would make "resume"
// ambiguous.
func (s *Store) CreateCampaign(ctx context.Context, name, configDigest, configDocument string,
	seed uint64) (*Campaign, error) {

	now := s.now().UTC()
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO campaign (name, config_digest, config_document, seed, status, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		name, configDigest, configDocument, int64(seed), StatusCreated, now.UnixNano(), now.UnixNano())
	if err != nil {
		return nil, fmt.Errorf("store: creating campaign %q: %w", name, err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return nil, err
	}
	return &Campaign{
		ID: id, Name: name, ConfigDigest: configDigest, ConfigDocument: configDocument,
		Seed: seed, Status: StatusCreated, CreatedAt: now, UpdatedAt: now,
	}, nil
}

// Campaign looks a campaign up by name.
func (s *Store) Campaign(ctx context.Context, name string) (*Campaign, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, name, config_digest, config_document, seed, status, created_at, updated_at
		 FROM campaign WHERE name = ?`, name)
	c, err := scanCampaign(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%w: %q", ErrNoCampaign, name)
	}
	return c, err
}

// Campaigns lists every campaign, oldest first.
func (s *Store) Campaigns(ctx context.Context) ([]*Campaign, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, name, config_digest, config_document, seed, status, created_at, updated_at
		 FROM campaign ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*Campaign
	for rows.Next() {
		c, err := scanCampaign(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// SetCampaignStatus updates a campaign's status.
func (s *Store) SetCampaignStatus(ctx context.Context, id int64, status string) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE campaign SET status = ?, updated_at = ? WHERE id = ?`,
		status, s.now().UTC().UnixNano(), id)
	if err != nil {
		return fmt.Errorf("store: setting campaign status: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("%w: id %d", ErrNoCampaign, id)
	}
	return nil
}

// DeleteCampaign removes a campaign and everything that hangs off it. The blobs
// its testcases referenced are left for the collector, because another campaign
// may share them — content addressing means an identical input is one file.
func (s *Store) DeleteCampaign(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM campaign WHERE id = ?`, id)
	return err
}

// scanner is satisfied by both *sql.Row and *sql.Rows.
type scanner interface{ Scan(dest ...any) error }

func scanCampaign(sc scanner) (*Campaign, error) {
	var (
		c            Campaign
		seed         int64
		created, upd int64
	)
	if err := sc.Scan(&c.ID, &c.Name, &c.ConfigDigest, &c.ConfigDocument, &seed,
		&c.Status, &created, &upd); err != nil {
		return nil, err
	}
	c.Seed = uint64(seed)
	c.CreatedAt = time.Unix(0, created).UTC()
	c.UpdatedAt = time.Unix(0, upd).UTC()
	return &c, nil
}
