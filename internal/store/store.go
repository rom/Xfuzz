package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/rom/Xfuzz/pkg/corpus"

	_ "modernc.org/sqlite" // pure-Go driver: no cgo (ADR-0017)
)

// SchemaVersion is the on-disk format this build understands.
//
// It is checked on open and never guessed at. Opening a newer store fails with
// an explicit error rather than reading fields it does not know about, because
// a corpus represents weeks of machine time and half-understanding it is worse
// than refusing it (ASR-0015).
const SchemaVersion = 2

// ErrNewerSchema is returned when the store was written by a later version.
var ErrNewerSchema = errors.New("store: written by a newer version of Xfuzz")

// Store is a campaign's durable state: corpus metadata, findings, coverage
// checkpoints, and the audit log.
//
// It is deliberately two things at once (ADR-0008). Metadata lives in embedded
// SQL, because the console needs real queries and triage needs mutable,
// long-lived records. Payloads live in a content-addressed blob store, because
// putting megabyte inputs in a database bloats it, slows every backup, and
// complicates export.
//
// Neither is on the hot path. Only interesting inputs are written, which is rare
// against the execution rate, and writes are batched.
type Store struct {
	db    *sql.DB
	blobs *BlobStore
	dir   string

	// now is the clock, replaceable in tests. Timestamps are recorded for
	// reporting; they never influence a fuzzing decision (ASR-0008).
	now func() time.Time
}

// Open opens or creates a store rooted at dir.
func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("store: creating %s: %w", dir, err)
	}
	blobs, err := OpenBlobStore(filepath.Join(dir, "blobs"))
	if err != nil {
		return nil, err
	}

	// WAL so readers — the console, a triage worker — never block the writer,
	// and NORMAL synchronous because a campaign that loses its last few seconds
	// of corpus to a power cut has lost very little, while an fsync per corpus
	// entry would be felt.
	dsn := "file:" + filepath.Join(dir, "xfuzz.db") +
		"?_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=foreign_keys(ON)&_pragma=busy_timeout(5000)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("store: opening the database: %w", err)
	}
	// One writer. Every write funnels through the daemon (ADR-0008), and SQLite
	// would serialise them anyway; making it explicit turns lock contention into
	// a queue rather than a stream of busy errors.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	s := &Store{db: db, blobs: blobs, dir: dir, now: time.Now}
	if err := s.migrate(context.Background()); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// Close releases the store.
func (s *Store) Close() error { return s.db.Close() }

// Dir returns the store's root directory.
func (s *Store) Dir() string { return s.dir }

// Blobs returns the payload store.
func (s *Store) Blobs() *BlobStore { return s.blobs }

// DB exposes the database, for queries the typed API does not cover.
func (s *Store) DB() *sql.DB { return s.db }

// SetClock replaces the timestamp source, for tests.
func (s *Store) SetClock(f func() time.Time) { s.now = f }

// migrate brings the schema up to SchemaVersion.
//
// Migrations run in order and each is a single transaction, so an interrupted
// upgrade leaves the store at its previous version rather than half-converted.
func (s *Store) migrate(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx,
		`CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)`); err != nil {
		return fmt.Errorf("store: creating the metadata table: %w", err)
	}

	have, err := s.schemaVersion(ctx)
	if err != nil {
		return err
	}
	if have > SchemaVersion {
		return fmt.Errorf("%w: store is at version %d, this build understands %d",
			ErrNewerSchema, have, SchemaVersion)
	}
	for v := have; v < SchemaVersion; v++ {
		if err := s.applyMigration(ctx, v+1); err != nil {
			return fmt.Errorf("store: migrating to version %d: %w", v+1, err)
		}
	}
	return nil
}

func (s *Store) schemaVersion(ctx context.Context) (int, error) {
	var raw string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM meta WHERE key = 'schema_version'`).Scan(&raw)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return 0, nil
	case err != nil:
		return 0, fmt.Errorf("store: reading the schema version: %w", err)
	}
	v, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("store: schema version %q is not a number", raw)
	}
	return v, nil
}

func (s *Store) applyMigration(ctx context.Context, to int) error {
	stmts, ok := migrations[to]
	if !ok {
		return fmt.Errorf("no migration defined")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	for _, stmt := range stmts {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("%w\nstatement: %s", err, stmt)
		}
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO meta (key, value) VALUES ('schema_version', ?)
		 ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
		strconv.Itoa(to)); err != nil {
		return err
	}
	return tx.Commit()
}

// migrations are keyed by the version they produce. They are append-only: a
// released migration is never edited, because someone's store has already run
// it and editing it would leave two stores claiming the same version with
// different shapes.
var migrations = map[int][]string{
	1: {
		`CREATE TABLE campaign (
			id            INTEGER PRIMARY KEY,
			name          TEXT NOT NULL UNIQUE,
			config_digest TEXT NOT NULL DEFAULT '',
			seed          INTEGER NOT NULL DEFAULT 0,
			status        TEXT NOT NULL DEFAULT 'created',
			created_at    INTEGER NOT NULL,
			updated_at    INTEGER NOT NULL
		)`,

		`CREATE TABLE testcase (
			id            INTEGER PRIMARY KEY,
			campaign_id   INTEGER NOT NULL REFERENCES campaign(id) ON DELETE CASCADE,
			digest        TEXT NOT NULL,
			size          INTEGER NOT NULL,
			coverage      INTEGER NOT NULL DEFAULT 0,
			new_signal    INTEGER NOT NULL DEFAULT 0,
			exec_time_ns  INTEGER NOT NULL DEFAULT 0,
			depth         INTEGER NOT NULL DEFAULT 0,
			fuzzed        INTEGER NOT NULL DEFAULT 0,
			children      INTEGER NOT NULL DEFAULT 0,
			favoured      INTEGER NOT NULL DEFAULT 0,
			discovered_at INTEGER NOT NULL,
			parent        TEXT NOT NULL DEFAULT '',
			origin        TEXT NOT NULL DEFAULT '',
			worker        INTEGER NOT NULL DEFAULT 0,
			ops           TEXT NOT NULL DEFAULT '',
			UNIQUE(campaign_id, digest)
		)`,
		`CREATE INDEX testcase_by_coverage ON testcase(campaign_id, coverage DESC)`,
		`CREATE INDEX testcase_by_size ON testcase(campaign_id, size)`,

		`CREATE TABLE bucket (
			id             INTEGER PRIMARY KEY,
			campaign_id    INTEGER NOT NULL REFERENCES campaign(id) ON DELETE CASCADE,
			strategy       TEXT NOT NULL,
			signature      TEXT NOT NULL,
			kind           TEXT NOT NULL DEFAULT '',
			summary        TEXT NOT NULL DEFAULT '',
			count          INTEGER NOT NULL DEFAULT 0,
			first_seen_at  INTEGER NOT NULL,
			UNIQUE(campaign_id, strategy, signature)
		)`,

		`CREATE TABLE finding (
			id               INTEGER PRIMARY KEY,
			campaign_id      INTEGER NOT NULL REFERENCES campaign(id) ON DELETE CASCADE,
			bucket_id        INTEGER NOT NULL REFERENCES bucket(id) ON DELETE CASCADE,
			digest           TEXT NOT NULL,
			minimized_digest TEXT NOT NULL DEFAULT '',
			original_size    INTEGER NOT NULL DEFAULT 0,
			minimized_size   INTEGER NOT NULL DEFAULT 0,
			kind             TEXT NOT NULL,
			summary          TEXT NOT NULL DEFAULT '',
			signal           INTEGER NOT NULL DEFAULT 0,
			detail           TEXT NOT NULL DEFAULT '',
			frames           TEXT NOT NULL DEFAULT '',
			repro_trials     INTEGER NOT NULL DEFAULT 0,
			repro_rate       REAL NOT NULL DEFAULT 0,
			triage_state     TEXT NOT NULL DEFAULT 'new',
			notes            TEXT NOT NULL DEFAULT '',
			found_at_exec    INTEGER NOT NULL DEFAULT 0,
			created_at       INTEGER NOT NULL,
			updated_at       INTEGER NOT NULL,
			UNIQUE(campaign_id, digest)
		)`,
		`CREATE INDEX finding_by_bucket ON finding(campaign_id, bucket_id)`,
		`CREATE INDEX finding_by_state ON finding(campaign_id, triage_state)`,

		`CREATE TABLE checkpoint (
			campaign_id   INTEGER PRIMARY KEY REFERENCES campaign(id) ON DELETE CASCADE,
			coverage      BLOB,
			execs         INTEGER NOT NULL DEFAULT 0,
			corpus_size   INTEGER NOT NULL DEFAULT 0,
			rng_positions TEXT NOT NULL DEFAULT '',
			saved_at      INTEGER NOT NULL
		)`,

		`CREATE TABLE audit (
			id        INTEGER PRIMARY KEY,
			at        INTEGER NOT NULL,
			actor     TEXT NOT NULL DEFAULT '',
			action    TEXT NOT NULL,
			detail    TEXT NOT NULL DEFAULT '',
			prev_hash TEXT NOT NULL DEFAULT '',
			hash      TEXT NOT NULL
		)`,
	},

	// A campaign's own configuration, kept beside its digest.
	//
	// The digest pins what ran; it cannot say what ran. A store holding a
	// finished campaign's findings and a hash of the file that produced them is
	// a store nobody can triage from without also finding the file — which is
	// exactly the case ADR-0003's "triage tomorrow" is about, and the one the
	// console has to serve. The resolved document is small, it is already the
	// campaign's whole interface (ADR-0016), and keeping it makes the store
	// self-contained.
	2: {
		`ALTER TABLE campaign ADD COLUMN config_document TEXT NOT NULL DEFAULT ''`,
	},
}

// Version returns the store's schema version.
func (s *Store) Version(ctx context.Context) (int, error) { return s.schemaVersion(ctx) }

// PutBlob stores a payload and returns its content address.
func (s *Store) PutBlob(_ context.Context, data []byte) (corpus.Digest, error) {
	return s.blobs.Put(data)
}
