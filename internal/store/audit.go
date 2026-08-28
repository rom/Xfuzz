package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

// Audit actions. The set is small on purpose: an audit log nobody reads is
// worthless, and a log that records everything is a log nobody reads.
const (
	AuditCampaignStart  = "campaign.start"
	AuditCampaignStop   = "campaign.stop"
	AuditTargetSpawn    = "target.spawn"
	AuditScopeAllow     = "scope.allow"
	AuditScopeDeny      = "scope.deny"
	AuditAuthzGrant     = "authz.grant"
	AuditSandboxDegrade = "sandbox.degrade"
	AuditFindingExport  = "finding.export"
	AuditCorpusImport   = "corpus.import"
)

// metaAuditHead is where the chain head is mirrored.
//
// A hash chain detects an entry that was altered or removed from the middle,
// because every later hash stops matching. It does not by itself detect the log
// being truncated at the end: a prefix of a valid chain is a valid chain. The
// head is kept outside the table so that truncation shows up as a head that no
// entry produces.
//
// This is tamper *evidence*, not tamper *proofing*. Anyone who can write the
// database can rewrite the chain and the head together. What it buys is that
// accidental corruption, a partial restore, and a careless edit are all caught,
// and that a deliberate rewrite has to be deliberate. Anything stronger needs a
// signature or an off-box copy, which is a v1.0 concern (SECURITY.md).
const metaAuditHead = "audit_head"

// ErrAuditTampered is returned when the audit log does not verify.
var ErrAuditTampered = errors.New("store: audit log does not verify")

// AuditEntry is one recorded action.
type AuditEntry struct {
	ID       int64
	At       time.Time
	Actor    string
	Action   string
	Detail   string
	PrevHash string
	Hash     string
}

// Audit appends an entry to the log.
//
// The read of the previous hash and the write of the new entry are one
// transaction, so two appends cannot both chain off the same predecessor and
// fork the log.
func (s *Store) Audit(ctx context.Context, actor, action, detail string) (*AuditEntry, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	var (
		lastID int64
		prev   string
	)
	err = tx.QueryRowContext(ctx,
		`SELECT id, hash FROM audit ORDER BY id DESC LIMIT 1`).Scan(&lastID, &prev)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("store: reading the audit head: %w", err)
	}

	e := &AuditEntry{
		ID:       lastID + 1,
		At:       s.now().UTC(),
		Actor:    actor,
		Action:   action,
		Detail:   detail,
		PrevHash: prev,
	}
	e.Hash = auditHash(e)

	if _, err := tx.ExecContext(ctx,
		`INSERT INTO audit (id, at, actor, action, detail, prev_hash, hash)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		e.ID, e.At.UnixNano(), e.Actor, e.Action, e.Detail, e.PrevHash, e.Hash); err != nil {
		return nil, fmt.Errorf("store: appending to the audit log: %w", err)
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO meta (key, value) VALUES (?, ?)
		 ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
		metaAuditHead, e.Hash); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return e, nil
}

// AuditLog returns the whole log in order.
func (s *Store) AuditLog(ctx context.Context) ([]AuditEntry, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, at, actor, action, detail, prev_hash, hash FROM audit ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []AuditEntry
	for rows.Next() {
		var (
			e  AuditEntry
			at int64
		)
		if err := rows.Scan(&e.ID, &at, &e.Actor, &e.Action, &e.Detail, &e.PrevHash, &e.Hash); err != nil {
			return nil, err
		}
		e.At = time.Unix(0, at).UTC()
		out = append(out, e)
	}
	return out, rows.Err()
}

// VerifyAudit recomputes the chain and reports the first entry that disagrees.
//
// It returns the number of entries verified alongside the error, so a caller can
// say "the log is intact for the first 412 entries and diverges at 413" rather
// than only "something is wrong".
func (s *Store) VerifyAudit(ctx context.Context) (int, error) {
	entries, err := s.AuditLog(ctx)
	if err != nil {
		return 0, err
	}
	prev := ""
	for i := range entries {
		e := entries[i]
		if e.ID != int64(i+1) {
			return i, fmt.Errorf("%w: entry %d of %d is numbered %d; an entry was removed",
				ErrAuditTampered, i+1, len(entries), e.ID)
		}
		if e.PrevHash != prev {
			return i, fmt.Errorf("%w: entry %d chains to %s but its predecessor hashes to %s",
				ErrAuditTampered, e.ID, shortHash(e.PrevHash), shortHash(prev))
		}
		want := auditHash(&e)
		if want != e.Hash {
			return i, fmt.Errorf("%w: entry %d records hash %s but its contents hash to %s",
				ErrAuditTampered, e.ID, shortHash(e.Hash), shortHash(want))
		}
		prev = e.Hash
	}

	head, err := s.metaValue(ctx, metaAuditHead)
	if err != nil {
		return len(entries), err
	}
	if head != prev {
		return len(entries), fmt.Errorf(
			"%w: the log ends at %s but the recorded head is %s; entries were removed from the end",
			ErrAuditTampered, shortHash(prev), shortHash(head))
	}
	return len(entries), nil
}

// auditHash is the chain function.
//
// Every field is length-prefixed before hashing. Without that, an actor of "ab"
// with action "c" and an actor of "a" with action "bc" would hash identically,
// and moving a character across a field boundary would be an undetectable edit.
func auditHash(e *AuditEntry) string {
	h := sha256.New()
	var n [8]byte

	binary.LittleEndian.PutUint64(n[:], uint64(e.ID))
	h.Write(n[:])
	binary.LittleEndian.PutUint64(n[:], uint64(e.At.UnixNano()))
	h.Write(n[:])

	for _, f := range []string{e.Actor, e.Action, e.Detail, e.PrevHash} {
		binary.LittleEndian.PutUint64(n[:], uint64(len(f)))
		h.Write(n[:])
		h.Write([]byte(f))
	}
	return hex.EncodeToString(h.Sum(nil))
}

func shortHash(h string) string {
	if h == "" {
		return "(none)"
	}
	if len(h) > 12 {
		return h[:12]
	}
	return h
}

func (s *Store) metaValue(ctx context.Context, key string) (string, error) {
	var v string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM meta WHERE key = ?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return v, err
}
