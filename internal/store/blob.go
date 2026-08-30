package store

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/rom/Xfuzz/pkg/corpus"
)

// ErrNotFound is returned for a blob the store does not hold.
var ErrNotFound = errors.New("store: blob not found")

// ErrCorrupt is returned when a blob's content does not hash to its name.
var ErrCorrupt = errors.New("store: blob is corrupt")

// BlobStore holds testcase payloads, addressed by the SHA-256 of their content
// (ADR-0008).
//
// Payloads are kept out of the database on purpose. A corpus entry can be a
// megabyte; a campaign can hold tens of thousands. In SQL that bloats every
// backup, defeats the page cache for the metadata that is actually queried, and
// makes export a serialisation problem instead of a copy. On disk, the same
// bytes are a file that any other tool can read.
//
// Content addressing is not just an identifier scheme here. It gives
// de-duplication for free — two workers that discover the same input write the
// same file — and it makes corruption detectable rather than silent, which
// matters for artefacts that will be attached to a bug report weeks later.
type BlobStore struct {
	root string

	// Sync forces each blob to disk before it is published.
	//
	// A store writes the blob first and the metadata row second, so a crash in
	// between leaves an orphan blob that the collector reclaims — harmless. The
	// dangerous ordering is the reverse: a durable row pointing at a payload
	// that never reached the platter. Syncing the payload rules that out. Blobs
	// are written only when an input is interesting, which is rare against the
	// execution rate, so the cost does not land on the hot path.
	Sync bool

	// Verify re-hashes a blob on read and refuses one that does not match its
	// name. Reads are rare — the scheduler works from in-memory entries — and a
	// reproducer that silently differs from the input that found the crash is
	// worse than a read that fails loudly.
	Verify bool

	mu          sync.Mutex
	count       int64
	bytes       int64
	quarantined int64
}

// OpenBlobStore opens or creates a blob store rooted at dir.
func OpenBlobStore(dir string) (*BlobStore, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("store: creating the blob directory %s: %w", dir, err)
	}
	b := &BlobStore{root: dir, Sync: true, Verify: true}

	// Usage is measured once at open rather than kept in a side file, because a
	// side file can disagree with the directory and then the budget is enforced
	// against a number that is not true. The walk is one pass of stat calls; if
	// it ever becomes the slow part of startup, the metadata table already
	// carries every size and can seed the counters instead.
	if err := b.Walk(func(_ corpus.Digest, size int64) error {
		b.count++
		b.bytes += size
		return nil
	}); err != nil {
		return nil, err
	}
	return b, nil
}

// Root returns the store's directory.
func (b *BlobStore) Root() string { return b.root }

// path returns the on-disk location of a digest.
//
// Two levels of 256-way fan-out keep directories small enough that lookups stay
// cheap on filesystems whose directory scan is linear, without burying blobs so
// deep that a human cannot find one by hand.
func (b *BlobStore) path(d corpus.Digest) string {
	h := d.String()
	return filepath.Join(b.root, h[0:2], h[2:4], h)
}

// Put stores data and returns its digest. Storing data already held is a no-op
// and is not an error: de-duplication is the point.
func (b *BlobStore) Put(data []byte) (corpus.Digest, error) {
	d := corpus.DigestOf(data)
	p := b.path(d)

	if _, err := os.Stat(p); err == nil {
		return d, nil
	}
	dir := filepath.Dir(p)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return d, fmt.Errorf("store: creating %s: %w", dir, err)
	}

	// Written to a temporary name in the destination directory and renamed into
	// place, so a reader never observes a partial blob and an interrupted write
	// leaves a stray temp file rather than a truncated one under a name that
	// promises its content.
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return d, fmt.Errorf("store: creating a temporary blob: %w", err)
	}
	tmpName := tmp.Name()
	defer func() {
		if tmpName != "" {
			os.Remove(tmpName)
		}
	}()

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return d, fmt.Errorf("store: writing blob %s: %w", d.Short(), err)
	}
	if b.Sync {
		if err := tmp.Sync(); err != nil {
			tmp.Close()
			return d, fmt.Errorf("store: syncing blob %s: %w", d.Short(), err)
		}
	}
	if err := tmp.Close(); err != nil {
		return d, fmt.Errorf("store: closing blob %s: %w", d.Short(), err)
	}
	if err := os.Chmod(tmpName, 0o400); err != nil {
		return d, fmt.Errorf("store: sealing blob %s: %w", d.Short(), err)
	}
	if err := os.Rename(tmpName, p); err != nil {
		return d, fmt.Errorf("store: publishing blob %s: %w", d.Short(), err)
	}
	tmpName = ""

	b.mu.Lock()
	b.count++
	b.bytes += int64(len(data))
	b.mu.Unlock()
	return d, nil
}

// Get returns a blob's content.
func (b *BlobStore) Get(d corpus.Digest) ([]byte, error) {
	data, err := os.ReadFile(b.path(d))
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil, fmt.Errorf("%w: %s", ErrNotFound, d.Short())
	case err != nil:
		return nil, fmt.Errorf("store: reading blob %s: %w", d.Short(), err)
	}
	if b.Verify {
		if got := sha256.Sum256(data); corpus.Digest(got) != d {
			// Quarantined rather than left in place. A file that does not hash
			// to its own name is not the blob it claims to be, and leaving it
			// means every later reader walks into the same wall — including
			// the collector, which would otherwise treat it as a live payload
			// forever. Moved rather than deleted, because it is evidence: a
			// corrupt corpus entry says something about the disk it was on.
			reason := fmt.Sprintf("hashes to %s", corpus.Digest(got).Short())
			qerr := b.Quarantine(d, reason)
			err := fmt.Errorf("%w: %s %s", ErrCorrupt, d.Short(), reason)
			if qerr != nil {
				return nil, fmt.Errorf("%w (and it could not be quarantined: %v)", err, qerr)
			}
			return nil, err
		}
	}
	return data, nil
}

// QuarantineDir is where blobs that failed their digest are kept.
const QuarantineDir = "quarantine"

// Quarantine moves a blob out of the store and records why.
//
// The store carries on without it. That is the point: one bad file on a disk
// that is going wrong must cost a campaign that entry, not the campaign
// (TESTS.md section 9).
func (b *BlobStore) Quarantine(d corpus.Digest, reason string) error {
	dir := filepath.Join(b.root, QuarantineDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("store: creating the quarantine: %w", err)
	}

	src := b.path(d)
	size := int64(0)
	if fi, err := os.Stat(src); err == nil {
		size = fi.Size()
	}
	if err := os.Chmod(src, 0o600); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("store: quarantining %s: %w", d.Short(), err)
	}
	if err := os.Rename(src, filepath.Join(dir, d.String())); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("store: quarantining %s: %w", d.Short(), err)
	}

	line := fmt.Sprintf("%s %s\n", d.String(), reason)
	f, err := os.OpenFile(filepath.Join(dir, "reasons"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("store: recording the quarantine of %s: %w", d.Short(), err)
	}
	defer f.Close()
	if _, err := f.WriteString(line); err != nil {
		return err
	}

	b.mu.Lock()
	if b.count > 0 {
		b.count--
	}
	b.bytes -= size
	if b.bytes < 0 {
		b.bytes = 0
	}
	b.quarantined++
	b.mu.Unlock()
	return nil
}

// Quarantined counts the blobs this store has moved aside, which is what a
// campaign reports rather than staying quiet about a disk going bad.
func (b *BlobStore) Quarantined() int64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.quarantined
}

// Open returns a reader over a blob. It does not verify: a caller streaming a
// large payload should hash as it reads if it cares.
func (b *BlobStore) Open(d corpus.Digest) (io.ReadCloser, error) {
	f, err := os.Open(b.path(d))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, d.Short())
	}
	return f, err
}

// Has reports whether the store holds a blob.
func (b *BlobStore) Has(d corpus.Digest) bool {
	_, err := os.Stat(b.path(d))
	return err == nil
}

// Size returns a blob's length in bytes.
func (b *BlobStore) Size(d corpus.Digest) (int64, error) {
	fi, err := os.Stat(b.path(d))
	if errors.Is(err, fs.ErrNotExist) {
		return 0, fmt.Errorf("%w: %s", ErrNotFound, d.Short())
	}
	if err != nil {
		return 0, err
	}
	return fi.Size(), nil
}

// Delete removes a blob. Removing one that is not held is not an error, so a
// collector that races another collector does not fail.
func (b *BlobStore) Delete(d corpus.Digest) error {
	p := b.path(d)
	fi, err := os.Stat(p)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	// Blobs are sealed read-only; the directory is writable, which is what
	// unlink actually needs, but restore the mode first so the failure mode on
	// a filesystem that disagrees is a clear error rather than a silent leak.
	_ = os.Chmod(p, 0o600)
	if err := os.Remove(p); err != nil {
		return fmt.Errorf("store: removing blob %s: %w", d.Short(), err)
	}
	b.mu.Lock()
	b.count--
	b.bytes -= fi.Size()
	b.mu.Unlock()
	return nil
}

// Walk visits every blob. Iteration order is the filesystem's, which is the
// digest order on any sane filesystem but is not relied upon.
func (b *BlobStore) Walk(fn func(d corpus.Digest, size int64) error) error {
	return filepath.WalkDir(b.root, func(p string, e fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if e.IsDir() {
			return skipQuarantine(b.root, p)
		}
		name := e.Name()
		if strings.HasPrefix(name, ".tmp-") {
			return nil
		}
		d, ok := parseDigest(name)
		if !ok {
			// Not ours. Leaving it alone is deliberate: a store directory a
			// user has dropped a note into should not lose the note.
			return nil
		}
		fi, err := e.Info()
		if err != nil {
			return err
		}
		return fn(d, fi.Size())
	})
}

// Usage reports how many blobs the store holds and how many bytes they occupy.
func (b *BlobStore) Usage() (count, bytes int64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.count, b.bytes
}

// Sweep removes temporary files left by an interrupted write. It is safe to run
// while the store is in use only in the sense that a live temp file will be
// re-created; callers run it at open, before any writer starts.
func (b *BlobStore) Sweep() (int, error) {
	n := 0
	err := filepath.WalkDir(b.root, func(p string, e fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if e.IsDir() {
			return skipQuarantine(b.root, p)
		}
		if strings.HasPrefix(e.Name(), ".tmp-") {
			if rmErr := os.Remove(p); rmErr == nil {
				n++
			}
		}
		return nil
	})
	return n, err
}

// parseDigest converts a blob filename back into a digest.
func parseDigest(name string) (corpus.Digest, bool) {
	var d corpus.Digest
	if len(name) != 2*len(d) {
		return d, false
	}
	for i := 0; i < len(d); i++ {
		hi, ok1 := unhex(name[2*i])
		lo, ok2 := unhex(name[2*i+1])
		if !ok1 || !ok2 {
			return corpus.Digest{}, false
		}
		d[i] = hi<<4 | lo
	}
	return d, true
}

func unhex(c byte) (byte, bool) {
	switch {
	case '0' <= c && c <= '9':
		return c - '0', true
	case 'a' <= c && c <= 'f':
		return c - 'a' + 10, true
	}
	return 0, false
}

// stat returns a blob's file information.
func (b *BlobStore) stat(d corpus.Digest) (os.FileInfo, error) {
	return os.Stat(b.path(d))
}

// skipQuarantine keeps a directory walk out of the quarantine.
//
// What is in there is no longer part of the store: it does not count towards a
// budget, it must not be swept away as a stray temporary file, and it must not
// be handed back to a reader. It is kept only because a corrupt payload is
// evidence about the disk it was on.
func skipQuarantine(root, dir string) error {
	if dir == filepath.Join(root, QuarantineDir) {
		return fs.SkipDir
	}
	return nil
}
