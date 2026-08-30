// The store's half of the fault-injection suite (docs/TESTS.md section 9).
//
// Four of the nine injected faults are the store's: a corrupted blob, a
// corrupted database, a full disk, and a store written by a newer version.
// Each is here rather than in an end-to-end test because each needs the fault
// injected at a byte, and because the required behaviour is the store's to
// provide — an end-to-end test can only observe that it did.

package store

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rom/Xfuzz/pkg/corpus"
)

// TestFaultCorruptedBlobIsQuarantinedAndTheCampaignContinues covers
// "Corrupted blob → Detected by digest; entry quarantined, campaign continues".
func TestFaultCorruptedBlobIsQuarantinedAndTheCampaignContinues(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	c, _ := s.CreateCampaign(ctx, "c", "", "", 1)

	good := testcase("a healthy corpus entry", 3, false)
	bad := testcase("the one that goes bad", 5, false)
	for _, tc := range []*corpus.Testcase{good, bad} {
		if err := s.SaveTestcase(ctx, c.ID, tc); err != nil {
			t.Fatal(err)
		}
	}

	var dropped []corpus.Digest
	s.OnDropped(func(d corpus.Digest, _ error) { dropped = append(dropped, d) })

	// The fault: a byte on the disk changes under the store's feet.
	p := s.Blobs().path(bad.ID)
	if err := os.Chmod(p, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("tampered, and the wrong length too"), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := s.Testcases(ctx, c.ID, TestcaseQuery{WithPayload: true})
	if err != nil {
		t.Fatalf("one corrupt payload failed the whole corpus read: %v", err)
	}
	if len(got) != 1 || string(got[0].Bytes) != "a healthy corpus entry" {
		t.Fatalf("corpus = %d entries, want the one healthy entry", len(got))
	}
	if len(dropped) != 1 || dropped[0] != bad.ID {
		t.Errorf("dropped = %v, want just the corrupt entry", dropped)
	}
	if s.Dropped() != 1 {
		t.Errorf("Dropped() = %d, want 1", s.Dropped())
	}

	// Quarantined: moved out of the store, recorded, and no longer counted.
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Errorf("the corrupt blob is still in the store at %s", p)
	}
	q := filepath.Join(s.Blobs().Root(), QuarantineDir, bad.ID.String())
	if _, err := os.Stat(q); err != nil {
		t.Errorf("the corrupt blob was not kept as evidence: %v", err)
	}
	reasons, err := os.ReadFile(filepath.Join(s.Blobs().Root(), QuarantineDir, "reasons"))
	if err != nil || !strings.Contains(string(reasons), bad.ID.String()) {
		t.Errorf("the quarantine records no reason for %s: %v", bad.ID.Short(), err)
	}
	if s.Blobs().Quarantined() != 1 {
		t.Errorf("Quarantined() = %d, want 1", s.Blobs().Quarantined())
	}

	// And the store carries on: a healthy write still works, and a reopen does
	// not count the quarantined file against the campaign's budget.
	if err := s.SaveTestcase(ctx, c.ID, testcase("written after the fault", 7, false)); err != nil {
		t.Fatalf("the store stopped accepting writes after a corrupt read: %v", err)
	}
	reopened, err := Open(s.Dir())
	if err != nil {
		t.Fatalf("reopening after a quarantine: %v", err)
	}
	defer reopened.Close()
	count, _ := reopened.Blobs().Usage()
	if count != 2 {
		t.Errorf("usage after reopen = %d blobs, want 2: the quarantine is being counted as live", count)
	}
}

// TestFaultCorruptedDatabaseIsRefusedOnOpen covers "Corrupted database →
// Detected on open; explicit error, never silent misbehaviour".
func TestFaultCorruptedDatabaseIsRefusedOnOpen(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateCampaign(context.Background(), "c", "", "", 1); err != nil {
		t.Fatal(err)
	}
	s.Close()

	// The fault: the file is still there, still the right size, and no longer
	// a database. This is what a bad sector looks like from userspace.
	path := filepath.Join(dir, "xfuzz.db")
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := range body {
		body[i] = 0x41
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}

	bad, err := Open(dir)
	if err == nil {
		bad.Close()
		t.Fatal("a corrupt database opened without complaint; " +
			"a campaign would have run against it and reported nothing wrong")
	}
	if !strings.Contains(err.Error(), "store:") {
		t.Errorf("the failure does not identify itself as the store's: %v", err)
	}
	t.Logf("refused: %v", err)
}

// TestFaultAStoreFromTheFutureIsRefused covers "Store opened by a newer version
// → Explicit version error".
func TestFaultAStoreFromTheFutureIsRefused(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO meta (key, value) VALUES ('schema_version', ?)
		 ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
		itoa(SchemaVersion+1)); err != nil {
		t.Fatal(err)
	}
	s.Close()

	reopened, err := Open(dir)
	if err == nil {
		reopened.Close()
		t.Fatal("a store written by a newer Xfuzz opened anyway; " +
			"a campaign would have run against a schema it does not understand")
	}
	if !errors.Is(err, ErrNewerSchema) {
		t.Fatalf("err = %v, want ErrNewerSchema", err)
	}
	if !strings.Contains(err.Error(), itoa(SchemaVersion)) {
		t.Errorf("the error does not say which version this build speaks: %v", err)
	}
}

// TestFaultAFullDiskDegradesRatherThanCorrupting covers "Disk full during
// corpus write → Graceful degradation; reported; no corruption".
//
// On a real full filesystem, because the failure mode is specific: a write
// that stops part-way. A test that simulated it with a permission error would
// prove the error is returned and nothing about what is left on disk.
func TestFaultAFullDiskDegradesRatherThanCorrupting(t *testing.T) {
	dir := tinyFilesystem(t)

	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	c, err := s.CreateCampaign(ctx, "c", "", "", 1)
	if err != nil {
		t.Fatal(err)
	}

	// One entry that fits, so there is something to lose.
	first := testcase("the entry written before the disk filled", 1, false)
	if err := s.SaveTestcase(ctx, c.ID, first); err != nil {
		t.Fatalf("the first write failed on an empty filesystem: %v", err)
	}

	// Then write until it will not take any more.
	var failed error
	var wrote int
	big := make([]byte, 64<<10)
	for i := 0; i < 256 && failed == nil; i++ {
		for j := range big {
			big[j] = byte(i)
		}
		if err := s.SaveTestcase(ctx, c.ID, testcase(string(big), i, false)); err != nil {
			failed = err
			break
		}
		wrote++
	}
	if failed == nil {
		t.Skipf("the filesystem never filled after %d writes; it is not as small as it claimed", wrote)
	}
	t.Logf("filled after %d entries: %v", wrote, failed)

	// Reported, not silent, and recognisable as a disk problem rather than a
	// bug in the store.
	if !strings.Contains(failed.Error(), "store:") {
		t.Errorf("the failure does not identify itself as the store's: %v", failed)
	}

	// And no corruption: everything the store said it had, it still has, and
	// every payload still hashes to its own name. A partial blob left under a
	// name that promises its content is the outcome this test exists to rule
	// out.
	entries, err := s.Testcases(ctx, c.ID, TestcaseQuery{WithPayload: true})
	if err != nil {
		t.Fatalf("reading the corpus back after a full disk: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("nothing survived the full disk, not even the entry written before it")
	}
	for _, tc := range entries {
		if corpus.DigestOf(tc.Bytes) != tc.ID {
			t.Errorf("entry %s does not hash to its own name: the write left a partial blob", tc.ID.Short())
		}
	}
	if s.Blobs().Quarantined() != 0 {
		t.Errorf("%d blob(s) had to be quarantined; a failed write left something behind",
			s.Blobs().Quarantined())
	}
	// No stray temporaries either: an interrupted write must leave a temp file
	// rather than a truncated blob, and the sweep must be able to find it.
	swept, err := s.Blobs().Sweep()
	if err != nil {
		t.Fatalf("sweeping after a full disk: %v", err)
	}
	t.Logf("%d entries survived; %d temporary file(s) swept", len(entries), swept)
}

// tinyFilesystem returns a directory on a filesystem of a few megabytes,
// skipping the test if one cannot be made here.
func tinyFilesystem(t *testing.T) string {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("mounting a small filesystem needs root; a full disk cannot be injected here")
	}
	dir := t.TempDir()
	mnt := filepath.Join(dir, "small")
	if err := os.MkdirAll(mnt, 0o700); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("mount", "-t", "tmpfs", "-o", "size=2M", "tmpfs", mnt).CombinedOutput()
	if err != nil {
		t.Skipf("cannot mount a tmpfs here: %v: %s", err, out)
	}
	t.Cleanup(func() { exec.Command("umount", "-l", mnt).Run() })
	return mnt
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
