package platform

import (
	"path/filepath"
	"testing"
)

// TestAFileLockExcludesASecondHolder is the property the daemon's socket lock
// is for: two daemons started at once must not both decide they are the one.
//
// Taken from a second handle rather than a second process, because that is what
// both mechanisms actually exclude — flock is per open file description and
// LockFileEx per handle — and it is the same question a second process asks,
// without a second process to arrange.
func TestAFileLockExcludesASecondHolder(t *testing.T) {
	path := filepath.Join(t.TempDir(), "daemon.lock")

	first, ok, err := TryLockFile(path)
	if err != nil {
		t.Fatalf("taking the lock: %v", err)
	}
	if !ok {
		t.Fatal("the first holder was refused a lock nobody held")
	}

	second, ok, err := TryLockFile(path)
	if err != nil {
		t.Fatalf("the second attempt failed rather than reporting the lock held: %v", err)
	}
	if ok {
		second.Release()
		first.Release()
		t.Fatal("two holders took the same lock; two daemons would serve one store, " +
			"and neither would know the other was there")
	}

	// And it is released, so a daemon that stops lets the next one start.
	if err := first.Release(); err != nil {
		t.Fatalf("releasing: %v", err)
	}
	third, ok, err := TryLockFile(path)
	if err != nil || !ok {
		t.Fatalf("the lock was not released: ok=%v err=%v", ok, err)
	}
	third.Release()
}
