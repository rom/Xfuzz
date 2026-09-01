//go:build !unix && !windows

package platform

import (
	"fmt"
	"os"
)

// FileLock is a lock file on a platform with no locking.
//
// It excludes nothing. Every platform Xfuzz supports has a real mechanism —
// flock on Unix, LockFileEx on Windows — and this is what is left for the
// others, where two daemons could serve one store and neither would notice.
// Said plainly rather than described as a lock, because a comment claiming an
// exclusion the code does not perform is worse than no lock at all: it is the
// reason this file spent a release asserting that Windows opened the file
// unshared, which os.OpenFile does not do.
type FileLock struct {
	f *os.File
}

// TryLockFile creates the lock file and reports success. It takes no lock.
func TryLockFile(path string) (*FileLock, bool, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		if os.IsPermission(err) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("platform: opening the lock file %s: %w", path, err)
	}
	_ = f.Truncate(0)
	_, _ = fmt.Fprintf(f, "%d\n", os.Getpid())
	return &FileLock{f: f}, true, nil
}

// Release drops the lock.
func (l *FileLock) Release() error {
	if l == nil || l.f == nil {
		return nil
	}
	err := l.f.Close()
	l.f = nil
	return err
}
