//go:build !unix

package platform

import (
	"fmt"
	"os"
)

// FileLock is an exclusive lock on a file.
//
// Windows takes the lock by opening the file without sharing, which is a
// different mechanism with the same effect: while this handle is open, no other
// process can take one.
type FileLock struct {
	f *os.File
}

// TryLockFile takes an exclusive lock on path without blocking.
func TryLockFile(path string) (*FileLock, bool, error) {
	// O_EXCL would fail on a lock file left behind by a crashed process, so the
	// exclusivity comes from holding the handle rather than from creating it.
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
