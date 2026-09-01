//go:build windows

package platform

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

// FileLock is an exclusive lock on a file, held for as long as the process
// holds it open.
type FileLock struct {
	f *os.File
}

// TryLockFile takes an exclusive lock on path without blocking.
//
// LockFileEx rather than opening the file unshared, because the two differ on
// the case the lock exists for. A daemon that crashed leaves its lock file
// behind, and an unshared open would then be refused by whatever else has the
// file open for any reason at all — a backup, an indexer, an editor — reporting
// a daemon that is not running. A byte-range lock is held by this handle alone
// and is dropped when the process exits however it exits, which is the same
// promise flock makes on Unix and the reason the two are the same mechanism
// here.
//
// The single byte at offset zero is the range. Nothing reads it; the pid
// written over it is for a person looking at the directory, and this handle
// owns the lock so its own write is not refused by it.
func TryLockFile(path string) (*FileLock, bool, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, false, fmt.Errorf("platform: opening the lock file %s: %w", path, err)
	}
	var ol windows.Overlapped
	err = windows.LockFileEx(windows.Handle(f.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &ol)
	if err != nil {
		f.Close()
		// Another process holds it, which is the answer the caller wanted
		// rather than a failure.
		if errors.Is(err, windows.ERROR_LOCK_VIOLATION) || errors.Is(err, windows.ERROR_IO_PENDING) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("platform: locking %s: %w", path, err)
	}
	_ = f.Truncate(0)
	_, _ = fmt.Fprintf(f, "%d\n", os.Getpid())
	return &FileLock{f: f}, true, nil
}

// Release drops the lock. Closing the handle would drop it too, which is what
// makes a crashed daemon's lock recoverable without anyone cleaning up.
func (l *FileLock) Release() error {
	if l == nil || l.f == nil {
		return nil
	}
	var ol windows.Overlapped
	err := windows.UnlockFileEx(windows.Handle(l.f.Fd()), 0, 1, 0, &ol)
	if cerr := l.f.Close(); err == nil {
		err = cerr
	}
	l.f = nil
	return err
}
