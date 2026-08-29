//go:build unix

package platform

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// FileLock is an exclusive advisory lock on a file, held for as long as the
// process holds it open.
type FileLock struct {
	f *os.File
}

// TryLockFile takes an exclusive lock on path without blocking.
//
// It reports whether the lock was taken. A failure to take it is not an error:
// it means another process holds it, which is the answer the caller wanted.
//
// The lock is what tells a starting daemon whether another one is already
// running. The alternative — connecting to its socket to see whether anything
// answers — cannot distinguish "a daemon is starting" from "a daemon has
// crashed and left its socket behind", and gives two daemons starting at once
// no way to notice each other at all.
func TryLockFile(path string) (*FileLock, bool, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, false, fmt.Errorf("platform: opening the lock file %s: %w", path, err)
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		f.Close()
		if err == unix.EWOULDBLOCK {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("platform: locking %s: %w", path, err)
	}
	// The pid is written for a human reading the directory, never read back:
	// the lock is the fact, and a pid file that disagreed with it would only
	// mislead.
	_ = f.Truncate(0)
	_, _ = fmt.Fprintf(f, "%d\n", os.Getpid())
	return &FileLock{f: f}, true, nil
}

// Release drops the lock. The lock is also released if the process exits,
// which is what makes a crashed daemon's lock recoverable without cleanup.
func (l *FileLock) Release() error {
	if l == nil || l.f == nil {
		return nil
	}
	err := unix.Flock(int(l.f.Fd()), unix.LOCK_UN)
	if cerr := l.f.Close(); err == nil {
		err = cerr
	}
	l.f = nil
	return err
}
