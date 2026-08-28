//go:build unix

package platform

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"github.com/rom/Xfuzz/pkg/executor"
)

// Shared memory on unix is a file in a memory-backed filesystem, mapped
// MAP_SHARED into both the fuzzer and the target.
//
// A file rather than System V or POSIX named shared memory because the
// identifier is then just a path: the child receives it in an environment
// variable, opens it, and maps it, with no extra API on either side. That keeps
// the C runtime small, which matters because it is compiled into every target.

// shmDir returns the best available memory-backed directory.
func shmDir() string {
	for _, d := range []string{"/dev/shm", "/run/shm"} {
		if fi, err := os.Stat(d); err == nil && fi.IsDir() {
			if f, err := os.CreateTemp(d, ".xfuzz-probe-"); err == nil {
				name := f.Name()
				f.Close()
				os.Remove(name)
				return d
			}
		}
	}
	// macOS has no /dev/shm. A regular temporary file still maps shared; it is
	// backed by the page cache rather than by tmpfs, which costs a little on a
	// cold map and nothing thereafter.
	return os.TempDir()
}

type unixShm struct {
	path string
	file *os.File
	data []byte
}

func (s *unixShm) Bytes() []byte { return s.data }
func (s *unixShm) ID() string    { return s.path }

func (s *unixShm) Close() error {
	var first error
	if s.data != nil {
		if err := syscall.Munmap(s.data); err != nil && first == nil {
			first = fmt.Errorf("unmapping %s: %w", s.path, err)
		}
		s.data = nil
	}
	if s.file != nil {
		if err := s.file.Close(); err != nil && first == nil {
			first = err
		}
		s.file = nil
	}
	if s.path != "" {
		if err := os.Remove(s.path); err != nil && !os.IsNotExist(err) && first == nil {
			first = err
		}
		s.path = ""
	}
	return first
}

type unixShmProvider struct{ dir string }

// NewSharedMemoryProvider returns the platform's shared memory implementation.
func NewSharedMemoryProvider() executor.SharedMemoryProvider {
	return &unixShmProvider{dir: shmDir()}
}

func (p *unixShmProvider) Available() bool { return true }

func (p *unixShmProvider) Create(size int) (executor.SharedMemory, error) {
	if size <= 0 {
		return nil, fmt.Errorf("platform: shared memory size must be positive, got %d", size)
	}
	f, err := os.CreateTemp(p.dir, "xfuzz-shm-")
	if err != nil {
		return nil, fmt.Errorf("platform: creating a shared region in %s: %w", p.dir, err)
	}
	path := f.Name()

	if err := f.Truncate(int64(size)); err != nil {
		f.Close()
		os.Remove(path)
		return nil, fmt.Errorf("platform: sizing %s: %w", path, err)
	}
	data, err := syscall.Mmap(int(f.Fd()), 0, size,
		syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_SHARED)
	if err != nil {
		f.Close()
		os.Remove(path)
		return nil, fmt.Errorf("platform: mapping %s: %w", path, err)
	}
	// The region is world-writable for the target, which runs confined and may
	// have a different uid once the sandbox lands. It lives in a private
	// temporary file that is removed on Close.
	if err := os.Chmod(path, 0o600); err != nil {
		syscall.Munmap(data)
		f.Close()
		os.Remove(path)
		return nil, fmt.Errorf("platform: securing %s: %w", path, err)
	}
	return &unixShm{path: path, file: f, data: data}, nil
}

// CleanupStaleShm removes shared regions left behind by a worker that died
// without closing them. Without this a long-running host slowly fills its
// memory-backed filesystem with orphans.
func CleanupStaleShm(olderThan int64) (int, error) {
	dir := shmDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, err
	}
	removed := 0
	for _, e := range entries {
		if e.IsDir() || len(e.Name()) < 10 || e.Name()[:10] != "xfuzz-shm-" {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		if info.ModTime().Unix() > olderThan {
			continue
		}
		if os.Remove(filepath.Join(dir, e.Name())) == nil {
			removed++
		}
	}
	return removed, nil
}
