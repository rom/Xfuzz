//go:build !unix

package platform

import (
	"errors"
	"os"

	"github.com/rom/Xfuzz/pkg/executor"
)

// ErrSharedMemoryUnsupported is returned where the platform has no shared
// memory implementation yet.
//
// This is a declared capability gap, not a silent failure: `xfuzz doctor`
// reports it, and a campaign requiring coverage refuses to start rather than
// running blind and looking merely unlucky (ASR-0006).
var ErrSharedMemoryUnsupported = errors.New(
	"platform: shared coverage memory is not implemented on this platform; " +
		"the subprocess tier still runs, without coverage")

type unsupportedShmProvider struct{}

// NewSharedMemoryProvider returns a provider that reports itself unavailable.
func NewSharedMemoryProvider() executor.SharedMemoryProvider { return unsupportedShmProvider{} }

// NewSharedMemoryProviderFor returns the same unsupported provider: there is no
// identity to grant access to where there is no shared memory.
func NewSharedMemoryProviderFor(uid, gid int) executor.SharedMemoryProvider {
	return unsupportedShmProvider{}
}

func (unsupportedShmProvider) Available() bool { return false }

func (unsupportedShmProvider) Create(int) (executor.SharedMemory, error) {
	return nil, ErrSharedMemoryUnsupported
}

// CleanupStaleShm is a no-op where shared memory is unsupported.
func CleanupStaleShm(int64) (int, error) { return 0, nil }

// shmDir names where shared memory would live. There is none here, but the
// confinement policy is assembled on every platform so that it can be read and
// tested on every platform, and it asks.
func shmDir() string { return os.TempDir() }
