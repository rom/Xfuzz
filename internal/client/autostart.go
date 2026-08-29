package client

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/rom/Xfuzz/internal/safety"
)

// ErrNoDaemon is returned when no daemon is running and none could be started.
var ErrNoDaemon = errors.New("client: no daemon is running")

// AutoStart connects to the daemon, starting a private one if none answers.
//
// The common single-user case should need no service management: `xfuzz run` on
// a fresh machine has to work. What it must not become is an in-process bypass
// — the daemon is still the engine, still owns the store and the safety layer,
// and still audits everything (ADR-0003). Starting one is exactly that, done
// for the user.
func AutoStart(ctx context.Context, opts Options) (*Client, error) {
	if opts.Addr != "" {
		// A named address is somebody else's daemon. Starting one would be
		// starting it in the wrong place.
		return New(opts)
	}

	c, err := New(opts)
	if err != nil {
		return nil, err
	}
	if c.Ping(ctx) == nil {
		return c, nil
	}

	binary, err := safety.FindTool(DaemonBinaryName)
	if err != nil {
		return nil, fmt.Errorf("%w and %s was not found beside %s or on PATH",
			ErrNoDaemon, DaemonBinaryName, selfPath())
	}

	if err := spawnDaemon(binary, opts.Socket); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNoDaemon, err)
	}

	// Wait for it to answer rather than assuming. A daemon that failed to start
	// must produce "no daemon is running", not a connection refused on every
	// subsequent command.
	deadline := time.Now().Add(startTimeout)
	for time.Now().Before(deadline) {
		if c.Ping(ctx) == nil {
			return c, nil
		}
		select {
		case <-time.After(50 * time.Millisecond):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return nil, fmt.Errorf("%w: %s was started but did not answer within %s",
		ErrNoDaemon, binary, startTimeout)
}

// DaemonBinaryName is the daemon executable.
const DaemonBinaryName = "xfuzzd"

// startTimeout is how long an auto-started daemon has to answer.
const startTimeout = 10 * time.Second

func selfPath() string {
	if p, err := os.Executable(); err == nil {
		return filepath.Dir(p)
	}
	return "the running binary"
}
