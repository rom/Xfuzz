package safety

import (
	"context"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/rom/Xfuzz/pkg/executor"
)

// Peer is a confined long-lived process the fuzzer talks to over a protocol,
// rather than one it runs inputs through.
//
// A plugin is the case that needs it (ADR-0025). It is not an executor: nothing
// is delivered to it, it has no per-execution lifecycle, and the fork server's
// control and status descriptors would be the wrong names for its pipes even if
// they existed on every platform — which they do not, since exec.Cmd.ExtraFiles
// is unsupported on Windows. So a peer gets the two streams every platform has,
// and this is still the only place in Xfuzz that creates a process.
//
// It is confined exactly as a target is. An extension is untrusted by
// construction — that is the reason it runs out of process at all — so it gets
// the campaign's isolation level, its resource limits, and its cgroup.
type Peer struct {
	cmd    *handle
	stdin  io.WriteCloser
	stdout io.Reader
	stderr *tail
}

// StartPeer launches a protocol peer and returns its streams.
//
// The return type is the interface rather than *Peer, so that this satisfies
// executor.Spawner: pkg/executor names the primitive it needs and this package
// is the only thing that can provide it.
func (s *Spawner) StartPeer(ctx context.Context, spec executor.ProcSpec) (executor.Peer, error) {
	inRead, inWrite, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("safety: creating the peer's input pipe: %w", err)
	}
	outRead, outWrite, perr := os.Pipe()
	if perr != nil {
		inRead.Close()
		inWrite.Close()
		return nil, fmt.Errorf("safety: creating the peer's output pipe: %w", perr)
	}

	cmd, cerr := s.command(spec, true)
	if cerr != nil {
		inRead.Close()
		inWrite.Close()
		outRead.Close()
		outWrite.Close()
		return nil, cerr
	}

	// Standard error is captured rather than discarded and rather than passed
	// through. It is outside the protocol by design, and it is where a plugin
	// that is about to die explains itself; a tail rather than a head, because
	// the explanation is the last thing printed, not the first.
	said := &tail{limit: s.peerOutputLimit()}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = inRead, outWrite, said

	h := &handle{cmd: cmd, exited: make(chan struct{}), start: time.Now()}
	if err := cmd.Start(); err != nil {
		inRead.Close()
		inWrite.Close()
		outRead.Close()
		outWrite.Close()
		return nil, fmt.Errorf("safety: starting the peer %s: %w", spec.Path, err)
	}
	s.placeInCgroup(cmd)

	// The child owns its ends now. Holding them open here would stop the pipes
	// ever reporting end-of-file, and a host waiting on a dead plugin would
	// wait forever rather than being told it died.
	inRead.Close()
	outWrite.Close()

	go h.reap()

	p := &Peer{cmd: h, stdin: inWrite, stdout: outRead, stderr: said}
	if ctx != nil && ctx.Done() != nil {
		go func() {
			select {
			case <-ctx.Done():
				p.Kill()
			case <-h.exited:
			}
		}()
	}
	return p, nil
}

// peerOutputLimit is how much of a peer's standard error is retained.
func (s *Spawner) peerOutputLimit() int {
	if s.MaxOutputBytes > 0 {
		return s.MaxOutputBytes
	}
	return 1 << 20
}

// Stdin is the peer's input, Stdout its output.
func (p *Peer) Stdin() io.WriteCloser { return p.stdin }
func (p *Peer) Stdout() io.Reader     { return p.stdout }

// Pid returns the process identifier.
func (p *Peer) Pid() int { return p.cmd.Pid() }

// Diagnose returns what the peer wrote to its standard error.
func (p *Peer) Diagnose() string { return p.stderr.String() }

// Kill ends the peer and closes its pipes.
//
// Closing the read end is what unblocks a host waiting on a peer that has
// stopped answering: the kill alone would leave the reader parked until the
// process actually died, which is precisely the case where it may not.
func (p *Peer) Kill() error {
	err := p.cmd.Kill()
	if c, ok := p.stdout.(io.Closer); ok {
		c.Close()
	}
	p.stdin.Close()
	return err
}

// Wait blocks until the peer exits.
func (p *Peer) Wait() (executor.ProcResult, error) { return p.cmd.Wait() }

// tail keeps the last bytes written to it.
//
// Concurrency-safe, unlike capped, because a peer writes to its standard error
// from its own goroutine while the host reads the tail from another — which is
// exactly when it is read, since the host only asks after something failed.
type tail struct {
	mu    sync.Mutex
	buf   []byte
	limit int
	over  bool
}

func (t *tail) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(p) >= t.limit {
		t.buf = append(t.buf[:0], p[len(p)-t.limit:]...)
		t.over = true
		return len(p), nil
	}
	if len(t.buf)+len(p) > t.limit {
		drop := len(t.buf) + len(p) - t.limit
		t.buf = append(t.buf[:0], t.buf[drop:]...)
		t.over = true
	}
	t.buf = append(t.buf, p...)
	return len(p), nil // never block the peer on us
}

func (t *tail) String() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.over {
		return "..." + string(t.buf)
	}
	return string(t.buf)
}
