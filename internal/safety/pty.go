package safety

import (
	"context"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/rom/Xfuzz/internal/platform"
	"github.com/rom/Xfuzz/pkg/executor"
)

// A terminal target is confined like any other.
//
// It is worth saying explicitly because a pseudo-terminal looks like a special
// case and is not: the process still goes through Spawner.command, so it still
// gets the sandbox, the working directory, the cgroup and the process-group
// kill. All the terminal changes is which file its standard descriptors point
// at, and that it has a session of its own.

// PTYSupported reports whether this host can drive a terminal target.
func PTYSupported() bool { return platform.PTYSupported() }

// PTY is a process running on a pseudo-terminal.
//
// Reading it is watching the program draw; writing it is typing. Both are safe
// to call from different goroutines, which is what the driver does: one
// goroutine drains the terminal continuously while the other delivers events.
type PTY struct {
	tty  *platform.TTY
	proc platform.TTYProcess

	mu       sync.Mutex
	closed   bool
	exit     platform.TTYExit
	haveExit bool
	waitErr  error

	exited chan struct{}
	start  time.Time
	once   sync.Once
}

// StartPTY launches a target on a pseudo-terminal of the given size.
//
// spec.Stdin, spec.StdinFile and spec.CaptureOutput are ignored: on a terminal
// there is one bidirectional channel and it is the terminal. Everything the
// program writes, on standard output and standard error alike, arrives through
// Read, because that is what a terminal is.
func (s *Spawner) StartPTY(ctx context.Context, spec executor.ProcSpec, cols, rows int) (*PTY, error) {
	if !platform.PTYSupported() {
		return nil, fmt.Errorf("safety: %w", platform.ErrNoPTY)
	}
	tty, err := platform.OpenTTY(cols, rows)
	if err != nil {
		return nil, fmt.Errorf("safety: %w", err)
	}

	cmd, err := s.command(spec, false)
	if err != nil {
		tty.Close()
		return nil, err
	}
	cmd.ExtraFiles = spec.ExtraFiles

	// Start on the terminal rather than through cmd.Start: the platform owns
	// how a target acquires one, because the two mechanisms have nothing in
	// common. On Unix it is a session and a controlling-terminal ioctl applied
	// to the command this layer built; on Windows the pseudo-console arrives in
	// a process attribute os/exec cannot carry, so that platform starts the
	// command itself — from the same path, argv, directory and environment the
	// sandbox put on it.
	proc, err := tty.Start(cmd)
	if err != nil {
		tty.Close()
		return nil, fmt.Errorf("safety: starting %s on a terminal: %w", spec.Path, err)
	}

	p := &PTY{tty: tty, proc: proc, exited: make(chan struct{}), start: time.Now()}
	s.placeInCgroupPid(proc.Pid())

	go p.reap()
	if ctx != nil && ctx.Done() != nil {
		go func() {
			select {
			case <-ctx.Done():
				p.Kill()
			case <-p.exited:
			}
		}()
	}
	return p, nil
}

func (p *PTY) reap() {
	exit, err := p.proc.Wait()
	p.mu.Lock()
	p.exit, p.haveExit, p.waitErr = exit, true, err
	p.mu.Unlock()
	close(p.exited)
}

// Pid returns the process identifier.
func (p *PTY) Pid() int { return p.proc.Pid() }

// Read returns whatever the program has drawn.
//
// A terminal whose child has exited returns EIO on Linux rather than EOF, which
// is a kernel detail no caller should have to know: it is translated to
// io.EOF here so that a drain loop ends the way every other drain loop does.
func (p *PTY) Read(b []byte) (int, error) {
	n, err := p.tty.Read(b)
	if err != nil && n == 0 && platform.IsTerminalEOF(err) {
		return 0, io.EOF
	}
	return n, err
}

// Write types into the program.
func (p *PTY) Write(b []byte) (int, error) { return p.tty.Write(b) }

// Resize changes the terminal's window size, which sends the program SIGWINCH.
func (p *PTY) Resize(cols, rows int) error {
	if err := p.tty.Resize(cols, rows); err != nil {
		return fmt.Errorf("safety: %w", err)
	}
	return nil
}

// Alive reports whether the target is still running.
func (p *PTY) Alive() bool {
	select {
	case <-p.exited:
		return false
	default:
		return true
	}
}

// Exited returns a channel closed when the target ends.
func (p *PTY) Exited() <-chan struct{} { return p.exited }

// Result returns how the target ended, or a zero result while it is running.
func (p *PTY) Result() executor.ProcResult {
	p.mu.Lock()
	defer p.mu.Unlock()
	res := executor.ProcResult{Duration: time.Since(p.start)}
	if !p.haveExit {
		return res
	}
	res.ExitCode = p.exit.ExitCode
	res.Signal = p.exit.Signal
	return res
}

// Signal sends a signal to the target's process group.
func (p *PTY) Signal(kill bool) error {
	pid := p.proc.Pid()
	if pid == 0 {
		return nil
	}
	if kill {
		return platform.KillGroup(pid)
	}
	return platform.TerminateGroup(pid)
}

// Kill terminates the target and everything it started.
func (p *PTY) Kill() error {
	if p.proc.Pid() == 0 || !p.Alive() {
		return nil
	}
	_ = p.Signal(false)
	select {
	case <-p.exited:
		return nil
	case <-time.After(gracePeriod):
	}
	if err := p.Signal(true); err != nil {
		return err
	}
	select {
	case <-p.exited:
		return nil
	case <-time.After(ReapTimeout):
		return fmt.Errorf("safety: terminal target %d did not die within %s of SIGKILL",
			p.Pid(), ReapTimeout)
	}
}

// Close kills the target and releases the terminal.
func (p *PTY) Close() error {
	var err error
	p.once.Do(func() {
		err = p.Kill()
		// The terminal last: closing it first sends the target SIGHUP, which is
		// a second, racing way of killing it, and a target that died of SIGHUP
		// rather than of the campaign's own kill looks like a crash.
		if cerr := p.tty.Close(); cerr != nil && err == nil {
			err = cerr
		}
		p.mu.Lock()
		p.closed = true
		p.mu.Unlock()
	})
	return err
}

// gracePeriod is how long a terminal target gets to exit on SIGTERM before the
// kill. Short, because it is spent on every reset and a T7 campaign resets on
// every sequence.
const gracePeriod = 200 * time.Millisecond
