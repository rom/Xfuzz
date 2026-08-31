package safety

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
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
	cmd    *exec.Cmd
	master *os.File
	slave  *os.File

	mu      sync.Mutex
	closed  bool
	state   *os.ProcessState
	waitErr error

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
	master, slave, err := platform.OpenPTY(cols, rows)
	if err != nil {
		return nil, fmt.Errorf("safety: %w", err)
	}

	cmd, err := s.command(spec, false)
	if err != nil {
		master.Close()
		slave.Close()
		return nil, err
	}
	cmd.ExtraFiles = spec.ExtraFiles
	// After command, which sets the process attributes this replaces: a
	// controlling terminal needs a session, and a session is a process group.
	platform.ConfigureTTY(cmd, slave)

	p := &PTY{cmd: cmd, master: master, slave: slave, exited: make(chan struct{}), start: time.Now()}
	if err := cmd.Start(); err != nil {
		master.Close()
		slave.Close()
		return nil, fmt.Errorf("safety: starting %s on a terminal: %w", spec.Path, err)
	}
	s.placeInCgroup(cmd)

	// The parent's copy of the slave goes now. Holding it open would keep the
	// terminal from ever reporting end-of-file, so a driver waiting for the
	// program to finish drawing would wait for ever after the program exited.
	slave.Close()
	p.slave = nil

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
	err := p.cmd.Wait()
	p.mu.Lock()
	p.state, p.waitErr = p.cmd.ProcessState, err
	p.mu.Unlock()
	close(p.exited)
}

// Pid returns the process identifier.
func (p *PTY) Pid() int {
	if p.cmd.Process == nil {
		return 0
	}
	return p.cmd.Process.Pid
}

// Read returns whatever the program has drawn.
//
// A terminal whose child has exited returns EIO on Linux rather than EOF, which
// is a kernel detail no caller should have to know: it is translated to
// io.EOF here so that a drain loop ends the way every other drain loop does.
func (p *PTY) Read(b []byte) (int, error) {
	n, err := p.master.Read(b)
	if err != nil && n == 0 && platform.IsTerminalEOF(err) {
		return 0, io.EOF
	}
	return n, err
}

// Write types into the program.
func (p *PTY) Write(b []byte) (int, error) { return p.master.Write(b) }

// Resize changes the terminal's window size, which sends the program SIGWINCH.
func (p *PTY) Resize(cols, rows int) error {
	if err := platform.SetPTYSize(p.master, cols, rows); err != nil {
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
	if p.state == nil {
		return res
	}
	res.ExitCode = p.state.ExitCode()
	res.Signal = platform.SignalOf(p.state)
	return res
}

// Signal sends a signal to the target's process group.
func (p *PTY) Signal(kill bool) error {
	if p.cmd.Process == nil {
		return nil
	}
	if kill {
		return platform.KillGroup(p.cmd.Process.Pid)
	}
	return platform.TerminateGroup(p.cmd.Process.Pid)
}

// Kill terminates the target and everything it started.
func (p *PTY) Kill() error {
	if p.cmd.Process == nil || !p.Alive() {
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
		// The master last: closing it first sends the target SIGHUP, which is a
		// second, racing way of killing it, and a target that died of SIGHUP
		// rather than of the campaign's own kill looks like a crash.
		if cerr := p.master.Close(); cerr != nil && err == nil {
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
