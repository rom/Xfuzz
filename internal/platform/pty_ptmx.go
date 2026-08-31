//go:build linux || darwin

package platform

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"syscall"

	"golang.org/x/sys/unix"
)

// A pseudo-terminal is the only honest way to drive a terminal program.
//
// The alternative — pipes — changes the program's behaviour before the fuzzer
// has sent a single keystroke. isatty returns false, so a TUI refuses to start
// or falls back to a line-oriented mode; the terminal size is unknown, so
// nothing that draws a full screen draws one; there is no controlling terminal,
// so job control and SIGWINCH do not exist. A campaign run over pipes is a
// campaign against a different program.
//
// The policy — how long to wait, when to kill, what confinement to apply —
// belongs to internal/safety. What belongs here is only how an operating system
// allocates the pair.

// PTYSupported reports whether this host can allocate a pseudo-terminal.
//
// Probed rather than assumed: a container without /dev/pts mounted, or with
// devpts mounted read-only, has a kernel that supports pseudo-terminals and a
// filesystem that will not hand one over. Discovering that after a campaign has
// started means having told the operator it was fuzzing when it was not.
func PTYSupported() bool {
	m, s, err := openPTY(DefaultPTYCols, DefaultPTYRows)
	if err != nil {
		return false
	}
	m.Close()
	s.Close()
	return true
}

// openPTY allocates a pseudo-terminal pair.
//
// The master is the fuzzer's end: writing to it is typing, reading from it is
// watching the program draw. The slave becomes the target's standard input,
// output and error, and its controlling terminal.
func openPTY(cols, rows int) (master, slave *os.File, err error) {
	m, err := os.OpenFile("/dev/ptmx", os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("opening /dev/ptmx: %w", err)
	}
	name, err := ptsName(m)
	if err != nil {
		m.Close()
		return nil, nil, err
	}
	s, err := os.OpenFile(name, os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		m.Close()
		return nil, nil, fmt.Errorf("opening %s: %w", name, err)
	}
	if err := setPTYSize(m, cols, rows); err != nil {
		m.Close()
		s.Close()
		return nil, nil, err
	}
	return m, s, nil
}

// setPTYSize sets the window size.
//
// The kernel sends SIGWINCH to the target's foreground process group as a side
// effect, which is exactly what a resize event has to do: a TUI redraws on the
// signal, not on the ioctl.
func setPTYSize(pty *os.File, cols, rows int) error {
	cols, rows = clampTTYSize(cols, rows)
	ws := &unix.Winsize{Col: uint16(cols), Row: uint16(rows)}
	if err := unix.IoctlSetWinsize(int(pty.Fd()), unix.TIOCSWINSZ, ws); err != nil {
		return fmt.Errorf("setting the terminal size to %dx%d: %w", cols, rows, err)
	}
	return nil
}

// configureTTY points a command's standard descriptors at the slave and makes it
// the process's controlling terminal.
//
// Setsid is not optional and not merely tidy. A controlling terminal can only be
// acquired by a session leader, so without it TIOCSCTTY fails and the program
// runs with a terminal on its descriptors and no terminal in its session —
// which is the shape that breaks job control, SIGINT delivery and every
// program that reads /dev/tty.
//
// It replaces the Setpgid that ConfigureProcess would otherwise apply, and
// costs nothing: a new session is a new process group whose identifier is the
// child's own pid, so killing the group still kills everything the target
// started.
func configureTTY(cmd *exec.Cmd, slave *os.File) {
	cmd.Stdin, cmd.Stdout, cmd.Stderr = slave, slave, slave
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setpgid = false
	cmd.SysProcAttr.Setsid = true
	cmd.SysProcAttr.Setctty = true
	// The child's descriptor number, after Go has arranged stdin, stdout and
	// stderr — not the parent's.
	cmd.SysProcAttr.Ctty = 0
}

// TTY is a pseudo-terminal pair: the fuzzer holds the master, the target gets
// the slave.
//
// The type exists so that internal/safety has one shape to drive on every
// platform. Windows reaches the same shape through an entirely different
// mechanism, and a policy layer that had to know which one it was talking to
// would end up carrying build tags — which the architecture lint forbids, for
// the reason that a policy written twice is a policy that differs once.
type TTY struct {
	master *os.File
	slave  *os.File
}

// OpenTTY allocates a pseudo-terminal of the given size.
func OpenTTY(cols, rows int) (*TTY, error) {
	m, s, err := openPTY(cols, rows)
	if err != nil {
		return nil, err
	}
	return &TTY{master: m, slave: s}, nil
}

// Start runs a prepared command on the terminal.
//
// The command is the one internal/safety built, with the sandbox, the working
// directory and the environment already on it. All this adds is the terminal
// itself and the session that makes it a controlling terminal.
func (t *TTY) Start(cmd *exec.Cmd) (TTYProcess, error) {
	if t.slave == nil {
		return nil, errors.New("platform: the terminal has already started a target")
	}
	configureTTY(cmd, t.slave)
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	// The parent's copy of the slave goes now. Holding it open would keep the
	// terminal from ever reporting end-of-file, so a caller waiting for the
	// program to finish drawing would wait for ever after the program exited.
	t.slave.Close()
	t.slave = nil
	return &cmdProcess{cmd: cmd}, nil
}

// Read returns whatever the target has drawn.
func (t *TTY) Read(b []byte) (int, error) { return t.master.Read(b) }

// Write types into the target.
func (t *TTY) Write(b []byte) (int, error) { return t.master.Write(b) }

// Resize changes the window size, which sends the target SIGWINCH.
func (t *TTY) Resize(cols, rows int) error { return setPTYSize(t.master, cols, rows) }

// Close releases the terminal.
//
// Closing the master sends the target SIGHUP, so the caller kills it first: a
// target that died of SIGHUP rather than of the campaign's own kill looks like
// a crash.
func (t *TTY) Close() error {
	if t.slave != nil {
		t.slave.Close()
		t.slave = nil
	}
	return t.master.Close()
}

// cmdProcess is a target started through os/exec.
type cmdProcess struct{ cmd *exec.Cmd }

func (p *cmdProcess) Pid() int {
	if p.cmd.Process == nil {
		return 0
	}
	return p.cmd.Process.Pid
}

func (p *cmdProcess) Wait() (TTYExit, error) {
	err := p.cmd.Wait()
	st := p.cmd.ProcessState
	if st == nil {
		return TTYExit{}, err
	}
	// The error is not returned alongside the exit: cmd.Wait reports a non-zero
	// exit as an error, and a target that exits non-zero is a target that ran,
	// not a spawn that failed. Distinguishing the two here rather than at every
	// call site is the point.
	return TTYExit{ExitCode: st.ExitCode(), Signal: SignalOf(st)}, nil
}
