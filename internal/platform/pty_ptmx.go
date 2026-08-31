//go:build linux || darwin

package platform

import (
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
	m, s, err := OpenPTY(DefaultPTYCols, DefaultPTYRows)
	if err != nil {
		return false
	}
	m.Close()
	s.Close()
	return true
}

// OpenPTY allocates a pseudo-terminal pair.
//
// The master is the fuzzer's end: writing to it is typing, reading from it is
// watching the program draw. The slave becomes the target's standard input,
// output and error, and its controlling terminal.
func OpenPTY(cols, rows int) (master, slave *os.File, err error) {
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
	if err := SetPTYSize(m, cols, rows); err != nil {
		m.Close()
		s.Close()
		return nil, nil, err
	}
	return m, s, nil
}

// SetPTYSize sets the window size.
//
// The kernel sends SIGWINCH to the target's foreground process group as a side
// effect, which is exactly what a resize event has to do: a TUI redraws on the
// signal, not on the ioctl.
func SetPTYSize(pty *os.File, cols, rows int) error {
	if cols < 1 {
		cols = 1
	}
	if rows < 1 {
		rows = 1
	}
	if cols > MaxPTYCols {
		cols = MaxPTYCols
	}
	if rows > MaxPTYRows {
		rows = MaxPTYRows
	}
	ws := &unix.Winsize{Col: uint16(cols), Row: uint16(rows)}
	if err := unix.IoctlSetWinsize(int(pty.Fd()), unix.TIOCSWINSZ, ws); err != nil {
		return fmt.Errorf("setting the terminal size to %dx%d: %w", cols, rows, err)
	}
	return nil
}

// ConfigureTTY points a command's standard descriptors at the slave and makes it
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
func ConfigureTTY(cmd *exec.Cmd, slave *os.File) {
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
