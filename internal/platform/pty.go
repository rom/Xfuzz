package platform

import (
	"errors"
	"io"
	"syscall"
)

// Terminal size limits. A window size is two 16-bit fields in the kernel's
// struct winsize, and a target that asks for more gets what fits.
const (
	DefaultPTYCols = 80
	DefaultPTYRows = 24
	MaxPTYCols     = 1000
	MaxPTYRows     = 1000
)

// ErrNoPTY is what every pseudo-terminal entry point returns on a host with no
// mechanism this package implements.
//
// Two platforms have one and they share no code: a Unix master and slave pair
// opened through /dev/ptmx, and a Windows pseudo-console, which is a console
// object plus two pipes and is passed to a child in a process attribute rather
// than on a descriptor. Everything else gets this error, because pretending a
// pipe is a terminal would produce a campaign whose findings are against a
// program in a mode nobody runs it in (ADR-0022, ADR-0030).
var ErrNoPTY = errors.New("platform: no pseudo-terminal support on this host")

// TTYExit is how a terminal target ended.
//
// Two fields rather than an *os.ProcessState, because Windows does not produce
// one: os/exec cannot start a process on a pseudo-console — the console is
// handed over in a STARTUPINFOEX attribute list and SysProcAttr has no field
// for one — so that platform calls CreateProcess itself and there is no
// os.Process behind the result to ask. Both platforms fill the same two fields,
// and Signal is what the crash classification reads.
type TTYExit struct {
	ExitCode int
	Signal   int
}

// TTYProcess is a target running on a pseudo-terminal.
//
// An interface with two methods, because the two platforms agree on nothing
// else: one waits on an *exec.Cmd and the other on a process handle. What the
// caller needs is the identifier, to kill it, and the exit, to classify it.
type TTYProcess interface {
	// Pid returns the process identifier.
	Pid() int

	// Wait blocks until the target exits and reports how it ended.
	Wait() (TTYExit, error)
}

// clampTTYSize keeps a window size inside what the mechanism can carry.
//
// Both platforms store the size in 16-bit fields, and both have a lower bound
// of one: a zero-column terminal is not a small terminal, it is a device every
// write to which is a division by zero somewhere in the program's layout code.
func clampTTYSize(cols, rows int) (int, int) {
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
	return cols, rows
}

// IsTerminalEOF reports whether an error is the kernel's way of saying the
// other end of a pseudo-terminal is gone.
//
// Linux answers a read on a master whose slave has closed with EIO rather than
// with end-of-file. That is a documented kernel behaviour and not an error the
// caller can do anything about, so translating it is the difference between a
// drain loop that ends when the program exits and one that reports a failure
// every time a target finishes normally.
func IsTerminalEOF(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, io.EOF) {
		return true
	}
	return errors.Is(err, syscall.EIO)
}
