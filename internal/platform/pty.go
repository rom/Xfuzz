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
// Windows has one — ConPTY, since Windows 10 1809 — and it is a different API
// with a different lifecycle rather than a different ioctl. Declaring the
// capability absent is the honest answer until that is written (ADR-0022);
// pretending a pipe is a terminal would produce a campaign whose findings are
// against a program in a mode nobody runs it in.
var ErrNoPTY = errors.New("platform: no pseudo-terminal support on this host")

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
