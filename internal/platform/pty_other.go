//go:build !linux && !darwin

package platform

import (
	"os"
	"os/exec"
)

// PTYSupported reports whether this host can allocate a pseudo-terminal.
func PTYSupported() bool { return false }

// OpenPTY allocates a pseudo-terminal pair.
func OpenPTY(cols, rows int) (master, slave *os.File, err error) { return nil, nil, ErrNoPTY }

// SetPTYSize sets the window size.
func SetPTYSize(pty *os.File, cols, rows int) error { return ErrNoPTY }

// ConfigureTTY points a command's standard descriptors at the slave.
func ConfigureTTY(cmd *exec.Cmd, slave *os.File) {}
