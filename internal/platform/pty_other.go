//go:build !linux && !darwin && !windows

package platform

import "os/exec"

// PTYSupported reports whether this host can allocate a pseudo-terminal.
func PTYSupported() bool { return false }

// TTY is the pseudo-terminal this platform does not have.
//
// The type exists so the rest of the tree compiles against one shape. Every
// method returns ErrNoPTY rather than doing nothing, because a terminal
// campaign that appeared to run and typed into nothing would report a program
// that draws no screens as a program with no states.
type TTY struct{}

// OpenTTY reports that there is no mechanism here.
func OpenTTY(cols, rows int) (*TTY, error) { return nil, ErrNoPTY }

// Start reports that there is no terminal to start on.
func (t *TTY) Start(cmd *exec.Cmd) (TTYProcess, error) { return nil, ErrNoPTY }

// Read reports that there is nothing to read.
func (t *TTY) Read(b []byte) (int, error) { return 0, ErrNoPTY }

// Write reports that there is nothing to type into.
func (t *TTY) Write(b []byte) (int, error) { return 0, ErrNoPTY }

// Resize reports that there is no window to size.
func (t *TTY) Resize(cols, rows int) error { return ErrNoPTY }

// Close has nothing to release.
func (t *TTY) Close() error { return nil }
