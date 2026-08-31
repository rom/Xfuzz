//go:build darwin

package platform

import (
	"bytes"
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

// ptsName grants, unlocks and names the slave side.
//
// Darwin does the same three things Linux does under different names and in a
// different order: TIOCPTYGRANT sets the slave's ownership and permissions (the
// job of a setuid helper on Linux), TIOCPTYUNLK clears the lock, and
// TIOCPTYGNAME writes the path into a caller-supplied buffer rather than
// returning a number.
func ptsName(master *os.File) (string, error) {
	fd := int(master.Fd())
	if err := unix.IoctlSetInt(fd, unix.TIOCPTYGRANT, 0); err != nil {
		return "", fmt.Errorf("granting the pseudo-terminal: %w", err)
	}
	if err := unix.IoctlSetInt(fd, unix.TIOCPTYUNLK, 0); err != nil {
		return "", fmt.Errorf("unlocking the pseudo-terminal: %w", err)
	}
	// The buffer size is fixed by the ioctl's encoding: 0x40807453 carries a
	// 128-byte payload, and the kernel writes a NUL-terminated path into it.
	var buf [128]byte
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd),
		uintptr(unix.TIOCPTYGNAME), uintptr(unsafe.Pointer(&buf[0]))); errno != 0 {
		return "", fmt.Errorf("naming the pseudo-terminal: %w", errno)
	}
	name := buf[:]
	if i := bytes.IndexByte(name, 0); i >= 0 {
		name = name[:i]
	}
	if len(name) == 0 {
		return "", fmt.Errorf("the kernel named the pseudo-terminal with an empty path")
	}
	return string(name), nil
}
