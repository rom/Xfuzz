//go:build linux

package platform

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// ptsName unlocks the slave side and returns its path.
//
// Two ioctls in a fixed order. TIOCSPTLCK with zero clears the lock the kernel
// puts on a freshly allocated slave — this is what glibc's unlockpt does — and
// TIOCGPTN returns the number the device is called. Opening /dev/pts/N without
// the unlock gives EIO, and the failure looks like a missing device rather than
// a missing step.
func ptsName(master *os.File) (string, error) {
	fd := int(master.Fd())
	if err := unix.IoctlSetPointerInt(fd, unix.TIOCSPTLCK, 0); err != nil {
		return "", fmt.Errorf("unlocking the pseudo-terminal: %w", err)
	}
	n, err := unix.IoctlGetInt(fd, unix.TIOCGPTN)
	if err != nil {
		return "", fmt.Errorf("naming the pseudo-terminal: %w", err)
	}
	return fmt.Sprintf("/dev/pts/%d", n), nil
}
