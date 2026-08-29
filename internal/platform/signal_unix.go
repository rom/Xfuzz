//go:build unix

package platform

import (
	"os"
	"syscall"
)

// TerminationSignals are the signals a long-running Xfuzz process should treat
// as a request to shut down cleanly.
//
// Here rather than at each command because the set is a platform fact: SIGTERM
// is what a service manager sends on Unix and does not exist on Windows, and a
// command that named it directly would both fail to build there and reach past
// the boundary that keeps OS specifics in one package.
func TerminationSignals() []os.Signal {
	return []os.Signal{os.Interrupt, syscall.SIGTERM}
}
