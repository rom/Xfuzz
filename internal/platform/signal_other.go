//go:build !unix

package platform

import "os"

// TerminationSignals are the signals a long-running Xfuzz process should treat
// as a request to shut down cleanly.
//
// Windows delivers console control events as os.Interrupt; there is no SIGTERM
// to listen for, and a service stop arrives through the service control manager
// rather than as a signal at all.
func TerminationSignals() []os.Signal { return []os.Signal{os.Interrupt} }
