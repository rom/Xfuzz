//go:build !unix

package platform

import (
	"os"
	"os/exec"
)

// ConfigureProcess is a no-op where process groups work differently. Windows
// gets Job Objects in M4.
func ConfigureProcess(cmd *exec.Cmd, quarantine bool) {}

// TerminateGroup kills the process; platforms without process groups cannot
// reach its children, which is a declared gap rather than a silent one.
func TerminateGroup(pid int) error { return killProcess(pid) }

// KillGroup kills the process.
func KillGroup(pid int) error { return killProcess(pid) }

func killProcess(pid int) error {
	p, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	return p.Kill()
}

// SignalOf reports no signal: platforms without POSIX signals surface a fatal
// fault as an exit code instead.
func SignalOf(*os.ProcessState) int { return 0 }

// ProcessGroupsSupported reports whether killing a process tree is possible.
func ProcessGroupsSupported() bool { return false }
