//go:build unix

package platform

import (
	"os"
	"os/exec"
	"syscall"
)

// Process control mechanism. The policy — when to confine, when to kill, how
// long to wait — belongs to internal/safety; what belongs here is only how a
// given operating system expresses it.

// ConfigureProcess applies the platform's process attributes before launch.
//
// Setpgid puts the target in its own process group so that killing it kills
// everything it started. Without it a target that forks leaves orphans behind on
// every timeout, and a campaign that hits a few thousand of those exhausts the
// host's process table.
func ConfigureProcess(cmd *exec.Cmd, quarantine bool) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

// TerminateGroup asks a process group to exit.
func TerminateGroup(pid int) error { return syscall.Kill(-pid, syscall.SIGTERM) }

// KillGroup terminates a process group outright.
func KillGroup(pid int) error { return syscall.Kill(-pid, syscall.SIGKILL) }

// SignalOf returns the fatal signal a process died from, or zero.
func SignalOf(st *os.ProcessState) int {
	ws, ok := st.Sys().(syscall.WaitStatus)
	if !ok || !ws.Signaled() {
		return 0
	}
	return int(ws.Signal())
}

// ProcessGroupsSupported reports whether killing a process tree is possible.
func ProcessGroupsSupported() bool { return true }
