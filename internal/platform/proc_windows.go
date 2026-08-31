//go:build windows

package platform

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"

	"golang.org/x/sys/windows"
)

// Process containment on Windows.
//
// Windows has no process groups in the Unix sense — no session, no pgid a
// signal can be sent to the negative of — and it has two things that together
// do the same work. A console process group can be sent a break event, which is
// the closest thing to SIGTERM a console program will act on, and a job object
// kills everything inside it when the fuzzer lets go, which is the tree kill.
// The job is created by the sandbox; what is here is the group and the
// translation of how a target died.

// ConfigureProcess puts the target in a console process group of its own.
//
// Without it a break event sent to the target reaches the fuzzer as well —
// console control events go to a group, and a child shares its parent's group
// by default. The campaign would stop itself trying to stop a target.
func ConfigureProcess(cmd *exec.Cmd, quarantine bool) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.CreationFlags |= windows.CREATE_NEW_PROCESS_GROUP
}

// TerminateGroup asks the target's process group to stop.
//
// A break event rather than a kill, so that a target with a handler runs it:
// the graceful half of the two-step the spawner does before it resorts to
// force. A target that installed no handler is terminated by the default
// handler, which is the same outcome SIGTERM has.
func TerminateGroup(pid int) error {
	if err := windows.GenerateConsoleCtrlEvent(windows.CTRL_BREAK_EVENT, uint32(pid)); err != nil {
		// A target with no console — a GUI program, or one started detached —
		// cannot be sent a control event at all. Falling back to the kill is
		// better than reporting that the target could not be stopped.
		return killProcess(pid)
	}
	return nil
}

// KillGroup terminates the target.
//
// It reaches the target and not its children: TerminateProcess is not
// recursive, and there is no group to terminate. The children are caught by the
// campaign's job object, which kills everything in it when the fuzzer releases
// it — which is why the sandbox creates one and why it is reported as the
// resource group.
func KillGroup(pid int) error { return killProcess(pid) }

func killProcess(pid int) error {
	p, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Errorf("platform: finding process %d: %w", pid, err)
	}
	return p.Kill()
}

// SignalOf reports the signal a Unix host would have raised for the fault this
// target died of.
//
// Windows reports a fatal exception as an exit code, so without this every
// crash on this platform reads as a clean exit and a campaign that is finding
// bugs reports that it found none. ExceptionSignal carries the mapping and the
// reasoning; this is only where it is applied.
func SignalOf(st *os.ProcessState) int {
	if st == nil {
		return 0
	}
	code := st.ExitCode()
	if code < 0 {
		return 0
	}
	return ExceptionSignal(uint32(code))
}

// ProcessGroupsSupported reports whether a target's whole tree can be killed.
//
// The job object is what does it, so the answer is whether one can be created.
// A host that cannot — a fuzzer already inside a job it may not nest within —
// leaks a target's children, and the doctor should say so rather than implying
// a containment that is not there.
func ProcessGroupsSupported() bool { return JobObjectsAvailable() }
