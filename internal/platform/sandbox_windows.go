//go:build windows

package platform

import (
	"errors"
	"fmt"
	"os/exec"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Confinement on Windows.
//
// There are no namespaces, no seccomp and no cgroups, and there is a job
// object, which does two of the three things a cgroup does and does them
// better in one respect. It caps memory and process count from the moment a
// process is assigned to it, and it kills everything in the job when the last
// handle closes — so a fuzzer that dies takes its targets with it rather than
// leaving a machine full of orphans, which is the failure that makes an
// unattended Windows campaign unusable.
//
// What it does not give is filesystem or network confinement. That needs a
// restricted or low-integrity token, which is a larger piece of work with a
// larger blast radius: a target that cannot read its own DLLs does not start,
// and the campaign reports a broken target. So the job object lands here, the
// token does not, and the level this reaches says which of the two it is.

// Cgroup is a Windows job object wearing the interface the rest of Xfuzz
// already has for a resource group.
//
// The same shape rather than a parallel mechanism, because the call sites are
// the same: create one per campaign, put each spawned target into it, close it
// when the campaign ends. Naming it Cgroup is a small lie about the kernel and
// a large truth about the code — the alternative was a second lifecycle in the
// spawner with a build tag around it.
//
// One per sandbox rather than one per target, so that the process cap is a cap
// on the campaign's targets together — a target that forks a hundred children
// has exceeded the campaign's budget whether or not any single process did.
type Cgroup struct {
	h windows.Handle
}

// NewCgroup creates a job object carrying the campaign's limits.
func NewCgroup(name string, l Limits) (*Cgroup, error) {
	h, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return nil, fmt.Errorf("platform: creating a job object: %w", err)
	}
	j := &Cgroup{h: h}

	var info windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	// Kill on close is the reason this exists at all. Without it a fuzzer that
	// is killed leaves its targets running, and on Windows there is no process
	// group to sweep them up with.
	info.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if l.AddressSpaceBytes > 0 {
		info.BasicLimitInformation.LimitFlags |= windows.JOB_OBJECT_LIMIT_PROCESS_MEMORY
		info.ProcessMemoryLimit = uintptr(l.AddressSpaceBytes)
	}
	if l.Processes > 0 {
		info.BasicLimitInformation.LimitFlags |= windows.JOB_OBJECT_LIMIT_ACTIVE_PROCESS
		info.BasicLimitInformation.ActiveProcessLimit = uint32(l.Processes)
	}
	if _, err := windows.SetInformationJobObject(h,
		windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil {
		j.Close()
		return nil, fmt.Errorf("platform: setting the job's limits: %w", err)
	}
	_ = name
	return j, nil
}

// Assign puts a process into the job.
//
// After the process exists rather than at creation, which is the same race
// cgroups v1 has and is named for the same reason: a target that forks before
// the assignment lands leaves a child outside the limit. The window is the time
// between CreateProcess returning and this call, and closing it properly needs
// the process created suspended — which conflicts with how os/exec starts one.
func (j *Cgroup) Add(pid int) error {
	if j == nil {
		return nil
	}
	h, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE,
		false, uint32(pid))
	if err != nil {
		return fmt.Errorf("platform: opening process %d to assign it to the job: %w", pid, err)
	}
	defer windows.CloseHandle(h)
	if err := windows.AssignProcessToJobObject(j.h, h); err != nil {
		return fmt.Errorf("platform: assigning process %d to the job: %w", pid, err)
	}
	return nil
}

// Mode reports that a job object backs this group.
func (j *Cgroup) Mode() string {
	if j == nil {
		return CgroupNone
	}
	return CgroupJob
}

// Attach reports that the kernel cannot place the child at creation.
//
// It could, with a suspended process and a handle — but os/exec does not offer
// one, so the assignment happens after the process exists and the caller is
// told to do it with Add. Saying so is what keeps the spawner from believing
// the child was already accounted for.
func (j *Cgroup) Attach(cmd *exec.Cmd) bool { return false }

// Close releases the job, which kills everything still in it.
func (j *Cgroup) Close() error {
	if j == nil || j.h == 0 {
		return nil
	}
	err := windows.CloseHandle(j.h)
	j.h = 0
	return err
}

// JobObjectsAvailable reports whether a job object can be created here.
//
// Probed rather than assumed from the version, because a process that is
// already inside a job it does not control — a container, or a CI agent that
// wraps its steps — may not be able to nest one, and on older Windows it could
// not nest at all.
func JobObjectsAvailable() bool {
	h, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return false
	}
	windows.CloseHandle(h)
	return true
}

// ApplyLimits does nothing in the target process.
//
// Windows has no rlimits: the caps are the job object's, and the job is applied
// by the fuzzer to the target rather than by the target to itself. Returning
// nil rather than an error is correct — the limits were applied, just not here.
func ApplyLimits(l Limits) error { return nil }

// DropPrivileges reports that this is not how Windows works.
//
// The equivalent is creating the process with a restricted token, which has to
// happen at creation rather than afterwards; there is nothing a process can do
// to become another user after the fact.
func DropPrivileges(uid, gid int) error {
	return errors.New("platform: a Windows process cannot change to another user after it " +
		"has started; the equivalent is a restricted token supplied at creation")
}

// DetectSandbox reports what this host can enforce.
func DetectSandbox() SandboxCapabilities {
	c := SandboxCapabilities{Cgroups: CgroupNone}
	if JobObjectsAvailable() {
		c.JobLimits = true
		// Reported as the resource group, because that is what the rest of
		// Xfuzz already knows how to create, attach and release.
		c.Cgroups = CgroupJob
		// The job object *is* the resource-limit mechanism here, so reporting
		// no rlimits and no job would say a campaign has no memory cap when it
		// has one the kernel enforces.
		c.Rlimits = true
	} else {
		c.Notes = append(c.Notes, "a job object could not be created, so a target has no "+
			"memory or process cap and will not be killed with the fuzzer; this usually "+
			"means the fuzzer is already inside a job it cannot nest within")
	}
	c.Notes = append(c.Notes,
		"namespaces, seccomp and cgroups are Linux mechanisms; on Windows the equivalent "+
			"is a job object, which caps memory and process count and kills the whole "+
			"tree when the fuzzer lets go",
		"a job object does not confine the filesystem or the network: that needs a "+
			"restricted or low-integrity token, which Xfuzz does not yet create, so a "+
			"target can write anywhere the fuzzer's own account can")
	return c
}

// ConfigureJob is where a job would be attached at creation, once os/exec can
// be asked to start a process suspended. It exists so the call site is written
// once rather than being added in three places later.
func ConfigureJob(cmd *exec.Cmd) {}
