//go:build !linux && !windows

package platform

import "os/exec"

// The resource group on a platform with no kernel object for one.
//
// Nil rather than an error: a host that cannot account a target's memory should
// report a lower isolation level and run, not refuse. The level a caller
// computes from DetectSandbox is what decides whether that is acceptable.

// Cgroup is a no-op resource group.
type Cgroup struct{}

// NewCgroup returns no cgroup.
func NewCgroup(name string, l Limits) (*Cgroup, error) { return nil, nil }

// Mode reports that no hierarchy backs this cgroup.
func (c *Cgroup) Mode() string { return CgroupNone }

// Attach reports that the kernel cannot place the child for us.
func (c *Cgroup) Attach(cmd *exec.Cmd) bool { return false }

// Add does nothing.
func (c *Cgroup) Add(pid int) error { return nil }

// Close does nothing.
func (c *Cgroup) Close() error { return nil }
