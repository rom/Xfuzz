//go:build linux

package platform

// UnenforceableLimits names the caps a campaign set that this host cannot
// enforce, in the campaign file's own terms. Linux enforces all of them:
// rlimits for each, and a cgroup for memory and processes where one can be
// created.
func UnenforceableLimits(l Limits) []string { return nil }

// LimitsDetail says which caps this host's mechanism provides, for the doctor.
func LimitsDetail() string {
	return "memory, file-size, CPU-time and process ceilings (rlimits), and a cgroup " +
		"for memory and process count where one can be created"
}
