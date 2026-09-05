//go:build darwin

package platform

// UnenforceableLimits names the caps a campaign set that this host cannot
// enforce, in the campaign file's own terms.
//
// One: the process cap. ApplyLimits sets no RLIMIT_NPROC because Go's syscall
// package does not export it for this platform, and a target that forks
// without bound is caught by its process group instead of being capped. That
// is containment rather than the limit the file asked for, and the report
// should say which.
func UnenforceableLimits(l Limits) []string {
	if l.Processes == 0 {
		return nil
	}
	return []string{
		"safety.process_limit is not enforced on macOS: there is no RLIMIT_NPROC to set " +
			"from Go, so a target that forks without bound is killed with its process " +
			"group rather than capped",
	}
}

// LimitsDetail says which caps this host's mechanism provides, for the doctor.
func LimitsDetail() string {
	return "memory, file-size and CPU-time ceilings (rlimits); no process cap, which " +
		"the process group stands in for"
}
