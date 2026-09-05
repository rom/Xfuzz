//go:build !linux && !darwin && !windows

package platform

// UnenforceableLimits names the caps a campaign set that this host cannot
// enforce, which here is every cap it set: ApplyLimits does nothing on a
// platform Xfuzz has no limit mechanism for.
func UnenforceableLimits(l Limits) []string {
	var out []string
	say := func(field string) {
		out = append(out, "safety."+field+" is not enforced on this platform: Xfuzz has no "+
			"resource-limit mechanism for it")
	}
	if l.AddressSpaceBytes > 0 {
		say("memory_limit")
	}
	if l.Processes > 0 {
		say("process_limit")
	}
	if l.FileSizeBytes > 0 {
		say("file_size_limit")
	}
	if l.CPUSeconds > 0 {
		say("cpu_limit")
	}
	return out
}

// LimitsDetail says which caps this host's mechanism provides, for the doctor.
func LimitsDetail() string {
	return "none: this platform has no resource-limit mechanism Xfuzz knows how to use"
}
