//go:build windows

package platform

// UnenforceableLimits names the caps a campaign set that this host cannot
// enforce, in the campaign file's own terms.
//
// One: the file-size cap. A job object caps memory, process count and CPU
// time, and Windows has no rlimits, so there is nothing to hang a file-size
// ceiling on. Before this was said, the limit was accepted from the file and
// dropped on the floor — in a tool whose isolation report exists to say what
// is enforced.
func UnenforceableLimits(l Limits) []string {
	if l.FileSizeBytes == 0 {
		return nil
	}
	return []string{
		"safety.file_size_limit is not enforced on Windows: a job object has no " +
			"file-size cap and there are no rlimits, so a target can fill the disk",
	}
}

// LimitsDetail says which caps this host's mechanism provides, for the doctor.
func LimitsDetail() string {
	return "memory, process-count and CPU-time caps from the job object; no file-size cap"
}
