package platform

// Confine is where a platform wraps a command in its own confinement mechanism.
//
// It exists because internal/safety may not carry build tags — the architecture
// lint enforces that, and rightly: a policy decision written three times, once
// per operating system, is a policy decision that will differ on two of them.
// So the policy stays in one place and asks the platform whether it has a
// mechanism, and the platform is the only thing that knows.
//
// The Linux answer is no, and that is not an omission. Linux confines through
// namespaces and a syscall filter installed by the helper process, which is a
// different shape entirely: it happens inside the process that becomes the
// target rather than by wrapping the command. macOS has no such helper and does
// have a policy engine reached by wrapping, which is what this is for.

// ConfineRequest is what a platform needs to build a confinement wrapper.
type ConfineRequest struct {
	// Path and Argv are the command as it would otherwise be run.
	Path string
	Argv []string

	// Writable are the directories the target must still be able to write:
	// its working directory, and whatever the campaign added. A target that
	// cannot write its own output is indistinguishable from a broken one.
	Writable []string

	// AllowNetwork leaves the network reachable, for a campaign whose target is
	// a network client or server.
	AllowNetwork bool
}

// ConfineWritable returns the directories a confined target must be able to
// write: what the caller asked for, and the fuzzer's own shared memory.
//
// The shared memory is not the target's convenience, it is the mechanism: the
// coverage map, the comparison map and the block map are files there that the
// target maps for writing, and a target that cannot write them reports no
// coverage at all — which reads as an uninstrumented target rather than as a
// tight sandbox, and sends whoever meets it looking at their compiler.
//
// Untagged, and assembled here rather than inside the one platform that
// currently wraps, because this is the half of a confinement policy that fails
// silently. A denied write does not stop a campaign; it makes it find nothing.
func ConfineWritable(r ConfineRequest) []string {
	return append([]string{shmDir()}, r.Writable...)
}
