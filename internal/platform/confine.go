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
