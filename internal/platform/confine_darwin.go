//go:build darwin

package platform

// Confine wraps a command in a Seatbelt profile.
//
// The profile denies file writes outside the working directory and denies the
// network, which are the two things a fuzzed target can do that reach past the
// campaign. It is applied by wrapping rather than from inside the target,
// because macOS has no equivalent of the Linux helper: sandbox_init in the
// target would need cgo, and ADR-0017 keeps C out of the fuzzer.
func Confine(r ConfineRequest) (path string, argv []string, ok bool) {
	if !SeatbeltAvailable() {
		return r.Path, r.Argv, false
	}
	// ConfineWritable rather than r.Writable: it adds the shared memory the
	// fuzzer's own mechanisms live in, and says why.
	//
	// This is where the Linux side already is rather than a relaxation of it.
	// There a read-only root is a bind remount of /, and /dev/shm is a separate
	// mount that the remount does not cover, so the map stays writable without
	// anyone having decided it should. macOS has no /dev/shm, the maps live
	// under the temporary directory, and a profile has to say so.
	profile := SeatbeltProfile(ConfineWritable(r), r.AllowNetwork)
	p, a := SeatbeltCommand(profile, r.Path, r.Argv)
	return p, a, true
}
