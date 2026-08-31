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
	profile := SeatbeltProfile(r.Writable, r.AllowNetwork)
	p, a := SeatbeltCommand(profile, r.Path, r.Argv)
	return p, a, true
}
