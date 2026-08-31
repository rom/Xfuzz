//go:build !darwin

package platform

// Confine reports that this platform confines some other way.
//
// Linux does, through the helper and the namespaces it enters; Windows does
// through a job object attached after the process exists. Neither is a wrapper
// around the command, so neither belongs here, and returning false is what
// keeps the caller from adding one.
func Confine(r ConfineRequest) (path string, argv []string, ok bool) {
	return r.Path, r.Argv, false
}
