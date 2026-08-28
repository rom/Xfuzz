//go:build !cgo

package version

// cgoEnabled reports whether this binary was built with cgo, which determines
// the availability of the native fast paths (ADR-0017).
const cgoEnabled = false
