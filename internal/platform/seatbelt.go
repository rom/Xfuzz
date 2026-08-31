package platform

import (
	"os"
	"path/filepath"
	"strings"
)

// The Seatbelt profile Xfuzz runs a macOS target under.
//
// Untagged, and that is on purpose: everything here is string building and one
// stat, so it can be read and tested on any host. Putting it behind //go:build
// darwin would have meant the one piece of this mechanism that can go wrong
// silently — a path that escapes its own quoting and rewrites the policy — being
// exercised only on a machine nobody in CI has. What genuinely needs macOS is
// applying the profile, and that is what sandbox_darwin.go and confine_darwin.go
// are for.

// SandboxExecPath is where the Seatbelt front end lives.
const SandboxExecPath = "/usr/bin/sandbox-exec"

// SeatbeltAvailable reports whether a profile can be applied on this host.
func SeatbeltAvailable() bool {
	fi, err := os.Stat(SandboxExecPath)
	return err == nil && !fi.IsDir() && fi.Mode()&0o111 != 0
}

// SeatbeltProfile builds the policy a target runs under.
//
// It is a write-and-network policy rather than a deny-by-default one, and that
// is a deliberate choice about which failures are acceptable. A deny-by-default
// profile has to enumerate every mach service, sysctl and dyld path the target
// needs, and getting one wrong produces a target that will not start — which a
// campaign reports as the target being broken. Denying writes and the network
// and allowing the rest denies what a fuzzed target can actually damage, and
// fails in the direction of running.
//
// The working directory stays writable, or the target cannot write its own
// output and the sandbox is indistinguishable from a broken program.
func SeatbeltProfile(writable []string, allowNetwork bool) string {
	var b strings.Builder
	b.WriteString("(version 1)\n")
	b.WriteString("(allow default)\n")
	b.WriteString("(deny file-write*)\n")
	seen := make(map[string]bool, len(writable)*2)
	allow := func(p string) {
		// Absolute or not at all. sandbox-exec rejects a relative subpath, and
		// it rejects the whole profile with it — which leaves the target
		// unrunnable rather than unconfined, so a path that cannot be made
		// absolute is dropped instead.
		if p == "" || !filepath.IsAbs(p) || seen[p] {
			return
		}
		seen[p] = true
		b.WriteString("(allow file-write* (subpath " + seatbeltString(p) + "))\n")
	}
	for _, p := range writable {
		if p == "" {
			continue
		}
		if abs, err := filepath.Abs(p); err == nil {
			p = abs
		}
		allow(p)
		// And the path with its symbolic links resolved, because the kernel
		// matches a subpath rule against the real path and macOS hands out
		// working directories that are not one. A temporary directory is
		// /var/folders/..., /var is a link to /private/var, and a profile that
		// allowed only what the caller was told the directory was called would
		// deny every write to the directory it meant to allow — with an error
		// from the target about its own files rather than about a sandbox.
		if real, err := filepath.EvalSymlinks(p); err == nil {
			allow(real)
		}
	}
	// Every target needs these three, and a profile that denied them would be
	// denying the C library rather than the target.
	b.WriteString("(allow file-write-data (literal \"/dev/null\"))\n")
	b.WriteString("(allow file-write-data (literal \"/dev/stdout\"))\n")
	b.WriteString("(allow file-write-data (literal \"/dev/stderr\"))\n")
	if !allowNetwork {
		b.WriteString("(deny network*)\n")
	}
	return b.String()
}

// seatbeltString quotes a path for the profile language.
//
// A path with a quote or a backslash in it would otherwise end the string early
// and change the policy — which is a sandbox escape written by whoever chose the
// working directory, so it is escaped rather than trusted.
func seatbeltString(p string) string {
	var b strings.Builder
	b.WriteByte('"')
	for i := 0; i < len(p); i++ {
		if p[i] == '"' || p[i] == '\\' {
			b.WriteByte('\\')
		}
		b.WriteByte(p[i])
	}
	b.WriteByte('"')
	return b.String()
}

// SeatbeltCommand returns the argv that runs path under a profile.
func SeatbeltCommand(profile, path string, argv []string) (string, []string) {
	args := []string{SandboxExecPath, "-p", profile, path}
	if len(argv) > 1 {
		args = append(args, argv[1:]...)
	}
	return SandboxExecPath, args
}
