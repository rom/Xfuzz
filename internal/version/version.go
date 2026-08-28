// Package version carries build identity, injected at link time.
package version

import (
	"fmt"
	"runtime"
	"runtime/debug"
)

// Set via -ldflags "-X github.com/rom/Xfuzz/internal/version.Version=..."
var (
	Version = "0.0.0-dev"
	Commit  = ""
	Date    = ""
)

// Info describes the running build.
type Info struct {
	Version  string
	Commit   string
	Date     string
	Go       string
	Platform string
	CGO      bool
}

// Get returns the build identity, falling back to VCS stamps recorded by the
// Go toolchain when link-time values were not supplied.
func Get() Info {
	i := Info{
		Version:  Version,
		Commit:   Commit,
		Date:     Date,
		Go:       runtime.Version(),
		Platform: runtime.GOOS + "/" + runtime.GOARCH,
		CGO:      cgoEnabled,
	}
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, s := range bi.Settings {
			switch s.Key {
			case "vcs.revision":
				if i.Commit == "" {
					i.Commit = s.Value
				}
			case "vcs.time":
				if i.Date == "" {
					i.Date = s.Value
				}
			}
		}
	}
	return i
}

// String renders the build identity as a single line.
func (i Info) String() string {
	s := fmt.Sprintf("%s (%s, %s", i.Version, i.Go, i.Platform)
	if i.CGO {
		s += ", cgo"
	} else {
		s += ", nocgo"
	}
	s += ")"
	if i.Commit != "" {
		c := i.Commit
		if len(c) > 12 {
			c = c[:12]
		}
		s += " commit " + c
	}
	return s
}
