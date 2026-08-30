//go:build console

package console

import (
	"embed"
	"io/fs"
	"time"
)

// dist holds the built console. It is produced by `make build-console` and is
// not in the repository: a compiled bundle in git is a diff nobody can review
// and a merge nobody can resolve.
//
//go:embed all:dist
var dist embed.FS

// Assets returns the built console's files, rooted at the bundle.
func Assets() (fs.FS, error) { return fs.Sub(dist, "dist") }

// indexModTime is fixed rather than the build time, so that two builds of one
// commit serve byte-identical responses and a reproducible build stays
// reproducible through the HTTP layer.
var indexModTime = time.Unix(0, 0)
