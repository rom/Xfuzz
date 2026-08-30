//go:build !console

package console

import (
	"errors"
	"io/fs"
	"time"
)

// Assets reports that this build carries no console.
//
// The default, so that `go build ./...` needs nothing but the Go toolchain.
// Building the console needs Node, and making the whole project need Node to
// compile would be a poor trade for a page.
func Assets() (fs.FS, error) {
	return nil, errors.New("console: this binary was built without the console tag")
}

var indexModTime = time.Time{}
