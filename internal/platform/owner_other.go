//go:build !unix

package platform

import "os"

// OwnerOf reports that file ownership is not expressed as ids here.
func OwnerOf(fi os.FileInfo) (uid, gid int, ok bool) { return 0, 0, false }
