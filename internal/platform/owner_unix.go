//go:build unix

package platform

import (
	"os"
	"syscall"
)

// OwnerOf returns a file's owning uid and gid.
//
// It is here rather than at the call site because reaching into the Stat_t is a
// platform detail, and the layering rule that keeps syscall out of the rest of
// the tree is the one that makes the safety layer's confinement checkable
// (ARCHITECTURE section 2).
func OwnerOf(fi os.FileInfo) (uid, gid int, ok bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, false
	}
	return int(st.Uid), int(st.Gid), true
}
