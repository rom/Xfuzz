package main

import "os"

// isTerminal reports whether a file is a character device.
//
// Enough to tell a terminal from a pipe or a file, which is the only question
// asked of it, and it needs no dependency and no build tags: a redirected
// stdout is a regular file or a pipe, and neither is a character device.
func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}
