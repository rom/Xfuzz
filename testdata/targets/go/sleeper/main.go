// Command sleeper does nothing, slowly.
//
// A timeout test needs a target that will not finish on its own, and the
// obvious one is not portable: /bin/sleep is a program on Unix and nothing at
// all on Windows, so a test naming it measures the host's coreutils before it
// measures the spawner. This is the same thing in Go, built the same way as
// every other fixture here.
//
// The duration is far longer than any timeout under test. What is being
// measured is that the spawner stops it, so a target that stopped by itself
// would be the test passing for the wrong reason.
package main

import "time"

func main() { time.Sleep(time.Hour) }
