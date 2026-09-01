// Command echoer reads one line and repeats it behind a marker.
//
// It is what a test needs when a campaign file has to name a target that
// something will actually start: an exit status to classify and a line of
// output to attribute. A shell script would say the same thing in three lines
// and is a program only where there is a shell to read it — on Windows it is a
// file the loader refuses, and naming it .exe there moves the failure from the
// campaign's validation to the moment it runs.
package main

import (
	"bufio"
	"fmt"
	"os"
)

func main() {
	sc := bufio.NewScanner(os.Stdin)
	if sc.Scan() {
		fmt.Printf("XFUZZ-MARKER: %s\n", sc.Text())
	}
}
