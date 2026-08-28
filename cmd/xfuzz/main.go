// Command xfuzz is the Xfuzz command-line client.
//
// xfuzz runs, inspects, and validates campaign files. It is a thin client of
// the xfuzzd API and holds no campaign state of its own (ADR-0003).
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/rom/Xfuzz/internal/version"
)

const name = "xfuzz"

func main() {
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "%s — the Xfuzz command-line client\n\nUsage:\n  %s [flags]\n\nFlags:\n", name, name)
		flag.PrintDefaults()
	}
	flag.Parse()

	if *showVersion {
		fmt.Printf("%s %s\n", name, version.Get())
		return
	}

	fmt.Fprintf(os.Stderr, "%s: not implemented yet — this is the M0 foundation build.\n", name)
	fmt.Fprintf(os.Stderr, "See docs/MVP_PLAN.md for the milestone that delivers it.\n")
	os.Exit(2)
}
