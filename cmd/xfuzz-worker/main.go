// Command xfuzz-worker is an Xfuzz worker process.
//
// xfuzz-worker runs one engine instance with its own deterministic RNG stream
// and strategy. Workers are processes rather than goroutines so that a target
// that corrupts memory cannot take down its siblings (ADR-0015).
//
// Not intended to be launched by hand; xfuzzd supervises these.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/rom/Xfuzz/internal/version"
)

const name = "xfuzz-worker"

func main() {
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "%s — an Xfuzz worker process\n\nUsage:\n  %s [flags]\n\nFlags:\n", name, name)
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
