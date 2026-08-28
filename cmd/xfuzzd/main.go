// Command xfuzzd is the Xfuzz control-plane daemon.
//
// xfuzzd owns campaign lifecycle, worker supervision, the store, the safety
// layer, and the event bus. It listens on a Unix domain socket by default;
// TCP/TLS is opt-in and never the default (ADR-0003, docs/SECURITY.md).
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/rom/Xfuzz/internal/version"
)

const name = "xfuzzd"

func main() {
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "%s — the Xfuzz control-plane daemon\n\nUsage:\n  %s [flags]\n\nFlags:\n", name, name)
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
