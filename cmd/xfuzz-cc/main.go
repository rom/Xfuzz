// Command xfuzz-cc is the Xfuzz instrumenting compiler wrapper.
//
// xfuzz-cc wraps a C/C++ compiler to inject the xfuzz-rt coverage runtime,
// giving Xfuzz a self-contained instrumentation path that does not depend on
// any external fuzzer (ADR-0001, ADR-0002).
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/rom/Xfuzz/internal/version"
)

const name = "xfuzz-cc"

func main() {
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "%s — the Xfuzz instrumenting compiler wrapper\n\nUsage:\n  %s [flags]\n\nFlags:\n", name, name)
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
