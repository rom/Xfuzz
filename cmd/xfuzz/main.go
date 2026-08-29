// Command xfuzz is the Xfuzz command-line client.
//
// It runs, inspects, and validates campaign files. It is a thin client of the
// xfuzzd API and holds no campaign state of its own (ADR-0003): every command
// here is one or more API calls, which is what makes the parity test between
// the two meaningful.
//
// It does not accept flags that alter fuzzing semantics. Those belong in the
// campaign file, so that what ran is a reviewable artefact rather than a shell
// history entry (ADR-0016). Flags cover runtime concerns only: which file,
// which daemon, how to format the output.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"strings"

	"github.com/rom/Xfuzz/internal/platform"
)

const name = "xfuzz"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), platform.TerminationSignals()...)
	defer stop()

	if len(os.Args) < 2 {
		usage(os.Stderr)
		os.Exit(2)
	}

	cmdName := os.Args[1]
	switch cmdName {
	case "-h", "--help", "help":
		usage(os.Stdout)
		return
	case "-v", "--version", "version":
		cmdName = "version"
	}

	cmd, ok := commands[cmdName]
	if !ok {
		fmt.Fprintf(os.Stderr, "%s: unknown command %q\n\n", name, cmdName)
		usage(os.Stderr)
		os.Exit(2)
	}

	if err := cmd.Run(ctx, os.Args[2:]); err != nil {
		fmt.Fprintf(os.Stderr, "%s %s: %v\n", name, cmdName, err)
		os.Exit(1)
	}
}

func usage(w *os.File) {
	fmt.Fprintf(w, `%s runs, inspects, and validates fuzzing campaigns.

usage: %s <command> [flags]

Fuzzing behaviour lives in the campaign file, not in flags: what ran should be a
reviewable artefact rather than a shell history entry. Start with

    %s init > campaign.yaml
    %s validate campaign.yaml
    %s run campaign.yaml

commands:
`, name, name, name, name, name)

	byGroup := map[string][]*Command{}
	for _, c := range commands {
		byGroup[c.Group] = append(byGroup[c.Group], c)
	}
	groups := make([]string, 0, len(byGroup))
	for g := range byGroup {
		groups = append(groups, g)
	}
	sort.Strings(groups)

	for _, g := range groups {
		fmt.Fprintf(w, "\n  %s\n", g)
		cs := byGroup[g]
		sort.Slice(cs, func(i, j int) bool { return cs[i].Name < cs[j].Name })
		for _, c := range cs {
			fmt.Fprintf(w, "    %-22s %s\n", c.Name, c.Short)
		}
	}
	fmt.Fprintf(w, "\nRun '%s <command> --help' for a command's own flags.\n", name)
}

// nameList renders a set of names for an error message.
func nameList(names []string) string {
	sort.Strings(names)
	return strings.Join(names, ", ")
}
