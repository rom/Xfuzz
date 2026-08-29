package main

import (
	"context"
	"fmt"

	"github.com/rom/Xfuzz/internal/version"
)

func init() {
	register(&Command{
		Name: "version", Group: "daemon", Short: "Print this client's version",
		Usage: "version",
		// Local by design: it reports the binary that is running, which is a
		// question no daemon can answer about this process. `xfuzz info` gives
		// the daemon's.
		Run: func(ctx context.Context, args []string) error {
			fmt.Printf("%s %s\n", name, version.Get())
			return nil
		},
	})
}
