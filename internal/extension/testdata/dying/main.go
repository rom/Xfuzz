// Command dying is a plugin that answers its handshake and then dies noisily,
// which is the fault-injection case in TESTS.md section 9: "plugin process dies
// → campaign fails cleanly with a clear error".
//
// It lives under testdata rather than in examples/ because misbehaving is the
// entire point of it, and an example is something people copy.
package main

import (
	"fmt"
	"os"

	"github.com/rom/Xfuzz/pkg/plugin"
)

func main() {
	plugin.Serve(plugin.Plugin{
		Name: "dying",
		Objectives: map[string]plugin.Oracle{
			"boom": plugin.OracleFunc(func([]plugin.Observation) ([]plugin.Verdict, error) {
				fmt.Fprintln(os.Stderr, "fatal: the model file is gone")
				os.Exit(3)
				return nil, nil
			}),
		},
	})
}
