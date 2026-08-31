package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// Building a Go target.
//
// A Go program cannot be built with xfuzz-cc's ordinary path — there is no C
// compiler in the picture and no source to instrument. But Go's own compiler
// carries the instrumentation already: `-d=libfuzzer` emits an inline counter
// increment per basic block and calls the same comparison hooks clang's
// trace-cmp does. What it needs is the runtime those symbols resolve to, which
// is the one embedded here.
//
// So this mode is a wrapper around `go build` that adds three things: the build
// tag that enables the Go runtime's half of the instrumentation, the compiler
// flag that emits it, and the linker flags that pull in the Xfuzz runtime object
// so the symbols resolve. The user's own arguments pass through unchanged.
//
// The reason it matters is coverage on a host without clang. ADR-0026 records
// that a Go target had no coverage backend and fell back to black box; this is
// the path that changes, and it works wherever the Go toolchain and a linker do.

// GoBuildTag is the build tag that compiles the Go runtime's libfuzzer hooks in.
const GoBuildTag = "libfuzzer"

// GoInstrumentFlag is the compiler flag that emits the instrumentation.
//
// `all=` matters: without it only the target's own packages are instrumented
// and the standard library is invisible, which for a program that spends its
// time in encoding/json is most of the coverage that would have been useful.
const GoInstrumentFlag = "all=-d=libfuzzer"

// goBuild compiles a Go target with instrumentation and the runtime linked in.
func goBuild(args []string) error {
	if _, err := exec.LookPath("go"); err != nil {
		return errors.New("the Go toolchain is not on PATH, so a Go target cannot be built")
	}
	// The runtime needs a C compiler even for a Go target: it is C, and it has
	// to become an object file before the Go linker can be handed it.
	compiler, err := findCompiler(false)
	if err != nil {
		return fmt.Errorf("a C compiler is needed to build the runtime object even for a "+
			"Go target: %w", err)
	}
	obj, cleanup, err := buildRuntime(compiler)
	if err != nil {
		return err
	}
	defer cleanup()

	tags := GoBuildTag
	var rest []string
	for i := 0; i < len(args); i++ {
		// A -tags the caller supplied is extended rather than replaced: a
		// target that needs its own tags still needs them.
		if args[i] == "-tags" && i+1 < len(args) {
			tags = args[i+1] + "," + tags
			i++
			continue
		}
		if v, ok := strings.CutPrefix(args[i], "-tags="); ok {
			tags = v + "," + tags
			continue
		}
		rest = append(rest, args[i])
	}

	// Our flags first and the caller's arguments after, because `go build`
	// takes its flags before the packages and reads anything after the first
	// non-flag as an import path.
	final := []string{"build",
		"-tags", tags,
		"-gcflags", GoInstrumentFlag,
		// External linking, because the runtime is an object file and Go's
		// internal linker will not take one.
		"-ldflags", "-linkmode external -extldflags " + obj,
	}
	final = append(final, rest...)

	cmd := exec.Command("go", final...)
	cmd.Stdout, cmd.Stderr, cmd.Stdin = os.Stdout, os.Stderr, os.Stdin
	cmd.Env = append(os.Environ(), "CGO_ENABLED=1")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("go build: %w", err)
	}
	return nil
}
