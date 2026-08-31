// Command xfuzz-cc compiles a target with Xfuzz coverage instrumentation.
//
// It wraps a C or C++ compiler, adds the instrumentation flag, and links the
// Xfuzz runtime. Existing build systems work unchanged:
//
//	make CC=xfuzz-cc CXX=xfuzz-c++
//	./configure CC=xfuzz-cc && make
//
// Having our own wrapper rather than depending on an existing fuzzer's is what
// ADR-0001 means by no runtime dependency: a user with source needs Xfuzz and a
// compiler, nothing else.
package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/rom/Xfuzz/internal/version"
	xfuzzrt "github.com/rom/Xfuzz/runtime"
)

const usage = `xfuzz-cc — compile a target with Xfuzz coverage instrumentation

Usage:
  xfuzz-cc [compiler flags] source.c ...      compile and link, instrumented
  xfuzz-cc --go [go build flags] ./pkg        build a Go target, instrumented
  xfuzz-cc --print-runtime                    write the C runtime to stdout
  xfuzz-cc --version

Environment:
  XFUZZ_CC        underlying compiler (default: clang, then cc)
  XFUZZ_CXX       underlying C++ compiler (default: clang++, then c++)
  XFUZZ_NO_INST   set to build without instrumentation, for comparison
  XFUZZ_NO_CMPLOG set to build without comparison logging, keeping coverage
  XFUZZ_SANITIZE  extra sanitizers, e.g. "address,undefined"

The runtime is embedded in this binary; --print-runtime writes it out for
inspection, because anyone asked to link code into their software should be able
to read it first.
`

func main() {
	if err := run(os.Args[1:]); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			os.Exit(ee.ExitCode())
		}
		fmt.Fprintf(os.Stderr, "xfuzz-cc: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, usage)
		return errors.New("no arguments")
	}
	switch args[0] {
	case "--help", "-h":
		fmt.Print(usage)
		return nil
	case "--version":
		fmt.Printf("xfuzz-cc %s\n", version.Get())
		return nil
	case "--print-runtime":
		_, err := os.Stdout.WriteString(xfuzzrt.Source())
		return err
	case "--go":
		return goBuild(args[1:])
	}

	cxx := isCXX(os.Args[0], args)
	compiler, err := findCompiler(cxx)
	if err != nil {
		return err
	}

	instrument := os.Getenv("XFUZZ_NO_INST") == ""
	if instrument && !isClang(compiler) {
		return fmt.Errorf("%s does not support %s; Xfuzz instrumentation needs clang.\n"+
			"Set XFUZZ_CC=clang, or set XFUZZ_NO_INST=1 to build without coverage "+
			"(the target still runs under the subprocess tier, black-box)",
			compiler, strings.Join(xfuzzrt.InstrumentFlags, " "))
	}

	sanitize := os.Getenv("XFUZZ_SANITIZE")

	final := make([]string, 0, len(args)+8)
	if instrument {
		// Comparison logging is on by default because it is what gets a campaign
		// past a magic number, and removable by name because someone auditing
		// what this wrapper asks their compiler to do should be able to turn any
		// one piece of it off.
		if os.Getenv("XFUZZ_NO_CMPLOG") != "" {
			final = append(final, xfuzzrt.InstrumentFlagsWithout(xfuzzrt.CmpFlag)...)
		} else {
			final = append(final, xfuzzrt.InstrumentFlags...)
		}
	}
	if sanitize != "" {
		final = append(final, "-fsanitize="+sanitize, "-fno-omit-frame-pointer")
	}
	final = append(final, args...)

	// The runtime is only needed when producing an executable. Adding it to a
	// compile-only invocation would duplicate its symbols at link time.
	if linking(args) && instrument {
		obj, cleanup, err := buildRuntime(compiler)
		if err != nil {
			return err
		}
		defer cleanup()
		final = append(final, obj)

		// Coverage instrumentation makes clang link its sanitizer runtime,
		// which supplies the very callbacks xfuzz-rt provides. We do not want
		// it, and on many installations it is not even present. When the user
		// has asked for a real sanitizer, they do want it, so leave it alone.
		if sanitize == "" {
			final = append(final, "-fno-sanitize-link-runtime")
		}
	}

	cmd := exec.Command(compiler, final...)
	cmd.Stdout, cmd.Stderr, cmd.Stdin = os.Stdout, os.Stderr, os.Stdin
	return cmd.Run()
}

// buildRuntime compiles the embedded runtime to an object file.
func buildRuntime(compiler string) (string, func(), error) {
	dir, err := os.MkdirTemp("", "xfuzz-rt-")
	if err != nil {
		return "", nil, fmt.Errorf("creating a build directory: %w", err)
	}
	cleanup := func() { os.RemoveAll(dir) }

	src := filepath.Join(dir, "xfuzz-rt.c")
	if err := os.WriteFile(src, []byte(xfuzzrt.Source()), 0o600); err != nil {
		cleanup()
		return "", nil, fmt.Errorf("writing the runtime: %w", err)
	}
	obj := filepath.Join(dir, "xfuzz-rt.o")

	// The runtime is compiled WITHOUT instrumentation, and that is not an
	// oversight.
	//
	// Its fork server loop runs in the parent process, which holds the same
	// shared coverage map the children write into. Instrumenting it means the
	// parent increments counters while the fuzzer is clearing the map and
	// reading it back — coverage that belongs to no input, arriving at a moment
	// that depends on scheduling. The symptom is a campaign that is almost
	// reproducible: identical for tens of thousands of executions and then
	// quietly divergent, which is the hardest kind of bug to attribute.
	args := []string{"-O2", "-fPIC", "-c", src, "-o", obj}
	cmd := exec.Command(compiler, args...)
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		cleanup()
		return "", nil, fmt.Errorf("compiling the runtime with %s: %w", compiler, err)
	}
	return obj, cleanup, nil
}

// linking reports whether this invocation produces an executable, as opposed to
// only compiling or only preprocessing.
func linking(args []string) bool {
	for _, a := range args {
		switch a {
		case "-c", "-E", "-S", "-M", "-MM", "--version", "-fsyntax-only":
			return false
		}
		if strings.HasPrefix(a, "-shared") {
			return false
		}
	}
	return true
}

func isCXX(argv0 string, args []string) bool {
	base := filepath.Base(argv0)
	if strings.Contains(base, "++") || strings.Contains(base, "cxx") {
		return true
	}
	for _, a := range args {
		if strings.HasSuffix(a, ".cc") || strings.HasSuffix(a, ".cpp") ||
			strings.HasSuffix(a, ".cxx") || strings.HasSuffix(a, ".C") {
			return true
		}
	}
	return false
}

// isClang reports whether the compiler supports the instrumentation Xfuzz
// needs. gcc offers -fsanitize-coverage=trace-pc, which reports blocks without
// the guard identifiers the runtime uses to build edges, so it is not a
// substitute.
func isClang(compiler string) bool {
	if strings.Contains(strings.ToLower(filepath.Base(compiler)), "clang") {
		return true
	}
	out, err := exec.Command(compiler, "--version").Output()
	return err == nil && strings.Contains(strings.ToLower(string(out)), "clang")
}

func findCompiler(cxx bool) (string, error) {
	envVar, candidates := "XFUZZ_CC", []string{"clang", "cc", "gcc"}
	if cxx {
		envVar, candidates = "XFUZZ_CXX", []string{"clang++", "c++", "g++"}
	}
	if c := os.Getenv(envVar); c != "" {
		if p, err := exec.LookPath(c); err == nil {
			return p, nil
		}
		return "", fmt.Errorf("%s is set to %q, which is not executable", envVar, c)
	}
	for _, c := range candidates {
		if p, err := exec.LookPath(c); err == nil {
			return p, nil
		}
	}
	return "", fmt.Errorf("no compiler found (tried %s); set %s",
		strings.Join(candidates, ", "), envVar)
}
