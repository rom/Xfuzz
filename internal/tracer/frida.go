package tracer

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/rom/Xfuzz/internal/safety"
	"github.com/rom/Xfuzz/pkg/binary"
	"github.com/rom/Xfuzz/pkg/executor"
)

//go:embed frida_agent.js
var fridaAgent string

// Frida is the frida backend: block coverage from dynamic instrumentation.
//
// It is the one backend at this tier that works on all three platforms, which is
// why ADR-0002 lists it that way. Stalker rewrites the target's code as it runs,
// reports every block it translates, and needs nothing from the program: no
// symbols, no source, no rebuild, and no particular architecture.
//
// It is driven through the frida command-line tool and a script, not through
// frida-gum linked into the fuzzer. That is a deliberate choice against
// ADR-0017: linking frida-gum means cgo, a large native dependency in the
// fuzzer's own address space, and a licence question of its own (ADR-0018) for
// something that runs on an operator's machine. Spawning the tool keeps the core
// pure Go, keeps the dependency optional and out-of-process, and costs a process
// per execution — which at a tier already paying an order of magnitude for
// instrumentation is not the expensive part.
//
// Coverage is written as DRcov, so what a campaign collects opens in any tool
// that draws coverage on a disassembly.
type Frida struct {
	spawner *safety.Spawner

	// Exe is the target program.
	Exe string

	// Tool is the frida command-line binary. Empty finds it on the path.
	Tool string

	// Runtime selects Frida's script runtime. Empty leaves the tool's default.
	Runtime string

	mu       sync.Mutex
	analysis *binary.Analysis
	known    []uint64
	pie      bool
	tool     string
	dir      string
	agent    string
	started  bool
}

// NewFrida returns the frida backend for a target executable.
func NewFrida(spawner *safety.Spawner, exe string) *Frida {
	return &Frida{spawner: spawner, Exe: exe}
}

// Name implements executor.Tracer.
func (f *Frida) Name() string { return "frida" }

// Granularity implements executor.Tracer.
//
// Block, not edge. The agent subscribes to compile events rather than execution
// events: a compile fires once per block for the life of the process, and an
// execution fires every time the block runs, which for a loop is millions of
// times and would spend the whole execution formatting them. The same trade the
// breakpoint backend makes, losing the same thing.
func (f *Frida) Granularity() executor.Granularity { return executor.GranularityBlock }

// ErrNoFrida reports that the Frida tooling is not installed.
var ErrNoFrida = errors.New("tracer: the frida command-line tool is not installed")

// Start locates the tool and writes the agent.
func (f *Frida) Start(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.started {
		return nil
	}

	name := f.Tool
	if name == "" {
		name = "frida"
	}
	tool, err := safety.FindTool(name)
	if err != nil {
		return fmt.Errorf("%w: %s is not on the path (it comes from the frida "+
			"package, and the backend cannot instrument anything without it)", ErrNoFrida, name)
	}

	im, err := binary.Open(f.Exe)
	if err != nil {
		return err
	}
	defer im.Close()
	// Best effort, as with the emulator: Frida discovers blocks itself and its
	// coverage records offsets from the module base, so the analysis is only
	// used to report a denominator.
	if a, aerr := binary.Analyze(im); aerr == nil {
		f.analysis, f.known = a, a.Addrs()
	}

	dir, err := os.MkdirTemp("", "xfuzz-frida-")
	if err != nil {
		return fmt.Errorf("tracer: frida: creating a work directory: %w", err)
	}
	agent := filepath.Join(dir, "agent.js")
	script := strings.ReplaceAll(fridaAgent, "__XFUZZ_OUTPUT__", jsString(filepath.Join(dir, "coverage.drcov")))
	if err := os.WriteFile(agent, []byte(script), 0o644); err != nil {
		os.RemoveAll(dir)
		return fmt.Errorf("tracer: frida: writing the agent: %w", err)
	}

	f.tool, f.pie, f.dir, f.agent, f.started = tool, im.PIE, dir, agent, true
	return nil
}

// jsString escapes a path for a JavaScript single-quoted literal. A Windows path
// is full of backslashes and would otherwise become escape sequences.
func jsString(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	return strings.ReplaceAll(s, `'`, `\'`)
}

// Blocks implements executor.Tracer.
func (f *Frida) Blocks() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.known)
}

// Analysis returns what static recovery found, for reporting.
func (f *Frida) Analysis() *binary.Analysis {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.analysis
}

// Trace implements executor.Tracer.
func (f *Frida) Trace(ctx context.Context, spec executor.ProcSpec) (executor.Trace, error) {
	f.mu.Lock()
	tool, dir, agent, pie, started := f.tool, f.dir, f.agent, f.pie, f.started
	f.mu.Unlock()
	if !started {
		return executor.Trace{}, errors.New("tracer: frida: Start was not called")
	}

	out := filepath.Join(dir, "coverage.drcov")
	_ = os.Remove(out)

	guest := spec.Args
	if len(guest) == 0 {
		guest = []string{spec.Path}
	}
	args := []string{tool, "-l", agent, "-q", "--stdio=pipe"}
	if f.Runtime != "" {
		args = append(args, "--runtime="+f.Runtime)
	}
	// -f spawns the program rather than attaching to one already running, which
	// is what a per-input execution needs. Everything after it is the target's
	// own argument vector.
	args = append(args, "-f")
	args = append(args, guest...)

	sub := spec
	sub.Path = tool
	sub.Args = args

	res, err := f.spawner.Run(ctx, sub)
	if err != nil {
		return executor.Trace{}, err
	}

	fh, oerr := os.Open(out)
	if oerr != nil {
		return executor.Trace{Result: res}, fmt.Errorf("tracer: frida: no coverage at %s "+
			"(the tool exited %d): %w", out, res.ExitCode, oerr)
	}
	defer fh.Close()

	cov, perr := readDRcov(fh)
	if perr != nil {
		return executor.Trace{Result: res}, fmt.Errorf("tracer: frida: %w", perr)
	}
	return executor.Trace{
		Blocks:  cov.blocksFor(filepath.Base(f.Exe), pie),
		Ordered: false,
		Result:  res,
	}, nil
}

// Close implements executor.Tracer.
func (f *Frida) Close() error {
	f.mu.Lock()
	dir := f.dir
	f.dir = ""
	f.mu.Unlock()
	if dir != "" {
		return os.RemoveAll(dir)
	}
	return nil
}

// FridaAvailable reports whether the Frida tooling is installed, for the
// capability report and for xfuzz doctor. The name comes back either way, so an
// operator is told what to install rather than that a backend is unavailable.
func FridaAvailable() (string, bool) {
	if _, err := safety.FindTool("frida"); err != nil {
		return "frida", false
	}
	return "frida", true
}

// Version returns the tool's own version, for the capability report. Through the
// spawner, for the reason every other process is (ADR-0012).
func (f *Frida) Version(ctx context.Context) string {
	f.mu.Lock()
	path := f.tool
	f.mu.Unlock()
	if path == "" {
		return ""
	}
	res, err := f.spawner.Run(ctx, executor.ProcSpec{
		Path: path, Args: []string{path, "--version"},
		CaptureOutput: true, Timeout: 5 * time.Second,
	})
	if err != nil {
		return ""
	}
	line, _, _ := strings.Cut(string(res.Stdout), "\n")
	return strings.TrimSpace(line)
}
