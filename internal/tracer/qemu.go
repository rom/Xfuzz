package tracer

import (
	"context"
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

// Qemu is the qemu backend: block coverage from user-mode emulation.
//
// It runs the target under qemu-user with the emulator's own execution log
// turned on, and reads the translation blocks out of it. That is deliberately
// the *stock* emulator: the usual way to get coverage out of QEMU is a patched
// build that writes a shared bitmap, and requiring one would mean requiring a
// particular version of a particular fork to be built and installed before a
// campaign could start. Reading the log a distribution's own package already
// produces costs a great deal of speed and costs the operator nothing.
//
// What it buys over ptrace-bb is fidelity and reach. The emulator sees every
// block, including the ones static analysis missed behind an indirect branch,
// and it sees them in order — so this backend produces edge coverage where the
// breakpoint backend produces only block coverage. It also runs foreign
// architectures, which is the case where nothing else here applies at all.
type Qemu struct {
	spawner *safety.Spawner

	// Exe is the guest program.
	Exe string

	// Emulator is the qemu-user binary. Empty selects one from the target's
	// architecture, which is what an operator wants and is also the only way to
	// get this right for a foreign-architecture target.
	Emulator string

	// MaxBlocks bounds how much of one execution's log is read. A target that
	// runs for a second under emulation can print millions of lines, and the
	// fuzzer must not spend its memory on the tail of a trace whose beginning
	// already told it everything.
	MaxBlocks int

	mu       sync.Mutex
	analysis *binary.Analysis
	known    []uint64
	pie      bool
	emulator string
	logDir   string
	started  bool

	// base is the guest load address, worked out once from the first execution
	// that produces enough of a trace to decide it. It is stable for the life of
	// the campaign because the emulator lays the guest out the same way each
	// time, and re-deriving it per execution would spend the analysis on every
	// input.
	base       uint64
	baseKnown  bool
	unresolved int
}

// DefaultMaxTraceBlocks bounds one execution's log.
const DefaultMaxTraceBlocks = 1 << 20

// NewQemu returns the qemu backend for a target executable.
func NewQemu(spawner *safety.Spawner, exe string) *Qemu {
	return &Qemu{spawner: spawner, Exe: exe, MaxBlocks: DefaultMaxTraceBlocks}
}

// Name implements executor.Tracer.
func (q *Qemu) Name() string { return "qemu" }

// Granularity implements executor.Tracer. The emulator reports blocks in the
// order it ran them, so the fold can record transitions.
func (q *Qemu) Granularity() executor.Granularity { return executor.GranularityEdge }

// ErrNoEmulator reports that user-mode emulation is not installed.
var ErrNoEmulator = errors.New("tracer: qemu-user is not installed")

// EmulatorFor returns the qemu-user binary that runs a given architecture.
func EmulatorFor(a binary.Arch) string {
	switch a {
	case binary.ArchAMD64:
		return "qemu-x86_64"
	case binary.ArchARM64:
		return "qemu-aarch64"
	case binary.Arch386:
		return "qemu-i386"
	}
	return ""
}

// Start locates the emulator and analyses the guest.
//
// The analysis is not what produces coverage here — the emulator reports every
// block it runs, whether or not static recovery found it — but it is what makes
// the trace interpretable: a position-independent guest is loaded at an address
// the emulator chooses and does not report, and the analysed block addresses are
// what that address is recovered from.
func (q *Qemu) Start(context.Context) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.started {
		return nil
	}

	im, err := binary.Open(q.Exe)
	if err != nil {
		return err
	}
	defer im.Close()

	name := q.Emulator
	if name == "" {
		name = EmulatorFor(im.Arch)
		if name == "" {
			return fmt.Errorf("tracer: qemu: no user-mode emulator is known for %v", im.Arch)
		}
	}
	path, err := safety.FindTool(name)
	if err != nil {
		// Named, so the operator knows what to install rather than being told
		// that a backend "is unavailable".
		return fmt.Errorf("%w: %s is not on the path, and it is what runs a %v guest",
			ErrNoEmulator, name, im.Arch)
	}

	// The analysis is a best effort here. An architecture this build cannot
	// decode still emulates perfectly well; what is lost is only the ability to
	// resolve a position-independent guest's load address, and a non-relocatable
	// guest does not need it.
	if a, aerr := binary.Analyze(im); aerr == nil {
		q.analysis, q.known = a, a.Addrs()
	} else if im.PIE {
		return fmt.Errorf("tracer: qemu: %s is position-independent and its blocks "+
			"cannot be analysed here (%w), so the emulator's addresses could not be "+
			"related back to the image", q.Exe, aerr)
	}

	dir, err := os.MkdirTemp("", "xfuzz-qemu-")
	if err != nil {
		return fmt.Errorf("tracer: qemu: creating a log directory: %w", err)
	}
	q.emulator, q.pie, q.logDir, q.started = path, im.PIE, dir, true
	return nil
}

// Blocks implements executor.Tracer. The emulator discovers blocks as it runs
// rather than being told about them, so what static analysis found is reported
// as the denominator when there is one and zero when there is not.
func (q *Qemu) Blocks() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.known)
}

// Analysis returns what static recovery found, for reporting.
func (q *Qemu) Analysis() *binary.Analysis {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.analysis
}

// Trace implements executor.Tracer.
func (q *Qemu) Trace(ctx context.Context, spec executor.ProcSpec) (executor.Trace, error) {
	q.mu.Lock()
	emulator, dir, started := q.emulator, q.logDir, q.started
	q.mu.Unlock()
	if !started {
		return executor.Trace{}, errors.New("tracer: qemu: Start was not called")
	}

	logPath := filepath.Join(dir, "exec.log")
	_ = os.Remove(logPath)

	// The emulator becomes the process; the guest's own argument vector follows
	// its arguments. -d exec asks for the execution log and -D sends it to a
	// file rather than to standard error, which the campaign is already using
	// for the target's own output.
	guest := spec.Args
	if len(guest) == 0 {
		guest = []string{spec.Path}
	}
	sub := spec
	sub.Path = emulator
	sub.Args = append([]string{emulator, "-d", "exec", "-D", logPath, "--"}, guest...)

	res, err := q.spawner.Run(ctx, sub)
	if err != nil {
		return executor.Trace{}, err
	}

	f, oerr := os.Open(logPath)
	if oerr != nil {
		// No log at all means the emulator did not run: a missing library, a
		// guest it refuses, an unwritable directory. The execution's result is
		// still returned, so the campaign sees the failure rather than an
		// input that mysteriously covered nothing.
		return executor.Trace{Result: res}, fmt.Errorf("tracer: qemu: no execution log at %s "+
			"(the emulator exited %d): %w", logPath, res.ExitCode, oerr)
	}
	defer f.Close()
	pcs := parseExecLog(f, q.MaxBlocks)

	return executor.Trace{
		Blocks: q.rebase(pcs),
		// The emulator logs blocks in the order it ran them, which is what makes
		// this backend's coverage edge coverage rather than block coverage.
		Ordered: true,
		Result:  res,
	}, nil
}

// rebase converts guest addresses to link-time addresses.
func (q *Qemu) rebase(pcs []uint64) []uint64 {
	if !q.pie || len(pcs) == 0 {
		return pcs
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if !q.baseKnown {
		base, ok := resolveBase(q.known, pcs)
		if !ok {
			// Nothing can be said about this execution. Returning no blocks is
			// right: coverage against an unknown base is coverage against noise,
			// and it would look exactly like a working campaign.
			q.unresolved++
			return nil
		}
		q.base, q.baseKnown = base, true
	}
	out := make([]uint64, 0, len(pcs))
	for _, pc := range pcs {
		if pc >= q.base {
			out = append(out, pc-q.base)
		}
	}
	return out
}

// Unresolved returns how many executions produced a trace that could not be
// related to the image. A campaign where this is not zero is one whose coverage
// figures are missing executions, and it is reported rather than silently
// absorbed.
func (q *Qemu) Unresolved() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.unresolved
}

// Close implements executor.Tracer.
func (q *Qemu) Close() error {
	q.mu.Lock()
	dir := q.logDir
	q.logDir = ""
	q.mu.Unlock()
	if dir != "" {
		return os.RemoveAll(dir)
	}
	return nil
}

// QemuAvailable reports whether user-mode emulation for an architecture is
// installed, for the capability report and for xfuzz doctor.
//
// It returns the emulator's name whether or not it was found, because the name
// is the useful half: an operator told that "the qemu backend is unavailable"
// learns nothing, and one told that qemu-aarch64 is not on the path knows
// exactly what to install.
func QemuAvailable(a binary.Arch) (string, bool) {
	name := EmulatorFor(a)
	if name == "" {
		return "", false
	}
	if _, err := safety.FindTool(name); err != nil {
		return name, false
	}
	return name, true
}

// Version returns the emulator's own version line, for the capability report.
//
// Through the spawner like every other process, not through os/exec: ADR-0012
// admits no exceptions, and a version probe against a tool an operator named in
// a campaign file is exactly the kind of thing that looks harmless until the
// name comes from somewhere untrusted.
func (q *Qemu) Version(ctx context.Context) string {
	q.mu.Lock()
	path := q.emulator
	q.mu.Unlock()
	if path == "" {
		return ""
	}
	res, err := q.spawner.Run(ctx, executor.ProcSpec{
		Path: path, Args: []string{path, "-version"},
		CaptureOutput: true, Timeout: 5 * time.Second,
	})
	if err != nil {
		return ""
	}
	line, _, _ := strings.Cut(string(res.Stdout), "\n")
	return strings.TrimSpace(line)
}
