package safety

import (
	"context"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/rom/Xfuzz/internal/platform"
	"github.com/rom/Xfuzz/pkg/executor"
)

// RunTraced runs a target under breakpoint tracing and reports which of the
// given blocks it entered.
//
// It is here rather than in the T5 backend for the reason every other spawn is:
// ADR-0012 makes confinement structural, and a tracer that started its own
// processes would be a hole in it exactly where the target is least trusted — a
// stripped binary nobody can read. So the target is built by the same command
// path as every other, wrapped in the same sandbox helper, placed in the same
// cgroup.
//
// The tracing itself is the awkward part. A process started with PTRACE_TRACEME
// is traced by the *thread* that forked it, not by the process, and Go moves
// goroutines between threads whenever it likes. The whole spawn-and-trace
// sequence therefore runs with the goroutine pinned, which is also why this
// cannot be a Spawner method that hands back a handle: the caller would have to
// hold the lock across the boundary and nothing in the type system would say so.
func (s *Spawner) RunTraced(ctx context.Context, spec executor.ProcSpec, opt platform.TraceOptions) (
	platform.TraceOutcome, executor.ProcResult, error) {

	var out platform.TraceOutcome
	var res executor.ProcResult

	if !platform.TraceSupported() {
		return out, res, platform.ErrTraceUnsupported
	}
	if ctx != nil && ctx.Err() != nil {
		return out, res, ctx.Err()
	}

	unlock := platform.LockTracingThread()
	defer unlock()

	cmd, err := s.command(spec, false)
	if err != nil {
		return out, res, err
	}
	platform.EnableTrace(cmd)
	cmd.ExtraFiles = spec.ExtraFiles

	// Files at every end of the process, never pipes.
	//
	// exec.Cmd connects a non-file Reader or Writer through a pipe and a
	// goroutine that copies it, and cleans those goroutines up in Wait. This
	// runs its own wait — the tracer must, since it has to see every stop — so
	// Wait is never called, and a copier goroutine would still be appending to
	// the output buffer while this function returned it. That is a data race in
	// the literal sense and a wrong answer in the practical one. A file has no
	// copier: the kernel writes it and this reads it afterwards.
	switch {
	case spec.StdinFile != nil:
		cmd.Stdin = spec.StdinFile
	case len(spec.Stdin) > 0:
		f, err := stdinTemp(spec.Stdin)
		if err != nil {
			return out, res, err
		}
		defer os.Remove(f.Name())
		defer f.Close()
		cmd.Stdin = f
	default:
		cmd.Stdin = devNull()
	}

	var outFile, errFile *os.File
	if spec.CaptureOutput {
		var err error
		if outFile, err = captureTemp(); err != nil {
			return out, res, err
		}
		defer os.Remove(outFile.Name())
		defer outFile.Close()
		if errFile, err = captureTemp(); err != nil {
			return out, res, err
		}
		defer os.Remove(errFile.Name())
		defer errFile.Close()
		cmd.Stdout, cmd.Stderr = outFile, errFile
	}

	timeout := opt.Timeout
	if timeout <= 0 {
		timeout = spec.Timeout
	}
	if timeout <= 0 {
		timeout = s.DefaultTimeout
	}
	opt.Timeout = timeout

	start := time.Now()
	if err := cmd.Start(); err != nil {
		return out, res, fmt.Errorf("safety: starting %s under trace: %w", spec.Path, err)
	}
	pid := cmd.Process.Pid
	s.placeInCgroup(cmd)

	out, err = platform.TraceRun(pid, opt)
	res.Duration = time.Since(start)

	// The tracee has been reaped by TraceRun's own wait, so cmd.Wait would
	// return ECHILD and would also race for a status that has already been
	// taken. Releasing the process object without waiting is what tells the
	// os/exec machinery to leave it alone.
	_ = cmd.Process.Release()

	if err != nil {
		return out, res, err
	}
	if outFile != nil {
		res.Stdout = readCapture(outFile, s.MaxOutputBytes)
		res.Stderr = readCapture(errFile, s.MaxOutputBytes)
	}
	res.ExitCode = out.ExitCode
	res.Signal = out.Signal
	res.TimedOut = out.TimedOut
	return out, res, nil
}

// stdinTemp writes an input to a file the target can read from start to finish
// without anything on the other end.
func stdinTemp(b []byte) (*os.File, error) {
	f, err := os.CreateTemp("", "xfuzz-trace-in-")
	if err != nil {
		return nil, fmt.Errorf("safety: creating the input file: %w", err)
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		os.Remove(f.Name())
		return nil, fmt.Errorf("safety: writing the input file: %w", err)
	}
	if _, err := f.Seek(0, 0); err != nil {
		f.Close()
		os.Remove(f.Name())
		return nil, fmt.Errorf("safety: rewinding the input file: %w", err)
	}
	// The target may be running as another user, so the file it reads from must
	// be readable by one.
	if err := f.Chmod(0o644); err != nil {
		f.Close()
		os.Remove(f.Name())
		return nil, fmt.Errorf("safety: opening the input file to the target: %w", err)
	}
	return f, nil
}

// captureTemp opens a file for one execution's output.
func captureTemp() (*os.File, error) {
	f, err := os.CreateTemp("", "xfuzz-trace-out-")
	if err != nil {
		return nil, fmt.Errorf("safety: creating an output file: %w", err)
	}
	// The target may be running as another user and must be able to write it.
	if err := f.Chmod(0o622); err != nil {
		f.Close()
		os.Remove(f.Name())
		return nil, fmt.Errorf("safety: opening an output file to the target: %w", err)
	}
	return f, nil
}

// readCapture reads back what a target wrote, up to the limit.
//
// Truncating rather than growing: a target that writes on every execution would
// otherwise let one bad input consume the fuzzer's memory, and the first
// kilobytes are where a sanitizer report and a stack trace are.
func readCapture(f *os.File, limit int) []byte {
	if f == nil {
		return nil
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil
	}
	var r io.Reader = f
	if limit > 0 {
		r = io.LimitReader(f, int64(limit))
	}
	b, err := io.ReadAll(r)
	if err != nil {
		return nil
	}
	return b
}
