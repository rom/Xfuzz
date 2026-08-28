package safety

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/rom/Xfuzz/internal/platform"
	"github.com/rom/Xfuzz/pkg/executor"
)

// Spawner is the only thing in Xfuzz that creates a process.
//
// Executors cannot call os/exec: they are in pkg/, which cannot import
// internal/, and the architecture lint forbids the import outright. That is
// deliberate. ADR-0012 makes confinement mandatory, and the only way to
// guarantee a rule like that is to leave no other path — a warning in a comment
// is a rule that holds until someone is in a hurry.
//
// The confinement itself is staged. This is the M3 spawner: process groups,
// enforced timeouts, bounded output capture, and a clean kill of the whole
// group. Namespaces, seccomp, and cgroups arrive in M4; until then
// IsolationLevel reports "minimal" rather than implying protection that is not
// there.
type Spawner struct {
	// MaxOutputBytes caps how much of a target's output is retained. A target
	// that writes on every execution would otherwise make capture the dominant
	// cost, and a runaway one would exhaust memory.
	MaxOutputBytes int

	// KillGrace is how long a process gets between a polite termination signal
	// and being killed outright.
	KillGrace time.Duration

	// DefaultTimeout applies when a spec sets none. A campaign with no timeout
	// at all stalls on the first input that loops.
	DefaultTimeout time.Duration
}

// NewSpawner returns a spawner with defaults.
func NewSpawner() *Spawner {
	return &Spawner{
		MaxOutputBytes: 1 << 20,
		KillGrace:      100 * time.Millisecond,
		DefaultTimeout: 5 * time.Second,
	}
}

// IsolationLevel implements executor.Spawner.
//
// It reports what the platform actually enforces, not what is planned. A
// campaign may require a minimum level and refuse to start below it, which only
// works if the level is honest.
func (s *Spawner) IsolationLevel() string { return platform.IsolationLevel() }

// Run implements executor.Spawner: execute once and wait.
func (s *Spawner) Run(ctx context.Context, spec executor.ProcSpec) (executor.ProcResult, error) {
	timeout := spec.Timeout
	if timeout <= 0 {
		timeout = s.DefaultTimeout
	}

	cmd, err := command(spec)
	if err != nil {
		return executor.ProcResult{}, err
	}
	cmd.ExtraFiles = spec.ExtraFiles

	switch {
	case spec.StdinFile != nil:
		cmd.Stdin = spec.StdinFile
	case len(spec.Stdin) > 0:
		cmd.Stdin = bytes.NewReader(spec.Stdin)
	default:
		cmd.Stdin = devNull()
	}

	var stdout, stderr *capped
	if spec.CaptureOutput {
		stdout = &capped{limit: s.MaxOutputBytes}
		stderr = &capped{limit: s.MaxOutputBytes}
		cmd.Stdout, cmd.Stderr = stdout, stderr
	}

	start := time.Now()
	if err := cmd.Start(); err != nil {
		return executor.ProcResult{}, fmt.Errorf("safety: starting %s: %w", spec.Path, err)
	}

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	res := executor.ProcResult{}
	var waitErr error
	select {
	case waitErr = <-done:
	case <-timer.C:
		res.TimedOut = true
		s.terminate(cmd)
		waitErr = <-done
	case <-ctx.Done():
		s.terminate(cmd)
		<-done
		return executor.ProcResult{}, ctx.Err()
	}

	res.Duration = time.Since(start)
	if stdout != nil {
		res.Stdout, res.Stderr = stdout.buf, stderr.buf
	}
	fillStatus(&res, cmd, waitErr)

	// A timeout kill shows up as a signal; reporting it as a crash would turn
	// every slow input into a spurious finding.
	if res.TimedOut {
		res.Signal = 0
	}
	return res, nil
}

// command builds the process, treating ProcSpec.Args as the complete argv.
func command(spec executor.ProcSpec) (*exec.Cmd, error) {
	path := spec.Path
	if !filepath.IsAbs(path) && !strings.ContainsRune(path, filepath.Separator) {
		resolved, err := exec.LookPath(path)
		if err != nil {
			return nil, fmt.Errorf("safety: %w", err)
		}
		path = resolved
	}
	argv := spec.Args
	if len(argv) == 0 {
		argv = []string{path}
	}
	cmd := &exec.Cmd{Path: path, Args: argv, Dir: spec.Dir, Env: spec.Env}
	platform.ConfigureProcess(cmd, spec.Quarantine)
	return cmd, nil
}

// handle is a running process an executor talks to over its lifetime.
type handle struct {
	cmd     *exec.Cmd
	control *os.File
	status  *os.File
	done    chan error
	result  executor.ProcResult
	start   time.Time
	waited  bool
}

func (h *handle) Pid() int          { return h.cmd.Process.Pid }
func (h *handle) Control() *os.File { return h.control }
func (h *handle) Status() *os.File  { return h.status }

func (h *handle) Wait() (executor.ProcResult, error) {
	if !h.waited {
		err := <-h.done
		h.waited = true
		h.result.Duration = time.Since(h.start)
		fillStatus(&h.result, h.cmd, err)
	}
	return h.result, nil
}

func (h *handle) Kill() error {
	if h.control != nil {
		h.control.Close()
	}
	if h.status != nil {
		h.status.Close()
	}
	if h.cmd.Process == nil {
		return nil
	}
	err := platform.KillGroup(h.cmd.Process.Pid)
	if !h.waited {
		<-h.done
		h.waited = true
	}
	return err
}

// Start implements executor.Spawner: launch a long-lived process with a control
// and a status pipe.
//
// The child receives the read end of the control pipe as descriptor 3 and the
// write end of the status pipe as descriptor 4, after any ExtraFiles the caller
// supplied. This is how a fork server is driven: the fuzzer writes a command,
// the server forks a child, and writes back its result.
func (s *Spawner) Start(ctx context.Context, spec executor.ProcSpec) (executor.Handle, error) {
	ctlRead, ctlWrite, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("safety: creating the control pipe: %w", err)
	}
	stRead, stWrite, perr := os.Pipe()
	if perr != nil {
		ctlRead.Close()
		ctlWrite.Close()
		return nil, fmt.Errorf("safety: creating the status pipe: %w", perr)
	}

	cmd, err := command(spec)
	if err != nil {
		ctlRead.Close()
		ctlWrite.Close()
		stRead.Close()
		stWrite.Close()
		return nil, err
	}
	cmd.ExtraFiles = append(append([]*os.File(nil), spec.ExtraFiles...), ctlRead, stWrite)
	if spec.StdinFile != nil {
		cmd.Stdin = spec.StdinFile
	} else {
		cmd.Stdin = devNull()
	}
	switch {
	case spec.StderrFile != nil:
		cmd.Stdout, cmd.Stderr = devNull(), spec.StderrFile
	case spec.CaptureOutput:
		cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	default:
		cmd.Stdout, cmd.Stderr = devNull(), devNull()
	}

	h := &handle{cmd: cmd, control: ctlWrite, status: stRead, done: make(chan error, 1), start: time.Now()}
	if err := cmd.Start(); err != nil {
		ctlRead.Close()
		ctlWrite.Close()
		stRead.Close()
		stWrite.Close()
		return nil, fmt.Errorf("safety: starting %s: %w", spec.Path, err)
	}
	// The child owns its ends now; holding them open in the parent would stop
	// the pipes ever reporting end-of-file when the child dies, and the fuzzer
	// would block forever on a dead fork server.
	ctlRead.Close()
	stWrite.Close()

	go func() { h.done <- cmd.Wait() }()

	if ctx != nil && ctx.Done() != nil {
		go func() {
			select {
			case <-ctx.Done():
				h.Kill()
			case <-h.done:
			}
		}()
	}
	return h, nil
}

func (s *Spawner) terminate(cmd *exec.Cmd) {
	if cmd.Process == nil {
		return
	}
	// The whole process group, not just the leader: a target that forks would
	// otherwise leave children running, and after a few thousand timeouts the
	// host is out of process slots.
	_ = platform.TerminateGroup(cmd.Process.Pid)
	time.Sleep(s.KillGrace)
	_ = platform.KillGroup(cmd.Process.Pid)
}

// fillStatus translates a wait error into a result.
func fillStatus(res *executor.ProcResult, cmd *exec.Cmd, waitErr error) {
	if cmd.ProcessState != nil {
		res.ExitCode = cmd.ProcessState.ExitCode()
		res.Signal = platform.SignalOf(cmd.ProcessState)
	}
	if waitErr == nil {
		return
	}
	var ee *exec.ExitError
	if errors.As(waitErr, &ee) {
		return // already reflected in ProcessState
	}
}

// capped is a writer that keeps at most a fixed number of bytes and silently
// drops the rest, so a chatty target cannot exhaust memory.
type capped struct {
	buf   []byte
	limit int
}

func (c *capped) Write(p []byte) (int, error) {
	if room := c.limit - len(c.buf); room > 0 {
		if len(p) > room {
			c.buf = append(c.buf, p[:room]...)
		} else {
			c.buf = append(c.buf, p...)
		}
	}
	return len(p), nil // report success so the target is never blocked on us
}

func devNull() io.ReadWriteCloser {
	f, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		return nopRWC{}
	}
	return f
}

type nopRWC struct{}

func (nopRWC) Read([]byte) (int, error)    { return 0, io.EOF }
func (nopRWC) Write(p []byte) (int, error) { return len(p), nil }
func (nopRWC) Close() error                { return nil }

// Platform returns the running platform, for capability reporting.
func Platform() string { return runtime.GOOS + "/" + runtime.GOARCH }
