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
	"sync"
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
// Confinement itself is the Sandbox's, and every process this spawner creates
// passes through it. What the spawner adds around that is the part that is the
// same at every isolation level: an enforced timeout, bounded output capture,
// and a kill that takes the whole process group rather than leaving orphans.
type Spawner struct {
	// Sandbox is the confinement policy. A nil Sandbox means the zero policy,
	// which still confines: ADR-0012 makes that the default rather than an
	// option, because the default is what people run.
	Sandbox *Sandbox

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

	// defaultOnce materialises the default Sandbox exactly once.
	defaultOnce sync.Once
}

// NewSpawner returns a spawner with defaults. Its targets are confined.
func NewSpawner() *Spawner {
	return &Spawner{
		MaxOutputBytes: 1 << 20,
		KillGrace:      100 * time.Millisecond,
		DefaultTimeout: 5 * time.Second,
	}
}

// NewTrustedSpawner returns a spawner for Xfuzz's own processes.
//
// The daemon starts workers, and a worker is this binary rather than a target.
// Confining it would nest a namespace inside a namespace and strip the
// privilege the worker needs to confine the target itself — so the exemption is
// for the process, never for what it runs. Every target a worker executes still
// goes through a confining spawner of the worker's own.
//
// It is a separate constructor rather than a flag on Run so that "this spawn is
// not confined" is a decision made once, in one visible place, by code that can
// say why.
func NewTrustedSpawner() *Spawner {
	s := NewSpawner()
	s.Sandbox = &Sandbox{Unconfined: true}
	return s
}

// IsolationLevel implements executor.Spawner.
//
// It reports what is actually in force, not what was configured. A campaign may
// require a minimum level and refuse to start below it, which only works if the
// level is honest — so this is computed from the mechanisms the host provides
// and the helper that was found, never from the policy that was asked for.
func (s *Spawner) IsolationLevel() string { return s.sandbox().Level().String() }

// Explain describes the isolation in force and why it is not stronger.
func (s *Spawner) Explain() string { return s.sandbox().Explain() }

// sandbox returns the policy, defaulting to the confining zero value.
//
// The default is materialised once rather than on each call: a spawner is shared
// by every worker in a campaign, and two of them installing a default
// simultaneously would give half the workers a different sandbox — including a
// different cgroup — from the other half.
func (s *Spawner) sandbox() *Sandbox {
	s.defaultOnce.Do(func() {
		if s.Sandbox == nil {
			s.Sandbox = &Sandbox{}
		}
	})
	return s.Sandbox
}

// Run implements executor.Spawner: execute once and wait.
func (s *Spawner) Run(ctx context.Context, spec executor.ProcSpec) (executor.ProcResult, error) {
	timeout := spec.Timeout
	if timeout <= 0 {
		timeout = s.DefaultTimeout
	}

	cmd, err := s.command(spec, false)
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
	s.placeInCgroup(cmd)

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	res := executor.ProcResult{}
	var waitErr error
	reaped := true
	select {
	case waitErr = <-done:
	case <-timer.C:
		res.TimedOut = true
		s.terminate(cmd)
		reaped, waitErr = reap(done)
	case <-ctx.Done():
		s.terminate(cmd)
		reap(done)
		return executor.ProcResult{}, ctx.Err()
	}

	res.Duration = time.Since(start)
	// Only once the child has been reaped. Capturing output means Wait also
	// waits for the goroutines copying it, so until Wait returns those
	// goroutines may still be appending to these buffers and reading them here
	// would be a race against a process we have already given up on.
	if stdout != nil && reaped {
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
//
// This is the one place a process is constructed, so it is the one place
// confinement is applied. Nothing reaches exec without passing through here.
// command builds the process, wrapped in the helper and confined.
//
// forks says whether the process will fork its own executions rather than being
// the executed program itself; it decides whether a PID namespace is safe. See
// Sandbox.namespaces.
func (s *Spawner) command(spec executor.ProcSpec, forks bool) (*exec.Cmd, error) {
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

	sb := s.sandbox()
	sb.Probe()

	dir := spec.Dir
	if dir == "" {
		dir = sb.Workdir
	}

	// The helper chdirs for us when it is in use, so the command's own Dir is
	// left alone: setting both would mean the target's working directory
	// depended on which of the two happened to be relative.
	helperPath, helperArgv := sb.wrap(path, argv, dir)
	cmdDir := dir
	if helperPath != path {
		cmdDir = ""
	}

	cmd := &exec.Cmd{Path: helperPath, Args: helperArgv, Dir: cmdDir, Env: spec.Env}
	platform.ConfigureProcess(cmd, spec.Quarantine)
	if sb.Require != LevelNone || sb.Level() > LevelMinimal {
		platform.ConfigureSandbox(cmd, sb.namespaces(forks))
	}
	if cg := sb.ensureCgroup(); cg != nil {
		cg.Attach(cmd)
	}
	return cmd, nil
}

// placeInCgroup adds a started process to the campaign's cgroup where the
// kernel could not do it at clone time.
//
// Under cgroups v1 this is the only interface there is, and it races: a target
// that forks before the write lands leaves children outside the limit. The
// window is microseconds and the alternative is no limit at all, but it is a
// real gap and it is why v1 does not count towards the strong level.
func (s *Spawner) placeInCgroup(cmd *exec.Cmd) {
	if cmd.Process == nil {
		return
	}
	s.placeInCgroupPid(cmd.Process.Pid)
}

// placeInCgroupPid is the same by identifier, for a target this layer did not
// start through os/exec — a Windows pseudo-console target, which the platform
// starts itself because os/exec cannot hand a console to a child.
func (s *Spawner) placeInCgroupPid(pid int) {
	cg := s.sandbox().currentCgroup()
	if cg == nil || pid == 0 {
		return
	}
	switch cg.Mode() {
	case platform.CgroupV1, platform.CgroupJob:
		// Both are attached after the process exists and both race the same
		// way. A Windows job object could be attached at creation with a
		// suspended process, which os/exec does not offer; until it does, the
		// window is the same microseconds cgroups v1 has, and it is the reason
		// neither counts towards a strong level.
	default:
		return
	}
	_ = cg.Add(pid)
}

// ReapTimeout bounds how long a caller waits for a killed process to be
// reaped.
//
// SIGKILL cannot be refused, so a process group that does not disappear is one
// that is no longer entirely in the group: a descendant that called setsid, or
// one wedged in an uninterruptible kernel call. Either keeps the pipes open,
// and exec.Cmd.Wait does not return until they close. Waiting forever for that
// would trade a leaked process for a wedged fuzzer, which is the worse of the
// two — a leak is visible in ps and bounded by the campaign, whereas a wedge
// stops everything and looks like a hang with no cause.
const ReapTimeout = 5 * time.Second

// handle is a running process an executor talks to over its lifetime.
//
// Several parties race for its end: the executor calling Wait, a Close calling
// Kill, and the goroutine watching the context. That is why the exit is
// published by closing a channel rather than by sending on one. A value can be
// taken only once, so with a one-shot channel the first waiter wins and every
// other one blocks forever on a process that has already gone — a deadlock that
// looks exactly like a target that will not die.
type handle struct {
	cmd     *exec.Cmd
	control *os.File
	status  *os.File
	start   time.Time

	// exited is closed once the child is reaped; result and waitErr are final
	// from that moment and are only read after a receive on it, which is what
	// makes them safe to publish without a lock.
	exited  chan struct{}
	result  executor.ProcResult
	waitErr error
}

func (h *handle) Pid() int          { return h.cmd.Process.Pid }
func (h *handle) Control() *os.File { return h.control }
func (h *handle) Status() *os.File  { return h.status }

// reap waits for the child and publishes its result.
func (h *handle) reap() {
	h.waitErr = h.cmd.Wait()
	h.result.Duration = time.Since(h.start)
	fillStatus(&h.result, h.cmd, h.waitErr)
	close(h.exited)
}

func (h *handle) Wait() (executor.ProcResult, error) {
	<-h.exited
	return h.result, nil
}

// Kill ends the process group and reaps it.
//
// Safe to call more than once and from more than one goroutine: closing an
// already-closed file and killing an already-dead group are both harmless, and
// the wait is a broadcast.
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
	// Not if it has already been reaped. Killing a process group is
	// kill(-pid), and once the leader is reaped that pid can be handed to
	// something else — which for a fuzzer is not a remote possibility but a
	// routine one, since a campaign creates processes by the million and walks
	// the pid space several times an hour. Signalling a reaped handle would
	// then kill an unrelated process group, and the symptom is a daemon or a
	// worker vanishing for no reason anybody can trace.
	//
	// A window remains between this check and the kill, and it cannot be closed
	// with kill(2) — only a pidfd would, and there is no pidfd for a group. It
	// is the difference between a race that needs the process to die in the
	// microseconds after the check and one that fires every time Close runs
	// after Wait.
	select {
	case <-h.exited:
		return nil
	default:
	}

	err := platform.KillGroup(h.cmd.Process.Pid)

	timer := time.NewTimer(ReapTimeout)
	defer timer.Stop()
	select {
	case <-h.exited:
	case <-timer.C:
		return fmt.Errorf("safety: process %d did not die within %s of SIGKILL; "+
			"something escaped its process group", h.cmd.Process.Pid, ReapTimeout)
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

	cmd, err := s.command(spec, true)
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

	h := &handle{cmd: cmd, control: ctlWrite, status: stRead, exited: make(chan struct{}), start: time.Now()}
	if err := cmd.Start(); err != nil {
		ctlRead.Close()
		ctlWrite.Close()
		stRead.Close()
		stWrite.Close()
		return nil, fmt.Errorf("safety: starting %s: %w", spec.Path, err)
	}
	s.placeInCgroup(cmd)

	// The child owns its ends now; holding them open in the parent would stop
	// the pipes ever reporting end-of-file when the child dies, and the fuzzer
	// would block forever on a dead fork server.
	ctlRead.Close()
	stWrite.Close()

	go h.reap()

	if ctx != nil && ctx.Done() != nil {
		go func() {
			select {
			case <-ctx.Done():
				h.Kill()
			case <-h.exited:
			}
		}()
	}
	return h, nil
}

// reap takes a process's wait result, giving up after ReapTimeout.
//
// Giving up is not the same as forgetting: done is buffered, so the waiting
// goroutine still finishes and the process is still reaped if it ever dies. All
// that is abandoned is this caller's interest in the answer, which is what
// keeps a target that escaped its process group from wedging the fuzz loop.
func reap(done <-chan error) (reaped bool, waitErr error) {
	timer := time.NewTimer(ReapTimeout)
	defer timer.Stop()
	select {
	case err := <-done:
		return true, err
	case <-timer.C:
		return false, nil
	}
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
