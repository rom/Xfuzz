package executor

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/rom/Xfuzz/pkg/feedback"
)

// Fork server protocol constants. These match the values in the C runtime; a
// disagreement shows up as a handshake failure rather than as silent
// corruption, which is why the handshake carries a magic word at all.
const (
	// forkServerHello is written by the runtime once it is ready. It also
	// selects the protocol version.
	forkServerHello uint32 = 0x58465A32 // "XFZ2"

	// controlFD and statusFD are the descriptors the child receives. They are 3
	// and 4 rather than AFL's 198 and 199 because that is where Go's exec places
	// inherited files; the runtime reads both from the environment, so a binary
	// built against either convention works.
	controlFD = 3
	statusFD  = 4

	// timeoutSignal is SIGALRM. The child arms a timer for its own deadline, so
	// a target that loops is killed by the kernel; the status then shows this
	// signal, which is a timeout rather than a crash.
	timeoutSignal = 14
)

// DefaultHandshakeTimeout is how long a fork server has to announce itself.
//
// Generous on purpose. The cost of waiting too long is a slow failure on a
// target that was never going to work; the cost of waiting too little is a
// working target rejected on a loaded machine, which looks like a bug in the
// target and is the more expensive mistake.
const DefaultHandshakeTimeout = 10 * time.Second

const ()

// ForkServer is the T2 executor: a long-lived server process forks a
// pre-initialised copy of the target for every input.
//
// The saving is everything the target does before it reads its first byte —
// dynamic linking, static initialisers, table construction — which happens once
// instead of once per input. On a small parser that is the difference between a
// few hundred executions a second and several thousand.
//
// It needs a target built with xfuzz-cc, or any binary speaking the same
// protocol.
type ForkServer struct {
	name    string
	spawner Spawner
	spec    ProcSpec

	// Coverage is pointed at the shared region the target writes into, so no
	// copying happens per execution.
	Coverage *feedback.CoverageMap
	Shm      SharedMemory

	// CmpShm is the comparison table, when the campaign asked for one, and
	// BlockShm the block trace a directed campaign reads. Both are handed to the
	// fork server at startup like the coverage region, so every forked child
	// inherits the mapping and no per-execution setup is needed.
	CmpShm   SharedMemory
	BlockShm SharedMemory

	// HandshakeTimeout bounds how long Start waits for the fork server to
	// announce itself. Zero means DefaultHandshakeTimeout.
	//
	// It is separate from Timeout because it is measuring something else: a
	// target's first execution can be slow — dynamic linking, a large static
	// initialiser — while an execution once running is fast, and one budget for
	// both would have to be the larger of the two.
	HandshakeTimeout time.Duration

	// Timeout bounds one execution. On expiry the child is killed and the
	// server serves the next input; the server itself survives.
	Timeout time.Duration

	// Backend names the instrumentation, for reporting.
	Backend string

	// Output, when set, receives each execution's standard error.
	//
	// The children of a fork server inherit its descriptors, so there is no
	// per-execution pipe. Instead their stderr is a file that is truncated
	// before each run and read after — two syscalls, against the alternative of
	// giving up on diagnostics at this tier entirely. Without it a campaign can
	// tell that the target crashed but not why, and every crash buckets
	// together.
	Output *feedback.OutputObserver

	handle      Handle
	inputFile   *os.File
	stderrFile  *os.File
	stderrBuf   []byte
	stderrDirty bool
	inputPath   string
	workDir     string
	ownedDir    bool

	execs      uint64
	timeouts   uint64
	restarts   uint64
	lastStatus uint32
}

// NewForkServer returns a T2 executor. Start must be called before Run.
func NewForkServer(name string, spawner Spawner, spec ProcSpec) *ForkServer {
	return &ForkServer{
		name: name, spawner: spawner, spec: spec,
		Timeout: 1 * time.Second, Backend: "forkserver",
	}
}

// Name implements Executor.
func (e *ForkServer) Name() string { return e.name }

// Capabilities implements Executor.
func (e *ForkServer) Capabilities() Caps {
	c := Caps{
		Tier:            TierForkServer,
		Backend:         e.Backend,
		Platform:        runtime.GOOS + "/" + runtime.GOARCH,
		Granularity:     GranularityNone,
		TimeoutEnforced: true,
		Deterministic:   true,
	}
	if e.Coverage != nil {
		c.Granularity = GranularityEdge
		c.MapSize = e.Coverage.Size()
	}
	return c
}

// Stats returns execution counters, for the health diagnostics in ASR-0012.
func (e *ForkServer) Stats() (execs, timeouts, restarts uint64) {
	return e.execs, e.timeouts, e.restarts
}

// Start launches the fork server and completes the handshake.
func (e *ForkServer) Start(ctx context.Context) error {
	if err := e.ensureInputFile(); err != nil {
		return err
	}

	spec := e.spec
	// The control and status streams are the fork server: the whole tier is a
	// word written to one and a word read from the other.
	spec.Protocol = true
	spec.StdinFile = e.inputFile
	if e.Output != nil {
		if err := e.ensureStderrFile(); err != nil {
			return err
		}
		spec.StderrFile = e.stderrFile
	}
	spec.Env = append(append([]string(nil), spec.Env...),
		"XFUZZ_FORKSERVER=1",
		fmt.Sprintf("XFUZZ_CTL_FD=%d", controlFD),
		fmt.Sprintf("XFUZZ_ST_FD=%d", statusFD),
	)
	if e.Shm != nil {
		spec.Env = append(spec.Env, ShmEnvVar+"="+e.Shm.ID())
	}
	if e.CmpShm != nil {
		spec.Env = append(spec.Env, CmpShmEnvVar+"="+e.CmpShm.ID())
	}
	if e.BlockShm != nil {
		spec.Env = append(spec.Env, BlockShmEnvVar+"="+e.BlockShm.ID())
	}

	h, err := e.spawner.Start(ctx, spec)
	if err != nil {
		return fmt.Errorf("executor %s: %w", e.name, err)
	}

	// The handshake is where a target that is not instrumented, or is
	// instrumented against a different runtime, is caught. Reporting it here
	// costs one confusing error; not reporting it costs a campaign that runs for
	// a week and finds nothing.
	handshake := e.HandshakeTimeout
	if handshake <= 0 {
		handshake = DefaultHandshakeTimeout
	}
	if err := h.Status().SetReadDeadline(time.Now().Add(handshake)); err != nil {
		h.Kill()
		return fmt.Errorf("executor %s: %w", e.name, err)
	}
	var hello uint32
	if err := readWord(h.Status(), &hello); err != nil {
		h.Kill()
		return fmt.Errorf("executor %s: no fork server handshake from %s: %w\n"+
			"the target is probably not built with xfuzz-cc; "+
			"use the subprocess tier for an uninstrumented binary", e.name, e.spec.Path, err)
	}
	if hello != forkServerHello {
		h.Kill()
		return fmt.Errorf("executor %s: fork server sent %#08x, expected %#08x; "+
			"the target's runtime and this build disagree about the protocol",
			e.name, hello, forkServerHello)
	}
	_ = h.Status().SetReadDeadline(time.Time{})

	e.handle = h
	e.restarts++
	return nil
}

func (e *ForkServer) ensureInputFile() error {
	if e.inputFile != nil {
		return nil
	}
	dir := e.workDir
	if dir == "" {
		d, err := os.MkdirTemp("", "xfuzz-fs-")
		if err != nil {
			return fmt.Errorf("creating a work directory: %w", err)
		}
		dir, e.ownedDir, e.workDir = d, true, d
	}
	e.inputPath = filepath.Join(dir, "cur_input")
	f, err := os.OpenFile(e.inputPath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("creating the input file: %w", err)
	}
	e.inputFile = f
	return nil
}

func (e *ForkServer) ensureStderrFile() error {
	if e.stderrFile != nil {
		return nil
	}
	f, err := os.OpenFile(filepath.Join(e.workDir, "cur_stderr"),
		os.O_RDWR|os.O_CREATE|os.O_TRUNC|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("creating the stderr file: %w", err)
	}
	e.stderrFile = f
	return nil
}

// readStderr collects what the child wrote and clears the file for the next
// execution.
//
// Almost every execution produces no output at all, so the common path is a
// single stat and nothing else. Truncating and seeking unconditionally cost
// three syscalls on every execution to serve the rare one that says anything.
func (e *ForkServer) readStderr() []byte {
	if e.stderrFile == nil {
		return nil
	}
	fi, err := e.stderrFile.Stat()
	if err != nil {
		return nil
	}
	size := fi.Size()
	if size == 0 {
		e.stderrDirty = false
		return nil
	}
	e.stderrDirty = true

	if int64(cap(e.stderrBuf)) < size {
		e.stderrBuf = make([]byte, size)
	}
	buf := e.stderrBuf[:size]
	n, err := e.stderrFile.ReadAt(buf, 0)
	if err != nil && err != io.EOF {
		return nil
	}
	return buf[:n]
}

// resetStderr clears the file only when the previous execution actually wrote
// to it. The child opens it O_APPEND, so its writes always start at the end and
// the file offset never needs rewinding.
func (e *ForkServer) resetStderr() {
	if e.stderrFile == nil || !e.stderrDirty {
		return
	}
	_ = e.stderrFile.Truncate(0)
	e.stderrDirty = false
}

// Run implements Executor.
func (e *ForkServer) Run(ctx context.Context, in Input, obs []feedback.Observer) (feedback.ExitKind, error) {
	if e.handle == nil {
		if err := e.Start(ctx); err != nil {
			return feedback.ExitError, err
		}
	}

	if err := e.writeInput(in.Bytes); err != nil {
		return feedback.ExitError, err
	}
	e.resetStderr()
	if err := Arm(obs, in); err != nil {
		return feedback.ExitError, err
	}

	start := time.Now()
	ek, err := e.cycle()
	elapsed := time.Since(start)
	if err != nil {
		return feedback.ExitError, err
	}
	e.execs++

	if e.Output != nil {
		e.Output.Record(nil, e.readStderr(), 0, SignalOfWaitStatus(e.lastStatus))
	}
	for _, o := range obs {
		if err := o.Post(ek); err != nil {
			return feedback.ExitError, fmt.Errorf("harvesting %s: %w", o.Name(), err)
		}
	}
	recordDuration(obs, elapsed)
	return ek, nil
}

// writeInput rewrites the shared input file and rewinds it.
//
// The rewind is the load-bearing part: the fork server's standard input is the
// same open file description, so seeking here is what makes the next forked
// child read from the beginning of the new input.
func (e *ForkServer) writeInput(data []byte) error {
	// WriteAt rather than Seek-then-Write, because it does not move the file
	// offset: only the rewind below does, and that one is unavoidable — the
	// previous child consumed the offset while reading.
	if err := e.inputFile.Truncate(int64(len(data))); err != nil {
		return fmt.Errorf("truncating the input file: %w", err)
	}
	if len(data) > 0 {
		if _, err := e.inputFile.WriteAt(data, 0); err != nil {
			return fmt.Errorf("writing the input: %w", err)
		}
	}
	if _, err := e.inputFile.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("rewinding the input file: %w", err)
	}
	return nil
}

// cycle runs one fork-execute-wait round trip.
//
// One write and one read. The runtime replies with the child's pid and its exit
// status together, after waiting, rather than the pid immediately and the status
// later. The obvious protocol costs the fuzzer two blocking reads per execution,
// and each one parks a goroutine and wakes it through the network poller — a
// scheduling round trip that, at these rates, is a large share of the budget.
func (e *ForkServer) cycle() (feedback.ExitKind, error) {
	timeoutMS := uint32(e.Timeout / time.Millisecond)
	if err := writeWord(e.handle.Control(), timeoutMS); err != nil {
		return feedback.ExitError, e.serverDied("sending the run command", err)
	}

	// The fuzzer's own deadline is a backstop for a child the timer could not
	// reach — one wedged in an uninterruptible syscall. It is deliberately
	// slack, because the child's own timer is the mechanism that matters.
	if err := e.handle.Status().SetReadDeadline(time.Now().Add(e.cycleDeadline())); err != nil {
		return feedback.ExitError, err
	}

	var reply [2]uint32
	if err := readWords(e.handle.Status(), reply[:]); err != nil {
		if !os.IsTimeout(err) {
			return feedback.ExitError, e.serverDied("reading the reply", err)
		}
		// The child outlived even the backstop. There is no pid to kill — the
		// reply never arrived — so the server goes with it and is restarted on
		// the next execution.
		e.timeouts++
		return feedback.ExitTimeout, e.serverDied("waiting for a child that never returned", err)
	}

	status := reply[1]
	e.lastStatus = status
	if SignalOfWaitStatus(status) == timeoutSignal {
		e.timeouts++
		return feedback.ExitTimeout, nil
	}
	return exitKindOfWaitStatus(status), nil
}

func (e *ForkServer) cycleDeadline() time.Duration {
	if e.Timeout > 5*time.Second {
		return e.Timeout
	}
	return 5 * time.Second
}

// serverDied reports the loss of the fork server and drops the handle so the
// next execution restarts it.
func (e *ForkServer) serverDied(during string, err error) error {
	if e.handle != nil {
		e.handle.Kill()
		e.handle = nil
	}
	return fmt.Errorf("executor %s: fork server lost while %s: %w", e.name, during, err)
}

// exitKindOfWaitStatus decodes a POSIX wait status.
//
// The encoding is arithmetic rather than a syscall, so this file needs no build
// tag and no platform package: the low seven bits hold the terminating signal,
// 0x7f means stopped, and zero there means a normal exit whose code is in the
// next eight bits.
func exitKindOfWaitStatus(status uint32) feedback.ExitKind {
	if sig := status & 0x7f; sig != 0 && sig != 0x7f {
		return feedback.ExitCrash
	}
	return feedback.ExitOK
}

// SignalOfWaitStatus returns the terminating signal, or zero.
func SignalOfWaitStatus(status uint32) int {
	if sig := status & 0x7f; sig != 0 && sig != 0x7f {
		return int(sig)
	}
	return 0
}

// Reset implements Executor. Each execution already gets a fresh fork of the
// server, so nothing carries over; a restart replaces the server itself.
func (e *ForkServer) Reset(p ResetPolicy) error {
	if p != ResetRestart {
		return nil
	}
	if e.handle != nil {
		e.handle.Kill()
		e.handle = nil
	}
	return nil
}

// Close implements Executor.
func (e *ForkServer) Close() error {
	if e.handle != nil {
		e.handle.Kill()
		e.handle = nil
	}
	if e.inputFile != nil {
		e.inputFile.Close()
		e.inputFile = nil
	}
	if e.stderrFile != nil {
		e.stderrFile.Close()
		e.stderrFile = nil
	}
	if e.ownedDir && e.workDir != "" {
		return os.RemoveAll(e.workDir)
	}
	return nil
}

func writeWord(w io.Writer, v uint32) error {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], v)
	n, err := w.Write(b[:])
	if err != nil {
		return err
	}
	if n != 4 {
		return io.ErrShortWrite
	}
	return nil
}

func readWord(r io.Reader, v *uint32) error {
	var b [4]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return err
	}
	*v = binary.LittleEndian.Uint32(b[:])
	return nil
}

// readWords fills a slice of words in one call, so the caller blocks once
// rather than once per word.
func readWords(r io.Reader, out []uint32) error {
	var b [16]byte
	buf := b[:4*len(out)]
	if _, err := io.ReadFull(r, buf); err != nil {
		return err
	}
	for i := range out {
		out[i] = binary.LittleEndian.Uint32(buf[4*i:])
	}
	return nil
}
