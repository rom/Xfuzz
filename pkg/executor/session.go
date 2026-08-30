package executor

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"sync/atomic"
	"time"

	"github.com/rom/Xfuzz/pkg/feedback"
	"github.com/rom/Xfuzz/pkg/ir"
)

// Dialer opens a connection to the target.
//
// An interface for the same reason Spawner is one: pkg/ cannot reach
// internal/safety, and reaching out to the network must pass the scope guard
// (ADR-0012). Every connection a session makes goes through whatever the
// campaign wired in here, and the architecture lint forbids this package from
// dialling any other way — so an executor that bypassed the guard would not
// compile rather than merely being wrong.
type Dialer interface {
	Dial(ctx context.Context, network, address string) (net.Conn, error)
}

// ResponseObserver is fed each reply as it arrives.
//
// The state observer implements it. Declared here rather than imported so that
// the executor knows only "something wants to see the replies" — the executor
// delivers messages and reads answers, and what a state is remains entirely
// pkg/state's business (ADR-0006).
type ResponseObserver interface {
	// Response records one reply from the target.
	Response(resp []byte)

	// Hangup records that the target closed the connection.
	Hangup()
}

// Framing is how the executor decides one reply is complete.
//
// This is the hardest thing about black-box protocol fuzzing and there is no
// universally correct answer, so it is configuration rather than a guess. Get it
// wrong in one direction and a reply is split across two messages, so every
// state label is off by one; get it wrong in the other and the executor waits
// for a reply that already arrived.
type Framing uint8

// The framing modes.
const (
	// FrameIdle reads until the target has been quiet for QuietPeriod.
	//
	// The only mode that needs no knowledge of the protocol, and therefore the
	// default. It costs one quiet period per message, which sets the ceiling on
	// a stateful campaign's throughput — a real cost, and the reason a campaign
	// against a text protocol should say so and use FrameLine instead.
	FrameIdle Framing = iota

	// FrameLine reads to the next newline. Right for SMTP, FTP, IRC, Redis and
	// every other line-oriented protocol, and far faster than idle: the reply
	// ends when it ends rather than when a timer says it might have.
	FrameLine

	// FrameNone sends without reading a reply, for one-way protocols. The state
	// function then has nothing to label, so a campaign using it is
	// code-coverage-guided with sessions as structure.
	FrameNone
)

var framingNames = [...]string{FrameIdle: "idle", FrameLine: "line", FrameNone: "none"}

func (f Framing) String() string {
	if int(f) < len(framingNames) {
		return framingNames[f]
	}
	return "unknown"
}

// FramingNamed returns the framing a campaign file asked for.
func FramingNamed(name string) (Framing, error) {
	switch name {
	case "idle", "":
		return FrameIdle, nil
	case "line":
		return FrameLine, nil
	case "none":
		return FrameNone, nil
	}
	return 0, fmt.Errorf("executor: %q is not a framing mode; use idle, line, or none", name)
}

// SessionOptions configure the T6 executor.
type SessionOptions struct {
	// Network and Address say where the target listens.
	Network string
	Address string

	// Reset is what happens to the target between sessions (ADR-0006).
	Reset ResetPolicy

	// Framing decides when a reply is complete.
	Framing Framing

	// QuietPeriod is how long FrameIdle waits for more data before calling a
	// reply finished.
	QuietPeriod time.Duration

	// ConnectTimeout bounds establishing a connection, ReadTimeout one reply,
	// and SessionTimeout the whole session. All three are needed: a target can
	// refuse to accept, accept and never answer, or answer every message
	// slowly enough that the session never ends.
	ConnectTimeout time.Duration
	ReadTimeout    time.Duration
	SessionTimeout time.Duration

	// ReadLimit bounds one reply. A target that answers a one-byte message with
	// a gigabyte is a finding, not a reason to run out of memory.
	ReadLimit int

	// ReadyTimeout is how long a managed server has to accept connections after
	// it is started.
	ReadyTimeout time.Duration
}

// Session defaults. Named because they are tuning parameters for a tier whose
// throughput is dominated by exactly these numbers.
const (
	DefaultQuietPeriod    = 5 * time.Millisecond
	DefaultConnectTimeout = 2 * time.Second

	// A reply that has not arrived in this long is not coming, on a target
	// reachable in microseconds. It is deliberately loopback-scale: the tier's
	// throughput is the message count times this number, and a campaign against
	// something further away should say so rather than have every campaign pay
	// for the possibility.
	DefaultReadTimeout    = 250 * time.Millisecond
	DefaultSessionTimeout = 10 * time.Second
	DefaultReadLimit      = 1 << 20
	DefaultReadyTimeout   = 10 * time.Second
)

func (o *SessionOptions) withDefaults() {
	if o.QuietPeriod <= 0 {
		o.QuietPeriod = DefaultQuietPeriod
	}
	if o.ConnectTimeout <= 0 {
		o.ConnectTimeout = DefaultConnectTimeout
	}
	if o.ReadTimeout <= 0 {
		o.ReadTimeout = DefaultReadTimeout
	}
	if o.SessionTimeout <= 0 {
		o.SessionTimeout = DefaultSessionTimeout
	}
	if o.ReadLimit <= 0 {
		o.ReadLimit = DefaultReadLimit
	}
	if o.ReadyTimeout <= 0 {
		o.ReadyTimeout = DefaultReadyTimeout
	}
	if o.Network == "" {
		o.Network = "tcp"
	}
}

// ErrSnapshotUnsupported is returned for the reset policy ADR-0006 defers.
var ErrSnapshotUnsupported = errors.New(
	"executor: the snapshot reset policy needs KVM-based checkpointing, which ADR-0006 " +
		"defers past v1; use restart for correctness or reconnect for speed")

// Session is the T6 executor: a target that speaks a protocol over a connection.
//
// One execution is a whole session — connect, send each message, read each
// reply, close — because for a stateful target the session is the unit of work
// (ASR-0002). A stateless input is a session of one message, which is why this
// tier needs no special case for the degenerate configuration.
type Session struct {
	name string
	opts SessionOptions

	dial Dialer

	// spawner and spec manage the server process, when the campaign gave one.
	// Both nil means the target is already listening, which is the case the
	// scope guard and the authorization record exist for.
	spawner Spawner
	spec    ProcSpec

	// Observers wired by the campaign.
	States ResponseObserver
	Output *feedback.OutputObserver

	// stderr is where the managed server's own output is collected.
	//
	// A file rather than a pipe, for the reason the fork server needs one: the
	// server is long-lived and its children inherit its descriptors, so there
	// is no per-execution pipe to read. Truncating before a session and reading
	// after gives that session's output for two cheap syscalls — and without it
	// a crash arrives as "target terminated abnormally" with the target's own
	// account of which assertion failed thrown away, which is the difference
	// between a finding somebody can act on and a byte sequence.
	stderr *os.File

	// Shm is the coverage region the server writes into, and Backend names the
	// instrumentation for reports. A server is long-lived, so the region is
	// attached once at startup rather than per execution — which also means the
	// map accumulates across the sessions of one server's life, and the reset
	// policy is what bounds that.
	Shm     SharedMemory
	Backend string

	// srv is the managed target, or nil when the campaign did not give one.
	srv  *server
	conn net.Conn

	// lifetime is the context the managed server's life is tied to: the
	// campaign's, never one session's. See spawnCtx.
	lifetime context.Context

	execs uint64
	buf   []byte
}

// server is one generation of the managed target: its handle, whether it has
// exited, and how.
//
// Per generation rather than per session, because a restart replaces the
// process while the goroutine reaping the previous one is still running.
// Sharing one flag and one result across generations lets that goroutine
// report the old process's death against the new one, and the campaign files
// a finding against an input that did nothing wrong. Measured: a session
// following a restart reported a crash whose summary named no signal, because
// the stale result that made it look like a crash had been overwritten by a
// clean one before the output was harvested. Giving each generation its own
// state makes a stale reaper write where nothing reads.
type server struct {
	handle Handle

	// exited is set by the reaper goroutine when this generation ends, and
	// result holds how. A flag rather than a Wait with a short timeout on
	// every session: that cost fifty milliseconds per execution, which on a
	// tier whose whole budget is a few milliseconds per message was most of
	// the execution.
	exited atomic.Bool
	result ProcResult
}

// NewSession returns a session executor. Nothing is started until Start.
func NewSession(name string, dial Dialer, opts SessionOptions) *Session {
	opts.withDefaults()
	return &Session{name: name, opts: opts, dial: dial, buf: make([]byte, 32<<10)}
}

// Manage tells the executor to run the server itself, rather than connecting to
// one that is already listening.
func (e *Session) Manage(spawner Spawner, spec ProcSpec) {
	e.spawner, e.spec = spawner, spec
}

// Name implements Executor.
func (e *Session) Name() string { return e.name }

// Executions returns how many sessions have run.
func (e *Session) Executions() uint64 { return e.execs }

// Capabilities implements Executor.
func (e *Session) Capabilities() Caps {
	backend, granularity := e.Backend, GranularityNone
	if backend == "" {
		backend = "blackbox"
	}
	if e.Shm != nil {
		granularity = GranularityEdge
	}
	return Caps{
		Tier:        TierSession,
		Backend:     backend,
		Granularity: granularity,
		Platform:    runtime.GOOS + "/" + runtime.GOARCH,
		// A protocol server is not deterministic in the way a file parser is:
		// it has timers, sequence numbers and a scheduler. Claiming otherwise
		// would let the engine treat a differing replay as a corpus bug.
		Deterministic:   false,
		TimeoutEnforced: true,
	}
}

// Start brings the target up, if this executor is managing it.
func (e *Session) Start(ctx context.Context) error {
	e.lifetime = ctx
	if e.opts.Reset == ResetSnapshot {
		return ErrSnapshotUnsupported
	}
	if e.spawner == nil {
		return e.waitReady(ctx)
	}
	return e.startServer(ctx)
}

// startServer launches the managed target and waits for it to listen.
// spawnCtx is the context a managed server's life is tied to.
//
// The executor's, never the caller's. The spawner kills a process when the
// context it was started with is done, and a session context carries
// SessionTimeout — so a server restarted in the middle of a session was killed
// some seconds later, in the middle of a *later* session, and the SIGKILL was
// read as the target dying. Measured: a finding per campaign reading "target
// terminated abnormally" with signal 9, filed against an input that did
// nothing, and reproducing 0 times out of 5.
func (e *Session) spawnCtx() context.Context {
	if e.lifetime != nil {
		return e.lifetime
	}
	return context.Background()
}

func (e *Session) startServer(ctx context.Context) error {
	spec := e.spec
	if e.Shm != nil {
		spec.Env = append(append([]string(nil), spec.Env...), ShmEnvVar+"="+e.Shm.ID())
	}
	if e.Output != nil {
		if err := e.openStderr(); err != nil {
			return err
		}
		spec.StderrFile = e.stderr
	}
	h, err := e.spawner.Start(e.spawnCtx(), spec)
	if err != nil {
		return fmt.Errorf("executor %s: starting the target: %w", e.name, err)
	}
	srv := &server{handle: h}
	e.srv = srv
	go func() {
		res, _ := h.Wait()
		// Written before the flag, and read after it: the flag is the
		// happens-before edge, so no lock is needed for a value only ever
		// written once. Written into this generation's own state, so a reaper
		// that outlives its restart reports nothing about its successor.
		srv.result = res
		srv.exited.Store(true)
	}()
	if err := e.waitReady(ctx); err != nil {
		h.Kill()
		e.srv = nil
		return err
	}
	return nil
}

// waitReady polls until the target accepts a connection.
//
// Polling rather than a fixed sleep: a sleep long enough for a slow start wastes
// it on every fast one, and a sleep short enough for a fast start makes a slow
// one look like a target that does not listen at all.
func (e *Session) waitReady(ctx context.Context) error {
	deadline := time.Now().Add(e.opts.ReadyTimeout)
	var last error
	for time.Now().Before(deadline) {
		if err := ctx.Err(); err != nil {
			return err
		}
		c, err := e.connect(ctx)
		if err == nil {
			c.Close()
			return nil
		}
		last = err
		select {
		case <-time.After(10 * time.Millisecond):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return fmt.Errorf("executor %s: %s/%s did not accept a connection within %s: %w",
		e.name, e.opts.Network, e.opts.Address, e.opts.ReadyTimeout, last)
}

func (e *Session) connect(ctx context.Context) (net.Conn, error) {
	dctx, cancel := context.WithTimeout(ctx, e.opts.ConnectTimeout)
	defer cancel()
	return e.dial.Dial(dctx, e.opts.Network, e.opts.Address)
}

// Run implements Executor: deliver one session and observe what came back.
func (e *Session) Run(ctx context.Context, in Input, obs []feedback.Observer) (feedback.ExitKind, error) {
	msgs := messagesOf(in)
	if len(msgs) == 0 {
		// Nothing to send is not a harness failure; it is an input that says
		// nothing, and the right answer is that nothing happened.
		return feedback.ExitOK, nil
	}

	if err := Arm(obs, in); err != nil {
		return feedback.ExitError, err
	}

	sctx, cancel := context.WithTimeout(ctx, e.opts.SessionTimeout)
	defer cancel()

	e.truncateStderr()

	start := time.Now()
	ek, err := e.deliver(sctx, msgs)
	if err != nil {
		return feedback.ExitError, err
	}

	e.execs++
	e.harvestStderr(ek)

	for _, o := range obs {
		if perr := o.Post(ek); perr != nil {
			return feedback.ExitError, fmt.Errorf("harvesting %s: %w", o.Name(), perr)
		}
	}
	recordDuration(obs, time.Since(start))
	return ek, nil
}

// deliver sends each message and reads its reply.
func (e *Session) deliver(ctx context.Context, msgs [][]byte) (feedback.ExitKind, error) {
	conn, err := e.session(ctx)
	if err != nil {
		return feedback.ExitError, err
	}

	// Once one message has gone unanswered, later ones wait only a quiet period
	// rather than the full read timeout.
	//
	// Silence nearly always means the target is mid-message: mutation strips
	// the terminator from a line, the target sits in its read waiting for the
	// rest, and the fuzzer sits waiting for a reply. Charging the full timeout
	// for that on every remaining message is what turns one bad byte into a
	// whole session's budget — measured here as a single session consuming its
	// entire ten seconds and the worker reporting nothing at all. Waiting a
	// little rather than not at all keeps a pipelined protocol's late replies,
	// which do arrive once a later message completes the line.
	silent := false

	for _, m := range msgs {
		if err := ctx.Err(); err != nil {
			// The session's own budget ran out. That is a hang: the target is
			// answering, or not answering, slowly enough that a person waiting
			// for it would call it stuck.
			e.dropConnection()
			return feedback.ExitTimeout, nil
		}
		if werr := e.write(conn, m); werr != nil {
			// A write that fails means the peer is gone, which for a target
			// under test is nearly always because it just died. Reporting it as
			// a harness error would hide the crash; the process status decides.
			return e.afterHangup(), nil
		}
		if e.opts.Framing == FrameNone {
			continue
		}
		resp, rerr := e.read(conn, e.readBudget(ctx, silent))
		if len(resp) > 0 && e.States != nil {
			e.States.Response(resp)
		}
		if len(resp) > 0 && e.Output != nil {
			e.Output.Record(nil, resp, 0, 0)
		}
		switch {
		case errors.Is(rerr, io.EOF):
			return e.afterHangup(), nil
		case isTimeout(rerr):
			// No reply within the per-message budget. Not fatal on its own —
			// plenty of protocols answer some messages and not others — so the
			// session continues and the trace records the silence.
			if e.States != nil && len(resp) == 0 {
				e.States.Response(nil)
			}
			// Unless the target has died, which is what silence usually means
			// on the tier where the target is a server: it aborted before it
			// could reply. Continuing would spend the read timeout again on
			// every remaining message, and on a target with a shallow bug that
			// is most of the campaign's wall-clock time.
			silent = true
			if e.exited() {
				return e.afterHangup(), nil
			}
		case rerr != nil:
			return e.afterHangup(), nil
		}
	}

	e.endSession()
	return e.liveness(), nil
}

// afterHangup records the close and reports how the target ended.
//
// This is the one path that waits for the reaper, and it has to. A crash and an
// orderly disconnect look identical from the socket: both are a connection that
// stopped. Only the process status separates them, and the process has just
// died — so its exit is in flight rather than already recorded, and checking
// without waiting reports every crash as a clean session. Measured: a campaign
// that hit its planted bug thousands of times reported no findings at all. The
// wait is short and only on this path, so a campaign that never crashes never
// pays it.
func (e *Session) afterHangup() feedback.ExitKind {
	if e.States != nil {
		e.States.Hangup()
	}
	e.dropConnection()
	e.awaitExit(HangupGrace)
	return e.liveness()
}

// Signals a target cannot raise on itself as a fault, so their presence means
// something outside the target ended it.
const (
	sigKill = 9
	sigTerm = 15
)

// HangupGrace is how long a dropped connection waits for the target's exit
// status before concluding the target is still alive.
const HangupGrace = 100 * time.Millisecond

// awaitExit waits briefly for the reaper to observe the managed target's exit.
func (e *Session) awaitExit(d time.Duration) {
	if e.srv == nil || e.exited() {
		return
	}
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
		if e.exited() {
			return
		}
	}
}

// exited reports whether the current generation of the managed target has ended.
func (e *Session) exited() bool { return e.srv != nil && e.srv.exited.Load() }

// liveness asks the managed process whether the target is still alive.
//
// A protocol fuzzer's central ambiguity: a closed connection means the target
// crashed, or that it closed the connection. Only the process status separates
// them, and where the target is not ours to manage nothing can — so an
// unmanaged target's crash is reported as an ordinary end, and the campaign is
// told at startup that this is what it is getting.
func (e *Session) liveness() feedback.ExitKind {
	if e.srv == nil || !e.exited() {
		return feedback.ExitOK
	}
	res := e.srv.result
	switch {
	case res.OOM:
		return feedback.ExitOOM
	case res.TimedOut:
		return feedback.ExitTimeout
	case res.Signal == sigKill || res.Signal == sigTerm:
		// Not a finding, whatever else it is. A target does not send itself
		// these; something outside it did — this executor replacing the
		// server, an operator, the kernel where the cgroup accounting did not
		// reach us — and filing an infrastructure event as a crash produces a
		// bug report that never reproduces and an input that is not to blame.
		return feedback.ExitOK
	case res.Signal != 0:
		return feedback.ExitCrash
	}
	// Exited without a signal. A server that stops on its own mid-campaign is
	// not a crash, but it is not nothing either: every later session will fail
	// to connect, and restarting is the only way on.
	return feedback.ExitOK
}

// session returns the connection to use, honouring the reset policy.
func (e *Session) session(ctx context.Context) (net.Conn, error) {
	// A dead server is restarted whatever the policy says. The policy describes
	// what happens between sessions in the ordinary case; it is not a licence
	// to keep dialling a process that is gone. Without this a campaign using
	// reconnect stops fuzzing at its first finding, which is the moment it
	// starts being useful.
	if e.srv != nil && e.exited() && e.opts.Reset != ResetRestart {
		if err := e.restartServer(ctx); err != nil {
			return nil, err
		}
		return e.newConnection(ctx)
	}

	switch e.opts.Reset { //nolint:exhaustive // the remaining policy is the default
	case ResetRestart:
		if err := e.restartServer(ctx); err != nil {
			return nil, err
		}
		return e.newConnection(ctx)

	case ResetNone:
		// State carries over deliberately: one connection for the life of the
		// campaign, which is what a campaign fuzzing a long-lived session
		// wants, and what makes its findings depend on everything that ran
		// before them.
		if e.conn != nil {
			return e.conn, nil
		}
		return e.newConnection(ctx)

	default: // ResetReconnect
		e.dropConnection()
		return e.newConnection(ctx)
	}
}

func (e *Session) newConnection(ctx context.Context) (net.Conn, error) {
	c, err := e.connect(ctx)
	if err == nil {
		e.conn = c
		return c, nil
	}

	// A refused connection to a target we manage is the target being down, not
	// a harness failure. It happens constantly on a target with a reachable
	// bug: the server dies, its socket file outlives it, and the next session
	// dials something nothing is listening on. The exit is often still in
	// flight at this point, which is why the check above cannot catch it — so
	// the recovery is here, where the evidence is unambiguous.
	//
	// Without this a campaign ends at its first crash with "connection
	// refused", which reads as a configuration error and is not one.
	if e.spawner == nil {
		return nil, fmt.Errorf("executor %s: connecting to %s: %w", e.name, e.opts.Address, err)
	}
	if rerr := e.restartServer(ctx); rerr != nil {
		return nil, rerr
	}
	c, err = e.connect(ctx)
	if err != nil {
		return nil, fmt.Errorf("executor %s: connecting to %s after restarting it: %w",
			e.name, e.opts.Address, err)
	}
	e.conn = c
	return c, nil
}

// endSession closes the connection unless the policy keeps it.
func (e *Session) endSession() {
	if e.opts.Reset != ResetNone {
		e.dropConnection()
	}
}

func (e *Session) dropConnection() {
	if e.conn != nil {
		e.conn.Close()
		e.conn = nil
	}
}

// restartServer replaces the managed process.
func (e *Session) restartServer(ctx context.Context) error {
	if e.spawner == nil {
		// Nothing to restart. The campaign asked for the correct policy and the
		// host cannot provide it, which is worth saying once rather than
		// silently downgrading to reconnect.
		e.dropConnection()
		return nil
	}
	e.dropConnection()
	if e.srv != nil {
		e.srv.handle.Kill()
		e.srv = nil
	}
	return e.startServer(ctx)
}

// write sends one message.
func (e *Session) write(c net.Conn, m []byte) error {
	if err := c.SetWriteDeadline(time.Now().Add(e.opts.ReadTimeout)); err != nil {
		return err
	}
	_, err := c.Write(m)
	return err
}

// readBudget is how long to wait for one reply.
//
// Bounded by what the session has left as well as by the per-message timeout: a
// read that could outlast the session would make the session timeout advisory,
// and a target that answers nothing would hold a worker for the read timeout
// times the message count rather than for the session's own budget.
func (e *Session) readBudget(ctx context.Context, silent bool) time.Duration {
	d := e.opts.ReadTimeout
	if silent {
		d = e.opts.QuietPeriod
	}
	if dl, ok := ctx.Deadline(); ok {
		if left := time.Until(dl); left < d {
			d = left
		}
	}
	return d
}

// read collects one reply according to the framing.
func (e *Session) read(c net.Conn, budget time.Duration) ([]byte, error) {
	if budget <= 0 {
		return nil, os.ErrDeadlineExceeded
	}
	switch e.opts.Framing {
	case FrameLine:
		return e.readLine(c, budget)
	default:
		return e.readIdle(c, budget)
	}
}

// readIdle reads until the target goes quiet.
func (e *Session) readIdle(c net.Conn, budget time.Duration) ([]byte, error) {
	var out []byte
	deadline := time.Now().Add(budget)
	first := true
	for {
		// The first read waits for the reply to begin; later ones wait only for
		// the quiet period, because by then the question is whether there is
		// more of the same reply rather than whether there is a reply at all.
		wait := e.opts.QuietPeriod
		if first {
			wait = budget
		}
		if d := time.Until(deadline); d < wait {
			wait = d
		}
		if wait <= 0 {
			return out, nil
		}
		if err := c.SetReadDeadline(time.Now().Add(wait)); err != nil {
			return out, err
		}
		n, err := c.Read(e.buf)
		if n > 0 {
			out = append(out, e.buf[:n]...)
			first = false
			if len(out) >= e.opts.ReadLimit {
				return out[:e.opts.ReadLimit], nil
			}
			continue
		}
		if isTimeout(err) {
			if first {
				return out, err // nothing arrived at all
			}
			return out, nil // the reply ended
		}
		return out, err
	}
}

// readLine reads to the next newline.
func (e *Session) readLine(c net.Conn, budget time.Duration) ([]byte, error) {
	var out []byte
	if err := c.SetReadDeadline(time.Now().Add(budget)); err != nil {
		return nil, err
	}
	for {
		n, err := c.Read(e.buf[:1])
		if n > 0 {
			out = append(out, e.buf[0])
			if e.buf[0] == '\n' || len(out) >= e.opts.ReadLimit {
				return out, nil
			}
			continue
		}
		if err != nil {
			return out, err
		}
	}
}

// Reset implements Executor.
func (e *Session) Reset(p ResetPolicy) error {
	switch p {
	case ResetSnapshot:
		return ErrSnapshotUnsupported
	case ResetRestart:
		return e.restartServer(context.Background())
	case ResetReconnect:
		e.dropConnection()
	}
	return nil
}

// openStderr creates the file the managed server writes its output to.
func (e *Session) openStderr() error {
	if e.stderr != nil {
		return nil
	}
	f, err := os.CreateTemp("", "xfuzz-session-*.err")
	if err != nil {
		return fmt.Errorf("executor %s: creating the output file: %w", e.name, err)
	}
	// Unlinked immediately: the descriptor keeps it alive, and a campaign that
	// restarts its target thousands of times must not leave thousands of files
	// behind when it is killed.
	os.Remove(f.Name())
	// Readable by the target's identity, which is not the fuzzer's.
	_ = f.Chmod(0o666)
	e.stderr = f
	return nil
}

func (e *Session) truncateStderr() {
	if e.stderr == nil {
		return
	}
	_ = e.stderr.Truncate(0)
	_, _ = e.stderr.Seek(0, io.SeekStart)
}

// harvestStderr hands the session's output and exit status to the observer.
//
// The status matters as much as the output. Without it every crash on this tier
// reports "target terminated abnormally" rather than naming the signal, and a
// summary that is identical for every crash is one that cannot distinguish two
// bugs.
func (e *Session) harvestStderr(ek feedback.ExitKind) {
	if e.Output == nil {
		return
	}
	var buf []byte
	if e.stderr != nil {
		if _, err := e.stderr.Seek(0, io.SeekStart); err == nil {
			buf, _ = io.ReadAll(io.LimitReader(e.stderr, int64(e.opts.ReadLimit)))
		}
	}
	exitCode, signal := 0, 0
	if e.srv != nil && e.exited() {
		exitCode, signal = e.srv.result.ExitCode, e.srv.result.Signal
	}
	if ek == feedback.ExitOK && len(buf) == 0 && signal == 0 && exitCode == 0 {
		// Nothing new to say, and the observer already holds this session's
		// last response. Overwriting it with an empty buffer would throw away
		// the only account of what the target said.
		return
	}
	// An execution that did not end well always records, even with nothing to
	// record. Otherwise the observer keeps whatever the last reply left there
	// and the objective reads a status of zero — which is how a crash comes to
	// be reported as "target terminated abnormally" with no signal named and
	// no output, the least actionable finding a fuzzer can produce.
	e.Output.Record(nil, buf, exitCode, signal)
}

// Close implements Executor.
func (e *Session) Close() error {
	if e.stderr != nil {
		e.stderr.Close()
		e.stderr = nil
	}
	e.dropConnection()
	if e.srv != nil {
		err := e.srv.handle.Kill()
		e.srv = nil
		return err
	}
	return nil
}

// messagesOf splits a session input into the messages to send.
//
// A session is a Repeat node whose children are messages (ADR-0005), so each
// child is encoded on its own — that is what makes the boundary between two
// messages a real boundary rather than a position in a byte stream, and what
// lets the sequence mutators insert, delete and reorder messages without any
// framing knowledge.
//
// An input that is not a Repeat is one message, which is how a stateless
// campaign runs on this tier unchanged.
func messagesOf(in Input) [][]byte {
	if in.Node == nil {
		if len(in.Bytes) == 0 {
			return nil
		}
		return [][]byte{in.Bytes}
	}
	if in.Node.Kind != ir.KindRepeat {
		return [][]byte{ir.Encode(in.Node)}
	}
	out := make([][]byte, 0, len(in.Node.Children))
	for _, kid := range in.Node.Children {
		out = append(out, ir.Encode(kid))
	}
	return out
}

// isTimeout reports whether an error is a deadline expiring.
func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}
