package executor

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"runtime"
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
	DefaultReadTimeout    = 2 * time.Second
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

	handle Handle
	conn   net.Conn

	execs uint64
	buf   []byte
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
	return Caps{
		Tier:        TierSession,
		Backend:     "blackbox",
		Granularity: GranularityNone,
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
	if e.opts.Reset == ResetSnapshot {
		return ErrSnapshotUnsupported
	}
	if e.spawner == nil {
		return e.waitReady(ctx)
	}
	return e.startServer(ctx)
}

// startServer launches the managed target and waits for it to listen.
func (e *Session) startServer(ctx context.Context) error {
	h, err := e.spawner.Start(ctx, e.spec)
	if err != nil {
		return fmt.Errorf("executor %s: starting the target: %w", e.name, err)
	}
	e.handle = h
	if err := e.waitReady(ctx); err != nil {
		h.Kill()
		e.handle = nil
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

	for _, o := range obs {
		if err := o.Pre(); err != nil {
			return feedback.ExitError, fmt.Errorf("arming %s: %w", o.Name(), err)
		}
	}

	sctx, cancel := context.WithTimeout(ctx, e.opts.SessionTimeout)
	defer cancel()

	start := time.Now()
	ek, err := e.deliver(sctx, msgs)
	if err != nil {
		return feedback.ExitError, err
	}

	e.execs++
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
		resp, rerr := e.read(conn)
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
		case rerr != nil:
			return e.afterHangup(), nil
		}
	}

	e.endSession()
	return e.liveness(), nil
}

// afterHangup records the close and reports how the target ended.
func (e *Session) afterHangup() feedback.ExitKind {
	if e.States != nil {
		e.States.Hangup()
	}
	e.dropConnection()
	return e.liveness()
}

// liveness asks the managed process whether the target is still alive.
//
// A protocol fuzzer's central ambiguity: a closed connection means the target
// crashed, or that it closed the connection. Only the process status separates
// them, and where the target is not ours to manage nothing can — so an
// unmanaged target's crash is reported as an ordinary end, and the campaign is
// told at startup that this is what it is getting.
func (e *Session) liveness() feedback.ExitKind {
	if e.handle == nil {
		return feedback.ExitOK
	}
	res, alive := e.serverStatus()
	if alive {
		return feedback.ExitOK
	}
	switch {
	case res.OOM:
		return feedback.ExitOOM
	case res.Signal != 0:
		return feedback.ExitCrash
	case res.TimedOut:
		return feedback.ExitTimeout
	}
	// Exited without a signal. A server that stops on its own mid-campaign is
	// not a crash, but it is not nothing either: every later session will fail
	// to connect, and restarting is the only way on.
	return feedback.ExitOK
}

// serverStatus reports the managed process's result, and whether it is running.
func (e *Session) serverStatus() (ProcResult, bool) {
	done := make(chan ProcResult, 1)
	go func() {
		res, _ := e.handle.Wait()
		done <- res
	}()
	select {
	case res := <-done:
		return res, false
	case <-time.After(50 * time.Millisecond):
		// Still running. The goroutine stays parked on Wait, which is what we
		// want: it is the reaper, and it will deliver into a buffered channel
		// nobody reads.
		return ProcResult{}, true
	}
}

// session returns the connection to use, honouring the reset policy.
func (e *Session) session(ctx context.Context) (net.Conn, error) {
	switch e.opts.Reset {
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
	if err != nil {
		return nil, fmt.Errorf("executor %s: connecting to %s: %w", e.name, e.opts.Address, err)
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
	if e.handle != nil {
		e.handle.Kill()
		e.handle = nil
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

// read collects one reply according to the framing.
func (e *Session) read(c net.Conn) ([]byte, error) {
	switch e.opts.Framing {
	case FrameLine:
		return e.readLine(c)
	default:
		return e.readIdle(c)
	}
}

// readIdle reads until the target goes quiet.
func (e *Session) readIdle(c net.Conn) ([]byte, error) {
	var out []byte
	deadline := time.Now().Add(e.opts.ReadTimeout)
	first := true
	for {
		// The first read waits for the reply to begin; later ones wait only for
		// the quiet period, because by then the question is whether there is
		// more of the same reply rather than whether there is a reply at all.
		wait := e.opts.QuietPeriod
		if first {
			wait = e.opts.ReadTimeout
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
func (e *Session) readLine(c net.Conn) ([]byte, error) {
	var out []byte
	if err := c.SetReadDeadline(time.Now().Add(e.opts.ReadTimeout)); err != nil {
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

// Close implements Executor.
func (e *Session) Close() error {
	e.dropConnection()
	if e.handle != nil {
		err := e.handle.Kill()
		e.handle = nil
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
