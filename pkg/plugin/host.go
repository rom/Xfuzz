package plugin

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Transport is a plugin process the host talks to.
//
// The host does not create it. Nothing in pkg/ may spawn a process — only
// internal/safety may, and the architecture lint enforces it — because ADR-0012
// makes confinement mandatory and a rule with an exception is not a rule. So a
// plugin arrives already running, already confined, and the host's only powers
// over it are to write, to read, and to kill.
type Transport struct {
	// Stdin is written to; Stdout is read from. A plugin's own diagnostics go
	// to its standard error, which is deliberately not part of the protocol:
	// a plugin author should be able to print without corrupting a frame.
	Stdin  io.WriteCloser
	Stdout io.Reader

	// Kill terminates the process. It must be safe to call more than once, and
	// from a timer goroutine while a read is blocked.
	Kill func() error

	// Diagnose returns what the process wrote to its standard error, or an
	// empty string. It is called only when something has already gone wrong,
	// so it may be slow, and it is what turns "the plugin died" into a message
	// naming the panic that killed it.
	Diagnose func() string
}

// Options configure a host.
type Options struct {
	// Transport is the running plugin. Required.
	Transport Transport

	// Label names the plugin in errors and in the names of the extensions it
	// provides. It comes from the campaign file, so it is the name the person
	// reading the failure chose.
	Label string

	// Engine is the engine version reported in the handshake, so a plugin can
	// refuse a build it does not support.
	Engine string

	// Seed is the campaign seed. A plugin that makes random choices must derive
	// them from this and nothing else, or the campaign stops replaying
	// (ASR-0008).
	Seed uint64

	// Config is the plugin's own settings from the campaign file, passed
	// through uninterpreted.
	Config map[string]string

	// CallTimeout bounds one exchange. A plugin that exceeds it is killed: the
	// protocol is synchronous, so a plugin that does not answer is not slow,
	// it is broken, and a fuzz loop must never wait on one indefinitely.
	CallTimeout time.Duration

	// HandshakeTimeout bounds the hello exchange, which is allowed to be slower
	// because a plugin may load a model or open a database at startup.
	HandshakeTimeout time.Duration

	// MaxFrameBytes bounds a frame in either direction. Zero uses the default.
	MaxFrameBytes int
}

// Default bounds for a call and a handshake.
const (
	DefaultCallTimeout      = 10 * time.Second
	DefaultHandshakeTimeout = 30 * time.Second
)

// Host is one plugin process, seen as the extensions it provides.
//
// Failure is contained here and nowhere else. Any protocol error, timeout, or
// death of the process puts the host into a permanently failed state: every
// later call returns the same error, the process is killed, and the campaign
// that asked for the plugin fails with a message naming it. A dying plugin
// never reaches the daemon and never touches a sibling campaign (ADR-0010).
type Host struct {
	opts Options
	conn *Conn

	// failed holds the first error, which is the informative one: a timeout
	// followed by the end-of-file that killing the process produces should be
	// reported as the timeout.
	failed atomic.Pointer[hostErr]

	mu   sync.Mutex // serialises calls; the protocol has one in flight
	next uint64
	bye  bool

	name     string
	version  string
	provides Provides

	// pending is the judgement waiting to be settled, per extension. It is sent
	// with that extension's next call rather than in a round trip of its own.
	pending map[string]*bool

	// calls and inside are the extension-overhead accounting ADR-0010 requires
	// be visible: a slow plugin should be diagnosable from the campaign's own
	// metrics rather than by guessing.
	calls  atomic.Int64
	inside atomic.Int64
}

// hostErr wraps the sticky failure so it can be stored atomically.
type hostErr struct{ err error }

// ErrFailed reports that a plugin is no longer usable. Every error a failed
// host returns wraps it, so a caller can distinguish "this plugin is gone" from
// "this plugin said no".
var ErrFailed = errors.New("plugin: the plugin failed")

// Dial performs the handshake and returns a usable host.
//
// The version check is the whole reason the handshake exists. A plugin built
// against a different protocol is refused here, with both versions named,
// rather than misreading a field later.
func Dial(opts Options) (*Host, error) {
	if opts.Transport.Stdin == nil || opts.Transport.Stdout == nil {
		return nil, errors.New("plugin: the transport has no pipes")
	}
	if opts.Label == "" {
		opts.Label = "plugin"
	}
	if opts.CallTimeout <= 0 {
		opts.CallTimeout = DefaultCallTimeout
	}
	if opts.HandshakeTimeout <= 0 {
		opts.HandshakeTimeout = DefaultHandshakeTimeout
	}

	h := &Host{opts: opts, conn: NewConn(opts.Transport.Stdout, opts.Transport.Stdin), pending: map[string]*bool{}}
	h.conn.SetMaxFrame(opts.MaxFrameBytes)

	req := &Request{
		Op:       OpHello,
		Protocol: ProtocolVersion,
		Engine:   opts.Engine,
		Seed:     opts.Seed,
		Config:   opts.Config,
	}
	var resp Response
	if err := h.exchange(req, &resp, opts.HandshakeTimeout); err != nil {
		return nil, err
	}
	if resp.Protocol != ProtocolVersion {
		err := fmt.Errorf("plugin %s: it speaks protocol %d and this build speaks %d; "+
			"rebuild the plugin against this release", opts.Label, resp.Protocol, ProtocolVersion)
		h.fail(err)
		return nil, err
	}
	h.name, h.version, h.provides = resp.Name, resp.Version, resp.Provides
	return h, nil
}

// Label, Name and Version identify the plugin: the label a campaign gave it,
// and the name and version it gave itself.
func (h *Host) Label() string   { return h.opts.Label }
func (h *Host) Name() string    { return h.name }
func (h *Host) Version() string { return h.version }

// Provides is what the plugin declared in the handshake.
func (h *Host) Provides() Provides { return h.provides }

// Calls and Inside report how many times the plugin was called and how long was
// spent waiting for it, which is the extension-overhead metric ADR-0010 makes
// first class.
func (h *Host) Calls() int64          { return h.calls.Load() }
func (h *Host) Inside() time.Duration { return time.Duration(h.inside.Load()) }

// Err returns the failure that took this plugin out of service, or nil.
//
// It is an atomic load, so the engine can check it once per iteration without
// paying for a lock. That is what makes a plugin mutator's silent failure
// impossible: Mutate cannot return an error, so the campaign asks here.
func (h *Host) Err() error {
	if e := h.failed.Load(); e != nil {
		return e.err
	}
	return nil
}

// fail records the first failure and kills the process.
func (h *Host) fail(err error) error {
	if err == nil {
		return nil
	}
	if !errors.Is(err, ErrFailed) {
		err = fmt.Errorf("%w: %s: %w", ErrFailed, h.opts.Label, err)
	}
	if h.failed.CompareAndSwap(nil, &hostErr{err: err}) {
		if k := h.opts.Transport.Kill; k != nil {
			k()
		}
	}
	return h.Err()
}

// describe adds whatever the plugin said on its standard error, which is
// usually the only place a crashing plugin explains itself.
func (h *Host) describe(err error) error {
	if h.opts.Transport.Diagnose == nil {
		return err
	}
	said := strings.TrimSpace(h.opts.Transport.Diagnose())
	if said == "" {
		return err
	}
	if len(said) > diagnosticBytes {
		said = "..." + said[len(said)-diagnosticBytes:]
	}
	return fmt.Errorf("%w; it said: %s", err, said)
}

// diagnosticBytes bounds how much of a plugin's standard error is quoted back.
// Enough for a stack trace's top frames, not enough to bury the error.
const diagnosticBytes = 4 << 10

// exchange sends one request and reads its response, under a deadline.
//
// The deadline is enforced by killing the process rather than by a read
// deadline, because the transport is an io.Reader and may not have one — and
// because killing is the right answer anyway. A plugin that has stopped
// answering is not going to start.
func (h *Host) exchange(req *Request, resp *Response, timeout time.Duration) error {
	if err := h.Err(); err != nil {
		return err
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	h.next++
	req.ID = h.next

	start := time.Now()
	defer func() {
		h.calls.Add(1)
		h.inside.Add(int64(time.Since(start)))
	}()

	timer := time.AfterFunc(timeout, func() {
		h.fail(fmt.Errorf("it did not answer %s within %s", req.Op, timeout))
	})
	defer timer.Stop()

	if err := h.conn.Send(req); err != nil {
		return h.fail(h.describe(err))
	}
	if err := h.conn.Receive(resp); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			err = errors.New("it exited without answering")
		}
		return h.fail(h.describe(err))
	}
	if resp.ID != req.ID {
		return h.fail(fmt.Errorf("it answered request %d with a reply to %d", req.ID, resp.ID))
	}
	if resp.Error != "" {
		// The plugin refused the call. That is a campaign failure — a feedback
		// that cannot judge cannot be quietly skipped without changing what the
		// campaign measures — but it is the plugin's error, not a protocol
		// fault, so the process stays alive to be asked again.
		return fmt.Errorf("%s: %s", h.opts.Label, resp.Error)
	}
	return nil
}

// call is exchange with the pending commit for this extension folded in.
func (h *Host) call(req *Request, resp *Response) error {
	h.mu.Lock()
	if keep, ok := h.pending[req.Name]; ok {
		req.Keep = keep
		delete(h.pending, req.Name)
	}
	h.mu.Unlock()
	return h.exchange(req, resp, h.opts.CallTimeout)
}

// settle records how the engine resolved the last judgement. It is sent with
// the next call to the same extension, or flushed by Close.
func (h *Host) settle(name string, keep bool) {
	if h.Err() != nil {
		return
	}
	h.mu.Lock()
	h.pending[name] = &keep
	h.mu.Unlock()
}

// flush sends any commit still owed, so a plugin that persists what it learned
// is not cheated of the last one.
func (h *Host) flush() {
	h.mu.Lock()
	owed := make(map[string]*bool, len(h.pending))
	for k, v := range h.pending {
		owed[k] = v
	}
	clear(h.pending)
	h.mu.Unlock()

	for name, keep := range owed {
		var resp Response
		h.exchange(&Request{Op: OpCommit, Name: name, Keep: keep}, &resp, h.opts.CallTimeout)
	}
}

// Close settles what is owed, asks the plugin to exit, and kills it if it does
// not. It is safe to call on a failed host and safe to call twice.
func (h *Host) Close() error {
	h.mu.Lock()
	already := h.bye
	h.bye = true
	h.mu.Unlock()
	if already {
		return nil
	}

	// Whatever had already gone wrong is what Close reports. A failure that
	// happens *during* the shutdown is not the campaign's failure: the pipes
	// are being torn down, and "write: file already closed" from the goodbye
	// exchange would turn every clean stop into a reported error.
	failed := h.Err()
	if failed == nil {
		h.flush()
		var resp Response
		h.exchange(&Request{Op: OpBye}, &resp, h.opts.CallTimeout)
	}
	if h.opts.Transport.Stdin != nil {
		h.opts.Transport.Stdin.Close()
	}
	if k := h.opts.Transport.Kill; k != nil {
		k()
	}
	return failed
}
