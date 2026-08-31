package driver

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/rom/Xfuzz/internal/atspi"
	"github.com/rom/Xfuzz/internal/safety"
	"github.com/rom/Xfuzz/pkg/executor"
)

// The desktop backend: an application driven through its accessibility tree.
//
// ADR-0013 names three of these — AT-SPI on Linux, UI Automation on Windows,
// the accessibility API on macOS — and this is the first. What they have in
// common is the idea: the application already publishes what its interface
// contains, because assistive technology needs it, and that publication is a
// far better observable than a screenshot. What they do not have in common is a
// single line of mechanism, which is why each is a backend rather than a
// parameter.
//
// The tree is the state and the keystroke is the input, so everything above
// this file is the same machine the terminal and web backends run under: the
// same corpus, the same sequence operators, the same state model, the same
// oracles. The one thing this backend cannot do is hold a modifier down —
// AT-SPI's synthesis presses a keysym and releases it — and that is reported as
// a skipped event rather than approximated.

// GUIOptions describe the application to drive.
type GUIOptions struct {
	// Path and Args are the program, with Args the complete argv as everywhere
	// else in the spawn boundary.
	Path string
	Args []string
	Env  []string
	Dir  string

	// StartTimeout bounds how long the application gets to appear on the
	// accessibility bus. It is longer than a process start: a toolkit registers
	// its tree after it has built its first window.
	StartTimeout time.Duration

	// Settle is how long the interface must be quiet before its tree is read.
	Settle time.Duration

	// MaxNodes and MaxDepth bound one snapshot. An application with a large
	// list in it has thousands of accessible objects, and reading them all
	// costs a D-Bus round trip each — which would make the state read, rather
	// than the program, the campaign's throughput.
	MaxNodes int
	MaxDepth int
}

// Defaults for a desktop campaign.
const (
	DefaultGUIStartTimeout = 20 * time.Second
	DefaultGUISettle       = 150 * time.Millisecond
	DefaultGUIMaxNodes     = 400
	DefaultGUIMaxDepth     = 12
)

// GUI drives a desktop application over AT-SPI.
type GUI struct {
	spawn *safety.Spawner
	opts  GUIOptions

	// done is closed when the backend is closed, so a restart in flight stops
	// waiting rather than holding the worker open for its start timeout.
	done chan struct{}
	once sync.Once

	mu  sync.Mutex
	cur *guiSession
}

// guiSession is one run of the application.
type guiSession struct {
	proc   executor.Handle
	conn   *atspi.Conn
	app    atspi.Ref
	cancel context.CancelFunc

	// tail keeps the end of what the application wrote to standard error.
	//
	// It is where a desktop application's failure actually lands. A toolkit
	// catches an exception in a signal handler, prints it, and carries on: the
	// process does not die, the exit status is zero, and nothing about the
	// widget tree says anything went wrong. Without this the campaign's only
	// evidence would be a screen that looks fine.
	tail *tail

	mu     sync.Mutex
	exit   executor.ProcResult
	exited bool
}

// NewGUI returns a desktop driver backend.
func NewGUI(spawner *safety.Spawner, opts GUIOptions) *GUI {
	if opts.StartTimeout <= 0 {
		opts.StartTimeout = DefaultGUIStartTimeout
	}
	if opts.Settle <= 0 {
		opts.Settle = DefaultGUISettle
	}
	if opts.MaxNodes <= 0 {
		opts.MaxNodes = DefaultGUIMaxNodes
	}
	if opts.MaxDepth <= 0 {
		opts.MaxDepth = DefaultGUIMaxDepth
	}
	return &GUI{spawn: spawner, opts: opts, done: make(chan struct{})}
}

// Name implements executor.DriverBackend.
func (d *GUI) Name() string { return "gui-atspi" }

// Supported reports whether this host has an accessibility bus.
func (d *GUI) Supported() bool { return atspi.Available() }

// Start implements executor.DriverBackend.
func (d *GUI) Start(ctx context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.cur != nil {
		return nil
	}
	s, err := d.launch(ctx)
	if err != nil {
		return err
	}
	d.cur = s
	return nil
}

// launch starts the application and waits for its tree to appear.
func (d *GUI) launch(ctx context.Context) (*guiSession, error) {
	conn, err := atspi.Dial(ctx)
	if err != nil {
		return nil, err
	}

	args := d.opts.Args
	if len(args) == 0 {
		args = []string{d.opts.Path}
	}
	pr, pw, err := os.Pipe()
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("driver: creating the application's output pipe: %w", err)
	}

	// A context of its own, for the reason the web backend has one: the
	// spawner kills the process when the context it was given is done, and the
	// context that bounds *starting* is done the moment starting succeeded.
	procCtx, cancel := context.WithCancel(context.Background())
	proc, err := d.spawn.Start(procCtx, executor.ProcSpec{
		Path: d.opts.Path, Args: args, Dir: d.opts.Dir,
		// Plus the session variables, without which the application has no
		// display to draw on and no bus to publish its tree to — so the
		// campaign would start, the program would run, and the driver would
		// wait for a tree that never appears.
		Env:        WithSessionEnv(d.opts.Env),
		StderrFile: pw,
	})
	if err != nil {
		cancel()
		pr.Close()
		pw.Close()
		conn.Close()
		return nil, fmt.Errorf("driver: starting %s: %w", d.opts.Path, err)
	}
	// The child owns the write end now: holding it open here would stop the
	// pipe ever reporting end-of-file, so the reader would outlive the target.
	pw.Close()

	s := &guiSession{proc: proc, conn: conn, cancel: cancel, tail: newTail(stderrKeep)}
	go func() {
		io.Copy(s.tail, pr)
		pr.Close()
	}()
	app, err := d.await(ctx, s)
	if err != nil {
		s.stop()
		return nil, err
	}
	s.app = app
	go s.watch()
	return s, nil
}

// await waits for the application to publish its tree.
//
// Matched by process rather than by name: an application's own idea of its
// identity is a string it chose, two copies of the same program are
// indistinguishable by it, and a desktop has other programs on it. The
// connection's process identifier is exact.
func (d *GUI) await(ctx context.Context, s *guiSession) (atspi.Ref, error) {
	deadline := time.Now().Add(d.opts.StartTimeout)
	pid := s.proc.Pid()
	for {
		if app, ok := s.conn.FindApplication(pid); ok {
			return app, nil
		}
		if time.Now().After(deadline) {
			return atspi.Ref{}, fmt.Errorf("driver: %s did not publish an accessibility "+
				"tree within %s: it may have no interface yet, or the toolkit's "+
				"accessibility bridge may not be installed (GTK needs at-spi2-atk, Qt "+
				"needs the accessibility plugin)", d.opts.Path, d.opts.StartTimeout)
		}
		timer := time.NewTimer(50 * time.Millisecond)
		select {
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
			return atspi.Ref{}, ctx.Err()
		case <-d.done:
			timer.Stop()
			return atspi.Ref{}, errors.New("driver: the campaign stopped while the " +
				"application was starting")
		}
		timer.Stop()
	}
}

func (s *guiSession) watch() {
	res, _ := s.proc.Wait()
	s.mu.Lock()
	s.exit, s.exited = res, true
	s.mu.Unlock()
}

func (s *guiSession) stop() {
	if s.cancel != nil {
		s.cancel()
	}
	if s.proc != nil {
		_ = s.proc.Kill()
	}
	if s.conn != nil {
		s.conn.Close()
		s.conn = nil
	}
}

func (d *GUI) session() (*guiSession, error) {
	d.mu.Lock()
	s := d.cur
	d.mu.Unlock()
	if s == nil {
		return nil, errors.New("driver: the application was never started")
	}
	return s, nil
}

// Send implements executor.DriverBackend.
func (d *GUI) Send(ctx context.Context, e executor.Event) error {
	s, err := d.session()
	if err != nil {
		return err
	}
	switch e.Kind {
	case executor.EventKey:
		sym, kerr := GUIKeysym(e.Text)
		if kerr != nil {
			// A key this backend cannot press is a property of the input, not a
			// failure of the harness — which after two mutations is most of
			// what a corpus contains.
			return fmt.Errorf("%w: %v", executor.ErrSkipEvent, kerr)
		}
		return s.conn.PressKeysym(sym)

	case executor.EventText:
		if e.Text == "" {
			return nil
		}
		if !utf8.ValidString(e.Text) || strings.ContainsRune(e.Text, 0) {
			// A D-Bus string is valid UTF-8 and NUL-terminated, so neither an
			// invalid sequence nor an interior NUL can be carried at all — not
			// "is awkward to carry". A mutator produces both constantly, and
			// reporting one as a harness failure ends the campaign on an input
			// that is merely undeliverable.
			return fmt.Errorf("%w: the text is not a string D-Bus can carry "+
				"(it must be valid UTF-8 with no NUL)", executor.ErrSkipEvent)
		}
		return s.conn.TypeString(e.Text)

	case executor.EventClick:
		x, y := d.toScreen(s, e.X, e.Y)
		return s.conn.Click(x, y)

	case executor.EventWait:
		return nil

	case executor.EventResize:
		// A window manager resizes windows, and a campaign runs against a
		// desktop that may not have one. Refusing is better than pretending:
		// an event that silently does nothing is one the corpus keeps paying
		// for.
		return fmt.Errorf("%w: AT-SPI has no way to resize a window", executor.ErrSkipEvent)
	}
	return fmt.Errorf("%w: %v", executor.ErrSkipEvent, e)
}

// toScreen turns a window-relative point into the screen coordinate the
// pointer is moved to.
//
// Window-relative is the coordinate system a click event carries, and that is a
// decision rather than a detail. A recorded sequence has to mean the same thing
// the next time the campaign runs, and a window does not land in the same place
// twice — so a click stored in screen coordinates is a click that lands
// somewhere else, or on somebody else's window. It also puts a mutator's small
// numbers inside the application rather than in the corner of the desktop.
//
// The offset is the application's first window. Where there is none — the tree
// has not been built yet, or the application has no frame — the point is used
// as it stands, which is right for a desktop whose windows start at the origin
// and is the only answer available.
func (d *GUI) toScreen(s *guiSession, x, y int) (int32, int32) {
	fx, fy, ok := s.windowOrigin()
	if !ok {
		return int32(x), int32(y)
	}
	return fx + int32(x), fy + int32(y)
}

// windowOrigin returns where the application's first window is on screen.
func (s *guiSession) windowOrigin() (int32, int32, bool) {
	if !s.app.Valid() {
		return 0, 0, false
	}
	kids, err := s.conn.Children(s.app)
	if err != nil || len(kids) == 0 {
		return 0, 0, false
	}
	x, y, _, _, err := s.conn.Extents(kids[0])
	if err != nil {
		return 0, 0, false
	}
	return x, y, true
}

// State implements executor.DriverBackend.
func (d *GUI) State() []byte {
	s, err := d.session()
	if err != nil {
		return nil
	}
	if !s.app.Valid() {
		return nil
	}
	snap := s.conn.Snapshot(s.app, d.opts.MaxNodes, d.opts.MaxDepth)
	return []byte(snap)
}

// Alive implements executor.DriverBackend.
func (d *GUI) Alive() bool {
	s, err := d.session()
	if err != nil {
		return false
	}
	s.mu.Lock()
	exited := s.exited
	s.mu.Unlock()
	return !exited
}

// Result implements executor.DriverBackend.
func (d *GUI) Result() executor.ProcResult {
	s, err := d.session()
	if err != nil {
		return executor.ProcResult{}
	}
	s.mu.Lock()
	res := executor.ProcResult{}
	if s.exited {
		res = s.exit
	}
	s.mu.Unlock()
	// What the application said, which for a toolkit that caught an exception
	// is the only place it said anything.
	if said := s.tail.String(); said != "" {
		res.Stderr = []byte(said)
	}
	return res
}

// Reset implements executor.DriverBackend: a fresh application.
//
// The whole program, not a fresh window. A desktop application accumulates
// state everywhere — the widget tree, the toolkit's caches, whatever it wrote
// to its configuration — and there is no equivalent of a new browser tab.
// Restarting is the only reset a GUI has, and it is the dominant cost of the
// tier (ADR-0013).
func (d *GUI) Reset() error {
	ctx, cancel := closeCtx(d.done, d.opts.StartTimeout)
	defer cancel()
	return d.ResetWith(ctx)
}

// ResetWith implements executor.ContextResetter: the same restart, bounded by
// the sequence that asked for it, so a campaign being stopped does not wait out
// a start timeout for an application that is not coming back.
func (d *GUI) ResetWith(ctx context.Context) error {
	d.mu.Lock()
	old := d.cur
	d.cur = nil
	d.mu.Unlock()
	if old != nil {
		old.stop()
	}

	fresh, err := d.launch(ctx)
	if err != nil {
		return err
	}
	d.mu.Lock()
	d.cur = fresh
	d.mu.Unlock()
	return nil
}

// Close implements executor.DriverBackend.
func (d *GUI) Close() error {
	d.once.Do(func() { close(d.done) })
	d.mu.Lock()
	s := d.cur
	d.cur = nil
	d.mu.Unlock()
	if s != nil {
		s.stop()
	}
	return nil
}

// DesktopEnvironment reports what a desktop campaign needs from the daemon's
// own environment, and what is missing.
//
// A campaign that starts and then cannot find its application is the hardest
// failure here to diagnose, and it has two ordinary causes: no display, so the
// program never draws; and no session bus, so there is no accessibility bus to
// publish to. Both are in the environment the daemon was started with, and
// neither is something the campaign file can fix — so the doctor says it.
func DesktopEnvironment() (ok bool, detail string) {
	var missing []string
	if os.Getenv("DISPLAY") == "" && os.Getenv("WAYLAND_DISPLAY") == "" {
		missing = append(missing, "no DISPLAY or WAYLAND_DISPLAY: there is no screen to draw on")
	}
	if os.Getenv("DBUS_SESSION_BUS_ADDRESS") == "" {
		missing = append(missing, "no DBUS_SESSION_BUS_ADDRESS: there is no session bus, "+
			"so no accessibility bus to publish a tree on")
	}
	if len(missing) > 0 {
		return false, strings.Join(missing, "; ")
	}
	if !atspi.Available() {
		return false, "a session bus is present but at-spi is not answering on it: " +
			"install at-spi2-core and make sure accessibility is enabled"
	}
	return true, "desktop applications can be driven through their accessibility tree"
}
