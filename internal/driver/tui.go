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

	"github.com/rom/Xfuzz/internal/safety"
	"github.com/rom/Xfuzz/pkg/executor"
	"github.com/rom/Xfuzz/pkg/vt"
)

// TUIOptions describe the terminal program to drive.
type TUIOptions struct {
	// Path and Args are the target, with Args the complete argv as everywhere
	// else in the spawn boundary.
	Path string
	Args []string
	Env  []string
	Dir  string

	// Cols and Rows are the terminal's size.
	//
	// Fixed for the campaign unless a resize event changes it, because the size
	// is an input: a program that draws correctly at eighty columns and
	// misaligns at forty has a bug that only one of those finds.
	Cols, Rows int

	// StartTimeout bounds how long the program gets to draw its first screen.
	StartTimeout time.Duration

	// Settle is how long the program must be quiet before its screen counts as
	// drawn.
	Settle time.Duration

	// MaxOutputBytes caps how much a runaway program may write before the
	// driver stops feeding the emulator.
	//
	// A program stuck in a redraw loop produces megabytes a second, and every
	// byte of it is parsed. Without a cap the fuzzer spends its whole budget
	// emulating a terminal for a program that is not going to stop.
	MaxOutputBytes int64

	// Quarantine asks for the strongest isolation available.
	Quarantine bool
}

// Defaults for a terminal campaign.
const (
	DefaultStartTimeout   = 5 * time.Second
	DefaultSettle         = 50 * time.Millisecond
	DefaultMaxOutputBytes = 8 << 20

	// exitWait bounds how long the driver waits for a program whose terminal
	// has closed to actually be reaped. It is a bound on a race, not a policy:
	// the wait normally ends in microseconds.
	exitWait = 2 * time.Second
)

// TUI drives a terminal program: a pseudo-terminal, an emulator watching what
// the program draws, and a table turning named keys into the bytes a terminal
// sends.
//
// It implements executor.DriverBackend, so everything above it is the machine
// every other tier uses.
type TUI struct {
	spawn *safety.Spawner
	opts  TUIOptions

	mu   sync.Mutex
	cur  *session
	cols int
	rows int
}

// session is one run of the program. A fresh one per reset, so that a goroutine
// still draining a dying program cannot write into the next run's screen — which
// would show up as a state that no sequence produced and would never reproduce.
type session struct {
	pty  *safety.PTY
	done chan struct{}

	mu       sync.Mutex
	term     *vt.Terminal
	overflow bool
	readErr  error
}

// NewTUI returns a terminal driver backend.
func NewTUI(spawner *safety.Spawner, opts TUIOptions) *TUI {
	if opts.Cols <= 0 {
		opts.Cols = vt.DefaultCols
	}
	if opts.Rows <= 0 {
		opts.Rows = vt.DefaultRows
	}
	if opts.StartTimeout <= 0 {
		opts.StartTimeout = DefaultStartTimeout
	}
	if opts.Settle <= 0 {
		opts.Settle = DefaultSettle
	}
	if opts.MaxOutputBytes <= 0 {
		opts.MaxOutputBytes = DefaultMaxOutputBytes
	}
	return &TUI{spawn: spawner, opts: opts, cols: opts.Cols, rows: opts.Rows}
}

// Name implements executor.DriverBackend.
func (d *TUI) Name() string { return "tui" }

// Supported reports whether this host can run a terminal campaign at all.
func (d *TUI) Supported() bool { return safety.PTYSupported() }

// Start launches the program and waits for its first screen.
func (d *TUI) Start(ctx context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.cur != nil {
		return nil
	}
	return d.startLocked(ctx)
}

func (d *TUI) startLocked(ctx context.Context) error {
	spec := executor.ProcSpec{
		Path: d.opts.Path,
		Args: d.opts.Args,
		Env:  terminalEnv(d.opts.Env, d.cols, d.rows),
		Dir:  d.opts.Dir,
		// No Timeout: the tier bounds a sequence, and a terminal program is
		// meant to keep running between events.
		Quarantine: d.opts.Quarantine,
	}
	pty, err := d.spawn.StartPTY(ctx, spec, d.cols, d.rows)
	if err != nil {
		return err
	}
	s := &session{pty: pty, done: make(chan struct{}), term: vt.New(d.cols, d.rows)}
	go s.drain(d.opts.MaxOutputBytes)
	d.cur = s
	d.settle(ctx, s, d.opts.StartTimeout)
	return nil
}

// terminalEnv makes sure the program knows it is on a terminal and what kind.
//
// TERM decides whether a program draws at all: unset, a curses application
// refuses to start, and set to something the terminfo database does not have it
// falls back to a mode nobody runs it in. The caller's own value wins, because
// running the target under the terminal its users have is the point.
func terminalEnv(env []string, cols, rows int) []string {
	out := append([]string(nil), env...)
	if out == nil {
		out = []string{}
	}
	for _, kv := range [][2]string{
		{"TERM", "xterm-256color"},
		{"COLUMNS", fmt.Sprint(cols)},
		{"LINES", fmt.Sprint(rows)},
		// A program whose output depends on the ambient locale is a program
		// whose screen differs between two hosts running the same campaign,
		// which is the reproducibility claim (ASR-0008) failing outside the
		// fuzzer.
		{"LC_ALL", "C.UTF-8"},
	} {
		if !hasEnv(out, kv[0]) {
			out = append(out, kv[0]+"="+kv[1])
		}
	}
	return out
}

func hasEnv(env []string, name string) bool {
	p := name + "="
	for _, kv := range env {
		if strings.HasPrefix(kv, p) {
			return true
		}
	}
	return false
}

// drain reads the terminal into the emulator until the program ends.
func (s *session) drain(limit int64) {
	defer close(s.done)
	buf := make([]byte, 32*1024)
	var total int64
	for {
		n, err := s.pty.Read(buf)
		if n > 0 {
			total += int64(n)
			s.mu.Lock()
			if total <= limit {
				s.term.Write(buf[:n])
			} else if !s.overflow {
				s.overflow = true
			}
			s.mu.Unlock()
		}
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, os.ErrClosed) {
				s.mu.Lock()
				s.readErr = err
				s.mu.Unlock()
			}
			return
		}
	}
}

// written returns how many bytes the emulator has consumed, which is how the
// driver tells "the program is drawing" from "the program has stopped".
func (s *session) written() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.term.Written()
}

// settle waits until the program has been quiet for one settle interval.
//
// This is the tier's throughput and it cannot be avoided: a terminal program
// redraws asynchronously, so reading the screen immediately after a keystroke
// reads the screen as it was. Waiting a fixed interval would be simpler and
// slower — most events produce a redraw in a millisecond and the occasional one
// takes a hundred — so the driver waits for quiet instead, up to a bound.
//
// It is also, unavoidably, a wall-clock input to what the campaign observes.
// ASR-0008 forbids wall-clock inputs to fuzzing *decisions*; this is not one,
// but it does mean two runs of the same sequence can observe different screens,
// which is why the tier declares itself non-deterministic and why the triage
// layer verifies a T7 finding by replaying it rather than by trusting it.
func (d *TUI) settle(ctx context.Context, s *session, bound time.Duration) {
	deadline := time.Now().Add(bound)
	last := s.written()
	quiet := time.NewTimer(d.opts.Settle)
	defer quiet.Stop()
	for {
		select {
		case <-quiet.C:
			now := s.written()
			if now == last || time.Now().After(deadline) {
				return
			}
			last = now
			quiet.Reset(d.opts.Settle)
		case <-s.done:
			// The terminal reported end-of-file, so the program's side of it is
			// closed. Wait for the process itself to be reaped before
			// returning: the drain and the wait are separate goroutines and the
			// terminal always notices first, so a caller asking "is it still
			// running?" the instant this returns would be told yes about a
			// program that has already died — and a crash would be recorded as
			// a clean run.
			select {
			case <-s.pty.Exited():
			case <-ctx.Done():
			case <-time.After(exitWait):
			}
			return
		case <-ctx.Done():
			return
		}
	}
}

// Send delivers one event.
func (d *TUI) Send(ctx context.Context, e executor.Event) error {
	d.mu.Lock()
	s := d.cur
	d.mu.Unlock()
	if s == nil {
		return fmt.Errorf("driver tui: not started")
	}

	switch e.Kind {
	case executor.EventWait:
		// The tier's settle already waits; a wait event only asks for longer,
		// and the tier is what knows how long.
		return nil

	case executor.EventResize:
		return d.resize(s, e.X, e.Y)

	case executor.EventText:
		if e.Text == "" {
			return nil
		}
		return d.write(s, []byte(e.Text))

	case executor.EventKey:
		s.mu.Lock()
		app := s.term.AppCursor()
		s.mu.Unlock()
		b, err := EncodeKey(e.Text, app)
		if err != nil {
			// Skipped rather than reported. A hand-written seed with a typo in
			// a key name loses one keystroke, which the tier counts; a mutated
			// sequence contains an unnameable key almost always, and treating
			// that as a harness failure ends the campaign on its first
			// interesting mutation.
			return fmt.Errorf("driver tui: %w: %v", executor.ErrSkipEvent, err)
		}
		return d.write(s, b)

	case executor.EventClick:
		s.mu.Lock()
		mode, enc := s.term.Mouse()
		s.mu.Unlock()
		b := EncodeMouse(mode, enc, e.X, e.Y)
		if b == nil {
			// The program never asked for mouse reporting. Sending nothing is
			// the honest answer; sending a report would be typing escape
			// sequences at a program that reads them as keys.
			return nil
		}
		return d.write(s, b)
	}
	return nil
}

func (d *TUI) write(s *session, b []byte) error {
	if !s.pty.Alive() {
		// Writing to a dead program's terminal is not an error the campaign
		// should hear about: the sequence is over and the tier reads the result.
		return nil
	}
	if _, err := s.pty.Write(b); err != nil {
		if errors.Is(err, os.ErrClosed) || errors.Is(err, io.EOF) {
			return nil
		}
		return fmt.Errorf("driver tui: typing: %w", err)
	}
	return nil
}

func (d *TUI) resize(s *session, cols, rows int) error {
	if cols <= 0 || rows <= 0 {
		return nil
	}
	d.mu.Lock()
	d.cols, d.rows = cols, rows
	d.mu.Unlock()

	// The emulator first, then the kernel. The ioctl sends SIGWINCH, and a
	// program that redraws on the signal would otherwise draw its new screen
	// into an emulator still holding the old dimensions.
	s.mu.Lock()
	s.term.Resize(cols, rows)
	s.mu.Unlock()
	if err := s.pty.Resize(cols, rows); err != nil {
		return fmt.Errorf("driver tui: %w", err)
	}
	return nil
}

// Settle implements executor.Settler: it returns once the program has been quiet
// for one settle interval, or once ctx is done.
func (d *TUI) Settle(ctx context.Context) {
	s := d.session()
	if s == nil {
		return
	}
	d.settle(ctx, s, d.opts.StartTimeout)
}

// State returns the screen as text.
//
// Text rather than the cell grid: what a campaign does with a UI state is hash
// it and ask whether it has seen it, and what a person does with a T7 finding is
// read it. Attributes distinguish states that look identical, and a campaign
// that treated a colour change as new coverage would spend itself on a progress
// bar.
func (d *TUI) State() []byte {
	s := d.session()
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return []byte(s.term.Text())
}

// Screen returns the full grid, for a caller that wants more than the text.
func (d *TUI) Screen() *vt.Screen {
	s := d.session()
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.term.Screen()
}

// Bells returns how many times the program rang the terminal bell, which is one
// of the few things a TUI does that leaves no mark on the screen and is worth
// noticing: a program that starts beeping has usually hit an error path.
func (d *TUI) Bells() uint64 {
	s := d.session()
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.term.Bells()
}

// Overflowed reports whether the program wrote more than the driver was willing
// to emulate, which is a finding in itself: a redraw loop.
func (d *TUI) Overflowed() bool {
	s := d.session()
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.overflow
}

// Alive implements executor.DriverBackend.
func (d *TUI) Alive() bool {
	s := d.session()
	return s != nil && s.pty.Alive()
}

// Result implements executor.DriverBackend.
func (d *TUI) Result() executor.ProcResult {
	s := d.session()
	if s == nil {
		return executor.ProcResult{}
	}
	res := s.pty.Result()
	// The last screen is the diagnostic. A terminal program that dies leaves
	// nothing on standard error, because standard error was the terminal.
	s.mu.Lock()
	res.Stderr = []byte(s.term.Text())
	s.mu.Unlock()
	return res
}

// Reset restarts the program.
//
// A restart rather than anything cheaper, because there is nothing cheaper: a
// terminal program's state is its own memory, and the only interface for
// clearing it is exit. This is the dominant cost of a T7 campaign (ADR-0013),
// and it is why the tier runs at a rate five orders of magnitude below a parser.
func (d *TUI) Reset() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.cur != nil {
		if err := d.cur.pty.Close(); err != nil {
			return fmt.Errorf("driver tui: stopping the previous run: %w", err)
		}
		<-d.cur.done
		d.cur = nil
	}
	return d.startLocked(context.Background())
}

// Close stops the program and releases the terminal.
func (d *TUI) Close() error {
	d.mu.Lock()
	s := d.cur
	d.cur = nil
	d.mu.Unlock()
	if s == nil {
		return nil
	}
	err := s.pty.Close()
	<-s.done
	return err
}

func (d *TUI) session() *session {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.cur
}
