package daemon

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rom/Xfuzz/pkg/executor"
)

// WorkerSpec describes one worker process to start.
type WorkerSpec struct {
	// ID is the worker's index within the campaign. It is also what derives its
	// RNG streams, so it must be stable across a restart: a worker that comes
	// back with a different id is a different worker exploring a different
	// sequence, and the campaign is no longer reproducible (ASR-0008).
	ID int

	// Binary is the worker executable.
	Binary string

	// Args are the arguments after the program name.
	Args []string

	// Env is the worker's environment.
	Env []string

	// Dir is the worker's working directory.
	Dir string

	// Strategy is the ensemble strategy assigned to this worker.
	Strategy string
}

// WorkerState is where a supervised worker is in its life.
type WorkerState string

// Worker states.
const (
	WorkerStarting WorkerState = "starting"
	WorkerRunning  WorkerState = "running"
	WorkerStopping WorkerState = "stopping"
	WorkerStopped  WorkerState = "stopped"
	WorkerFailed   WorkerState = "failed"
)

// WorkerStatus is what the supervisor knows about a worker.
type WorkerStatus struct {
	ID       int         `json:"id"`
	State    WorkerState `json:"state"`
	Pid      int         `json:"pid,omitempty"`
	Strategy string      `json:"strategy,omitempty"`
	Restarts int         `json:"restarts"`
	Started  time.Time   `json:"started,omitempty"`
	LastSeen time.Time   `json:"last_seen,omitempty"`
	Err      string      `json:"error,omitempty"`
}

// Healthy reports whether the worker is running and has been heard from
// recently.
func (s WorkerStatus) Healthy(silence time.Duration) bool {
	if s.State != WorkerRunning {
		return false
	}
	return s.LastSeen.IsZero() || time.Since(s.LastSeen) < silence
}

// Spawner is the process-creation boundary, as internal/safety implements it.
//
// Declared here rather than imported so that this package depends on the
// capability and not on the safety layer's concrete type — which is what lets a
// test supervise a fake worker without a process (ARCHITECTURE section 2 keeps
// the real one the only path to exec).
type Spawner interface {
	Start(ctx context.Context, spec executor.ProcSpec) (executor.Handle, error)
}

// Supervisor keeps a campaign's workers running.
//
// Restart is routine rather than exceptional (ADR-0015): a worker that dies
// because its target corrupted memory has done exactly what running targets in
// separate processes is for, and the campaign should not notice beyond a line in
// the log. What restart must not do is hide a worker that cannot start at all,
// so a worker that fails repeatedly in quick succession is given up on and
// reported.
type Supervisor struct {
	spawner Spawner
	bus     *Bus
	name    string

	// OnMessage receives every message a worker sends. It runs on the
	// supervisor's reader goroutine, so it must not block for long.
	OnMessage func(w int, m *Message)

	// MaxRestarts is how many times a worker may be restarted before the
	// supervisor gives up on it. Zero means DefaultMaxRestarts.
	MaxRestarts int

	// RestartWindow is the period over which restarts are counted. A worker
	// that has run for longer than this has its count forgiven, so a campaign
	// running for a week is not eventually killed by a slow accumulation of
	// unrelated crashes.
	RestartWindow time.Duration

	// Backoff is the delay before the first restart; it doubles up to
	// MaxBackoff. Restarting instantly in a loop is how a broken target turns
	// into a busy machine that never says why.
	Backoff    time.Duration
	MaxBackoff time.Duration

	mu      sync.Mutex
	workers map[int]*worker
	stopped bool
}

// Supervision defaults.
const (
	DefaultMaxRestarts   = 5
	DefaultRestartWindow = 5 * time.Minute
	DefaultBackoff       = 250 * time.Millisecond
	DefaultMaxBackoff    = 30 * time.Second

	// workerSilence is how long a running worker may say nothing before it is
	// counted unhealthy. Workers report metrics on a timer well inside this.
	workerSilence = 60 * time.Second
)

type worker struct {
	spec   WorkerSpec
	status WorkerStatus

	handle executor.Handle
	enc    *Encoder

	// outbox decouples the campaign's control loop from the worker's pipe.
	//
	// Writing straight to the pipe looks harmless and is not: a worker that
	// stops reading — busy, wedged, or merely slow — fills the pipe buffer, and
	// then the goroutine that wrote to it blocks. That goroutine is the one
	// driving termination checks, checkpoints and corpus sync for *every*
	// worker, so one unresponsive worker stalls the whole campaign. The bus
	// already refuses to let a slow subscriber back-pressure the engine; this
	// is the same rule applied to the other direction.
	outbox   chan *Message
	dropped  atomic.Uint64
	writerWG sync.WaitGroup

	cancel   context.CancelFunc
	done     chan struct{}
	restarts int
	stopping atomic.Bool
}

// NewSupervisor returns a supervisor for one campaign's workers.
func NewSupervisor(name string, spawner Spawner, bus *Bus) *Supervisor {
	return &Supervisor{
		spawner:       spawner,
		bus:           bus,
		name:          name,
		workers:       map[int]*worker{},
		MaxRestarts:   DefaultMaxRestarts,
		RestartWindow: DefaultRestartWindow,
		Backoff:       DefaultBackoff,
		MaxBackoff:    DefaultMaxBackoff,
	}
}

// Start launches a worker and supervises it until ctx is cancelled or Stop is
// called.
func (s *Supervisor) Start(ctx context.Context, spec WorkerSpec) error {
	s.mu.Lock()
	if s.stopped {
		s.mu.Unlock()
		return errors.New("daemon: the supervisor has been stopped")
	}
	if _, dup := s.workers[spec.ID]; dup {
		s.mu.Unlock()
		return fmt.Errorf("daemon: worker %d is already supervised", spec.ID)
	}
	w := &worker{
		spec:   spec,
		status: WorkerStatus{ID: spec.ID, State: WorkerStarting, Strategy: spec.Strategy},
		outbox: make(chan *Message, outboxDepth),
		done:   make(chan struct{}),
	}
	s.workers[spec.ID] = w
	s.mu.Unlock()

	runCtx, cancel := context.WithCancel(ctx)
	w.cancel = cancel
	go s.supervise(runCtx, w)
	return nil
}

// supervise runs one worker, restarting it as needed.
func (s *Supervisor) supervise(ctx context.Context, w *worker) {
	defer close(w.done)

	backoff := s.Backoff
	for {
		started := time.Now()
		err := s.runOnce(ctx, w)

		if ctx.Err() != nil || w.stopping.Load() {
			s.setState(w, WorkerStopped, nil)
			return
		}

		// A worker that ran for a decent while and then died is a normal
		// casualty; one that dies immediately is broken and restarting it is
		// just a way of not saying so.
		if time.Since(started) > s.RestartWindow {
			w.restarts = 0
			backoff = s.Backoff
		}
		w.restarts++

		s.mu.Lock()
		w.status.Restarts = w.restarts
		s.mu.Unlock()

		if w.restarts > s.MaxRestarts {
			s.setState(w, WorkerFailed, fmt.Errorf(
				"worker %d failed %d times in %s and will not be restarted: %w",
				w.spec.ID, w.restarts, s.RestartWindow, err))
			return
		}

		s.publish(EventWorker, w.spec.ID, map[string]any{
			"state":    "restarting",
			"restarts": w.restarts,
			"backoff":  backoff.String(),
			"error":    errText(err),
		})

		select {
		case <-time.After(backoff):
		case <-ctx.Done():
			s.setState(w, WorkerStopped, nil)
			return
		}
		if backoff *= 2; backoff > s.MaxBackoff {
			backoff = s.MaxBackoff
		}
	}
}

// runOnce starts the process and pumps its messages until it exits.
func (s *Supervisor) runOnce(ctx context.Context, w *worker) error {
	handle, err := s.spawner.Start(ctx, executor.ProcSpec{
		Path: w.spec.Binary,
		Args: append([]string{w.spec.Binary}, w.spec.Args...),
		Env:  w.spec.Env,
		Dir:  w.spec.Dir,
		// A worker's own output goes to the daemon's, which matters for the one
		// case the protocol cannot cover: a worker that dies before it can send
		// a message. Discarding it means "worker 0 exited with status 1" is the
		// entire diagnosis of a campaign that never ran.
		CaptureOutput: true,
	})
	if err != nil {
		return fmt.Errorf("starting worker %d: %w", w.spec.ID, err)
	}

	s.mu.Lock()
	w.handle = handle
	w.enc = NewEncoder(handle.Control())
	w.status.State = WorkerRunning
	w.status.Pid = handle.Pid()
	w.status.Started = time.Now()
	w.status.Err = ""
	s.mu.Unlock()

	s.publish(EventWorker, w.spec.ID, map[string]any{
		"state": "running", "pid": handle.Pid(), "strategy": w.spec.Strategy,
	})

	// Reading a pipe is not interruptible by a context, so cancellation has to
	// close the pipe underneath the reader. Without this a worker that ignores
	// the stop request wedges Stop forever — and "the daemon will not shut
	// down" is the failure that turns a tidy exit into a kill -9 and a lost
	// checkpoint.
	pumpDone := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = handle.Kill()
		case <-pumpDone:
		}
	}()

	// One writer goroutine per worker owns the control pipe, so a blocked write
	// blocks nothing but itself.
	writerDone := make(chan struct{})
	w.writerWG.Add(1)
	go func() {
		defer w.writerWG.Done()
		w.writeLoop(writerDone)
	}()

	readErr := s.pump(w, handle)
	close(pumpDone)
	close(writerDone)
	w.writerWG.Wait()

	// A short grace period before killing, because a worker on its way out has
	// shutdown of its own to do and killing it takes that away: closing its
	// store, and releasing the resources its executor holds — a session-tier
	// worker manages a long-lived server process, and every target runs in its
	// own process group so that killing the worker does not reach it.
	//
	// Bounded, because a supervisor that waits on a wedged worker is a campaign
	// that will not stop. The worker has already closed its status pipe here,
	// so it is on its way out and the wait is short in every ordinary case.
	res, _ := waitOrKill(handle, workerExitGrace)

	s.mu.Lock()
	w.handle = nil
	w.enc = nil
	w.status.Pid = 0
	s.mu.Unlock()

	if readErr != nil && !errors.Is(readErr, io.EOF) {
		return readErr
	}
	if res.Signal != 0 {
		return fmt.Errorf("worker %d died on signal %d", w.spec.ID, res.Signal)
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("worker %d exited with status %d", w.spec.ID, res.ExitCode)
	}
	return nil
}

// pump reads the worker's messages until the stream ends.
func (s *Supervisor) pump(w *worker, handle executor.Handle) error {
	dec := NewDecoder(handle.Status())
	for {
		m, err := dec.Decode()
		if err != nil {
			return err
		}
		m.Worker = w.spec.ID

		s.mu.Lock()
		w.status.LastSeen = time.Now()
		if m.Type == MsgReady && m.Ready != nil && m.Ready.Strategy != "" {
			w.status.Strategy = m.Ready.Strategy
		}
		s.mu.Unlock()

		if s.OnMessage != nil {
			s.OnMessage(w.spec.ID, m)
		}
		if m.Type == MsgStopped {
			// The worker finished its own budget. Returning EOF here rather
			// than waiting for the pipe to close means the campaign learns it
			// stopped now rather than whenever the process gets round to
			// exiting.
			w.stopping.Store(true)
			return io.EOF
		}
	}
}

// outboxDepth is how many commands may be queued for one worker.
//
// Small on purpose. A deep queue does not stop a worker falling behind; it only
// delays the moment anyone notices, and by then the commands being delivered
// are answers to questions the campaign has stopped asking.
const outboxDepth = 64

// Send queues a command for one worker. It never blocks.
//
// A command that does not fit is dropped and counted. Every command here
// tolerates that: corpus sync is a best-effort optimisation and the next round
// carries the same entries, a checkpoint request repeats on its own timer, and
// a stop request that a wedged worker never reads is followed by a kill.
func (s *Supervisor) Send(id int, m *Message) error {
	s.mu.Lock()
	w, ok := s.workers[id]
	s.mu.Unlock()
	if !ok {
		return fmt.Errorf("daemon: no worker %d", id)
	}
	m.Worker = id

	select {
	case w.outbox <- m:
		return nil
	default:
		w.dropped.Add(1)
		return nil
	}
}

// writeLoop drains the outbox onto the control pipe until the worker ends.
func (w *worker) writeLoop(done <-chan struct{}) {
	for {
		select {
		case m := <-w.outbox:
			if enc := w.encoder(); enc != nil {
				// An error here means the worker has gone. The supervisor will
				// see the same thing on the read side and restart it; there is
				// nothing useful to do with the error twice.
				_ = enc.Encode(m)
			}
		case <-done:
			return
		}
	}
}

func (w *worker) encoder() *Encoder {
	// Read without the supervisor's lock: the encoder is set once when the
	// process starts and cleared once when it ends, both before and after this
	// goroutine exists.
	return w.enc
}

// Dropped returns how many commands could not be queued for a worker.
func (s *Supervisor) Dropped(id int) uint64 {
	s.mu.Lock()
	w, ok := s.workers[id]
	s.mu.Unlock()
	if !ok {
		return 0
	}
	return w.dropped.Load()
}

// Broadcast delivers a command to every worker except one.
//
// The exception is how corpus sync avoids echoing an entry back to the worker
// that found it, which would double-count its provenance and waste a round trip.
func (s *Supervisor) Broadcast(m *Message, except int) {
	s.mu.Lock()
	ids := make([]int, 0, len(s.workers))
	for id := range s.workers {
		if id != except {
			ids = append(ids, id)
		}
	}
	s.mu.Unlock()

	for _, id := range ids {
		clone := *m
		_ = s.Send(id, &clone)
	}
}

// Status returns every worker's state.
func (s *Supervisor) Status() []WorkerStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]WorkerStatus, 0, len(s.workers))
	for _, w := range s.workers {
		out = append(out, w.status)
	}
	sortStatus(out)
	return out
}

// Healthy returns how many workers are running and reporting.
func (s *Supervisor) Healthy() int {
	n := 0
	for _, st := range s.Status() {
		if st.Healthy(workerSilence) {
			n++
		}
	}
	return n
}

// Stop asks every worker to finish and waits for them.
func (s *Supervisor) Stop(grace time.Duration) {
	s.mu.Lock()
	if s.stopped {
		s.mu.Unlock()
		return
	}
	s.stopped = true
	ws := make([]*worker, 0, len(s.workers))
	for _, w := range s.workers {
		ws = append(ws, w)
	}
	s.mu.Unlock()

	// Ask first. A worker given the chance to stop writes its checkpoint, and a
	// checkpoint written on the way out is the difference between losing the
	// last interval's work and losing none of it.
	for _, w := range ws {
		w.stopping.Store(true)
		_ = s.Send(w.spec.ID, &Message{Type: CmdStop})
	}

	// One deadline shared by every worker, expressed as a context rather than
	// a channel: a time.After channel fires once, so the first worker to wait
	// on it consumes the only tick and every worker after it waits forever.
	waitCtx, cancelWait := context.WithTimeout(context.Background(), grace)
	defer cancelWait()

	for _, w := range ws {
		select {
		case <-w.done:
		case <-waitCtx.Done():
		}
	}
	// Whatever is left did not take the hint. Cancelling closes its pipes,
	// which is what unblocks the reader; the worker's own process is killed
	// with it.
	for _, w := range ws {
		w.cancel()
		<-w.done
	}
}

func (s *Supervisor) setState(w *worker, state WorkerState, err error) {
	s.mu.Lock()
	w.status.State = state
	w.status.Pid = 0
	if err != nil {
		w.status.Err = err.Error()
	}
	s.mu.Unlock()

	data := map[string]any{"state": string(state)}
	if err != nil {
		data["error"] = err.Error()
	}
	s.publish(EventWorker, w.spec.ID, data)
}

func (s *Supervisor) publish(kind EventKind, worker int, data any) {
	if s.bus == nil {
		return
	}
	s.bus.Publish(Event{Kind: kind, Campaign: s.name, Worker: worker, Data: data})
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func sortStatus(s []WorkerStatus) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j].ID < s[j-1].ID; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

// workerExitGrace is how long a worker gets to finish its own shutdown after
// its status pipe closes. Long enough to kill a managed target and flush a
// checkpoint, short enough that a wedged worker does not hold up a campaign.
const workerExitGrace = 3 * time.Second

// waitOrKill waits for a process to exit, killing it if it takes too long.
func waitOrKill(h executor.Handle, d time.Duration) (executor.ProcResult, error) {
	type outcome struct {
		res executor.ProcResult
		err error
	}
	done := make(chan outcome, 1)
	go func() {
		res, err := h.Wait()
		done <- outcome{res, err}
	}()

	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case o := <-done:
		return o.res, o.err
	case <-timer.C:
	}
	_ = h.Kill()
	o := <-done
	return o.res, o.err
}
