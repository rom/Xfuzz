package daemon

import (
	"context"
	"errors"
	"io"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rom/Xfuzz/pkg/executor"
)

// fakeHandle is a worker process that exists only as a pair of pipes, so
// supervision can be tested without spawning anything.
type fakeHandle struct {
	control *os.File // daemon writes here, the fake worker reads
	status  *os.File // the fake worker writes here, the daemon reads

	workerIn  *os.File
	workerOut *os.File

	pid    int
	result executor.ProcResult

	killOnce sync.Once
	waited   chan struct{}
}

func newFakeHandle(t *testing.T, pid int, res executor.ProcResult) *fakeHandle {
	t.Helper()
	ctlR, ctlW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stR, stW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	h := &fakeHandle{
		control: ctlW, status: stR, workerIn: ctlR, workerOut: stW,
		pid: pid, result: res, waited: make(chan struct{}),
	}
	t.Cleanup(h.closeAll)
	return h
}

func (h *fakeHandle) closeAll() {
	h.control.Close()
	h.status.Close()
	h.workerIn.Close()
	h.workerOut.Close()
}

func (h *fakeHandle) Pid() int          { return h.pid }
func (h *fakeHandle) Control() *os.File { return h.control }
func (h *fakeHandle) Status() *os.File  { return h.status }
func (h *fakeHandle) Wait() (executor.ProcResult, error) {
	<-h.waited
	return h.result, nil
}
func (h *fakeHandle) Kill() error {
	h.killOnce.Do(func() {
		h.workerOut.Close()
		close(h.waited)
	})
	return nil
}

// exit ends the fake worker, as a process exiting would.
func (h *fakeHandle) exit() { h.Kill() }

// fakeSpawner hands out prepared handles.
//
// Assignment is by the worker id in the spec's arguments, not by call order:
// each worker is supervised on its own goroutine, so call order is whatever the
// scheduler decides and a test that depended on it would pass or fail by luck.
type fakeSpawner struct {
	mu      sync.Mutex
	handles []*fakeHandle
	next    int
	starts  atomic.Int32
	err     error
}

func (s *fakeSpawner) Start(_ context.Context, spec executor.ProcSpec) (executor.Handle, error) {
	s.starts.Add(1)
	if s.err != nil {
		return nil, s.err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	if id, ok := workerIDOf(spec.Args); ok && id < len(s.handles) {
		return s.handles[id], nil
	}
	if s.next >= len(s.handles) {
		return nil, errors.New("no handles left")
	}
	h := s.handles[s.next]
	s.next++
	return h, nil
}

func workerIDOf(args []string) (int, bool) {
	for i, a := range args {
		if a == "--worker" && i+1 < len(args) {
			n, err := strconv.Atoi(args[i+1])
			return n, err == nil
		}
	}
	return 0, false
}

func TestSupervisorPumpsMessages(t *testing.T) {
	h := newFakeHandle(t, 100, executor.ProcResult{})
	sp := &fakeSpawner{handles: []*fakeHandle{h}}
	bus := NewBus(0)
	sup := NewSupervisor("c", sp, bus)

	got := make(chan *Message, 8)
	sup.OnMessage = func(_ int, m *Message) { got <- m }

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := sup.Start(ctx, WorkerSpec{ID: 0, Binary: "/bin/true"}); err != nil {
		t.Fatal(err)
	}

	enc := NewEncoder(h.workerOut)
	if err := enc.Encode(&Message{Type: MsgReady, Ready: &ReadyInfo{Pid: 100, Executor: "forkserver"}}); err != nil {
		t.Fatal(err)
	}
	m := <-got
	if m.Type != MsgReady || m.Ready.Executor != "forkserver" {
		t.Fatalf("first message = %+v", m)
	}
	if m.Worker != 0 {
		t.Errorf("the message was not stamped with the worker id: %d", m.Worker)
	}

	waitFor(t, func() bool {
		st := sup.Status()
		return len(st) == 1 && st[0].State == WorkerRunning && st[0].Pid == 100
	}, "the worker never reached running")

	sup.Stop(time.Second)
}

func TestSupervisorDeliversCommandsToTheWorker(t *testing.T) {
	h := newFakeHandle(t, 101, executor.ProcResult{})
	sup := NewSupervisor("c", &fakeSpawner{handles: []*fakeHandle{h}}, NewBus(0))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := sup.Start(ctx, WorkerSpec{ID: 3, Binary: "/bin/true"}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return len(sup.Status()) == 1 && sup.Status()[0].State == WorkerRunning },
		"the worker never started")

	if err := sup.Send(3, &Message{Type: CmdSync, Entries: []CorpusEntry{{Digest: "ab", Payload: []byte("x")}}}); err != nil {
		t.Fatal(err)
	}

	dec := NewDecoder(h.workerIn)
	m, err := dec.Decode()
	if err != nil {
		t.Fatal(err)
	}
	if m.Type != CmdSync || len(m.Entries) != 1 || string(m.Entries[0].Payload) != "x" {
		t.Fatalf("the worker received %+v", m)
	}
	if m.Worker != 3 {
		t.Errorf("the command was not addressed to worker 3: %d", m.Worker)
	}
	cancel()
	h.exit()
}

func TestSupervisorRestartsACasualty(t *testing.T) {
	// A worker that dies because its target corrupted memory has done exactly
	// what running targets in separate processes is for.
	first := newFakeHandle(t, 1, executor.ProcResult{Signal: 11})
	second := newFakeHandle(t, 2, executor.ProcResult{})
	sp := &fakeSpawner{handles: []*fakeHandle{first, second}}
	sup := NewSupervisor("c", sp, NewBus(0))
	sup.Backoff = time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := sup.Start(ctx, WorkerSpec{ID: 0, Binary: "/bin/true"}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return sp.starts.Load() >= 1 }, "the worker never started")

	first.exit()

	waitFor(t, func() bool { return sp.starts.Load() >= 2 }, "the worker was not restarted")
	waitFor(t, func() bool {
		st := sup.Status()
		return len(st) == 1 && st[0].Pid == 2 && st[0].Restarts == 1
	}, "the restarted worker did not come back running")

	sup.Stop(time.Second)
}

func TestSupervisorGivesUpOnAWorkerThatCannotStart(t *testing.T) {
	// Restarting forever hides a broken target behind a busy machine that never
	// says why.
	sp := &fakeSpawner{err: errors.New("no such file")}
	sup := NewSupervisor("c", sp, NewBus(0))
	sup.Backoff = time.Millisecond
	sup.MaxRestarts = 3

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := sup.Start(ctx, WorkerSpec{ID: 0, Binary: "/nope"}); err != nil {
		t.Fatal(err)
	}

	waitFor(t, func() bool {
		st := sup.Status()
		return len(st) == 1 && st[0].State == WorkerFailed
	}, "a worker that can never start was restarted forever")

	st := sup.Status()[0]
	if st.Err == "" {
		t.Error("the failed worker reports no reason")
	}
	if got := int(sp.starts.Load()); got > sup.MaxRestarts+1 {
		t.Errorf("%d start attempts against a limit of %d", got, sup.MaxRestarts)
	}
}

func TestSupervisorBroadcastSkipsTheOriginator(t *testing.T) {
	// Echoing an entry back to the worker that found it would double-count its
	// provenance and waste a round trip.
	a := newFakeHandle(t, 1, executor.ProcResult{})
	b := newFakeHandle(t, 2, executor.ProcResult{})
	sup := NewSupervisor("c", &fakeSpawner{handles: []*fakeHandle{a, b}}, NewBus(0))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	for id := 0; id < 2; id++ {
		if err := sup.Start(ctx, WorkerSpec{
			ID: id, Binary: "/bin/true", Args: []string{"--worker", strconv.Itoa(id)},
		}); err != nil {
			t.Fatal(err)
		}
	}
	waitFor(t, func() bool { return len(sup.Status()) == 2 && sup.Healthy() == 2 },
		"both workers never came up")

	sup.Broadcast(&Message{Type: CmdSync, Entries: []CorpusEntry{{Digest: "x"}}}, 0)

	// Worker 1 gets it.
	done := make(chan *Message, 1)
	go func() {
		m, err := NewDecoder(b.workerIn).Decode()
		if err == nil {
			done <- m
		}
	}()
	select {
	case m := <-done:
		if m.Type != CmdSync {
			t.Fatalf("worker 1 received %v", m.Type)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("worker 1 never received the broadcast")
	}

	// Worker 0 does not. Its pipe must be empty, which a non-blocking read of a
	// pipe with a deadline can establish.
	a.workerIn.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
	buf := make([]byte, 1)
	if n, err := a.workerIn.Read(buf); err == nil && n > 0 {
		t.Fatal("the originating worker received its own discovery back")
	} else if err != nil && !errors.Is(err, os.ErrDeadlineExceeded) && !errors.Is(err, io.EOF) {
		t.Fatalf("unexpected read error: %v", err)
	}

	cancel()
}

func TestSupervisorStopAsksBeforeKilling(t *testing.T) {
	// A worker given the chance to stop writes its checkpoint, and that is the
	// difference between losing an interval's work and losing none of it.
	h := newFakeHandle(t, 1, executor.ProcResult{})
	sup := NewSupervisor("c", &fakeSpawner{handles: []*fakeHandle{h}}, NewBus(0))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := sup.Start(ctx, WorkerSpec{ID: 0, Binary: "/bin/true"}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return sup.Healthy() == 1 }, "the worker never started")

	got := make(chan MessageType, 1)
	go func() {
		if m, err := NewDecoder(h.workerIn).Decode(); err == nil {
			got <- m.Type
			h.exit()
		}
	}()

	stopped := make(chan struct{})
	go func() { sup.Stop(2 * time.Second); close(stopped) }()

	select {
	case m := <-got:
		if m != CmdStop {
			t.Fatalf("the worker was sent %v, not a stop", m)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Stop killed the worker without asking it to finish")
	}
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("Stop did not return")
	}
}

func TestSupervisorReportsUnhealthySilence(t *testing.T) {
	st := WorkerStatus{State: WorkerRunning, LastSeen: time.Now().Add(-2 * time.Hour)}
	if st.Healthy(time.Minute) {
		t.Error("a worker silent for two hours is reported healthy")
	}
	if !(WorkerStatus{State: WorkerRunning, LastSeen: time.Now()}).Healthy(time.Minute) {
		t.Error("a worker that just reported is not healthy")
	}
	if (WorkerStatus{State: WorkerFailed, LastSeen: time.Now()}).Healthy(time.Minute) {
		t.Error("a failed worker is reported healthy")
	}
}

func TestProtocolRoundTrip(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	want := &Message{
		Type:   MsgFinding,
		Worker: 2,
		Finding: &FindingReport{
			Digest: "abcd", Payload: []byte{0, 1, 2, 255}, Kind: "crash", Signal: 11,
			Frames: []string{"parse", "main"}, FoundAtExec: 4242,
			Coverage: []byte{0, 3, 0},
		},
	}
	enc := NewEncoder(w)
	if err := enc.Encode(want); err != nil {
		t.Fatal(err)
	}
	w.Close()

	got, err := NewDecoder(r).Decode()
	if err != nil {
		t.Fatal(err)
	}
	if got.Type != want.Type || got.Worker != 2 {
		t.Fatalf("header lost: %+v", got)
	}
	f := got.Finding
	if f == nil || f.Digest != "abcd" || f.Signal != 11 || f.FoundAtExec != 4242 {
		t.Fatalf("finding lost: %+v", f)
	}
	if string(f.Payload) != string(want.Finding.Payload) {
		t.Fatalf("payload = %v, want %v", f.Payload, want.Finding.Payload)
	}
	if len(f.Frames) != 2 || len(f.Coverage) != 3 {
		t.Fatalf("frames or coverage lost: %+v", f)
	}
	if got.At.IsZero() {
		t.Error("the encoder did not stamp a time")
	}
}

func TestDecoderReportsUnreadableLines(t *testing.T) {
	// A worker's stream also carries whatever the Go runtime writes on a panic.
	// The error has to carry the offending text, or the failure is a protocol
	// error on top of a crash and neither is readable.
	r, w, _ := os.Pipe()
	go func() {
		w.Write([]byte("panic: something went wrong\n"))
		w.Close()
	}()
	_, err := NewDecoder(r).Decode()
	if err == nil {
		t.Fatal("a non-JSON line was accepted")
	}
	if !containsAll(err.Error(), "unreadable worker message", "panic: something went wrong") {
		t.Fatalf("err = %v", err)
	}
}

func waitFor(t *testing.T, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatal(msg)
}

func containsAll(s string, subs ...string) bool {
	for _, sub := range subs {
		if !contains(s, sub) {
			return false
		}
	}
	return true
}

func contains(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func TestSendNeverBlocksOnAWorkerThatStoppedReading(t *testing.T) {
	// A worker that stops reading its control pipe must not stall the campaign
	// loop that writes to it — that loop also drives termination checks,
	// checkpoints and corpus sync for every other worker.
	h := newFakeHandle(t, 1, executor.ProcResult{})
	sup := NewSupervisor("c", &fakeSpawner{handles: []*fakeHandle{h}}, NewBus(0))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := sup.Start(ctx, WorkerSpec{ID: 0, Binary: "/bin/true"}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return sup.Healthy() == 1 }, "the worker never started")

	// Nothing reads h.workerIn, so the pipe buffer fills and stays full.
	done := make(chan struct{})
	go func() {
		big := make([]byte, 4096)
		for i := 0; i < 5_000; i++ {
			_ = sup.Send(0, &Message{Type: CmdSync,
				Entries: []CorpusEntry{{Digest: "x", Payload: big}}})
		}
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Send blocked on a worker that stopped reading its control pipe")
	}
	if sup.Dropped(0) == 0 {
		t.Error("commands were queued for a wedged worker but nothing is reported dropped")
	}
	cancel()
}

func TestStopWaitsForEveryWorkerNotJustTheFirst(t *testing.T) {
	// A single time.After channel fires once, so the first worker to wait on it
	// consumes the only tick and every worker after it waits forever.
	handles := []*fakeHandle{
		newFakeHandle(t, 1, executor.ProcResult{}),
		newFakeHandle(t, 2, executor.ProcResult{}),
		newFakeHandle(t, 3, executor.ProcResult{}),
	}
	sup := NewSupervisor("c", &fakeSpawner{handles: handles}, NewBus(0))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	for id := range handles {
		if err := sup.Start(ctx, WorkerSpec{
			ID: id, Binary: "/bin/true", Args: []string{"--worker", strconv.Itoa(id)},
		}); err != nil {
			t.Fatal(err)
		}
	}
	waitFor(t, func() bool { return sup.Healthy() == 3 }, "the workers never started")

	// None of them reads its control pipe, so none responds to the stop
	// request and every one has to be killed.
	stopped := make(chan struct{})
	go func() { sup.Stop(200 * time.Millisecond); close(stopped) }()

	select {
	case <-stopped:
	case <-time.After(10 * time.Second):
		t.Fatal("Stop hung waiting for workers after the first")
	}
	for _, st := range sup.Status() {
		if st.State != WorkerStopped && st.State != WorkerFailed {
			t.Errorf("worker %d is %s after Stop", st.ID, st.State)
		}
	}
}
