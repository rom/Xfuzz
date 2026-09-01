package safety

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rom/Xfuzz/internal/platform"
	"github.com/rom/Xfuzz/pkg/executor"
)

// sleeper starts a process that outlives the test unless it is killed.
//
// A trusted spawner rather than a confining one: what is under test is the
// handle's lifecycle, and confinement would make the test skip on hosts without
// namespaces without saying anything about the thing it is checking.
func sleeper(t *testing.T, ctx context.Context) executor.Handle {
	t.Helper()
	sleep, err := exec.LookPath("sleep")
	if err != nil {
		t.Skip("no sleep(1) on this host")
	}
	// Args carries argv in full, argv[0] included: a spec that omits it runs
	// sleep with no operand, which exits 1 immediately and makes this a test of
	// a process that was never alive.
	h, err := NewTrustedSpawner().Start(ctx, executor.ProcSpec{
		Path: sleep, Args: []string{sleep, "60"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// A handle's end is published to everyone who waits for it, not to whoever
// asks first.
//
// The executor waits for a process, a Close kills it, and the context watcher
// does both — and they overlap. When the exit was a single value on a channel
// the first of them took it and the others blocked forever on a process that
// had already died, which is a deadlock that looks exactly like a target
// refusing to die.
func TestHandleKillIsSafeFromSeveralGoroutines(t *testing.T) {
	h := sleeper(t, context.Background())

	const callers = 8
	var wg sync.WaitGroup
	wg.Add(callers)
	for i := range callers {
		go func() {
			defer wg.Done()
			if i%2 == 0 {
				h.Kill()
				return
			}
			// Wait after a kill must return too: an executor that is waiting
			// for a result when something else stops the campaign is the
			// ordinary shutdown, not an edge case.
			time.Sleep(50 * time.Millisecond)
			h.Wait()
		}()
	}

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("Kill and Wait deadlocked; the exit was consumed by one caller")
	}
}

// Cancelling the context kills the process without stealing its exit.
//
// The watcher goroutine has to observe the exit to stop waiting for it, and
// observing it must not consume it: a Close that runs afterwards is the normal
// order of a shutdown, and it used to hang.
func TestHandleSurvivesItsContextWatcher(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	h := sleeper(t, ctx)
	cancel()

	done := make(chan struct{})
	go func() {
		defer close(done)
		h.Wait()
		h.Kill()
		h.Wait()
	}()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("the context watcher consumed the exit that a later caller needed")
	}
}

// A killed process reports the signal that killed it, and reports it to every
// caller rather than only to the first.
func TestHandleReportsTheSameResultToEveryCaller(t *testing.T) {
	h := sleeper(t, context.Background())
	if err := h.Kill(); err != nil {
		t.Fatal(err)
	}
	first, _ := h.Wait()
	second, _ := h.Wait()
	if first.Signal != second.Signal || first.ExitCode != second.ExitCode {
		t.Errorf("Wait gave two different answers: %+v then %+v", first, second)
	}
	if first.Signal == 0 {
		t.Errorf("a killed process reported no signal: %+v", first)
	}
}

// TestSignalForFillsInWhatThePlatformCannotReport covers the Windows half of
// how a killed process is reported, from a host that is not Windows.
//
// The rule is not "report SIGKILL when killed": a kernel that already said how
// the process died is the better authority, and overwriting it would turn a
// target that segfaulted while being killed into one that was merely stopped.
func TestSignalForFillsInWhatThePlatformCannotReport(t *testing.T) {
	cases := []struct {
		name     string
		reported int
		killed   bool
		want     int
	}{
		{"the platform reported the kill", 9, true, 9},
		{"the platform reported a crash during the kill", 11, true, 11},
		{"the platform reported nothing and we killed it", 0, true, platform.SignalKilled},
		{"the platform reported nothing and it exited on its own", 0, false, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := signalFor(c.reported, c.killed); got != c.want {
				t.Errorf("signalFor(%d, %v) = %d, want %d", c.reported, c.killed, got, c.want)
			}
		})
	}
}

// Killing a handle whose process has already been reaped signals nothing.
//
// A process group is killed with kill(-pid), and once the leader is reaped the
// kernel is free to hand that pid to something else. A fuzzer creates processes
// by the million, so "something else" is not a remote possibility — and a Close
// that runs after Wait is the ordinary shutdown, not an edge case. What this
// pins is that the second call is a no-op rather than a signal aimed at
// whatever now holds the number.
func TestHandleDoesNotSignalAfterItHasBeenReaped(t *testing.T) {
	h := sleeper(t, context.Background())
	if err := h.Kill(); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Wait(); err != nil {
		t.Fatal(err)
	}

	// Reaped. From here the pid is not ours, so Kill must decline rather than
	// send a signal to it.
	hh, ok := h.(*handle)
	if !ok {
		t.Fatalf("Start returned %T, not *handle", h)
	}
	select {
	case <-hh.exited:
	default:
		t.Fatal("Wait returned before the process was reaped")
	}
	if err := hh.Kill(); err != nil {
		t.Errorf("Kill after reaping returned %v; it should decline quietly", err)
	}
}

func TestOneSpawnerServesConcurrentSpawns(t *testing.T) {
	// A Spawner is shared by every worker in a campaign, so it has always been
	// required to be safe under concurrent use. Nothing exercised that: until
	// the T3 pool, spawns were serial per worker, and the unsynchronised read
	// of the sandbox's cgroup sat latent behind a locked write.
	//
	// It surfaced on macOS under -race, in a contributor's first build, rather
	// than in any of this project's own runs. Concurrency this test creates
	// deliberately is worth more than concurrency a scheduler happens to
	// produce.
	sp := NewSpawner()
	sb := &Sandbox{}
	sp.Sandbox = sb
	t.Cleanup(func() { sb.Close() })

	// Looked up rather than hardcoded, for the reason the rest of this suite
	// does it: /bin/true exists on Linux and not on macOS, where it is
	// /usr/bin/true.
	target, err := exec.LookPath("true")
	if err != nil {
		t.Skip("no true(1) on this host")
	}

	const workers = 8
	var wg sync.WaitGroup
	errs := make(chan error, workers)
	start := make(chan struct{})
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start // release them together, so the spawns actually overlap
			if _, err := sp.Run(context.Background(), executor.ProcSpec{
				Path: target, Args: []string{target}, Timeout: 10 * time.Second,
			}); err != nil {
				errs <- err
			}
		}()
	}
	close(start)
	wg.Wait()
	close(errs)

	for err := range errs {
		t.Errorf("concurrent spawn: %v", err)
	}
}

// The child half of TestTheProtocolArrivesOnTheDescriptorsPromised.
//
// It runs as a subprocess of the test binary rather than as a program compiled
// for the purpose, so the test needs no toolchain and no fixture: what is under
// test is which descriptors a started process finds its streams on, and this
// binary is as good a process as any to ask.
const protocolChildEnv = "XFUZZ_TEST_PROTOCOL_CHILD"

func TestProtocolChild(t *testing.T) {
	if os.Getenv(protocolChildEnv) == "" {
		t.Skip("not the child half")
	}
	ctl, st := ControlDescriptors()
	in, out := descriptor(ctl), descriptor(st)

	var word [4]byte
	if _, err := io.ReadFull(in, word[:]); err != nil {
		fmt.Fprintf(os.Stderr, "child: reading the control stream: %v\n", err)
		os.Exit(3)
	}
	if _, err := out.Write([]byte("saw:" + string(word[:]))); err != nil {
		fmt.Fprintf(os.Stderr, "child: writing the status stream: %v\n", err)
		os.Exit(4)
	}
	out.Close()
	os.Exit(0)
}

// descriptor is the worker's namedFile, which cmd/xfuzz-worker documents: the
// three standard streams are the files the runtime holds rather than numbers,
// because a descriptor number is not what every platform opens a file from.
func descriptor(fd int) *os.File {
	switch fd {
	case 0:
		return os.Stdin
	case 1:
		return os.Stdout
	case 2:
		return os.Stderr
	}
	return os.NewFile(uintptr(fd), "protocol")
}

// TestTheProtocolArrivesOnTheDescriptorsPromised checks the one thing that
// makes the protocol portable: that ControlDescriptors describes what Start
// actually does.
//
// The two disagreeing is not a visible failure. A child that reads the wrong
// descriptor does not crash — it blocks, holding a campaign open until
// something times out — and the platform where they disagree is not the one the
// change is made on. So the child is asked where it found them, on every
// platform, rather than the numbers being asserted from this side.
func TestTheProtocolArrivesOnTheDescriptorsPromised(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Skipf("this host does not name the running binary: %v", err)
	}

	h, err := NewTrustedSpawner().Start(context.Background(), executor.ProcSpec{
		Path:     self,
		Args:     []string{self, "-test.run=TestProtocolChild", "-test.v=false"},
		Env:      append(os.Environ(), protocolChildEnv+"=1"),
		Protocol: true,
	})
	if err != nil {
		t.Fatalf("starting the child: %v", err)
	}
	defer h.Kill()

	if h.Control() == nil || h.Status() == nil {
		t.Fatal("a spawn that asked for the protocol got no streams")
	}
	if _, err := h.Control().Write([]byte("ping")); err != nil {
		t.Fatalf("writing the control stream: %v", err)
	}

	done := make(chan struct{})
	var got []byte
	var readErr error
	go func() {
		defer close(done)
		got, readErr = io.ReadAll(h.Status())
	}()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("the child never answered on the status stream, which is what a " +
			"descriptor mismatch looks like: nothing happens")
	}
	if readErr != nil {
		t.Fatalf("reading the status stream: %v", readErr)
	}
	if !strings.Contains(string(got), "saw:ping") {
		t.Fatalf("the child answered %q, so it did not read what was written to "+
			"the control stream", got)
	}
}

// TestASpawnThatDidNotAskForTheProtocolGetsNoStreams keeps the child's own
// streams its own: on a platform with no descriptors to inherit the protocol
// costs the child its standard input and output, so a browser or a daemon that
// never speaks one must not be given it.
func TestASpawnThatDidNotAskForTheProtocolGetsNoStreams(t *testing.T) {
	h := sleeper(t, context.Background())
	defer h.Kill()
	if h.Control() != nil || h.Status() != nil {
		t.Fatal("a spawn that asked for no protocol was given one anyway")
	}
}
