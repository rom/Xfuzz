package safety

import (
	"context"
	"os/exec"
	"sync"
	"testing"
	"time"

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
