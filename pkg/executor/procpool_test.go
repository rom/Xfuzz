package executor

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rom/Xfuzz/pkg/feedback"
)

// The pool's tests use a real spawner, because the thing under test is what
// happens to a process between being created and being given something to do —
// and a fake would be a fake of exactly that.

// poolSpawner is the smallest spawner that can start a peer: no confinement,
// because confinement is internal/safety's and pkg/ cannot reach it.
type poolSpawner struct{}

func (poolSpawner) Run(context.Context, ProcSpec) (ProcResult, error) {
	return ProcResult{}, errors.New("not used")
}

func (poolSpawner) Start(context.Context, ProcSpec) (Handle, error) {
	return nil, errors.New("not used")
}

func (poolSpawner) IsolationLevel() string { return "none" }

func (poolSpawner) StartPeer(ctx context.Context, spec ProcSpec) (Peer, error) {
	inR, inW, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	outR, outW, err := os.Pipe()
	if err != nil {
		inR.Close()
		inW.Close()
		return nil, err
	}
	cmd := exec.Command(spec.Path, spec.Args[1:]...)
	cmd.Stdin, cmd.Stdout = inR, outW
	var said strings.Builder
	cmd.Stderr = &said
	if err := cmd.Start(); err != nil {
		inR.Close()
		inW.Close()
		outR.Close()
		outW.Close()
		return nil, err
	}
	inR.Close()
	outW.Close()

	p := &testPeer{cmd: cmd, in: inW, out: outR, said: &said, done: make(chan struct{})}
	go func() {
		p.err = cmd.Wait()
		close(p.done)
	}()
	return p, nil
}

type testPeer struct {
	cmd  *exec.Cmd
	in   io.WriteCloser
	out  *os.File
	said *strings.Builder
	done chan struct{}
	err  error
	once sync.Once
}

func (p *testPeer) Stdin() io.WriteCloser { return p.in }
func (p *testPeer) Stdout() io.Reader     { return p.out }
func (p *testPeer) Pid() int              { return p.cmd.Process.Pid }
func (p *testPeer) Diagnose() string      { return p.said.String() }

func (p *testPeer) Wait() (ProcResult, error) {
	<-p.done
	res := ProcResult{ExitCode: p.cmd.ProcessState.ExitCode()}
	if res.ExitCode < 0 {
		res.Signal = 9
		res.ExitCode = 0
	}
	return res, nil
}

func (p *testPeer) Kill() error {
	p.once.Do(func() {
		p.in.Close()
		if p.cmd.Process != nil {
			p.cmd.Process.Kill()
		}
		p.out.Close()
	})
	return nil
}

// shellTarget writes a tiny script that reads its input and reports on it.
func shellTarget(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "target.sh")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func newPool(t *testing.T, target string) *ProcPool {
	t.Helper()
	p := NewProcPool("pool", poolSpawner{}, ProcSpec{Path: target, Args: []string{target}})
	if err := p.Start(context.Background()); err != nil {
		t.Fatalf("starting the pool: %v", err)
	}
	t.Cleanup(func() { p.Close() })
	return p
}

func TestAPooledProcessReceivesItsInput(t *testing.T) {
	// The whole mechanism in one assertion: a process created before the input
	// existed still gets it.
	target := shellTarget(t, `read line; echo "got:$line"`)
	pool := newPool(t, target)

	out := feedback.NewOutputObserver("output")
	pool.Output = out

	ek, err := pool.Run(context.Background(), Input{Bytes: []byte("hello\n")}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if ek != feedback.ExitOK {
		t.Errorf("exit = %v, want ok", ek)
	}
	if got := string(out.Stdout()); !strings.Contains(got, "got:hello") {
		t.Errorf("the target did not receive its input; it said %q", got)
	}
}

func TestEachPooledExecutionGetsItsOwnProcess(t *testing.T) {
	// Nothing may carry over. The pool reports itself deterministic on that
	// basis, and the engine treats a deterministic executor's differing replay
	// as a corpus bug rather than as the target's own state.
	target := shellTarget(t, `read line; echo "pid:$$ in:$line"`)
	pool := newPool(t, target)
	out := feedback.NewOutputObserver("output")
	pool.Output = out

	pids := map[string]bool{}
	for i := 0; i < 6; i++ {
		if _, err := pool.Run(context.Background(), Input{Bytes: []byte("x\n")}, nil); err != nil {
			t.Fatal(err)
		}
		line := strings.TrimSpace(string(out.Stdout()))
		if line == "" {
			t.Fatalf("execution %d produced no output", i)
		}
		if pids[line] {
			t.Fatalf("execution %d reused a process: %q", i, line)
		}
		pids[line] = true
	}
	if !pool.Capabilities().Deterministic {
		t.Error("a tier that gives every input a fresh process reports itself non-deterministic")
	}
}

func TestAPooledTargetThatCrashesIsAnExecutionNotAnError(t *testing.T) {
	// A crashing target is a successful execution reporting ExitCrash.
	// Conflating the two turns a finding into an infrastructure fault.
	target := shellTarget(t, `read line; kill -SEGV $$`)
	pool := newPool(t, target)

	ek, err := pool.Run(context.Background(), Input{Bytes: []byte("x\n")}, nil)
	if err != nil {
		t.Fatalf("a crashing target was reported as a harness error: %v", err)
	}
	if ek != feedback.ExitCrash {
		t.Errorf("exit = %v, want crash", ek)
	}
}

func TestAPooledTargetThatIgnoresItsInputDoesNotWedgeTheFuzzer(t *testing.T) {
	// A target that never reads fills the pipe buffer, and a fuzzer that wrote
	// inline would block on it forever. The write goes on a goroutine for
	// exactly this input.
	target := shellTarget(t, `echo done`)
	pool := newPool(t, target)

	big := make([]byte, 1<<20)
	done := make(chan error, 1)
	go func() {
		_, err := pool.Run(context.Background(), Input{Bytes: big}, nil)
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("a target that ignored a megabyte of input wedged the fuzzer")
	}
}

func TestAPooledTargetThatWritesWithoutStoppingIsBounded(t *testing.T) {
	// The mirror image: a target that writes more than a pipe holds would block
	// on its own write and never exit, so the output is drained while it runs
	// and bounded so it cannot exhaust memory.
	target := shellTarget(t, `read line; i=0; while [ $i -lt 4000 ]; do echo "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"; i=$((i+1)); done`)
	pool := newPool(t, target)
	out := feedback.NewOutputObserver("output")
	pool.Output = out

	done := make(chan error, 1)
	go func() {
		_, err := pool.Run(context.Background(), Input{Bytes: []byte("x\n")}, nil)
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("a chatty target wedged the fuzzer")
	}
	if n := len(out.Stdout()); n == 0 || n > maxPoolOutput {
		t.Errorf("captured %d bytes, want between 1 and %d", n, maxPoolOutput)
	}
}

func TestThePoolRefusesADeliveryItCannotProvide(t *testing.T) {
	// A process created before its input cannot be told about a file whose name
	// did not exist yet. Refusing says so; accepting would run every input
	// against whatever the placeholder happened to expand to.
	target := shellTarget(t, `echo hi`)
	p := NewProcPool("pool", poolSpawner{}, ProcSpec{Path: target, Args: []string{target}})
	p.Delivery = DeliverFile
	if err := p.Start(context.Background()); !errors.Is(err, ErrPoolDelivery) {
		t.Fatalf("Start with file delivery: %v, want ErrPoolDelivery", err)
	}
}

func TestThePoolReportsItselfBlackBox(t *testing.T) {
	// Not an omission: a process spawned before its input has already written
	// its own startup into any shared coverage map, so a pool that claimed
	// coverage would attribute one input's startup to another's execution.
	target := shellTarget(t, `echo hi`)
	pool := newPool(t, target)
	c := pool.Capabilities()
	if c.Tier != TierProcPool {
		t.Errorf("tier = %v, want T3", c.Tier)
	}
	if c.Granularity != GranularityNone || c.Backend != "blackbox" {
		t.Errorf("capabilities = %+v, want black-box with no granularity", c)
	}
	if !c.TimeoutEnforced {
		t.Error("a tier with a process boundary reports that it cannot enforce a timeout")
	}
}

func TestThePoolKeepsProcessesWarmAndCleansThemUp(t *testing.T) {
	target := shellTarget(t, `read line; echo ok`)
	p := NewProcPool("pool", poolSpawner{}, ProcSpec{Path: target, Args: []string{target}})
	p.Size = 3
	if err := p.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	p.mu.Lock()
	warm := len(p.warm)
	p.mu.Unlock()
	if warm != 3 {
		t.Errorf("the pool holds %d warm processes, want 3", warm)
	}
	if err := p.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
	// Closing twice is what a worker's release path does when a campaign both
	// ends and is closed by its owner.
	if err := p.Close(); err != nil {
		t.Errorf("the second Close: %v", err)
	}
}
