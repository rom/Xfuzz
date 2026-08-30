package executor

import (
	"context"
	"errors"
	"fmt"
	"io"
	"runtime"
	"sync"
	"time"

	"github.com/rom/Xfuzz/pkg/feedback"
)

// ProcPool is the T3 executor: a pool of processes spawned before their input
// exists.
//
// It is the portable stand-in for the fork server (ADR-0009). A fork server is
// several times faster than one process per input because it never pays for
// creating one; it is also Linux and macOS only, because it needs fork. On
// Windows the choice was between the fork server's speed and running at all,
// and the answer was T4 — one spawn in front of every execution, which on a
// small target is most of the execution.
//
// A pool gets most of the difference back without fork. Each process is created
// with its standard input as a pipe and blocks on the first read, so it exists
// but has not yet been given anything to do; when an input arrives it is written
// to the waiting process and a replacement is spawned immediately. The cost of
// creating a process is then paid *while the previous one is running* rather
// than in front of the next one.
//
// Black-box only, deliberately. A pre-spawned process has already run its own
// startup — the dynamic loader, the runtime's initialisers — before the fuzzer
// knows what to send it, and an instrumented one has already written the
// coverage of that startup into the shared map. Clearing the map after the
// spawn would race with a replacement being spawned for the next execution, and
// not clearing it would attribute one input's startup coverage to another's.
// Where coverage is wanted there is a fork server or a subprocess; where a
// process boundary is wanted on a platform without fork, this is the fast one.
type ProcPool struct {
	name    string
	spawner Spawner
	spec    ProcSpec

	// Size is how many processes are kept warm. Zero selects DefaultPoolSize.
	//
	// One is enough to overlap a spawn with an execution, which is the whole
	// mechanism; more absorbs a target whose startup is slower than its run, at
	// the cost of that many idle processes.
	Size int

	// Delivery selects how the input reaches the target. Only DeliverStdin is
	// supported: a pre-spawned process cannot be told about a file whose name
	// did not exist when it was created.
	Delivery Delivery

	// Output, when set, receives the process's exit status and output.
	Output *feedback.OutputObserver

	mu     sync.Mutex
	warm   []Peer
	closed bool
	execs  uint64
}

// DefaultPoolSize is how many processes a pool keeps warm.
//
// Two rather than one: the second covers the case where a replacement is still
// being created when the next input arrives, which happens whenever the target
// starts more slowly than it runs — and a target that starts slowly is exactly
// the one this tier is for.
const DefaultPoolSize = 2

// ErrPoolDelivery is returned when a pool is asked to deliver an input by any
// means other than standard input.
var ErrPoolDelivery = errors.New("executor: a pooled process can only be given its input on standard input")

// NewProcPool returns a T3 executor.
func NewProcPool(name string, spawner Spawner, spec ProcSpec) *ProcPool {
	return &ProcPool{name: name, spawner: spawner, spec: spec}
}

// Name implements Executor.
func (e *ProcPool) Name() string { return e.name }

// Executions returns how many inputs have been run.
func (e *ProcPool) Executions() uint64 { return e.execs }

// Capabilities implements Executor.
func (e *ProcPool) Capabilities() Caps {
	return Caps{
		Tier:            TierProcPool,
		Backend:         "blackbox",
		Granularity:     GranularityNone,
		Platform:        runtime.GOOS + "/" + runtime.GOARCH,
		TimeoutEnforced: true,
		// A fresh process per input, so nothing carries over by construction.
		Deterministic: true,
	}
}

// Start fills the pool.
//
// Called before the first execution so that the first input does not pay for a
// spawn either. A pool that filled lazily would be a subprocess executor for as
// long as it took to warm up, which on a short campaign is the whole campaign.
func (e *ProcPool) Start(ctx context.Context) error {
	if e.Delivery != DeliverStdin {
		return ErrPoolDelivery
	}
	for i := 0; i < e.size(); i++ {
		p, err := e.spawn(ctx)
		if err != nil {
			e.Close()
			return err
		}
		e.mu.Lock()
		e.warm = append(e.warm, p)
		e.mu.Unlock()
	}
	return nil
}

func (e *ProcPool) size() int {
	if e.Size <= 0 {
		return DefaultPoolSize
	}
	return e.Size
}

// spawn creates one process, blocked on its own standard input.
func (e *ProcPool) spawn(ctx context.Context) (Peer, error) {
	spec := e.spec
	// The bytes go down the pipe, not in the spec: the whole point is that the
	// process exists before they do.
	spec.Stdin = nil
	p, err := e.spawner.StartPeer(ctx, spec)
	if err != nil {
		return nil, fmt.Errorf("executor %s: %w", e.name, err)
	}
	return p, nil
}

// take removes a warm process, spawning one if the pool has run dry.
func (e *ProcPool) take(ctx context.Context) (Peer, error) {
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return nil, errors.New("executor: the pool is closed")
	}
	if n := len(e.warm); n > 0 {
		p := e.warm[n-1]
		e.warm = e.warm[:n-1]
		e.mu.Unlock()
		return p, nil
	}
	e.mu.Unlock()

	// Dry. That means the previous replacement has not finished being created,
	// so this execution pays for a spawn — exactly what T4 does, which is the
	// right floor to degrade to.
	return e.spawn(ctx)
}

// refill starts a replacement without waiting for it.
//
// Asynchronous on purpose: the cost of creating a process is meant to be paid
// while the target runs, and doing it inline would make this tier a subprocess
// executor with extra steps.
func (e *ProcPool) refill(ctx context.Context) {
	go func() {
		p, err := e.spawn(ctx)
		if err != nil {
			// The next take() spawns inline and reports the failure to a caller
			// that can do something with it. Failing here would mean failing on
			// a goroutine with nobody to tell.
			return
		}
		e.mu.Lock()
		if e.closed {
			e.mu.Unlock()
			p.Kill()
			return
		}
		e.warm = append(e.warm, p)
		e.mu.Unlock()
	}()
}

// Run implements Executor.
func (e *ProcPool) Run(ctx context.Context, in Input, obs []feedback.Observer) (feedback.ExitKind, error) {
	if e.Delivery != DeliverStdin {
		return feedback.ExitError, ErrPoolDelivery
	}

	p, err := e.take(ctx)
	if err != nil {
		return feedback.ExitError, err
	}
	e.refill(ctx)

	if err := Arm(obs, in); err != nil {
		p.Kill()
		return feedback.ExitError, err
	}

	start := time.Now()
	res, err := e.deliver(ctx, p, in.Bytes)
	if err != nil {
		return feedback.ExitError, err
	}
	if res.Duration == 0 {
		res.Duration = time.Since(start)
	}
	e.execs++

	ek := res.ExitKind()
	if e.Output != nil {
		e.Output.Record(res.Stdout, res.Stderr, res.ExitCode, res.Signal)
	}
	for _, o := range obs {
		if err := o.Post(ek); err != nil {
			return feedback.ExitError, fmt.Errorf("harvesting %s: %w", o.Name(), err)
		}
	}
	recordDuration(obs, res.Duration)
	return ek, nil
}

// deliver writes the input, closes the pipe, and waits for the process.
func (e *ProcPool) deliver(ctx context.Context, p Peer, input []byte) (ProcResult, error) {
	// Written on a goroutine because a target that reads nothing — or reads
	// less than it is given — fills the pipe buffer and would block the fuzzer
	// forever. Closing is what tells a target reading to end of file that the
	// input is complete, so it has to happen even when the write did not.
	werr := make(chan error, 1)
	go func() {
		_, err := p.Stdin().Write(input)
		p.Stdin().Close()
		werr <- err
	}()

	// The output is drained while the process runs, for the same reason: a
	// target that writes more than a pipe holds would block on its own write
	// and never exit.
	var out []byte
	done := make(chan struct{})
	go func() {
		out, _ = io.ReadAll(io.LimitReader(p.Stdout(), maxPoolOutput))
		close(done)
	}()

	res, err := p.Wait()
	<-done
	if err != nil {
		p.Kill()
		return res, fmt.Errorf("executor %s: %w", e.name, err)
	}
	<-werr // a write that failed is a target that closed early, which is its business

	if len(res.Stdout) == 0 {
		res.Stdout = out
	}
	if said := p.Diagnose(); said != "" && len(res.Stderr) == 0 {
		res.Stderr = []byte(said)
	}
	return res, nil
}

// maxPoolOutput bounds what is read from one process, so a target that writes
// without stopping cannot exhaust memory.
const maxPoolOutput = 1 << 20

// Reset implements Executor. Every execution gets a fresh process, so there is
// nothing to restore.
func (e *ProcPool) Reset(ResetPolicy) error { return nil }

// Close implements Executor: kill everything still warm.
func (e *ProcPool) Close() error {
	e.mu.Lock()
	e.closed = true
	warm := e.warm
	e.warm = nil
	e.mu.Unlock()

	var errs []error
	for _, p := range warm {
		if err := p.Kill(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
