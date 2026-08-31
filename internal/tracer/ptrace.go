package tracer

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/rom/Xfuzz/internal/platform"
	"github.com/rom/Xfuzz/internal/safety"
	"github.com/rom/Xfuzz/pkg/binary"
	"github.com/rom/Xfuzz/pkg/executor"
)

// Ptrace is the ptrace-bb backend: block coverage from one-shot breakpoints.
//
// It is the only T5 backend with no external dependency at all. Static analysis
// of the target finds where the basic blocks start, a trap instruction goes at
// the start of each, and the ones that fire are the blocks the execution
// entered. Each breakpoint is removed the first time it fires, which is what
// bounds an execution's cost at one context switch per *new* block rather than
// one per block *entry* — the difference between a usable backend and a target
// running ten thousand times slower.
//
// What it gives up, and what the campaign is told: block coverage rather than
// edge coverage, and no hit counts. See platform.TraceRun for why.
type Ptrace struct {
	spawner *safety.Spawner

	// Exe is the program to analyse and trace. It is separate from the process
	// specification because the specification's Path may be a wrapper — and
	// breakpoints belong in the program whose blocks were analysed.
	Exe string

	// MaxBlocks caps how many breakpoints are planted. Every one costs a context
	// switch the first time it is reached, so a target with fifty thousand
	// blocks would spend its first executions doing almost nothing else. The
	// cap is on the analysis, not on the target: blocks past it are simply not
	// instrumented, and the campaign is told how many were.
	MaxBlocks int

	mu       sync.Mutex
	blocks   []uint64
	analysis *binary.Analysis
	pie      bool
	started  bool
}

// DefaultMaxBlocks is how many breakpoints one target gets by default.
//
// Eight thousand is enough for a parser, a codec, or a single library entry
// point, which is what this tier is for. It is deliberately far below the block
// count of a whole browser: a campaign that needs that many is a campaign that
// should be using an instrumented build, and silently planting fifty thousand
// breakpoints would make this tier look broken rather than inapplicable.
const DefaultMaxBlocks = 8000

// NewPtrace returns the ptrace-bb backend for a target executable.
func NewPtrace(spawner *safety.Spawner, exe string) *Ptrace {
	return &Ptrace{spawner: spawner, Exe: exe, MaxBlocks: DefaultMaxBlocks}
}

// Name implements executor.Tracer.
func (p *Ptrace) Name() string { return "ptrace-bb" }

// Granularity implements executor.Tracer.
//
// Block, not edge. A one-shot breakpoint says a block was entered and nothing
// about what it was entered from, and reporting edges here would let a campaign
// require a precision this backend cannot deliver.
func (p *Ptrace) Granularity() executor.Granularity { return executor.GranularityBlock }

// ErrNoBlocks reports a target that static analysis could not find code in.
var ErrNoBlocks = errors.New("tracer: no basic blocks were recovered from the target")

// Start analyses the target and prepares the block list.
func (p *Ptrace) Start(context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.started {
		return nil
	}
	if !platform.TraceSupported() {
		return platform.ErrTraceUnsupported
	}

	im, err := binary.Open(p.Exe)
	if err != nil {
		return err
	}
	defer im.Close()

	a, err := binary.Analyze(im)
	if err != nil {
		return err
	}
	if len(a.Blocks) == 0 {
		return fmt.Errorf("%w: %s", ErrNoBlocks, p.Exe)
	}

	addrs := a.Addrs()
	if p.MaxBlocks > 0 && len(addrs) > p.MaxBlocks {
		addrs = addrs[:p.MaxBlocks]
	}
	p.blocks, p.analysis, p.pie, p.started = addrs, a, im.PIE, true
	return nil
}

// Blocks implements executor.Tracer.
func (p *Ptrace) Blocks() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.blocks)
}

// Analysis returns what static recovery found, for reporting. It is how an
// operator learns that a target's coverage will be partial — the indirect-branch
// count and the fraction of text accounted for are the two numbers that say so.
func (p *Ptrace) Analysis() *binary.Analysis {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.analysis
}

// Trace implements executor.Tracer.
func (p *Ptrace) Trace(ctx context.Context, spec executor.ProcSpec) (executor.Trace, error) {
	p.mu.Lock()
	blocks, pie, started := p.blocks, p.pie, p.started
	p.mu.Unlock()
	if !started {
		return executor.Trace{}, errors.New("tracer: ptrace-bb: Start was not called")
	}

	out, res, err := p.spawner.RunTraced(ctx, spec, platform.TraceOptions{
		Exe:     p.Exe,
		Blocks:  blocks,
		PIE:     pie,
		Timeout: spec.Timeout,
	})
	if err != nil {
		return executor.Trace{}, err
	}
	return executor.Trace{
		Blocks: out.Hits,
		// One-shot breakpoints record which blocks ran, and the order they first
		// ran in — but a block entered a second time leaves no trace, so the
		// sequence is not the execution's actual path. Treating it as one would
		// manufacture edges that did not happen.
		Ordered: false,
		Result:  res,
	}, nil
}

// Close implements executor.Tracer.
func (p *Ptrace) Close() error { return nil }
