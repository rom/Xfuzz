// Package worker runs one campaign worker: it builds an engine from the
// campaign file, fuzzes, and reports everything it finds to the daemon.
//
// A worker writes nothing to the store. Every corpus entry, finding and counter
// crosses the protocol to the daemon, which owns the store and the audit log
// (ADR-0003, ADR-0008). It reads the store for its starting corpus, because a
// corpus is exactly the kind of thing several readers may share.
package worker

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/rom/Xfuzz/internal/engine"
	"github.com/rom/Xfuzz/internal/extension"
	"github.com/rom/Xfuzz/internal/platform"
	"github.com/rom/Xfuzz/internal/safety"
	"github.com/rom/Xfuzz/internal/tracer"
	"github.com/rom/Xfuzz/internal/version"
	"github.com/rom/Xfuzz/pkg/binary"
	"github.com/rom/Xfuzz/pkg/campaign"
	"github.com/rom/Xfuzz/pkg/codec"
	"github.com/rom/Xfuzz/pkg/corpus"
	"github.com/rom/Xfuzz/pkg/executor"
	"github.com/rom/Xfuzz/pkg/feedback"
	"github.com/rom/Xfuzz/pkg/ir"
	"github.com/rom/Xfuzz/pkg/mutate"
	"github.com/rom/Xfuzz/pkg/schema"
	"github.com/rom/Xfuzz/pkg/state"
)

// built is everything a worker needs to fuzz, and everything it must release.
type built struct {
	engine   *engine.Engine
	executor executor.Executor
	coverage *feedback.CoverageMap
	mapFB    *feedback.MapFeedback
	output   *feedback.OutputObserver
	shm      executor.SharedMemory

	// cmp is the comparison table, when the campaign asked for substitution.
	// Its own region rather than a corner of the coverage map: the two are
	// written at different rates and read for different reasons, and a campaign
	// that wants coverage and not comparisons should not map the second.
	cmp    *feedback.CmpObserver
	cmpShm executor.SharedMemory
	valueP *feedback.ValueProfile

	// blocks, blockShm and distance are the directed campaign's machinery: what
	// the execution entered, where those addresses come from, and how far each
	// is from the places the campaign was aimed at.
	blocks   *feedback.BlockObserver
	blockShm executor.SharedMemory
	distance *feedback.DistanceFeedback
	sandbox  *safety.Sandbox

	// sessionAddr is the resolved per-worker address, empty on a file campaign.
	// Resolved before the sandbox because the sandbox has to know about it: a
	// server binding a Unix socket needs the directory holding it to be
	// writable, and a read-only root that the fuzzer itself imposed is a
	// confusing way for a campaign to fail.
	sessionAddr string

	// scope is the network boundary. It is the dialer a session executor uses,
	// so on a stateful campaign it is not merely a policy object but the thing
	// every connection goes through (ADR-0012).
	scope *safety.Scope

	// state is the protocol guidance, nil on a stateless campaign.
	state *state.Guidance

	// extensions are the campaign's out-of-process plugins. Always non-nil;
	// empty is the common case and costs nothing.
	extensions *extension.Set

	// input carries the executed bytes to the extensions that asked to see
	// them. Nil when none did, because copying every input is the largest cost
	// on that path and nobody should pay it for an observer nothing reads.
	input *feedback.InputObserver

	closers []closer
	closed  sync.Once

	// closeErrs is what release reported, kept so the worker can say it. A
	// closer that fails is saying the host is now in a state the next campaign
	// will meet — a target that outlived its worker, a region still mapped —
	// and discarding that is how one campaign quietly costs the next one.
	closeErrs []error

	// tier is which executor was actually used, which may not be the one asked
	// for, and fallbackReason says why when they differ. Reported to the daemon
	// in the ready message, so that a campaign which silently fell back to a
	// slower tier is visible in the first second rather than in a post-mortem.
	tier           string
	fallbackReason string

	// directedNote and directionReport say what a directed campaign is aimed at
	// and how much of the target can see it. Both go in the ready message: a
	// campaign whose targets half resolved, or whose target is reachable from a
	// tenth of the program, is one whose direction is worth less than it looks.
	directedNote    string
	directionReport string

	// analysisNote says what static recovery found on a binary-only campaign,
	// so an operator can judge the coverage figures rather than trusting them.
	// A target whose text is half unaccounted for, or which is full of indirect
	// branches, produces coverage with holes that the numbers alone do not show.
	analysisNote string
}

// closer releases one acquired resource, saying what it is when it fails.
type closer struct {
	what string
	fn   func() error
}

// close releases everything build acquired, in the reverse of the order it was
// acquired in.
//
// Once, because there are two paths to it — Run releases what it built when it
// returns, and a caller that owns the worker calls Close — and a second release
// is not harmless: closing a fork server twice used to mean two goroutines
// waiting for one process to die.
//
// Failures are collected rather than discarded. "The target did not die within
// five seconds of SIGKILL; something escaped its process group" is a sentence
// the operator needs, and it was being thrown away.
func (b *built) close() {
	b.closed.Do(func() {
		for i := len(b.closers) - 1; i >= 0; i-- {
			if err := b.closers[i].fn(); err != nil {
				b.closeErrs = append(b.closeErrs,
					fmt.Errorf("releasing the %s: %w", b.closers[i].what, err))
			}
		}
	})
}

// build assembles the engine described by a campaign file.
func build(ctx context.Context, cfg *campaign.Resolved, workerID int, seed uint64, strategy string) (*built, error) {
	b := &built{}
	ok := false
	defer func() {
		if !ok {
			b.close()
		}
	}()

	if cfg.Session != nil {
		addr, aerr := sessionAddress(cfg, workerID)
		if aerr != nil {
			return nil, aerr
		}
		b.sessionAddr = addr
	}

	if err := b.buildSafety(ctx, cfg); err != nil {
		return nil, err
	}
	// Plugins start before the executor, so a campaign whose extension will not
	// load fails before a target process exists rather than after.
	if err := b.buildExtensions(ctx, cfg, seed); err != nil {
		return nil, err
	}
	if err := b.buildFeedback(cfg); err != nil {
		return nil, err
	}
	// A session block is what makes a campaign stateful, so it is what chooses
	// the tier. Everything after this point is the same for both kinds, which
	// is the point of ASR-0002 treating statefulness as an axis rather than as
	// a separate tool.
	if cfg.Session != nil {
		if err := b.buildSession(ctx, cfg); err != nil {
			return nil, err
		}
	} else if err := b.buildExecutor(ctx, cfg); err != nil {
		return nil, err
	}

	cdc, err := codecFor(cfg)
	if err != nil {
		return nil, err
	}
	mutators, err := mutatorsFor(cfg, strategy, b.extensions)
	if err != nil {
		return nil, err
	}
	dict, err := dictionaryFor(cfg)
	if err != nil {
		return nil, err
	}

	ecfg := engine.Config{
		CampaignSeed:  seed,
		WorkerID:      uint32(workerID),
		Executor:      b.executor,
		Observers:     b.observers(),
		Feedback:      b.feedbackStack(cfg),
		Objective:     objectivesFor(cfg, b.output, b.extensions),
		Corpus:        corpus.New(),
		Schedule:      scheduleFor(cfg, strategy),
		Mutators:      mutators,
		Codec:         cdc,
		Dict:          dict,
		Suppress:      suppressFor(cfg),
		MaxInputBytes: int(cfg.Format.MaxInputBytes),
		MaxChildren:   maxChildrenFor(cfg),
		TrimBudget:    cfg.Mutation.TrimBudget,
		State:         b.state,
		Cmp:           b.cmp,
	}
	eng, err := engine.New(ecfg)
	if err != nil {
		return nil, err
	}
	b.engine = eng
	ok = true
	return b, nil
}

// defaultMaxChildren bounds how far a structural mutation may inflate a repeat.
const defaultMaxChildren = 64

// maxChildrenFor bounds sequence growth.
//
// For a session campaign the bound is the campaign's own message limit, because
// a session *is* the repeat: without it the sequence operators converge on
// sessions of thousands of messages that each take a second and explore
// nothing.
func maxChildrenFor(cfg *campaign.Resolved) int {
	if cfg.Session != nil && cfg.Session.MaxMessages > 0 {
		return cfg.Session.MaxMessages
	}
	return defaultMaxChildren
}

// buildSafety prepares the confinement the target will run under.
//
// Each worker builds its own rather than sharing the daemon's, because
// confinement is applied at spawn and each worker spawns its own target. It is
// checked here so a worker that cannot provide what the campaign asked for
// fails at startup rather than running unconfined.
func (b *built) buildSafety(ctx context.Context, cfg *campaign.Resolved) error {
	level, err := safety.ParseLevel(cfg.Safety.Isolation)
	if err != nil {
		return err
	}
	writable := cfg.Safety.Writable
	var creates []string
	if dir := socketDir(b.sessionAddr); dir != "" {
		// The target creates its socket here, so the read-only root must not
		// cover it. Added by the fuzzer rather than demanded of the campaign
		// file: the path is one the fuzzer resolved per worker, and asking
		// somebody to list a directory they did not name is asking them to
		// debug our arrangement rather than their campaign.
		writable = append(append([]string(nil), writable...), dir)
		_, path, _ := campaign.SplitAddress(b.sessionAddr)
		creates = append(creates, path)
	}

	b.sandbox = &safety.Sandbox{
		Require:  level,
		Name:     cfg.Name,
		Target:   cfg.Target.Path,
		Network:  cfg.Safety.Network,
		Writable: writable,
		Creates:  creates,
		Workdir:  cfg.Target.Dir,
		Limits: platform.Limits{
			AddressSpaceBytes: uint64(cfg.Safety.MemoryLimit),
			Processes:         uint64(cfg.Safety.ProcessLimit),
			FileSizeBytes:     uint64(cfg.Safety.FileSizeLimit),
			CPUSeconds:        uint64(cfg.Safety.CPULimit.Std().Seconds()),
			DisableCore:       true,
		},
	}
	b.closers = append(b.closers, closer{"sandbox", b.sandbox.Close})

	// The scope guard, which on a session campaign is the dialer itself. Built
	// even for a file campaign: a target that reaches out is refused by the
	// same rules whether or not the campaign is about connections.
	spec := safety.ScopeSpec{}
	if sc := cfg.Safety.Scope; sc != nil {
		spec.Loopback = sc.Loopback
		spec.AcknowledgePublic = sc.AcknowledgePublic
		for _, entry := range sc.Allow {
			host, ports, perr := campaign.ParseAllow(entry)
			if perr != nil {
				return perr
			}
			ranges := make([]safety.PortRange, 0, len(ports))
			for _, p := range ports {
				lo, hi, rerr := parsePortRange(p)
				if rerr != nil {
					return rerr
				}
				ranges = append(ranges, safety.PortRange{Lo: lo, Hi: hi})
			}
			spec.Allow = append(spec.Allow, safety.AllowEntry{Host: host, Ports: ranges})
		}
	}
	scope, err := safety.NewScopeFrom(spec, nil)
	if err != nil {
		return err
	}
	if err := scope.Validate(cfg.Safety.Network); err != nil {
		return err
	}
	b.scope = scope

	return b.sandbox.Check(ctx)
}

// parsePortRange reads "80" or "8000-8100".
func parsePortRange(s string) (lo, hi uint16, err error) {
	a, bb, ok := strings.Cut(s, "-")
	n, err := strconv.ParseUint(strings.TrimSpace(a), 10, 16)
	if err != nil {
		return 0, 0, fmt.Errorf("worker: %q is not a port", a)
	}
	if !ok {
		return uint16(n), uint16(n), nil
	}
	m, err := strconv.ParseUint(strings.TrimSpace(bb), 10, 16)
	if err != nil {
		return 0, 0, fmt.Errorf("worker: %q is not a port", bb)
	}
	return uint16(n), uint16(m), nil
}

// buildFeedback prepares the coverage map and the observers.
func (b *built) buildFeedback(cfg *campaign.Resolved) error {
	b.output = feedback.NewOutputObserver("output")

	if cfg.Feedback.Coverage == campaign.CoverageNone {
		return nil
	}

	// A binary-only backend needs no shared region. Nothing in the target writes
	// coverage — the fuzzer watches the process and folds what it saw into the
	// map itself — so the map is ordinary memory that the target never sees. That
	// is also why these backends work on a program that was never built for
	// fuzzing: there is nothing to link in.
	if campaign.IsBinaryOnlyCoverage(cfg.Feedback.Coverage) {
		b.coverage = feedback.NewCoverageMap("coverage", int(cfg.Feedback.MapSize))
		b.coverage.SetBackend(cfg.Feedback.Coverage)
		b.mapFB = feedback.NewMapFeedback("coverage", b.coverage)
		return nil
	}

	// The region has to be writable by whatever identity the target ends up
	// with, which is the sandbox's decision and not this one's.
	uid, gid := b.sandbox.TargetIdentity()
	provider := platform.NewSharedMemoryProviderFor(uid, gid)
	if !provider.Available() {
		return errors.New("worker: shared memory is unavailable, so coverage cannot be collected; " +
			"set feedback.coverage to none and feedback.novelty to true for a black-box campaign")
	}
	shm, err := provider.Create(int(cfg.Feedback.MapSize))
	if err != nil {
		return fmt.Errorf("worker: creating the coverage region: %w", err)
	}
	b.shm = shm
	b.closers = append(b.closers, closer{"coverage region", shm.Close})

	b.coverage = feedback.NewCoverageMap("coverage", int(cfg.Feedback.MapSize))
	b.coverage.SetBuffer(shm.Bytes())
	b.coverage.SetBackend(cfg.Feedback.Coverage)
	b.mapFB = feedback.NewMapFeedback("coverage", b.coverage)

	if err := b.buildDirection(cfg, provider); err != nil {
		return err
	}

	if cfg.Feedback.CmpLog {
		cmpShm, err := provider.Create(feedback.CmpRegionSize)
		if err != nil {
			return fmt.Errorf("worker: creating the comparison region: %w", err)
		}
		b.cmpShm = cmpShm
		b.closers = append(b.closers, closer{"comparison region", cmpShm.Close})
		b.cmp = feedback.NewCmpObserver("cmp", cmpShm.Bytes())
		if cfg.Feedback.ValueProfile {
			b.valueP = feedback.NewValueProfile("value-profile", b.cmp, 0)
		}
	}
	return nil
}

// buildDirection prepares a directed campaign: the analysis of the target, the
// distance map, and the region the target reports its blocks in.
//
// All of it before the campaign starts. Every failure here — a target that
// cannot be analysed, an address from a different build, a function nothing can
// reach — produces a campaign that runs perfectly and steers nowhere, which is
// the one outcome that cannot be diagnosed from the outside (ADR-0007).
func (b *built) buildDirection(cfg *campaign.Resolved, provider executor.SharedMemoryProvider) error {
	d := cfg.Feedback.Directed
	if d == nil {
		return nil
	}

	im, err := binary.Open(cfg.Target.Path)
	if err != nil {
		return fmt.Errorf("worker: a directed campaign has to analyse its target: %w", err)
	}
	defer im.Close()

	specs := make([]binary.TargetSpec, 0, len(d.Targets))
	for _, t := range d.Targets {
		specs = append(specs, binary.TargetSpec(t))
	}
	addrs, rerr := binary.Resolve(im, specs)
	if addrs == nil {
		return fmt.Errorf("worker: %w", rerr)
	}
	if rerr != nil {
		// Some resolved and some did not. Running is right; running without
		// saying which were dropped would report progress towards a place
		// nobody asked about.
		b.directedNote = rerr.Error()
	}

	analysis, aerr := binary.Analyze(im)
	if aerr != nil {
		return fmt.Errorf("worker: a directed campaign needs the target's control flow: %w", aerr)
	}
	dist, derr := binary.BuildDistanceMap(analysis, addrs)
	if derr != nil {
		return fmt.Errorf("worker: %w", derr)
	}

	reach := dist.Coverage(analysis)
	if d.MinReachable > 0 && reach < d.MinReachable {
		return fmt.Errorf("worker: only %.1f%% of the target's recovered blocks can reach "+
			"any of its %d target location(s), below the %.1f%% this campaign requires. "+
			"Direction measured over that little of the program is not direction: every "+
			"input scores the same and the campaign looks like it is simply not making "+
			"progress yet", 100*reach, len(dist.Targets), 100*d.MinReachable)
	}

	// Where the block addresses come from. A tier that watches the process
	// reports them itself; an instrumented build writes them into a region, and
	// then the load base has to be recovered from a symbol the runtime
	// publishes.
	var region []byte
	if !campaign.IsBinaryOnlyCoverage(cfg.Feedback.Coverage) {
		shm, serr := provider.Create(feedback.BlockRegionSize)
		if serr != nil {
			return fmt.Errorf("worker: creating the block-trace region: %w", serr)
		}
		b.blockShm = shm
		b.closers = append(b.closers, closer{"block-trace region", shm.Close})
		region = shm.Bytes()
	}

	b.blocks = feedback.NewBlockObserver("blocks", region)
	if region != nil {
		anchor, ok := im.Lookup(blockAnchorSymbol)
		if !ok {
			return fmt.Errorf("worker: the target carries no %s symbol, so the addresses it "+
				"reports blocks at cannot be related back to the binary. Build it with "+
				"xfuzz-cc and leave it unstripped, or use a binary-only coverage backend",
				blockAnchorSymbol)
		}
		b.blocks.SetAnchor(anchor)
	}
	b.distance = feedback.NewDistanceFeedback("distance", b.blocks, dist)
	b.directionReport = fmt.Sprintf("directed at %d location(s); %d of %d blocks reach one (%.0f%%), "+
		"furthest %d", len(dist.Targets), dist.Reachable, len(analysis.Blocks), 100*reach, dist.Max)
	return nil
}

// blockAnchorSymbol is the function the runtime publishes the runtime address
// of, so the fuzzer can recover where a position-independent target was loaded.
const blockAnchorSymbol = "xfuzz_map"

func (b *built) observers() []feedback.Observer {
	obs := []feedback.Observer{b.output}
	if b.coverage != nil {
		obs = append([]feedback.Observer{b.coverage}, obs...)
	}
	if b.cmp != nil {
		obs = append(obs, b.cmp)
	}
	if b.blocks != nil {
		obs = append(obs, b.blocks)
	}
	if b.state != nil {
		// The session executor feeds this one during the session rather than
		// after it, because that is the only time the replies exist. It still
		// belongs in the observer list: Pre is what returns the trace to the
		// start state, and an observer left out of the list is one whose trace
		// accumulates across every session the worker ever runs.
		obs = append(obs, b.state.Observer)
	}
	if b.input != nil {
		obs = append(obs, b.input)
	}
	return obs
}

// buildExtensions starts the campaign's plugins, confined by the same sandbox
// the target runs under.
//
// The same sandbox, deliberately. An extension is untrusted by construction —
// that is why it runs out of process at all (ADR-0010) — so a campaign that
// asked for strong isolation gets it for the plugin too.
func (b *built) buildExtensions(ctx context.Context, cfg *campaign.Resolved, seed uint64) error {
	spawner := safety.NewSpawner()
	spawner.Sandbox = b.sandbox

	// Not the campaign's context. Cancelling that is how a campaign *ends*,
	// and a plugin killed at the first sign of the end has no chance to be
	// told that the last judgement stood — the commit the host still owes it
	// is written during Close, on a pipe the cancellation would already have
	// shut. The set's lifetime belongs to the worker's close path, which
	// always runs and always kills.
	set, err := extension.Load(context.WithoutCancel(ctx), spawner, cfg, seed, version.Version)
	if err != nil {
		return err
	}
	b.extensions = set
	if !set.Empty() {
		b.closers = append(b.closers, closer{"plugins", set.Close})
	}
	if set.WantsInput() {
		b.input = feedback.NewInputObserver("input")
	}
	return nil
}

// feedbackStack decides what counts as interesting.
func (b *built) feedbackStack(cfg *campaign.Resolved) feedback.Feedback {
	var stack []feedback.Feedback
	if b.mapFB != nil {
		stack = append(stack, b.mapFB)
	}
	if cfg.Feedback.Novelty {
		stack = append(stack, feedback.NewNoveltyFeedback("output-novelty", b.output))
	}
	if b.distance != nil {
		// A peer of coverage, in an Any stack: an input that reached new code is
		// still worth keeping even when it went nowhere near the target, and one
		// that got closer is worth keeping even when it covered nothing new.
		// Requiring both would make each a filter on the other and the campaign
		// would keep almost nothing.
		stack = append(stack, b.distance)
	}
	if b.valueP != nil {
		// A peer of coverage, not a replacement for it. Value profiling admits
		// inputs that got *closer* to passing a comparison, which coverage
		// cannot see at all — and admits a great many of them, which is why it
		// is opt-in and why it sits in an Any stack where coverage can still
		// admit what it would have admitted anyway.
		stack = append(stack, b.valueP)
	}
	if b.state != nil {
		// The reason ADR-0006 exists. Two sessions can execute identical lines
		// and leave the target in different places, so a stack with only
		// coverage in it throws away the handshake that unlocked a new region
		// of the protocol — the code was already covered.
		stack = append(stack, state.NewFeedback("state", b.state.Observer, b.state.Model))
	}
	// A plugin feedback joins the stack as a peer, not as a special case. The
	// engine cannot tell the tiers apart and must not be able to: that is what
	// makes a plugin a real extension rather than a hook (ADR-0010).
	stack = append(stack, b.extensions.Feedbacks()...)

	switch len(stack) {
	case 0:
		// Validation refuses this combination, so reaching it means something
		// upstream changed. Never() keeps a corpus of exactly the seeds rather
		// than admitting everything, which would fill the store with noise.
		return feedback.Never()
	case 1:
		return stack[0]
	default:
		// Any, not All: two independent signals should each be able to admit an
		// input. Requiring both would make the weaker one a filter on the
		// stronger, which is not what adding a signal is for.
		return feedback.Any(stack...)
	}
}

// buildExecutor picks the delivery tier.
//
// "auto" tries the fork server and falls back, because the fork server is
// several times faster and needs an instrumented target, and working out
// whether a target is instrumented is exactly the kind of thing a person should
// not have to do by hand. The fallback is reported, never silent.
func (b *built) buildExecutor(ctx context.Context, cfg *campaign.Resolved) error {
	spec := procSpecFor(cfg)
	spawner := safety.NewSpawner()
	spawner.Sandbox = b.sandbox

	tier := cfg.Target.Executor
	if tier == campaign.ExecutorAuto && campaign.IsBinaryOnlyCoverage(cfg.Feedback.Coverage) {
		// A backend that works by watching the process needs the tier that
		// watches it. Nothing else can carry it, so there is nothing to choose.
		tier = campaign.ExecutorEmulated
	}
	if tier == campaign.ExecutorAuto {
		// With coverage, the fork server; without it, the pool. The pool is
		// black-box by construction — a process spawned before its input has
		// already written its startup coverage into the map — so "auto" picks
		// it exactly where there is no map to pollute, which is every campaign
		// that asked for none and every campaign on a platform without shared
		// memory. Measured against the tier it replaces there: 1,420 exec/s
		// against 559.
		if b.coverage == nil {
			tier = campaign.ExecutorPool
		} else {
			tier = campaign.ExecutorForkServer
		}
	}

	switch tier {
	case campaign.ExecutorForkServer:
		fs := executor.NewForkServer("forkserver", spawner, spec)
		fs.Coverage, fs.Shm, fs.Output = b.coverage, b.shm, b.output
		fs.CmpShm, fs.BlockShm = b.cmpShm, b.blockShm
		fs.Timeout = cfg.Target.Timeout.Std()
		if err := fs.Start(ctx); err != nil {
			if cfg.Target.Executor != campaign.ExecutorAuto {
				return err
			}
			// Asked for the fastest tier available, and this target cannot
			// provide it. Falling back is right; doing so quietly is not.
			b.fallbackReason = err.Error()
			return b.buildSubprocess(cfg, spawner, spec)
		}
		b.executor = fs
		b.tier = "forkserver"
		b.closers = append(b.closers, closer{"fork server", fs.Close})
		return nil

	case campaign.ExecutorPool:
		if b.coverage != nil {
			return errors.New("worker: the pool tier cannot collect coverage — a process " +
				"spawned before its input has already written its own startup into the " +
				"map — so set feedback.coverage to none, or use forkserver or subprocess")
		}
		pool := executor.NewProcPool("pool", spawner, spec)
		pool.Output = b.output
		if err := pool.Start(ctx); err != nil {
			if cfg.Target.Executor != campaign.ExecutorAuto {
				return err
			}
			b.fallbackReason = err.Error()
			return b.buildSubprocess(cfg, spawner, spec)
		}
		b.executor = pool
		b.tier = "pool"
		b.closers = append(b.closers, closer{"process pool", pool.Close})
		return nil

	case campaign.ExecutorSubprocess:
		return b.buildSubprocess(cfg, spawner, spec)

	case campaign.ExecutorEmulated:
		return b.buildEmulated(ctx, cfg, spawner, spec)

	case campaign.ExecutorInProc:
		return errors.New("worker: the in-process tier is for Go harnesses linked into the fuzzer, " +
			"which the campaign file cannot express yet; use forkserver or subprocess")

	default:
		return fmt.Errorf("worker: unknown executor tier %q", tier)
	}
}

// buildEmulated prepares the T5 tier and the binary-only backend it runs.
//
// There is no fallback here, deliberately. Every other tier has a slower one
// beneath it that always works, so falling back is right when a target turns out
// not to support the fast path. This tier *is* the answer for a target that
// supports nothing, and the thing below it collects no coverage at all — so a
// campaign that asked to watch a stripped binary and silently got a black-box
// run would be told it was fuzzing with coverage while learning nothing.
func (b *built) buildEmulated(ctx context.Context, cfg *campaign.Resolved,
	spawner *safety.Spawner, spec executor.ProcSpec) error {

	backend := cfg.Feedback.Coverage
	var tr executor.Tracer
	switch backend {
	case campaign.CoveragePtraceBB:
		tr = tracer.NewPtrace(spawner, cfg.Target.Path)
	case campaign.CoverageQemu:
		tr = tracer.NewQemu(spawner, cfg.Target.Path)
	case campaign.CoverageFrida:
		tr = tracer.NewFrida(spawner, cfg.Target.Path)
	default:
		return fmt.Errorf("worker: the emulated tier needs a binary-only coverage "+
			"backend and feedback.coverage is %q; set it to ptrace-bb, qemu or frida", backend)
	}

	e := executor.NewEmulated(backend, tr, spec)
	e.Delivery = deliveryFor(cfg)
	e.Output = b.output
	e.Coverage = b.coverage
	if err := e.Start(ctx); err != nil {
		return err
	}
	b.executor = e
	b.tier = "emulated"
	b.closers = append(b.closers, closer{"emulated executor", e.Close})

	// What static recovery found, so an operator can judge the coverage figures
	// rather than trusting them. A target whose text is half unaccounted for, or
	// which is full of indirect branches, produces coverage with holes in it —
	// and the holes are invisible from the numbers alone.
	if a, ok := tr.(interface{ Analysis() *binary.Analysis }); ok {
		if an := a.Analysis(); an != nil {
			b.analysisNote = fmt.Sprintf(
				"%d blocks recovered from %s, %.0f%% of its executable bytes, %d indirect branches",
				len(an.Blocks), filepath.Base(cfg.Target.Path), 100*an.Coverage, an.Indirect)
		}
	}
	return nil
}

func (b *built) buildSubprocess(cfg *campaign.Resolved, spawner *safety.Spawner, spec executor.ProcSpec) error {
	sub := executor.NewSubprocess("subprocess", spawner, spec)
	sub.Output = b.output
	sub.Delivery = deliveryFor(cfg)
	if b.coverage != nil {
		sub.Coverage, sub.Shm = b.coverage, b.shm
		sub.Backend = cfg.Feedback.Coverage
	}
	sub.CmpShm, sub.BlockShm = b.cmpShm, b.blockShm
	b.executor = sub
	b.tier = "subprocess"
	b.closers = append(b.closers, closer{"subprocess executor", sub.Close})
	return nil
}

// procSpecFor turns the campaign's target block into a process specification.
func procSpecFor(cfg *campaign.Resolved) executor.ProcSpec {
	t := cfg.Target
	argv := append([]string{t.Path}, t.Args...)

	env := make([]string, 0, len(t.Env))
	for k, v := range t.Env {
		env = append(env, k+"="+v)
	}

	return executor.ProcSpec{
		Path:          t.Path,
		Args:          argv,
		Env:           env,
		Dir:           t.Dir,
		Timeout:       t.Timeout.Std(),
		CaptureOutput: true,
	}
}

// deliveryFor maps the campaign's input mode onto the executor's.
func deliveryFor(cfg *campaign.Resolved) executor.Delivery {
	switch cfg.Target.Input {
	case campaign.InputFile:
		return executor.DeliverFile
	case campaign.InputArg:
		return executor.DeliverArg
	default:
		return executor.DeliverStdin
	}
}

func codecFor(cfg *campaign.Resolved) (codec.Codec, error) {
	// A grammar chooses the codec unless the campaign named one itself.
	//
	// Without this a grammar produced seeds and nothing more: the campaign
	// decoded them as opaque bytes, mutated them blindly, and the fixup pass —
	// the entire argument of ADR-0005 — never ran, because there was no
	// structure to fix. Writing a grammar bought a better starting corpus and
	// none of the thing it is for.
	//
	// An explicit codec still wins, and `codec: raw` beside a grammar is a
	// meaningful thing to ask for: it is grammar-generated seeds mutated at the
	// byte level, which is the control arm when measuring what structure buys.
	//
	// Not on a session campaign. There the codec's job is to split an input
	// into the messages of a conversation, and a grammar describes one message
	// rather than a sequence of them; taking it would silently turn a
	// conversation into a single blob. Composing the two — a session of
	// grammar-described messages — is a real thing to want and is not v0.1.
	if cfg.Format.Grammar != "" && cfg.Session == nil && !cfg.WasSet("format.codec") {
		sch, err := schema.ParseFile(cfg.Format.Grammar)
		if err != nil {
			return nil, fmt.Errorf("worker: %w", err)
		}
		return codec.NewSchema(sch), nil
	}

	switch cfg.Format.Codec {
	case "", "raw":
		return codec.Raw{}, nil
	case "png":
		return codec.PNG{}, nil
	case "session":
		return codec.Session{}, nil
	default:
		return nil, fmt.Errorf("worker: unknown codec %q", cfg.Format.Codec)
	}
}

// mutatorsFor builds the operator set, applying the campaign's weights and then
// the strategy's, so a strategy adjusts what the campaign chose rather than
// replacing it.
func mutatorsFor(cfg *campaign.Resolved, strategy string, ext *extension.Set) (*mutate.Scheduler, error) {
	s := mutate.Default()

	if len(cfg.Mutation.Operators) > 0 {
		filtered := mutate.NewScheduler()
		for _, name := range cfg.Mutation.Operators {
			op, ok := s.Operator(name)
			if !ok {
				return nil, fmt.Errorf("worker: no mutation operator named %q", name)
			}
			filtered.Add(op, 0)
		}
		s = filtered
	}

	// Plugin mutators are added after the operator filter, not through it: the
	// filter names built-in operators, and a plugin the campaign file already
	// asked for by name should not have to be named twice.
	for _, m := range ext.Mutators() {
		s.Add(m, 0)
	}

	apply := func(weights map[string]int) error {
		for name, w := range weights {
			if !s.SetWeight(name, w) {
				return fmt.Errorf("worker: no mutation operator named %q to weight", name)
			}
		}
		return nil
	}
	if err := apply(cfg.Mutation.Weights); err != nil {
		return nil, err
	}
	if st := strategyByName(cfg, strategy); st != nil && st.Mutation != nil {
		if err := apply(st.Mutation.Weights); err != nil {
			return nil, err
		}
	}
	return s, nil
}

func strategyByName(cfg *campaign.Resolved, name string) *campaign.Strategy {
	if name == "" {
		return nil
	}
	for i := range cfg.Workers.Strategies {
		if cfg.Workers.Strategies[i].Name == name {
			return &cfg.Workers.Strategies[i]
		}
	}
	return nil
}

// scheduleFor picks the power schedule, letting a strategy override it. Strategy
// diversity across workers beats N identical workers (ADR-0015).
func scheduleFor(cfg *campaign.Resolved, strategy string) corpus.Scheduler {
	name := ""
	if st := strategyByName(cfg, strategy); st != nil {
		name = st.Schedule
	}
	switch name {
	case "rand":
		return corpus.NewRandScheduler()
	case "roundrobin":
		return corpus.NewRoundRobinScheduler()
	default:
		fast := corpus.NewFastScheduler()
		// The other half of directed fuzzing. A distance feedback decides which
		// inputs to keep; without a schedule that spends more of the budget on
		// them, a corpus of ten thousand entries of which four are near the
		// target gives those four a four-in-ten-thousand share of the machine.
		// Direction that is kept and not spent does not arrive.
		if d := cfg.Feedback.Directed; d != nil {
			fast.Directed = d.Weight
			if fast.Directed == 0 {
				fast.Directed = corpus.DefaultDirectedWeight
			}
		}
		return fast
	}
}

func dictionaryFor(cfg *campaign.Resolved) (*mutate.Dictionary, error) {
	if cfg.Format.Dictionary == "" {
		return nil, nil
	}
	d, err := mutate.LoadDictionary(cfg.Format.Dictionary)
	if err != nil {
		return nil, fmt.Errorf("worker: loading the dictionary: %w", err)
	}
	return d, nil
}

func suppressFor(cfg *campaign.Resolved) ir.Suppress {
	var s ir.Suppress
	for _, name := range cfg.Format.Suppress {
		switch name {
		case "length":
			s.Length = true
		case "count":
			s.Count = true
		case "offset":
			s.Offset = true
		case "checksum":
			s.Checksum = true
		}
	}
	return s
}

// objectivesFor builds what counts as a finding.
func objectivesFor(cfg *campaign.Resolved, out *feedback.OutputObserver, ext *extension.Set) feedback.Objective {
	var objs []feedback.Objective
	for _, name := range cfg.Feedback.Objectives {
		switch name {
		case "crash":
			objs = append(objs, feedback.NewCrashObjective("crash", out))
		case "hang":
			objs = append(objs, feedback.NewHangObjective("hang"))
		case "oom":
			objs = append(objs, feedback.NewOOMObjective("oom"))
		case "sanitizer":
			objs = append(objs, feedback.NewSanitizerObjective("sanitizer", out))
		}
	}
	objs = append(objs, ext.Objectives()...)

	if len(objs) == 1 {
		return objs[0]
	}
	return feedback.NewAnyObjective("objectives", objs...)
}

// loadSeeds fills the engine's corpus from the store.
//
// The daemon imported them, so every worker sees the same starting corpus
// without N of them racing to read the same directory. Entries are added rather
// than executed: their coverage is already the campaign's, and re-running the
// corpus in every worker is minutes of execution before anything new happens.
func loadSeeds(ctx context.Context, eng *engine.Engine, entries []*corpus.Testcase) (int, error) {
	loaded, _, err := eng.LoadCorpus(entries)
	if err != nil {
		return 0, err
	}
	if loaded == 0 {
		return 0, errors.New("worker: the campaign has no seeds")
	}
	return loaded, nil
}

// resolveStoreDir returns where the campaign's store lives.
func resolveStoreDir(cfg *campaign.Resolved, override string) string {
	switch {
	case override != "":
		return override
	case cfg.Storage.Dir != "":
		return cfg.Storage.Dir
	default:
		return ""
	}
}

// describe renders the executor tier and any fallback for the ready message.
func (b *built) describe() string {
	desc := b.tier
	if b.fallbackReason != "" {
		reason := strings.SplitN(b.fallbackReason, "\n", 2)[0]
		desc = fmt.Sprintf("%s (fell back: %s)", desc, reason)
	}
	if b.analysisNote != "" {
		desc = fmt.Sprintf("%s (%s)", desc, b.analysisNote)
	}
	if b.directionReport != "" {
		desc = fmt.Sprintf("%s; %s", desc, b.directionReport)
	}
	if b.directedNote != "" {
		desc = fmt.Sprintf("%s; %s", desc, b.directedNote)
	}
	return desc
}

// sessionAddress resolves the campaign's session address for one worker.
func sessionAddress(cfg *campaign.Resolved, workerID int) (string, error) {
	addr := campaign.ResolveAddress(cfg.Session.Address, workerID)
	if _, _, err := campaign.SplitAddress(addr); err != nil {
		return "", fmt.Errorf("worker: session address: %w", err)
	}
	return addr, nil
}

// socketDir returns the directory a Unix socket address lives in, or "".
func socketDir(addr string) string {
	if addr == "" {
		return ""
	}
	network, path, err := campaign.SplitAddress(addr)
	if err != nil || network != "unix" {
		return ""
	}
	return filepath.Dir(path)
}
