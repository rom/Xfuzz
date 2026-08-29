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
	"github.com/rom/Xfuzz/internal/platform"
	"github.com/rom/Xfuzz/internal/safety"
	"github.com/rom/Xfuzz/pkg/campaign"
	"github.com/rom/Xfuzz/pkg/codec"
	"github.com/rom/Xfuzz/pkg/corpus"
	"github.com/rom/Xfuzz/pkg/executor"
	"github.com/rom/Xfuzz/pkg/feedback"
	"github.com/rom/Xfuzz/pkg/ir"
	"github.com/rom/Xfuzz/pkg/mutate"
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
	mutators, err := mutatorsFor(cfg, strategy)
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
		Objective:     objectivesFor(cfg, b.output),
		Corpus:        corpus.New(),
		Schedule:      scheduleFor(cfg, strategy),
		Mutators:      mutators,
		Codec:         cdc,
		Dict:          dict,
		Suppress:      suppressFor(cfg),
		MaxInputBytes: cfg.Format.MaxInputBytes,
		MaxChildren:   maxChildrenFor(cfg),
		TrimBudget:    cfg.Mutation.TrimBudget,
		State:         b.state,
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

	if cfg.Feedback.Coverage == "none" {
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
	shm, err := provider.Create(cfg.Feedback.MapSize)
	if err != nil {
		return fmt.Errorf("worker: creating the coverage region: %w", err)
	}
	b.shm = shm
	b.closers = append(b.closers, closer{"coverage region", shm.Close})

	b.coverage = feedback.NewCoverageMap("coverage", cfg.Feedback.MapSize)
	b.coverage.SetBuffer(shm.Bytes())
	b.coverage.SetBackend(cfg.Feedback.Coverage)
	b.mapFB = feedback.NewMapFeedback("coverage", b.coverage)
	return nil
}

func (b *built) observers() []feedback.Observer {
	obs := []feedback.Observer{b.output}
	if b.coverage != nil {
		obs = append([]feedback.Observer{b.coverage}, obs...)
	}
	if b.state != nil {
		// The session executor feeds this one during the session rather than
		// after it, because that is the only time the replies exist. It still
		// belongs in the observer list: Pre is what returns the trace to the
		// start state, and an observer left out of the list is one whose trace
		// accumulates across every session the worker ever runs.
		obs = append(obs, b.state.Observer)
	}
	return obs
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
	if b.state != nil {
		// The reason ADR-0006 exists. Two sessions can execute identical lines
		// and leave the target in different places, so a stack with only
		// coverage in it throws away the handshake that unlocked a new region
		// of the protocol — the code was already covered.
		stack = append(stack, state.NewFeedback("state", b.state.Observer, b.state.Model))
	}
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
	if tier == campaign.ExecutorAuto {
		if b.coverage == nil {
			tier = campaign.ExecutorSubprocess
		} else {
			tier = campaign.ExecutorForkServer
		}
	}

	switch tier {
	case campaign.ExecutorForkServer:
		fs := executor.NewForkServer("forkserver", spawner, spec)
		fs.Coverage, fs.Shm, fs.Output = b.coverage, b.shm, b.output
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

	case campaign.ExecutorSubprocess:
		return b.buildSubprocess(cfg, spawner, spec)

	case campaign.ExecutorInProc:
		return errors.New("worker: the in-process tier is for Go harnesses linked into the fuzzer, " +
			"which the campaign file cannot express yet; use forkserver or subprocess")

	default:
		return fmt.Errorf("worker: unknown executor tier %q", tier)
	}
}

func (b *built) buildSubprocess(cfg *campaign.Resolved, spawner *safety.Spawner, spec executor.ProcSpec) error {
	sub := executor.NewSubprocess("subprocess", spawner, spec)
	sub.Output = b.output
	sub.Delivery = deliveryFor(cfg)
	if b.coverage != nil {
		sub.Coverage, sub.Shm = b.coverage, b.shm
		sub.Backend = cfg.Feedback.Coverage
	}
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
func mutatorsFor(cfg *campaign.Resolved, strategy string) (*mutate.Scheduler, error) {
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
		return corpus.NewFastScheduler()
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
func objectivesFor(cfg *campaign.Resolved, out *feedback.OutputObserver) feedback.Objective {
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
	if b.fallbackReason == "" {
		return b.tier
	}
	reason := strings.SplitN(b.fallbackReason, "\n", 2)[0]
	return fmt.Sprintf("%s (fell back: %s)", b.tier, reason)
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
