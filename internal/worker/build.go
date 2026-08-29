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
	closers  []func()
	closed   sync.Once

	// tier is which executor was actually used, which may not be the one asked
	// for, and fallbackReason says why when they differ. Reported to the daemon
	// in the ready message, so that a campaign which silently fell back to a
	// slower tier is visible in the first second rather than in a post-mortem.
	tier           string
	fallbackReason string
}

// close releases everything build acquired, in the reverse of the order it was
// acquired in.
//
// Once, because there are two paths to it — Run releases what it built when it
// returns, and a caller that owns the worker calls Close — and a second release
// is not harmless: closing a fork server twice used to mean two goroutines
// waiting for one process to die.
func (b *built) close() {
	b.closed.Do(func() {
		for i := len(b.closers) - 1; i >= 0; i-- {
			b.closers[i]()
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

	if err := b.buildSafety(ctx, cfg); err != nil {
		return nil, err
	}
	if err := b.buildFeedback(cfg); err != nil {
		return nil, err
	}
	if err := b.buildExecutor(ctx, cfg); err != nil {
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
		MaxChildren:   defaultMaxChildren,
		TrimBudget:    cfg.Mutation.TrimBudget,
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
	b.sandbox = &safety.Sandbox{
		Require:  level,
		Name:     cfg.Name,
		Target:   cfg.Target.Path,
		Network:  cfg.Safety.Network,
		Writable: cfg.Safety.Writable,
		Workdir:  cfg.Target.Dir,
		Limits: platform.Limits{
			AddressSpaceBytes: uint64(cfg.Safety.MemoryLimit),
			Processes:         uint64(cfg.Safety.ProcessLimit),
			FileSizeBytes:     uint64(cfg.Safety.FileSizeLimit),
			CPUSeconds:        uint64(cfg.Safety.CPULimit.Std().Seconds()),
			DisableCore:       true,
		},
	}
	b.closers = append(b.closers, func() { b.sandbox.Close() })
	return b.sandbox.Check(ctx)
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
	b.closers = append(b.closers, func() { shm.Close() })

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
		b.closers = append(b.closers, func() { fs.Close() })
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
	b.closers = append(b.closers, func() { sub.Close() })
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
