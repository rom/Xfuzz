package daemon

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/rom/Xfuzz/internal/metrics"
	"github.com/rom/Xfuzz/internal/safety"
	"github.com/rom/Xfuzz/internal/store"
	"github.com/rom/Xfuzz/internal/triage"
	"github.com/rom/Xfuzz/pkg/campaign"
	"github.com/rom/Xfuzz/pkg/corpus"
	"github.com/rom/Xfuzz/pkg/corpusio"
	"github.com/rom/Xfuzz/pkg/feedback"
	"github.com/rom/Xfuzz/pkg/generate"
	"github.com/rom/Xfuzz/pkg/ir"
	"github.com/rom/Xfuzz/pkg/rng"
	"github.com/rom/Xfuzz/pkg/schema"
)

// State is where a campaign is in its life.
type State string

// Campaign states. They are a fact about the store, not about a process: a
// daemon that dies leaves a campaign at "running", and resume is what
// reconciles that.
const (
	StateCreated  State = "created"
	StateRunning  State = "running"
	StatePaused   State = "paused"
	StateStopping State = "stopping"
	StateFinished State = "finished"
	StateFailed   State = "failed"
)

// ErrNotRunning is returned for an operation that needs a running campaign.
var ErrNotRunning = errors.New("daemon: the campaign is not running")

// Campaign is one supervised fuzzing run.
type Campaign struct {
	// Config is the resolved campaign file. It is what ran, and it is recorded
	// with the campaign so that six months later the run can be explained
	// (ADR-0016).
	Config *campaign.Resolved

	// Seed is the campaign's root RNG seed. With the config digest it is half
	// of what a byte-identical replay needs (ASR-0008).
	Seed uint64

	store   *store.Store
	bus     *Bus
	metrics *metrics.Collector
	sup     *Supervisor
	sandbox *safety.Sandbox
	scope   *safety.Scope

	// triage re-runs the target outside the fuzz loop: verification,
	// minimisation, and the on-demand replay a person asks for from the console
	// days later. Nil when the campaign disabled triage, and every entry point
	// says so rather than silently doing nothing.
	//
	// The runner outlives the campaign's run — a finding is examined after the
	// campaign that produced it has finished — while triageQueue, which does
	// the automatic pass over new findings, stops with the workers.
	triage      *Triage
	triageQueue *triage.Worker

	id      int64
	binary  string
	workDir string

	mu      sync.Mutex
	state   State
	started time.Time
	stopped time.Time
	reason  string
	lastNew time.Time
	// bucketOf maps each finding to the bucket it currently belongs to, rather
	// than recording the set of buckets seen. Two things file a finding: the
	// engine, whose in-loop bucketing is deliberately cheap, and triage, which
	// re-buckets from the minimised reproducer and an execution it watched
	// itself. They disagree by design, and a set would then hold two entries
	// for one bug — so the campaign tracks where each finding *is*, and counts
	// the distinct answers.
	// stateReports holds each worker's latest state graph. Kept per worker and
	// merged on demand rather than merged as they arrive: a worker restarting
	// replaces its own contribution, where a running merge would leave the
	// dead worker's states in the campaign's graph forever.
	stateReports map[int]*StateReport

	bucketOf  map[int64]string
	findings  int
	seen      map[string]bool
	execsBase uint64

	cancel context.CancelFunc
	done   chan struct{}

	// pendingSync batches corpus entries so a burst of discoveries becomes one
	// broadcast rather than one per entry. Workers do not need each other's
	// finds instantly; they need them cheaply.
	syncMu      sync.Mutex
	pendingSync map[int][]CorpusEntry
}

// CampaignOptions are what a campaign needs beyond its file.
type CampaignOptions struct {
	// Store holds the corpus, findings, checkpoints and audit log.
	Store *store.Store

	// Bus carries events to API clients and between workers.
	Bus *Bus

	// Spawner starts worker processes. It must be a trusted spawner: a worker
	// is Xfuzz's own binary, and the target inside it is confined by the
	// worker's own sandbox.
	Spawner Spawner

	// WorkerBinary is the xfuzz-worker executable.
	WorkerBinary string

	// WorkDir is where workers run.
	WorkDir string

	// Seed is the campaign's root RNG seed. Zero draws one and records it,
	// because a campaign whose seed was never written down is a campaign that
	// cannot be replayed.
	Seed uint64

	// Retention bounds the metrics history.
	Retention time.Duration
}

// NewCampaign prepares a campaign without starting it.
func NewCampaign(ctx context.Context, cfg *campaign.Resolved, opts CampaignOptions) (*Campaign, error) {
	if opts.Store == nil {
		return nil, errors.New("daemon: a campaign needs a store")
	}
	if opts.Bus == nil {
		opts.Bus = NewBus(250 * time.Millisecond)
	}
	if opts.Retention == 0 {
		opts.Retention = 24 * time.Hour
	}

	seed := opts.Seed
	if seed == 0 {
		seed = drawSeed()
	}

	c := &Campaign{
		Config:       cfg,
		Seed:         seed,
		store:        opts.Store,
		bus:          opts.Bus,
		metrics:      metrics.NewCollector(opts.Retention),
		binary:       opts.WorkerBinary,
		workDir:      opts.WorkDir,
		state:        StateCreated,
		bucketOf:     map[int64]string{},
		stateReports: map[int]*StateReport{},
		seen:         map[string]bool{},
		pendingSync:  map[int][]CorpusEntry{},
		done:         make(chan struct{}),
	}

	if err := c.prepareSafety(ctx); err != nil {
		return nil, err
	}

	rec, err := opts.Store.Campaign(ctx, cfg.Name)
	switch {
	case err == nil:
		// Resuming. The seed and the configuration digest come from the store,
		// not from the file: a resumed campaign that adopted a new seed would
		// be a different campaign wearing the same name.
		c.id, c.Seed = rec.ID, rec.Seed
		if rec.ConfigDigest != c.configDigest() {
			c.warn("the campaign file has changed since this campaign was created; " +
				"the corpus is kept but the run is no longer a continuation of the same configuration")
		}
	case errors.Is(err, store.ErrNoCampaign):
		// The resolved document goes in with the digest. What ran has to be
		// readable from the store alone, or triaging a finished campaign means
		// first finding the file that produced it.
		doc, derr := cfg.YAML()
		if derr != nil {
			return nil, fmt.Errorf("daemon: rendering the campaign's configuration: %w", derr)
		}
		created, cerr := opts.Store.CreateCampaign(ctx, cfg.Name, c.configDigest(), string(doc), seed)
		if cerr != nil {
			return nil, cerr
		}
		c.id = created.ID
	default:
		return nil, err
	}

	if cfg.Triage.Enabled != nil && *cfg.Triage.Enabled {
		c.triage = NewTriage(cfg, c.sandbox)
		c.triageQueue = triage.NewWorker(triage.Config{
			Runner:       c.triage,
			Strategy:     triage.StrategyNamed(cfg.Triage.Strategy),
			Classifier:   triage.NewClassifier(cfg.Triage.Markers...),
			Trials:       cfg.Triage.Trials,
			SkipMinimize: cfg.Triage.Minimize != nil && !*cfg.Triage.Minimize,
			MinimizeOpts: triage.MinimizeOptions{MaxRuns: cfg.Triage.MinimizeBudget},
			// One at a time. More than one means more than one copy of the
			// target running, which for a target that binds a port or writes a
			// fixed path is wrong, and triage is off the hot path anyway.
			Workers: 1,
			Report:  c.onTriaged,
		})
	}

	if c.workDir != "" {
		if err := c.writeCampaignFile(); err != nil {
			return nil, err
		}
	}

	c.sup = NewSupervisor(cfg.Name, opts.Spawner, opts.Bus)
	c.sup.OnMessage = c.onMessage
	return c, nil
}

// prepareSafety builds the scope guard and the sandbox policy, and refuses the
// campaign if the host cannot meet what it asked for.
//
// Before anything starts, so a misconfiguration fails immediately rather than
// after the first packet or the first unconfined execution (ADR-0012).
func (c *Campaign) prepareSafety(ctx context.Context) error {
	s := c.Config.Safety

	scope := safety.NewScope()
	scope.Auditor = auditFunc(func(actor, action, detail string) error {
		_, err := c.store.Audit(ctx, actor, action, detail)
		return err
	})
	if s.Scope != nil {
		if s.Scope.Loopback != nil {
			scope.AllowLoopback = *s.Scope.Loopback
		}
		scope.AcknowledgePublic = s.Scope.AcknowledgePublic
		for _, entry := range s.Scope.Allow {
			dest, ports, err := campaign.ParseAllow(entry)
			if err != nil {
				return err
			}
			var ranges []safety.PortRange
			for _, p := range ports {
				lo, hi, err := parsePortRange(p)
				if err != nil {
					return err
				}
				ranges = append(ranges, safety.PortRange{Lo: lo, Hi: hi})
			}
			if err := scope.Allow(dest, ranges...); err != nil {
				return err
			}
		}
	}
	if err := scope.Validate(s.Network); err != nil {
		return err
	}
	c.scope = scope

	if s.Network {
		auth := &safety.Authorization{}
		if a := s.Authorization; a != nil {
			auth.Operator, auth.Reference, auth.Attestation = a.Operator, a.Reference, a.Attestation
		}
		if err := safety.Authorize(ctx, scope.Auditor, scope, auth, true); err != nil {
			return err
		}
	}

	level, err := safety.ParseLevel(s.Isolation)
	if err != nil {
		return err
	}
	// A session campaign's target binds a socket, and the daemon runs one of its
	// own for triage. The read-only root must not cover where it goes, and the
	// target's unprivileged identity must be able to create it — the same
	// arrangement the worker makes for its own copy, and for the same reason:
	// the path is one Xfuzz chose, so it is Xfuzz's job to make it usable.
	writable := s.Writable
	var creates []string
	if c.Config.Session != nil {
		addr := campaign.ResolveAddress(c.Config.Session.Address, triageWorkerID)
		if network, path, aerr := campaign.SplitAddress(addr); aerr == nil && network == "unix" {
			writable = append(append([]string(nil), writable...), filepath.Dir(path))
			creates = append(creates, path)
		}
	}

	c.sandbox = &safety.Sandbox{
		Require:  level,
		Name:     c.Config.Name,
		Target:   c.Config.Target.Path,
		Network:  s.Network,
		Writable: writable,
		Creates:  creates,
		Workdir:  c.Config.Target.Dir,
		Auditor:  scope.Auditor,
	}
	return c.sandbox.Check(ctx)
}

// Start launches the campaign's workers.
func (c *Campaign) Start(ctx context.Context) error {
	c.mu.Lock()
	if c.state == StateRunning {
		c.mu.Unlock()
		return errors.New("daemon: the campaign is already running")
	}
	c.state = StateRunning
	c.started = time.Now()
	c.lastNew = c.started
	c.mu.Unlock()

	if err := c.store.SetCampaignStatus(ctx, c.id, store.StatusRunning); err != nil {
		return err
	}
	if _, err := c.store.Audit(ctx, "", store.AuditCampaignStart,
		fmt.Sprintf("campaign=%s workers=%d seed=%d isolation=%s",
			c.Config.Name, c.Config.Workers.Count, c.Seed, c.sandbox.Level())); err != nil {
		return err
	}
	if err := c.importSeeds(ctx); err != nil {
		return err
	}

	runCtx, cancel := context.WithCancel(ctx)
	c.cancel = cancel

	if c.triageQueue != nil {
		// context.WithoutCancel: triage must finish the finding it is holding
		// even as the campaign stops, because a finding recorded but never
		// examined is the one a person will look at first.
		c.triageQueue.Start(context.WithoutCancel(runCtx))
	}

	for id := 0; id < c.Config.Workers.Count; id++ {
		spec := WorkerSpec{
			ID:       id,
			Binary:   c.binary,
			Args:     c.workerArgs(id),
			Env:      c.workerEnv(id),
			Dir:      c.workDir,
			Strategy: c.strategyFor(id),
		}
		if err := c.sup.Start(runCtx, spec); err != nil {
			cancel()
			return err
		}
	}

	c.publish(EventCampaign, map[string]any{"state": string(StateRunning), "workers": c.Config.Workers.Count})
	go c.run(runCtx)
	return nil
}

// strategyFor assigns ensemble strategies round-robin.
//
// Round-robin rather than one strategy per worker, so that writing three
// strategies for eight workers is a sensible thing to do. Strategy diversity
// across workers beats N identical workers (ADR-0015).
func (c *Campaign) strategyFor(id int) string {
	ss := c.Config.Workers.Strategies
	if len(ss) == 0 {
		return ""
	}
	return ss[id%len(ss)].Name
}

// run watches for termination and drives periodic work.
func (c *Campaign) run(ctx context.Context) {
	defer close(c.done)

	tick := time.NewTicker(500 * time.Millisecond)
	defer tick.Stop()
	syncTick := time.NewTicker(c.syncInterval())
	defer syncTick.Stop()
	checkpointTick := time.NewTicker(c.Config.Storage.CheckpointInterval.Std())
	defer checkpointTick.Stop()

	for {
		select {
		case <-ctx.Done():
			c.finish(context.WithoutCancel(ctx), "cancelled")
			return
		case <-syncTick.C:
			c.flushSync()
		case <-checkpointTick.C:
			c.sup.Broadcast(&Message{Type: CmdCheckpoint}, -1)
		case <-tick.C:
			if reason := c.terminationReason(); reason != "" {
				c.finish(context.WithoutCancel(ctx), reason)
				return
			}
			if c.sup.Healthy() == 0 && len(c.sup.Status()) > 0 && c.allWorkersDone() {
				c.finish(context.WithoutCancel(ctx), "all workers finished")
				return
			}
		}
	}
}

func (c *Campaign) syncInterval() time.Duration {
	d := c.Config.Workers.SyncInterval.Std()
	if d <= 0 {
		d = 5 * time.Second
	}
	return d
}

func (c *Campaign) allWorkersDone() bool {
	for _, st := range c.sup.Status() {
		switch st.State {
		case WorkerStopped, WorkerFailed:
		default:
			return false
		}
	}
	return true
}

// terminationReason reports why the campaign should stop, or "".
//
// Termination is a first-class part of the campaign file because CI usage
// requires a campaign to end deterministically (ASR-0015). Checking it here
// rather than in each worker means a budget is the campaign's, not each
// worker's — "stop after a million executions" must not mean a million per
// worker.
func (c *Campaign) terminationReason() string {
	stop := c.Config.Stop
	if stop.IsZero() {
		return ""
	}
	snap := c.metrics.Snapshot()

	c.mu.Lock()
	started, lastNew, buckets := c.started, c.lastNew, c.distinctBuckets()
	c.mu.Unlock()

	if stop.After > 0 && time.Since(started) >= stop.After.Std() {
		return fmt.Sprintf("time budget of %s reached", stop.After)
	}
	if stop.Execs > 0 && snap.Execs >= stop.Execs {
		return fmt.Sprintf("execution budget of %d reached", stop.Execs)
	}
	if stop.Findings > 0 && buckets >= stop.Findings {
		return fmt.Sprintf("%d distinct findings reached", buckets)
	}
	if stop.NoNewCoverage > 0 && time.Since(lastNew) >= stop.NoNewCoverage.Std() {
		return fmt.Sprintf("no new coverage for %s", stop.NoNewCoverage)
	}
	return ""
}

// finish stops the workers and records why.
func (c *Campaign) finish(ctx context.Context, reason string) {
	c.mu.Lock()
	if c.state == StateFinished || c.state == StateStopping {
		c.mu.Unlock()
		return
	}
	c.state = StateStopping
	c.reason = reason
	c.mu.Unlock()

	c.publish(EventCampaign, map[string]any{"state": string(StateStopping), "reason": reason})
	c.sup.Stop(10 * time.Second)
	c.flushSync()

	// After the workers, so every finding they reported is queued, and before
	// the campaign is declared finished, so "finished" means triage is done
	// too. On-demand replay and minimisation stay available: the runner is not
	// closed here.
	c.mu.Lock()
	q := c.triageQueue
	c.triageQueue = nil
	c.mu.Unlock()
	if q != nil {
		q.Close()
	}

	c.mu.Lock()
	c.state = StateFinished
	c.stopped = time.Now()
	c.mu.Unlock()

	_ = c.store.SetCampaignStatus(ctx, c.id, store.StatusFinished)
	_, _ = c.store.Audit(ctx, "", store.AuditCampaignStop,
		fmt.Sprintf("campaign=%s reason=%q execs=%d buckets=%d",
			c.Config.Name, reason, c.metrics.Snapshot().Execs, c.bucketCount()))
	c.publish(EventCampaign, map[string]any{"state": string(StateFinished), "reason": reason})
}

// Close releases what the campaign holds after it is no longer wanted.
//
// Separate from finish: a finished campaign is still answerable — its findings
// are replayed and minimised long after its workers are gone — so the triage
// runner and the sandbox outlive the run and are released only when the
// campaign itself is dropped.
func (c *Campaign) Close() error {
	c.mu.Lock()
	q := c.triageQueue
	c.triageQueue = nil
	c.mu.Unlock()
	if q != nil {
		q.Close()
	}
	if c.triage != nil {
		_ = c.triage.Close()
	}
	if c.sandbox != nil {
		return c.sandbox.Close()
	}
	return nil
}

// Stop ends the campaign.
func (c *Campaign) Stop(ctx context.Context, reason string) error {
	c.mu.Lock()
	state := c.state
	cancel := c.cancel
	c.mu.Unlock()

	if state != StateRunning && state != StatePaused {
		return ErrNotRunning
	}
	if reason == "" {
		reason = "stopped by request"
	}
	c.finish(ctx, reason)
	if cancel != nil {
		cancel()
	}
	return nil
}

// Pause suspends fuzzing without losing the workers' in-memory state, which a
// stop and restart would.
func (c *Campaign) Pause(ctx context.Context) error {
	c.mu.Lock()
	if c.state != StateRunning {
		c.mu.Unlock()
		return ErrNotRunning
	}
	c.state = StatePaused
	c.mu.Unlock()

	c.sup.Broadcast(&Message{Type: CmdPause}, -1)
	_ = c.store.SetCampaignStatus(ctx, c.id, store.StatusPaused)
	c.publish(EventCampaign, map[string]any{"state": string(StatePaused)})
	return nil
}

// Resume restarts a paused campaign.
func (c *Campaign) Resume(ctx context.Context) error {
	c.mu.Lock()
	if c.state != StatePaused {
		c.mu.Unlock()
		return errors.New("daemon: the campaign is not paused")
	}
	c.state = StateRunning
	c.mu.Unlock()

	c.sup.Broadcast(&Message{Type: CmdResume}, -1)
	_ = c.store.SetCampaignStatus(ctx, c.id, store.StatusRunning)
	c.publish(EventCampaign, map[string]any{"state": string(StateRunning)})
	return nil
}

// Wait blocks until the campaign has finished.
func (c *Campaign) Wait() { <-c.done }

// State returns the campaign's current state.
func (c *Campaign) State() State {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.state
}

// ID returns the campaign's store id.
func (c *Campaign) ID() int64 { return c.id }

// Metrics returns the metrics collector.
func (c *Campaign) Metrics() *metrics.Collector { return c.metrics }

// Workers returns the supervisor's view of the workers.
func (c *Campaign) Workers() []WorkerStatus { return c.sup.Status() }

// Sandbox returns the confinement policy in force.
func (c *Campaign) Sandbox() *safety.Sandbox { return c.sandbox }

// Scope returns the network allowlist in force.
func (c *Campaign) Scope() *safety.Scope { return c.scope }

// Status is the campaign summary the API returns.
type Status struct {
	Name  string `json:"name"`
	State State  `json:"state"`
	// Seed is written as a JSON string, not a number.
	//
	// It is a 64-bit identifier, and JSON numbers are IEEE doubles in every
	// browser: 14879488505964903031 arrives as 14879488505964902000. A seed is
	// half of what a byte-identical replay needs (ASR-0008), so a console
	// showing one that is close but wrong is worse than one showing none. Go
	// clients still decode it into a uint64.
	Seed      uint64               `json:"seed,string"`
	Profiles  []string             `json:"profiles,omitempty"`
	Started   time.Time            `json:"started,omitempty"`
	Stopped   time.Time            `json:"stopped,omitempty"`
	Reason    string               `json:"reason,omitempty"`
	Isolation string               `json:"isolation"`
	Metrics   metrics.Snapshot     `json:"metrics"`
	Health    []metrics.Diagnostic `json:"health,omitempty"`
	Workers   []WorkerStatus       `json:"workers,omitempty"`
}

// Status returns everything a client needs to render the campaign.
func (c *Campaign) Status() Status {
	c.mu.Lock()
	state, started, stopped, reason := c.state, c.started, c.stopped, c.reason
	c.mu.Unlock()

	snap := c.aggregate()
	snap.WorkersHealthy = c.sup.Healthy()
	snap.Workers = len(c.sup.Status())

	elapsed := time.Duration(0)
	if !started.IsZero() {
		end := time.Now()
		if !stopped.IsZero() {
			end = stopped
		}
		elapsed = end.Sub(started)
	}

	phase := metrics.PhaseStopped
	if state == StateRunning {
		phase = metrics.PhaseRunning
	}

	return Status{
		Name:      c.Config.Name,
		State:     state,
		Seed:      c.Seed,
		Profiles:  c.Config.Profiles,
		Started:   started,
		Stopped:   stopped,
		Reason:    reason,
		Isolation: c.sandbox.Level().String(),
		Metrics:   snap,
		Health:    metrics.Health(snap, elapsed, metrics.DefaultThresholds(), phase),
		Workers:   c.sup.Status(),
	}
}

// distinctBuckets counts the buckets findings are currently filed under. The
// caller holds c.mu.
func (c *Campaign) distinctBuckets() int {
	seen := make(map[string]struct{}, len(c.bucketOf))
	for _, key := range c.bucketOf {
		seen[key] = struct{}{}
	}
	return len(seen)
}

// hasBucket reports whether any finding is already filed under a key. The
// caller holds c.mu.
func (c *Campaign) hasBucket(key string) bool {
	for _, k := range c.bucketOf {
		if k == key {
			return true
		}
	}
	return false
}

// bucketCount is distinctBuckets for a caller that does not hold c.mu.
func (c *Campaign) bucketCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.distinctBuckets()
}

// aggregate returns the campaign's counters.
//
// The collector's total for everything the workers measure, and the campaign's
// own record for findings and buckets. A worker knows what it found; only the
// campaign has seen every worker's reports, so only it can tell two workers
// finding the same bug from two workers finding different ones — and a live
// view that disagrees with the campaign's own final status is worse than no
// live view.
func (c *Campaign) aggregate() metrics.Snapshot {
	snap := c.metrics.Snapshot()
	c.mu.Lock()
	snap.Findings, snap.Buckets = c.findings, c.distinctBuckets()
	c.mu.Unlock()

	// Protocol coverage comes from the merged graph rather than from the
	// workers' counters, for the same reason findings do: the campaign has
	// explored a state when any worker has, so the campaign's number is the
	// union and no worker holds it. Taking the largest a worker reported
	// under-counts whenever two workers explore different parts of the
	// protocol, which is the case a campaign runs several workers for.
	//
	// It also settles which of two numbers is right. The counters travel on
	// the reporting interval and the graph on the checkpoint interval, so they
	// disagree for as long as the gap between them — measured as a finished
	// campaign whose status said ten states while its graph held nine, on the
	// criterion whose whole subject is that this number is reported.
	if model := c.StateModel(); model != nil && len(model.States) > 0 {
		snap.States = len(model.States)
		snap.Transitions = len(model.Transitions)
		snap.IllegalMoves = len(model.Illegal)
	}
	return snap
}

// onMessage handles one worker message. It runs on the supervisor's reader
// goroutine, so nothing here may block for long.
func (c *Campaign) onMessage(worker int, m *Message) {
	ctx := context.Background()

	switch m.Type {
	case MsgReady:
		if m.Ready != nil {
			c.publish(EventWorker, map[string]any{
				"worker": worker, "state": "ready", "executor": m.Ready.Executor,
				"isolation": m.Ready.Isolation, "strategy": m.Ready.Strategy,
				"seeds": m.Ready.Seeds,
			})
		}

	case MsgMetrics:
		if m.Metrics != nil {
			c.metrics.Report(worker, *m.Metrics)
			// The campaign's aggregate, not the reporting worker's own
			// counters. Two things make that the right payload. A reader wants
			// the campaign's rate — one worker's figure looks like a campaign
			// running at half speed on two workers, and disagrees with the
			// final status for the same run. And the bus coalesces this kind on
			// the premise that only the newest matters, which holds for a total
			// and does not hold for a stream of per-worker numbers where the
			// newest is whichever worker happened to report last. Per-worker
			// counters are still exact, from the workers endpoint.
			snap := c.aggregate()
			c.bus.Publish(Event{Kind: EventMetrics, Campaign: c.Config.Name, Data: &snap})
		}

	case MsgCorpus:
		c.onCorpus(ctx, worker, m.Entries)

	case MsgFinding:
		c.onFinding(ctx, worker, m.Finding)

	case MsgCheckpoint:
		c.onCheckpoint(ctx, worker, m.Checkpoint)

	case MsgStates:
		c.onStates(worker, m.States)

	case MsgStopped:
		c.publish(EventWorker, map[string]any{"worker": worker, "state": "stopped", "reason": m.Reason})

	case MsgLog:
		c.bus.Publish(Event{Kind: EventLog, Campaign: c.Config.Name, Worker: worker,
			Data: map[string]any{"level": m.Level, "text": m.Text}})
	}
}

// onCorpus records newly admitted entries and queues them for siblings.
func (c *Campaign) onCorpus(ctx context.Context, worker int, entries []CorpusEntry) {
	if len(entries) == 0 {
		return
	}
	tcs := make([]*corpus.Testcase, 0, len(entries))
	fresh := make([]CorpusEntry, 0, len(entries))

	c.mu.Lock()
	for _, e := range entries {
		if c.seen[e.Digest] {
			continue
		}
		c.seen[e.Digest] = true
		fresh = append(fresh, e)
	}
	if len(fresh) > 0 {
		c.lastNew = time.Now()
	}
	c.mu.Unlock()

	for _, e := range fresh {
		tc := corpus.NewTestcase(nil, e.Payload)
		tc.Meta.Coverage = e.Coverage
		tc.Meta.Score = feedback.Score{NewSignal: e.NewSignal}
		tc.Meta.ExecTime = time.Duration(e.ExecTime)
		tc.Meta.Depth = e.Depth
		tc.Meta.Favoured = e.Favoured
		tc.Prov.Worker = uint32(worker)
		tc.Prov.Origin = e.Origin
		tcs = append(tcs, tc)
	}
	if len(tcs) == 0 {
		return
	}
	if err := c.store.SaveTestcases(ctx, c.id, tcs); err != nil {
		c.warn("saving corpus entries: " + err.Error())
		return
	}

	c.syncMu.Lock()
	c.pendingSync[worker] = append(c.pendingSync[worker], fresh...)
	c.syncMu.Unlock()

	c.bus.Publish(Event{Kind: EventCorpus, Campaign: c.Config.Name, Worker: worker,
		Data: map[string]any{"entries": len(fresh)}})
	c.bus.Publish(Event{Kind: EventCoverage, Campaign: c.Config.Name, Worker: worker,
		Data: map[string]any{"coverage": entries[len(entries)-1].Coverage}})
}

// flushSync broadcasts queued discoveries to the workers that did not make them.
//
// Batched rather than immediate: workers do not need each other's finds
// instantly, they need them cheaply, and a burst of fifty discoveries should
// cost one round of messages rather than fifty.
func (c *Campaign) flushSync() {
	c.syncMu.Lock()
	pending := c.pendingSync
	c.pendingSync = map[int][]CorpusEntry{}
	c.syncMu.Unlock()

	for from, entries := range pending {
		if len(entries) == 0 {
			continue
		}
		for i := range entries {
			// Marked so provenance does not claim the receiving worker found it.
			entries[i].Origin = fmt.Sprintf("sync:worker-%d", from)
		}
		c.sup.Broadcast(&Message{Type: CmdSync, Entries: entries}, from)
	}
}

// onFinding records a crash and its reproducer.
func (c *Campaign) onFinding(ctx context.Context, worker int, f *FindingReport) {
	if f == nil {
		return
	}
	digest, err := parseDigest(f.Digest)
	if err != nil {
		c.warn("finding has an unreadable digest: " + err.Error())
		return
	}

	rec := &store.Finding{
		CampaignID:   c.id,
		Digest:       digest,
		OriginalSize: len(f.Payload),
		Finding: feedback.Finding{
			Kind: f.Kind, Signal: f.Signal, Summary: f.Summary,
			Detail: f.Detail, Frames: f.Frames,
		},
		FoundAtExec: f.FoundAtExec,
	}
	strategy, signature := f.Strategy, f.Signature
	if strategy == "" {
		strategy = "signal"
	}
	if signature == "" {
		signature = fmt.Sprintf("%s/sig%d", f.Kind, f.Signal)
	}
	rec.SetBucket(strategy, signature)

	if err := c.store.SaveFinding(ctx, rec, f.Payload); err != nil {
		c.warn("saving a finding: " + err.Error())
		return
	}

	c.mu.Lock()
	key := strategy + ":" + signature
	isNew := !c.hasBucket(key)
	c.bucketOf[rec.ID] = key
	c.findings++
	buckets := c.distinctBuckets()
	c.mu.Unlock()

	c.bus.Publish(Event{Kind: EventFinding, Campaign: c.Config.Name, Worker: worker,
		Data: map[string]any{
			"id": rec.ID, "kind": f.Kind, "signal": f.Signal, "summary": f.Summary,
			"bucket": signature, "new_bucket": isNew, "buckets": buckets,
		}})

	// And now the slow part, off this goroutine. Submit never blocks: this runs
	// on the supervisor's reader, and a reader waiting on triage is a worker
	// waiting to report.
	c.submitTriage(triage.Job{
		ID:    rec.ID,
		Input: f.Payload,
		Observed: triage.Outcome{
			Signal:  f.Signal,
			Finding: rec.Finding,
		},
	})
}

// submitTriage queues a finding for the automatic pass, if there still is one.
//
// Under the lock for the whole submission, not just to read the queue. Closing
// a triage worker closes its job channel, so a submission that raced the close
// would panic rather than be dropped — and Submit itself never blocks, so
// holding the lock across it costs nothing.
func (c *Campaign) submitTriage(job triage.Job) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.triageQueue != nil {
		c.triageQueue.Submit(job)
	}
}

// onTriaged records what triage concluded about a finding.
//
// It runs on the triage worker's own goroutine, so it may take its time; what
// it must not do is disagree silently with what was already published. A
// finding that does not reproduce keeps its row and gains a state saying so,
// rather than disappearing — "we looked and it is not real" is a result, and
// deleting it would make the same crash a new finding an hour later.
func (c *Campaign) onTriaged(res triage.Result) {
	ctx := context.Background()
	if res.Err != nil {
		c.warn(fmt.Sprintf("triaging finding %d: %v", res.ID, res.Err))
		return
	}

	f, err := c.store.Finding(ctx, res.ID)
	if err != nil {
		c.warn(fmt.Sprintf("triage cannot find finding %d: %v", res.ID, err))
		return
	}

	minimized := f.Minimized
	size := f.MinimizedSize
	if len(res.Minimized) > 0 && len(res.Minimized) < f.OriginalSize {
		if d, err := c.store.PutBlob(ctx, res.Minimized); err == nil {
			minimized, size = d, len(res.Minimized)
		} else {
			c.warn(fmt.Sprintf("storing the minimised reproducer for finding %d: %v", res.ID, err))
		}
	}

	diagnosis := res.Verify.String()
	if res.Minimize.OriginalSize > 0 {
		diagnosis += "; " + res.Minimize.String()
	}
	if err := c.store.UpdateTriage(ctx, res.ID, res.State, res.Verify.Trials, res.Verify.Rate(),
		minimized, size, diagnosis); err != nil {
		c.warn(fmt.Sprintf("recording triage for finding %d: %v", res.ID, err))
		return
	}

	// Triage's bucket is computed from the minimised reproducer and from an
	// execution it watched itself, so it is better evidence than the worker's —
	// but only when it actually saw the failure. A reproducer that did not
	// reproduce yields no evidence at all, and filing every such finding under
	// one signature would merge unrelated bugs into a single bucket for the
	// sole reason that none of them could be re-run.
	if res.Signature != "" && res.Verify.Reproduced > 0 {
		if err := c.store.Rebucket(ctx, res.ID, res.Strategy, res.Signature); err != nil {
			c.warn(fmt.Sprintf("re-bucketing finding %d: %v", res.ID, err))
		} else {
			// Replaces the engine's provisional bucket for this finding
			// rather than joining it: they are two answers to one question,
			// and triage's is the better evidenced.
			c.mu.Lock()
			c.bucketOf[res.ID] = res.Strategy + ":" + res.Signature
			c.mu.Unlock()
		}
	}

	c.publish(EventTriage, map[string]any{
		"finding": res.ID, "state": res.State,
		"trials": res.Verify.Trials, "rate": res.Verify.Rate(),
		"bucket": res.Signature, "strategy": res.Strategy,
		"original_size": f.OriginalSize, "minimized_size": size,
	})
}

// onCheckpoint records a worker's resume state.
func (c *Campaign) onCheckpoint(ctx context.Context, worker int, cp *CheckpointState) {
	if cp == nil {
		return
	}
	// Worker 0's checkpoint is the campaign's. Every worker's coverage map is
	// the union of what it has seen, and the campaign's corpus is shared, so
	// one worker's state is enough to resume from — and writing every worker's
	// would make the checkpoint N times larger for nothing.
	if worker != 0 {
		return
	}
	if err := c.store.SaveCheckpoint(ctx, c.id, &store.Checkpoint{
		Coverage:     cp.Coverage,
		Execs:        cp.Execs,
		CorpusSize:   cp.CorpusSize,
		RNGPositions: cp.RNG,
	}); err != nil {
		c.warn("saving a checkpoint: " + err.Error())
	}
}

// importSeeds loads the campaign's starting corpus into the store.
//
// The daemon does it rather than each worker, so N workers do not each read the
// same directory and race to insert the same entries.
func (c *Campaign) importSeeds(ctx context.Context) error {
	s := c.Config.Seeds
	for _, dir := range s.Dirs {
		format, err := corpusio.ParseFormat(s.Format)
		if err != nil {
			return err
		}
		rep, err := c.store.ImportCorpus(ctx, c.id, dir, corpusio.ImportOptions{
			Format:      format,
			MaxFileSize: s.MaxFileSize,
		})
		if err != nil {
			return err
		}
		c.log("info", "imported "+rep.String())
	}
	if len(s.Inline) > 0 {
		tcs := make([]*corpus.Testcase, 0, len(s.Inline))
		for _, lit := range s.Inline {
			tc := corpus.NewTestcase(nil, []byte(lit))
			tc.Prov.Origin = "inline"
			tcs = append(tcs, tc)
		}
		if err := c.store.SaveTestcases(ctx, c.id, tcs); err != nil {
			return err
		}
	}
	if s.Generate > 0 {
		if err := c.generateSeeds(ctx, s.Generate); err != nil {
			return err
		}
	}
	return nil
}

// generateSeeds fills the corpus from the campaign's grammar.
//
// A campaign with a grammar and no corpus is not stuck: it can write its own
// starting inputs, and inputs a grammar produced are structurally valid in a
// way random bytes never are. The alternative is what this used to do — accept
// the configuration, import nothing, and leave the engine with an empty corpus
// and no account of why.
//
// Seeded from the campaign's own seed, so the same campaign generates the same
// starting corpus (ASR-0008). A generated corpus that differed run to run would
// make every comparison between two runs meaningless.
func (c *Campaign) generateSeeds(ctx context.Context, count int) error {
	sch, err := schema.ParseFile(c.Config.Format.Grammar)
	if err != nil {
		return fmt.Errorf("daemon: reading the grammar: %w", err)
	}
	gen := generate.New(sch)
	r := rng.Derive(c.Seed, 0, rng.StreamGenerate)
	arena := ir.NewArena()

	tcs := make([]*corpus.Testcase, 0, count)
	seen := map[corpus.Digest]bool{}
	for i := 0; i < count; i++ {
		arena.Reset()
		node, gerr := gen.Generate(arena, r)
		if gerr != nil {
			return fmt.Errorf("daemon: generating a seed: %w", gerr)
		}
		payload := ir.Encode(node)
		tc := corpus.NewTestcase(nil, payload)
		if seen[tc.ID] {
			// A grammar with few shapes repeats itself. Duplicates are dropped
			// rather than counted, so "generate: 100" means a hundred inputs
			// where it can and says so where it cannot.
			continue
		}
		seen[tc.ID] = true
		tc.Prov.Origin = "generated"
		tcs = append(tcs, tc)
	}
	if err := c.store.SaveTestcases(ctx, c.id, tcs); err != nil {
		return err
	}
	c.log("info", fmt.Sprintf("generated %d seed(s) from %s",
		len(tcs), filepath.Base(c.Config.Format.Grammar)))
	if len(tcs) < count {
		c.warn(fmt.Sprintf("the grammar produced %d distinct inputs from %d attempts; "+
			"it may have fewer shapes than the campaign asked for", len(tcs), count))
	}
	return nil
}

func (c *Campaign) configDigest() string {
	b, err := c.Config.YAML()
	if err != nil {
		return ""
	}
	return corpus.DigestOf(b).String()
}

func (c *Campaign) publish(kind EventKind, data any) {
	c.bus.Publish(Event{Kind: kind, Campaign: c.Config.Name, Data: data})
}

func (c *Campaign) log(level, text string) {
	c.bus.Publish(Event{Kind: EventLog, Campaign: c.Config.Name,
		Data: map[string]any{"level": level, "text": text}})
}

func (c *Campaign) warn(text string) { c.log("warn", text) }

// auditFunc adapts a function to safety.Auditor.
type auditFunc func(actor, action, detail string) error

func (f auditFunc) Audit(_ context.Context, actor, action, detail string) error {
	return f(actor, action, detail)
}

func parseDigest(s string) (corpus.Digest, error) {
	var d corpus.Digest
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != len(d) {
		return d, fmt.Errorf("%q is not a digest", s)
	}
	copy(d[:], b)
	return d, nil
}

func parsePortRange(s string) (lo, hi uint16, err error) {
	var l, h int
	n, _ := fmt.Sscanf(s, "%d-%d", &l, &h)
	if n == 2 {
		return uint16(l), uint16(h), nil
	}
	if _, err := fmt.Sscanf(s, "%d", &l); err != nil {
		return 0, 0, fmt.Errorf("daemon: %q is not a port range", s)
	}
	return uint16(l), uint16(l), nil
}

// Store returns the store this campaign writes to.
func (c *Campaign) Store() *store.Store { return c.store }

// onStates records a worker's view of the protocol state machine.
func (c *Campaign) onStates(worker int, rep *StateReport) {
	if rep == nil {
		return
	}
	c.mu.Lock()
	c.stateReports[worker] = rep
	c.mu.Unlock()
}

// StateModel returns the campaign's protocol state machine.
//
// Merged across workers, because each fuzzes the same protocol and the campaign
// has explored a state when any worker has. Counts are summed and exemplars
// taken from whichever worker saw the state first, so the graph reads as one
// campaign's rather than as N overlapping ones.
func (c *Campaign) StateModel() *StateReport {
	c.mu.Lock()
	reports := make([]*StateReport, 0, len(c.stateReports))
	for _, r := range c.stateReports {
		reports = append(reports, r)
	}
	c.mu.Unlock()

	out := &StateReport{}
	states := map[string]*StateCount{}
	moves := map[[2]string]*TransitionCount{}
	illegal := map[[2]string]*TransitionCount{}

	for _, r := range reports {
		if out.Fn == "" {
			out.Fn = r.Fn
		}
		for _, s := range r.States {
			if e, ok := states[s.Label]; ok {
				e.Count += s.Count
				if e.Exemplar == "" {
					e.Exemplar = s.Exemplar
				}
				// The largest a worker saw, not the sum: each holds its own
				// bounded sample of the same responses, so adding them would
				// count one coarse label several times over.
				if s.Variants > e.Variants {
					e.Variants = s.Variants
				}
				continue
			}
			cp := s
			states[s.Label] = &cp
		}
		mergeMoves(moves, r.Transitions)
		mergeMoves(illegal, r.Illegal)
	}

	out.States = sortedStateCounts(states)
	out.Transitions = sortedTransitionCounts(moves)
	out.Illegal = sortedTransitionCounts(illegal)
	return out
}

func mergeMoves(into map[[2]string]*TransitionCount, from []TransitionCount) {
	for _, t := range from {
		k := [2]string{t.From, t.To}
		if e, ok := into[k]; ok {
			e.Count += t.Count
			continue
		}
		cp := t
		into[k] = &cp
	}
}

// sortedStateCounts orders states by label, so two reads of one campaign agree
// and two campaigns can be diffed.
func sortedStateCounts(m map[string]*StateCount) []StateCount {
	out := make([]StateCount, 0, len(m))
	for _, v := range m {
		out = append(out, *v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Label < out[j].Label })
	return out
}

func sortedTransitionCounts(m map[[2]string]*TransitionCount) []TransitionCount {
	out := make([]TransitionCount, 0, len(m))
	for _, v := range m {
		out = append(out, *v)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].From != out[j].From {
			return out[i].From < out[j].From
		}
		return out[i].To < out[j].To
	})
	return out
}
