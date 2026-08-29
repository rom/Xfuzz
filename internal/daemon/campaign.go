package daemon

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/rom/Xfuzz/internal/metrics"
	"github.com/rom/Xfuzz/internal/safety"
	"github.com/rom/Xfuzz/internal/store"
	"github.com/rom/Xfuzz/pkg/campaign"
	"github.com/rom/Xfuzz/pkg/corpus"
	"github.com/rom/Xfuzz/pkg/corpusio"
	"github.com/rom/Xfuzz/pkg/feedback"
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

	id      int64
	binary  string
	workDir string

	mu        sync.Mutex
	state     State
	started   time.Time
	stopped   time.Time
	reason    string
	lastNew   time.Time
	buckets   map[string]bool
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
		Config:      cfg,
		Seed:        seed,
		store:       opts.Store,
		bus:         opts.Bus,
		metrics:     metrics.NewCollector(opts.Retention),
		binary:      opts.WorkerBinary,
		workDir:     opts.WorkDir,
		state:       StateCreated,
		buckets:     map[string]bool{},
		seen:        map[string]bool{},
		pendingSync: map[int][]CorpusEntry{},
		done:        make(chan struct{}),
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
		created, cerr := opts.Store.CreateCampaign(ctx, cfg.Name, c.configDigest(), seed)
		if cerr != nil {
			return nil, cerr
		}
		c.id = created.ID
	default:
		return nil, err
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
	c.sandbox = &safety.Sandbox{
		Require:  level,
		Name:     c.Config.Name,
		Target:   c.Config.Target.Path,
		Network:  s.Network,
		Writable: s.Writable,
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
	started, lastNew, buckets := c.started, c.lastNew, len(c.buckets)
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

	c.mu.Lock()
	c.state = StateFinished
	c.stopped = time.Now()
	c.mu.Unlock()

	_ = c.store.SetCampaignStatus(ctx, c.id, store.StatusFinished)
	_, _ = c.store.Audit(ctx, "", store.AuditCampaignStop,
		fmt.Sprintf("campaign=%s reason=%q execs=%d buckets=%d",
			c.Config.Name, reason, c.metrics.Snapshot().Execs, len(c.buckets)))
	c.publish(EventCampaign, map[string]any{"state": string(StateFinished), "reason": reason})
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
	Name      string               `json:"name"`
	State     State                `json:"state"`
	Seed      uint64               `json:"seed"`
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

	snap := c.metrics.Snapshot()
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
			snap := c.metrics.Snapshot()
			c.bus.Publish(Event{Kind: EventMetrics, Campaign: c.Config.Name, Data: &snap})
		}

	case MsgCorpus:
		c.onCorpus(ctx, worker, m.Entries)

	case MsgFinding:
		c.onFinding(ctx, worker, m.Finding)

	case MsgCheckpoint:
		c.onCheckpoint(ctx, worker, m.Checkpoint)

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
	isNew := !c.buckets[key]
	c.buckets[key] = true
	buckets := len(c.buckets)
	c.mu.Unlock()

	c.bus.Publish(Event{Kind: EventFinding, Campaign: c.Config.Name, Worker: worker,
		Data: map[string]any{
			"id": rec.ID, "kind": f.Kind, "signal": f.Signal, "summary": f.Summary,
			"bucket": signature, "new_bucket": isNew, "buckets": buckets,
		}})
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
