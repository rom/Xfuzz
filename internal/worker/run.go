package worker

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rom/Xfuzz/internal/daemon"
	"github.com/rom/Xfuzz/internal/engine"
	"github.com/rom/Xfuzz/internal/metrics"
	"github.com/rom/Xfuzz/internal/store"
	"github.com/rom/Xfuzz/pkg/campaign"
	"github.com/rom/Xfuzz/pkg/corpus"
	"github.com/rom/Xfuzz/pkg/state"
)

// Options configure one worker.
type Options struct {
	// Config is the resolved campaign file.
	Config *campaign.Resolved

	// ID is this worker's index, which derives its RNG streams.
	ID int

	// Seed is the campaign's root seed.
	Seed uint64

	// Strategy names the ensemble strategy assigned to this worker.
	Strategy string

	// StoreDir overrides the campaign's store location.
	StoreDir string

	// Control carries commands from the daemon, Status carries messages back.
	// Both nil runs the worker standalone, printing to stderr, which is what a
	// developer debugging a campaign file wants.
	Control io.Reader
	Status  io.Writer

	// ReportInterval is how often counters are sent. Zero means
	// DefaultReportInterval.
	ReportInterval time.Duration
}

// DefaultReportInterval is how often a worker reports its counters.
//
// Often enough that a live view is live, rarely enough that the reporting is
// invisible against the execution rate. A worker at 3,000 exec/s sends two
// messages a second; the campaign's own clock advances 1,500 times between
// them.
const DefaultReportInterval = 500 * time.Millisecond

// sliceExecs is how many executions run between checks for commands.
//
// The fuzz loop must not be interrupted per execution — that is the whole point
// of it being allocation-free and single-threaded — so control is handled
// between slices instead. A few thousand executions is a few hundred
// milliseconds at any realistic rate, which is faster than a person can notice
// and slower than the loop can feel.
const sliceExecs = 2000

// Worker runs one campaign worker.
type Worker struct {
	opts Options

	built *built
	store *store.Store
	enc   *daemon.Encoder

	mu        sync.Mutex
	paused    bool
	reported  map[corpus.Digest]bool
	findings  int
	execsBase uint64

	stop     atomic.Bool
	stopMsg  string
	incoming chan *daemon.Message

	// started is set by Run before it builds anything, and running is closed
	// when Run returns. Close consults both: Run releases what it built, so a
	// Close overlapping it would be tearing down an executor mid-execution.
	started   atomic.Bool
	running   chan struct{}
	closeOnce sync.Once
	closeErr  error
}

// New prepares a worker.
func New(opts Options) *Worker {
	if opts.ReportInterval <= 0 {
		opts.ReportInterval = DefaultReportInterval
	}
	return &Worker{
		opts:     opts,
		reported: map[corpus.Digest]bool{},
		incoming: make(chan *daemon.Message, 64),
		running:  make(chan struct{}),
	}
}

// Run builds the engine and fuzzes until the budget ends, the daemon says stop,
// or the context is cancelled.
func (w *Worker) Run(ctx context.Context) error {
	w.started.Store(true) // before anything is built, so Close never races it
	defer close(w.running)

	if w.opts.Status != nil {
		w.enc = daemon.NewEncoder(w.opts.Status)
	}

	b, err := build(ctx, w.opts.Config, w.opts.ID, w.opts.Seed, w.opts.Strategy)
	if err != nil {
		w.report("error", err.Error())
		return err
	}
	w.built = b
	defer func() {
		b.close()
		// Said on the way out, because a closer that failed has left something
		// behind on this host and the next campaign is the one that meets it.
		//
		// To stderr as well as to the daemon: by the time release runs, the
		// status pipe may already be closed at the far end — the supervisor
		// stops reading once the worker is on its way out — and a report
		// written into a pipe nobody reads is the same as no report. The
		// daemon captures a worker's output, so that channel outlives this one.
		for _, err := range b.closeErrs {
			w.report("warn", err.Error())
			fmt.Fprintf(os.Stderr, "worker %d: %v\n", w.opts.ID, err)
		}
	}()

	seeds, err := w.loadCorpus(ctx)
	if err != nil {
		w.report("error", err.Error())
		return err
	}

	w.send(&daemon.Message{Type: daemon.MsgReady, Ready: &daemon.ReadyInfo{
		Pid:             os.Getpid(),
		Strategy:        w.opts.Strategy,
		Executor:        b.describe(),
		Isolation:       b.sandbox.Level().String(),
		Seeds:           seeds,
		CoverageMapSize: w.opts.Config.Feedback.MapSize,
	}})

	if w.opts.Control != nil {
		go w.readCommands(ctx)
	}
	return w.loop(ctx)
}

// loadCorpus fills the engine from the store the daemon imported into.
func (w *Worker) loadCorpus(ctx context.Context) (int, error) {
	dir := resolveStoreDir(w.opts.Config, w.opts.StoreDir)
	if dir == "" {
		// Standalone, with no daemon and no store: the inline seeds in the file
		// are all there is, which is exactly the case a developer checking a
		// campaign file is in.
		return w.loadInlineSeeds(ctx)
	}
	st, err := store.Open(dir)
	if err != nil {
		return 0, fmt.Errorf("worker: opening the store: %w", err)
	}
	w.store = st

	rec, err := st.Campaign(ctx, w.opts.Config.Name)
	if err != nil {
		return 0, fmt.Errorf("worker: reading the campaign: %w", err)
	}
	entries, err := st.Testcases(ctx, rec.ID, store.TestcaseQuery{
		WithPayload: true, Order: "discovered",
	})
	if err != nil {
		return 0, err
	}
	n, err := loadSeeds(ctx, w.built.engine, entries)
	if err != nil {
		return 0, err
	}
	// Already the campaign's, so they are not reported back as discoveries.
	w.markReported(entries)
	return n, nil
}

func (w *Worker) loadInlineSeeds(ctx context.Context) (int, error) {
	var entries []*corpus.Testcase
	for _, lit := range w.opts.Config.Seeds.Inline {
		tc := corpus.NewTestcase(nil, []byte(lit))
		tc.Prov.Origin = "inline"
		entries = append(entries, tc)
	}
	if len(entries) == 0 {
		return 0, errors.New("worker: no store and no inline seeds, so there is nothing to fuzz from")
	}
	n, err := loadSeeds(ctx, w.built.engine, entries)
	if err != nil {
		return 0, err
	}
	w.markReported(entries)
	return n, nil
}

func (w *Worker) markReported(entries []*corpus.Testcase) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, tc := range entries {
		w.reported[tc.ID] = true
	}
}

// loop fuzzes in slices, handling commands and reporting between them.
func (w *Worker) loop(ctx context.Context) error {
	report := time.NewTicker(w.opts.ReportInterval)
	defer report.Stop()

	budget := w.budget()
	start := time.Now()

	for {
		if ctx.Err() != nil {
			w.finish("cancelled")
			return nil
		}
		if w.stop.Load() {
			w.flush(ctx)
			w.finish(w.stopReason())
			return nil
		}

		w.drainCommands(ctx)

		if w.isPaused() {
			// Paused rather than stopped, so the engine keeps its corpus,
			// coverage and RNG position: resuming is meant to be free.
			select {
			case <-time.After(50 * time.Millisecond):
			case <-ctx.Done():
			}
			continue
		}

		slice := budget
		slice.MaxExecs = w.built.engine.Stats().Execs + sliceExecs
		if budget.MaxExecs > 0 && slice.MaxExecs > budget.MaxExecs {
			slice.MaxExecs = budget.MaxExecs
		}
		// Bounded by time as well as by executions, and this is the important
		// half. A slice bounded only by a count runs as long as the target
		// takes: at the 2-second timeout a slow or misconfigured target makes
		// one slice over an hour, and since commands and metrics are handled
		// *between* slices, the worker would look alive and silent for that
		// whole hour. Bounding by the reporting interval means a worker reports
		// and answers its daemon at that interval no matter how slow the target
		// is — which is exactly the case where somebody is waiting to be told
		// something is wrong.
		slice.MaxTime = w.opts.ReportInterval

		stats, err := w.built.engine.Run(ctx, slice)
		if err != nil {
			w.report("error", err.Error())
			w.finish("engine error: " + err.Error())
			return err
		}

		w.flush(ctx)

		select {
		case <-report.C:
			w.sendMetrics(stats, time.Since(start))
		default:
		}

		if budget.MaxExecs > 0 && stats.Execs >= budget.MaxExecs {
			w.finish("execution budget reached")
			return nil
		}
		if budget.MaxTime > 0 && time.Since(start) >= budget.MaxTime {
			w.finish("time budget reached")
			return nil
		}
	}
}

// budget is the worker's own bound.
//
// The campaign's stop conditions are the *campaign's*, enforced by the daemon
// across every worker; a worker with the campaign's execution budget would run
// it N times over. What a worker carries is a safety net for the standalone
// case, where there is no daemon to stop it.
func (w *Worker) budget() engine.Budget {
	if w.opts.Control != nil {
		return engine.Budget{}
	}
	stop := w.opts.Config.Stop
	return engine.Budget{MaxExecs: stop.Execs, MaxTime: stop.After.Std()}
}

// flush reports newly admitted corpus entries and new findings.
func (w *Worker) flush(ctx context.Context) {
	w.flushCorpus()
	w.flushFindings()
}

func (w *Worker) flushCorpus() {
	entries := w.opts.Config != nil && w.built != nil
	if !entries {
		return
	}
	var fresh []daemon.CorpusEntry

	w.mu.Lock()
	for _, tc := range w.built.engine.Corpus().Entries() {
		if w.reported[tc.ID] {
			continue
		}
		w.reported[tc.ID] = true
		fresh = append(fresh, daemon.CorpusEntry{
			Digest:    tc.ID.String(),
			Payload:   tc.Bytes,
			Coverage:  tc.Meta.Coverage,
			NewSignal: tc.Meta.Score.NewSignal,
			ExecTime:  int64(tc.Meta.ExecTime),
			Depth:     tc.Meta.Depth,
			Favoured:  tc.Meta.Favoured,
			Origin:    tc.Prov.Origin,
		})
	}
	w.mu.Unlock()

	if len(fresh) > 0 {
		w.send(&daemon.Message{Type: daemon.MsgCorpus, Entries: fresh})
	}
}

func (w *Worker) flushFindings() {
	all := w.built.engine.Findings()

	w.mu.Lock()
	from := w.findings
	w.findings = len(all)
	w.mu.Unlock()

	for _, f := range all[from:] {
		w.send(&daemon.Message{Type: daemon.MsgFinding, Finding: &daemon.FindingReport{
			Digest:      f.Digest.String(),
			Payload:     f.Input,
			Kind:        f.Kind,
			Signal:      f.Signal,
			Summary:     f.Summary,
			Detail:      f.Detail,
			Frames:      f.Frames,
			Signature:   f.Bucket,
			Strategy:    w.opts.Config.Triage.Strategy,
			FoundAtExec: f.Execs,
			Coverage:    w.coverageSnapshot(),
		}})
	}
}

// coverageSnapshot copies the map for coverage bucketing.
//
// Only when there is a finding to attach it to: it is a copy of the whole map,
// which is cheap once per crash and ruinous once per execution.
func (w *Worker) coverageSnapshot() []byte {
	if w.built.coverage == nil {
		return nil
	}
	return append([]byte(nil), w.built.coverage.Buffer()...)
}

func (w *Worker) sendMetrics(stats engine.Stats, elapsed time.Duration) {
	snap := metrics.Snapshot{
		At:              time.Now(),
		Execs:           stats.Execs,
		ExecsPerS:       ratePerSecond(stats.Execs, elapsed),
		Coverage:        stats.Coverage,
		MapDensity:      stats.MapDensity,
		States:          stats.States,
		Transitions:     stats.Transitions,
		IllegalMoves:    stats.IllegalMoves,
		CorpusSize:      stats.CorpusSize,
		Findings:        stats.Findings,
		Buckets:         stats.Buckets,
		Crashes:         stats.Crashes,
		Timeouts:        stats.Timeouts,
		HarnessError:    stats.HarnessError,
		Stability:       stats.Stability,
		Overhead:        stats.Overhead(),
		WorkersHealthy:  1,
		LastNewCoverage: time.Now(),
	}
	w.send(&daemon.Message{Type: daemon.MsgMetrics, Metrics: &snap})
}

func ratePerSecond(n uint64, d time.Duration) float64 {
	if d <= 0 {
		return 0
	}
	return float64(n) / d.Seconds()
}

// readCommands pumps the daemon's commands onto the worker's queue.
func (w *Worker) readCommands(ctx context.Context) {
	dec := daemon.NewDecoder(w.opts.Control)
	for {
		m, err := dec.Decode()
		if err != nil {
			// The daemon has gone. A worker with no daemon has nowhere to
			// report and nothing to report to, so it stops rather than fuzzing
			// on into a void.
			w.requestStop("the daemon closed the control channel")
			return
		}
		select {
		case w.incoming <- m:
		case <-ctx.Done():
			return
		default:
			// The queue is full only if the worker is wedged, in which case the
			// command it would drop is one it could not have acted on.
		}
	}
}

// drainCommands handles every queued command.
func (w *Worker) drainCommands(ctx context.Context) {
	for {
		select {
		case m := <-w.incoming:
			w.handle(ctx, m)
		default:
			return
		}
	}
}

func (w *Worker) handle(ctx context.Context, m *daemon.Message) {
	switch m.Type {
	case daemon.CmdSync:
		w.acceptSync(m.Entries)
	case daemon.CmdPause:
		w.setPaused(true)
	case daemon.CmdResume:
		w.setPaused(false)
	case daemon.CmdCheckpoint:
		w.sendCheckpoint()
	case daemon.CmdStop:
		w.requestStop("asked to stop")
	}
}

// acceptSync admits entries a sibling discovered.
//
// Marked as reported before they are added, so they are not sent straight back
// to the daemon as this worker's own discovery — which would loop an entry
// around the campaign forever.
func (w *Worker) acceptSync(entries []daemon.CorpusEntry) {
	if len(entries) == 0 {
		return
	}
	tcs := make([]*corpus.Testcase, 0, len(entries))
	for _, e := range entries {
		tc := corpus.NewTestcase(nil, e.Payload)
		tc.Meta.Coverage = e.Coverage
		tc.Meta.Depth = e.Depth
		tc.Meta.Favoured = e.Favoured
		tc.Prov.Origin = e.Origin
		tcs = append(tcs, tc)
	}

	w.mu.Lock()
	for _, tc := range tcs {
		w.reported[tc.ID] = true
	}
	w.mu.Unlock()

	if _, _, err := w.built.engine.LoadCorpus(tcs); err != nil {
		w.report("warn", "accepting synced entries: "+err.Error())
	}
}

func (w *Worker) sendCheckpoint() {
	snap := w.built.engine.Snapshot()
	w.send(&daemon.Message{Type: daemon.MsgCheckpoint, Checkpoint: &daemon.CheckpointState{
		Coverage:   snap.Coverage,
		Execs:      snap.Execs,
		CorpusSize: snap.CorpusSize,
		RNG:        snap.RNG,
	}})
	w.sendStates()
}

// sendStates reports the protocol state machine this worker has inferred.
//
// On the checkpoint cadence rather than the metrics one. A state graph is not
// small and does not change several times a second, and the metrics kind is
// coalesced — a subscriber that fell behind would see one worker's graph and
// call it the campaign's.
func (w *Worker) sendStates() {
	if w.built == nil || w.built.state == nil {
		return
	}
	g := w.built.state
	labels, counts := g.Model.States()
	moves, moveCounts := g.Model.Transitions()
	illegal, illegalCounts := g.Model.Illegal()

	rep := &daemon.StateReport{Fn: g.Observer.Fn().Name()}
	for _, l := range labels {
		sc := daemon.StateCount{
			Label:    string(l),
			Count:    counts[l],
			Variants: g.Model.Variants(l),
		}
		if ex, ok := g.Model.Exemplar(l); ok {
			sc.Exemplar = state.Excerpt(ex, stateExemplarBytes)
		}
		rep.States = append(rep.States, sc)
	}
	for _, t := range moves {
		rep.Transitions = append(rep.Transitions, daemon.TransitionCount{
			From: string(t.From), To: string(t.To), Count: moveCounts[t],
		})
	}
	for _, t := range illegal {
		rep.Illegal = append(rep.Illegal, daemon.TransitionCount{
			From: string(t.From), To: string(t.To), Count: illegalCounts[t],
		})
	}
	w.send(&daemon.Message{Type: daemon.MsgStates, States: rep})
}

// stateExemplarBytes is how much of a response accompanies a state label. Long
// enough to recognise a protocol reply, short enough that a graph of hundreds
// of states is still readable.
const stateExemplarBytes = 96

func (w *Worker) setPaused(v bool) {
	w.mu.Lock()
	w.paused = v
	w.mu.Unlock()
}

func (w *Worker) isPaused() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.paused
}

func (w *Worker) requestStop(reason string) {
	w.mu.Lock()
	if w.stopMsg == "" {
		w.stopMsg = reason
	}
	w.mu.Unlock()
	w.stop.Store(true)
}

func (w *Worker) stopReason() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.stopMsg
}

// finish reports the worker's last state on the way out.
//
// The checkpoint goes first: a worker given the chance to stop writes one, and
// that is the difference between losing the last interval's work and losing
// none of it.
func (w *Worker) finish(reason string) {
	w.sendCheckpoint()
	w.send(&daemon.Message{Type: daemon.MsgStopped, Reason: reason})
}

func (w *Worker) send(m *daemon.Message) {
	if w.enc == nil {
		return
	}
	m.Worker = w.opts.ID
	if err := w.enc.Encode(m); err != nil {
		// The daemon has gone. Reporting it to the daemon is not an option.
		w.requestStop("the daemon closed the status channel")
	}
}

func (w *Worker) report(level, text string) {
	if w.enc == nil {
		fmt.Fprintf(os.Stderr, "worker %d [%s] %s\n", w.opts.ID, level, text)
		return
	}
	w.send(&daemon.Message{Type: daemon.MsgLog, Level: level, Text: text})
}

// Close releases the worker's resources.
//
// Safe to call while Run is in flight, and that is the case worth being careful
// about: Run owns the executor for as long as it is fuzzing, so a Close that
// simply released it would be tearing down a fork server mid-execution. Instead
// Close asks the worker to stop and waits for Run to return, which it does at
// the end of the current slice — bounded by the reporting interval, not by the
// campaign's budget.
//
// Idempotent, and safe before Run is ever called: a worker whose build failed
// is closed by a caller that never got as far as fuzzing.
func (w *Worker) Close() error {
	w.closeOnce.Do(func() {
		if w.started.Load() {
			w.requestStop("closed")
			<-w.running
		}
		if w.built != nil {
			w.built.close()
		}
		if w.store != nil {
			w.closeErr = w.store.Close()
		}
	})
	return w.closeErr
}
