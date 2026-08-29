package triage

import (
	"context"
	"sync"
	"sync/atomic"

	"github.com/rom/Xfuzz/pkg/ir"
)

// Job is one candidate finding handed to triage.
type Job struct {
	// ID is the caller's identifier, echoed in the result. For a store-backed
	// worker it is the finding's row id.
	ID int64

	// Input is the reproducer as the engine found it.
	Input []byte

	// Node is the structured form of the reproducer, when the campaign had
	// one. Its presence changes which minimiser runs, and on a format with
	// lengths or checksums that is the difference between reducing the
	// reproducer and not reducing it at all.
	Node *ir.Node

	// Observed is what the engine saw when it found it. It is advisory: triage
	// re-runs the input and believes what it sees itself, because a finding
	// that does not reproduce is the thing this exists to catch.
	Observed Outcome
}

// Result is what triage concluded about a job.
type Result struct {
	ID int64

	Verify   VerifyReport
	Minimize MinimizeReport

	// Minimized is the reduced reproducer, or the original when minimisation
	// was skipped or achieved nothing.
	Minimized []byte

	// MinimizedNode is the reduced tree, when minimisation was structured.
	MinimizedNode *ir.Node

	// Strategy and Signature are the bucket, computed from the minimised input.
	Strategy  string
	Signature string

	// State is the triage state the finding should move to.
	State string

	// Err is set when triage could not finish. The finding stays where it was
	// rather than being recorded as unverified: "we could not check" and "it
	// does not reproduce" are different facts.
	Err error
}

// Config configures a worker.
type Config struct {
	// Runner executes candidates. Required.
	Runner Runner

	// Strategy buckets findings. Nil means DefaultChain.
	Strategy Strategy

	// Classifier recognises the target's own failure markers. Nil means the
	// generic set, which is right for a target that says nothing of its own.
	Classifier *Classifier

	// Trials is how many times each reproducer is verified. Zero means
	// DefaultTrials.
	Trials int

	// Minimize enables minimisation. On by default; set Skip to disable it for
	// a campaign that wants findings as fast as possible.
	SkipMinimize bool

	// MinimizeOpts bounds minimisation.
	MinimizeOpts MinimizeOptions

	// Queue is how many jobs may wait. Zero means DefaultQueue.
	Queue int

	// Workers is how many jobs are triaged at once. Zero means one.
	//
	// More than one means more than one copy of the target running, which for
	// a target that binds a port or writes a fixed path is wrong. One is the
	// safe default and the campaign can raise it.
	Workers int

	// Report receives each result. Required.
	Report func(Result)
}

// DefaultQueue is how many findings may wait for triage.
const DefaultQueue = 256

// Worker triages findings off the fuzz loop's thread.
//
// The queue is bounded and Submit never blocks. That is the whole point: triage
// re-runs the target hundreds of times per finding, and a campaign that hit a
// bug it can reach easily will produce findings faster than they can be
// triaged. Blocking would turn a productive campaign into a stalled one, so
// instead the overflow is dropped and counted — a dropped candidate is a
// duplicate of one already queued far more often than not, and the count says
// so honestly rather than the number silently being wrong.
type Worker struct {
	cfg     Config
	jobs    chan Job
	wg      sync.WaitGroup
	started bool

	dropped   atomic.Uint64
	completed atomic.Uint64
}

// NewWorker returns a worker. It does not start it.
func NewWorker(cfg Config) *Worker {
	if cfg.Queue <= 0 {
		cfg.Queue = DefaultQueue
	}
	if cfg.Workers <= 0 {
		cfg.Workers = 1
	}
	if cfg.Strategy == nil {
		cfg.Strategy = DefaultChain()
	}
	return &Worker{cfg: cfg, jobs: make(chan Job, cfg.Queue)}
}

// Start begins triaging. The worker stops when ctx is cancelled or Close is
// called.
func (w *Worker) Start(ctx context.Context) {
	if w.started {
		return
	}
	w.started = true
	for i := 0; i < w.cfg.Workers; i++ {
		w.wg.Add(1)
		go func() {
			defer w.wg.Done()
			for job := range w.jobs {
				if ctx.Err() != nil {
					return
				}
				res := w.Triage(ctx, job)
				w.completed.Add(1)
				if w.cfg.Report != nil {
					w.cfg.Report(res)
				}
			}
		}()
	}
}

// Submit queues a candidate. It returns false when the queue is full, having
// dropped the job.
func (w *Worker) Submit(job Job) bool {
	select {
	case w.jobs <- job:
		return true
	default:
		w.dropped.Add(1)
		return false
	}
}

// Close stops accepting jobs and waits for those queued to finish.
func (w *Worker) Close() {
	close(w.jobs)
	w.wg.Wait()
}

// Stats returns how many jobs were dropped and how many completed.
func (w *Worker) Stats() (dropped, completed uint64) {
	return w.dropped.Load(), w.completed.Load()
}

// Triage runs the full pipeline on one job, synchronously.
//
// It is exported because the pipeline is worth running directly — from a CLI
// triage command, or a test — without a queue and a goroutine in the way.
func (w *Worker) Triage(ctx context.Context, job Job) Result {
	res := Result{ID: job.ID, Minimized: job.Input}

	verify, err := w.classifier().Verify(ctx, w.cfg.Runner, job.Input, w.cfg.Trials)
	res.Verify = verify
	if err != nil {
		res.Err = err
		return res
	}
	res.State = verify.State()
	if verify.Reproduced == 0 {
		// Nothing further is meaningful: minimising an input that does not fail
		// would minimise it to nothing, and bucketing it would file a
		// non-reproducer alongside real bugs.
		res.Strategy, res.Signature = w.cfg.Strategy.Name(), "unreproducible"
		return res
	}

	if !w.cfg.SkipMinimize {
		opts := w.cfg.MinimizeOpts
		if opts.Preserve == nil {
			want := verify.Class
			opts.Preserve = func(o Outcome) bool {
				return o.Crashed() && w.classifier().Classify(o).Equal(want)
			}
		}
		var (
			minimized []byte
			mrep      MinimizeReport
			err       error
		)
		if job.Node != nil {
			var node *ir.Node
			node, minimized, mrep, err = MinimizeStructured(ctx, w.cfg.Runner, job.Node, opts)
			res.MinimizedNode = node
		} else {
			minimized, mrep, err = Minimize(ctx, w.cfg.Runner, job.Input, opts)
		}
		if err != nil {
			res.Err = err
			return res
		}
		res.Minimized = minimized
		res.Minimize = mrep
		if verify.Reproduced == verify.Trials {
			res.State = "minimized"
		}
	}

	// The bucket is computed from the minimised input, not the original. A
	// minimised reproducer has almost no path left to vary, which is what makes
	// coverage bucketing converge instead of giving one bucket per input.
	final, err := w.cfg.Runner.Run(ctx, res.Minimized)
	if err != nil {
		res.Err = err
		return res
	}
	res.Strategy, res.Signature = Bucket(w.cfg.Strategy, final, w.classifier().Classify(final))
	return res
}

// classifier is the campaign's classifier, or the generic one.
func (w *Worker) classifier() *Classifier {
	if w.cfg.Classifier != nil {
		return w.cfg.Classifier
	}
	return DefaultClassifier
}
