package daemon

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/rom/Xfuzz/internal/safety"
	"github.com/rom/Xfuzz/internal/store"
	"github.com/rom/Xfuzz/internal/triage"
	"github.com/rom/Xfuzz/pkg/campaign"
	"github.com/rom/Xfuzz/pkg/codec"
	"github.com/rom/Xfuzz/pkg/executor"
	"github.com/rom/Xfuzz/pkg/feedback"
)

// Triage runs a campaign's target outside the fuzz loop.
//
// The daemon owns findings, so it is the daemon that answers "does this still
// reproduce" and "how small can this get". A worker could not: it is busy, and
// the answer must stay available after every worker has exited — a finding is
// re-examined days later, from the console, against a campaign that finished
// (ADR-0003).
//
// Deliberately the subprocess tier rather than the fork server. Triage runs a
// reproducer tens or hundreds of times, not millions, and a fork server's speed
// is bought with a process that persists between executions. For a question of
// the form "is this crash real", a fresh process per run is the answer that can
// be trusted.
type Triage struct {
	cfg     *campaign.Resolved
	sandbox *safety.Sandbox

	// One executor, serialised. Triage is off the hot path by construction, and
	// two concurrent minimisations of the same target would compete for the
	// same working directory.
	mu   sync.Mutex
	exec executor.Executor
	out  *feedback.OutputObserver

	// codec lifts a stored reproducer back into the structure the executor
	// needs. It matters only for the session tier, where an input is a
	// conversation and delivering it as one blob would send the whole exchange
	// as a single message — which for most protocols means the target sees one
	// malformed line and the finding does not reproduce.
	codec codec.Codec

	// lastFailure is what the target printed on the most recent run that
	// failed. Kept because verification does not return it and it is usually
	// the most useful line in a report — an assertion message names the bug,
	// where a signal number only says the program died — and because the
	// alternative, one more execution afterwards purely to capture output, both
	// costs a run and reports a run that nobody verified.
	lastFailure string

	// started records whether a session executor's server has been brought up.
	// Lazily, because a campaign that never produces a finding should never pay
	// for a second copy of its target.
	started bool
}

// NewTriage prepares on-demand triage for a campaign.
//
// The campaign's own sandbox, not a fresh one: a reproducer is the input that
// made a hostile program misbehave, and re-running it is exactly as dangerous as
// the run that produced it (ADR-0012).
func NewTriage(cfg *campaign.Resolved, sandbox *safety.Sandbox) *Triage {
	out := feedback.NewOutputObserver("triage")
	spawner := safety.NewSpawner()
	spawner.Sandbox = sandbox

	// A stateful campaign's findings are conversations, and a conversation
	// replayed as a blob on standard input is not the same execution. The tier
	// has to match the one that found it or every finding reads as
	// unreproducible — which is worse than not triaging at all, because it
	// dismisses real bugs with a number that looks like evidence.
	if cfg.Session != nil {
		return newSessionTriage(cfg, sandbox, spawner, out)
	}

	spec := executor.ProcSpec{
		Path:          cfg.Target.Path,
		Args:          append([]string{cfg.Target.Path}, cfg.Target.Args...),
		Dir:           cfg.Target.Dir,
		Timeout:       cfg.Target.Timeout.Std(),
		CaptureOutput: true,
	}
	for k, v := range cfg.Target.Env {
		spec.Env = append(spec.Env, k+"="+v)
	}

	sub := executor.NewSubprocess("triage", spawner, spec)
	sub.Output = out
	sub.Delivery = deliveryFor(cfg.Target.Input)
	return &Triage{cfg: cfg, sandbox: sandbox, exec: sub, out: out, codec: codec.Raw{}}
}

// newSessionTriage builds triage for a stateful campaign.
//
// Its own server on its own address, started lazily and separate from the
// workers': triage runs while the campaign does, and a reproducer replayed
// against a worker's target would perturb the campaign it is meant to be
// explaining.
func newSessionTriage(cfg *campaign.Resolved, sandbox *safety.Sandbox,
	spawner *safety.Spawner, out *feedback.OutputObserver) *Triage {

	addr := campaign.ResolveAddress(cfg.Session.Address, triageWorkerID)
	network, address, err := campaign.SplitAddress(addr)
	if err != nil {
		// Validation refused this shape long before now, so reaching it means
		// something upstream changed. Triage without a runner is refused by
		// name at the entry points rather than panicking here.
		return &Triage{cfg: cfg, sandbox: sandbox, out: out}
	}
	framing, _ := executor.FramingNamed(cfg.Session.Framing)

	sess := executor.NewSession("triage", scopeFor(cfg), executor.SessionOptions{
		Network: network,
		Address: address,
		// Always a restart, whatever the campaign runs with. Triage asks
		// whether an input reproduces, and an answer that depended on what the
		// previous trial left behind would not be one.
		Reset:          executor.ResetRestart,
		Framing:        framing,
		QuietPeriod:    cfg.Session.QuietPeriod.Std(),
		ConnectTimeout: cfg.Session.ConnectTimeout.Std(),
		ReadTimeout:    cfg.Session.ReadTimeout.Std(),
		SessionTimeout: cfg.Session.SessionTimeout.Std(),
		ReadLimit:      cfg.Session.ReadLimit,
	})
	sess.Output = out
	if cfg.Session.Managed != nil && *cfg.Session.Managed {
		sess.Manage(spawner, sessionSpecFor(cfg, addr))
	}
	return &Triage{cfg: cfg, sandbox: sandbox, exec: sess, out: out, codec: codec.Session{}}
}

// triageWorkerID is the worker index triage's own server binds under.
//
// Deliberately far from any real worker's, so that triage and the campaign
// never contend for one address however many workers a campaign runs.
const triageWorkerID = 9000

// sessionSpecFor describes triage's own copy of the server.
func sessionSpecFor(cfg *campaign.Resolved, addr string) executor.ProcSpec {
	argv := append([]string{cfg.Target.Path}, cfg.Target.Args...)
	substituted := false
	for i, a := range argv {
		if replaced := strings.ReplaceAll(a, AddressPlaceholder, addr); replaced != a {
			argv[i] = replaced
			substituted = true
		}
	}
	if !substituted {
		argv = append(argv, "--listen", addr)
	}
	env := make([]string, 0, len(cfg.Target.Env))
	for k, v := range cfg.Target.Env {
		env = append(env, k+"="+v)
	}
	return executor.ProcSpec{
		Path: cfg.Target.Path, Args: argv, Env: env, Dir: cfg.Target.Dir,
		CaptureOutput: true,
	}
}

// AddressPlaceholder is replaced with the session address in a target's
// arguments.
const AddressPlaceholder = "{address}"

// scopeFor builds the dialer triage connects through.
func scopeFor(cfg *campaign.Resolved) *safety.Scope {
	spec := safety.ScopeSpec{}
	if sc := cfg.Safety.Scope; sc != nil {
		spec.Loopback = sc.Loopback
		spec.AcknowledgePublic = sc.AcknowledgePublic
	}
	s, err := safety.NewScopeFrom(spec, nil)
	if err != nil {
		return safety.NewScope()
	}
	return s
}

// Close releases the executor.
func (t *Triage) Close() error {
	if t == nil {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.exec == nil {
		return nil
	}
	return t.exec.Close()
}

// Run implements triage.Runner: execute one input and classify how it ended.
func (t *Triage) Run(ctx context.Context, input []byte) (triage.Outcome, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.exec == nil {
		return triage.Outcome{}, ErrNoTriage
	}
	if s, ok := t.exec.(*executor.Session); ok && !t.started {
		if err := s.Start(ctx); err != nil {
			return triage.Outcome{}, err
		}
		t.started = true
	}

	// Through the codec, so a session reproducer is delivered as the
	// conversation it is rather than as one long message.
	in := executor.Input{Bytes: input}
	if t.codec != nil {
		if node, err := t.codec.Decode(nil, input); err == nil {
			in.Node = node
		}
	}

	obs := []feedback.Observer{t.out}
	kind, err := t.exec.Run(ctx, in, obs)
	if err != nil {
		return triage.Outcome{}, err
	}
	out := triage.Outcome{
		Exit:   kind,
		Signal: t.out.Signal(),
		Output: t.out.Combined(),
	}
	if out.Crashed() {
		t.lastFailure = out.Output
	}
	return out, nil
}

// LastFailure returns what the target printed on the most recent run that
// failed.
func (t *Triage) LastFailure() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.lastFailure
}

// deliveryFor maps the campaign's input mode onto the executor's.
//
// Duplicated from the worker's own mapping rather than shared through it: the
// worker is a separate process and importing it here would pull an engine into
// the daemon for the sake of a four-line switch.
func deliveryFor(input string) executor.Delivery {
	switch input {
	case campaign.InputFile:
		return executor.DeliverFile
	case campaign.InputArg:
		return executor.DeliverArg
	default:
		return executor.DeliverStdin
	}
}

// ErrNoTriage is returned when a campaign cannot re-run its own target.
var ErrNoTriage = errors.New("daemon: this campaign cannot re-run its target")

// ReplayReport is what a replay found.
type ReplayReport struct {
	Trials     int     `json:"trials"`
	Reproduced int     `json:"reproduced"`
	Rate       float64 `json:"rate"`
	Kind       string  `json:"kind"`
	Signal     int     `json:"signal"`
	Marker     string  `json:"marker,omitempty"`
	Divergent  bool    `json:"divergent"`
	State      string  `json:"triage_state"`
	Output     string  `json:"output,omitempty"`
}

// Replay re-runs a finding's reproducer and records what it found.
//
// Trials rather than one run, because "it crashed once" and "it crashes every
// time" are different facts and only the second is worth acting on. The count
// is recorded alongside the rate so that a finding nobody has examined cannot
// read as one that never reproduces (ASR-0011).
func (c *Campaign) Replay(ctx context.Context, id int64, trials int) (*ReplayReport, error) {
	tr, st := c.triage, c.store
	if tr == nil {
		return nil, ErrNoTriage
	}
	f, err := st.Finding(ctx, id)
	if err != nil {
		return nil, err
	}
	payload, err := reproducerOf(st, f)
	if err != nil {
		return nil, err
	}
	if trials <= 0 {
		trials = c.Config.Triage.Trials
	}

	rep, err := triage.Verify(ctx, tr, payload, trials)
	if err != nil {
		return nil, err
	}
	out := &ReplayReport{
		Trials: rep.Trials, Reproduced: rep.Reproduced, Rate: rep.Rate(),
		Divergent: len(rep.Divergent) > 0, State: stateFor(rep),
		Kind: rep.Class.Kind, Signal: rep.Class.Signal, Marker: rep.Class.Marker,
		Output: tr.LastFailure(),
	}

	err = st.UpdateTriage(ctx, f.ID, out.State, rep.Trials, rep.Rate(),
		f.Minimized, f.MinimizedSize, f.Notes)
	if err != nil {
		return nil, err
	}
	c.publish(EventTriage, map[string]any{
		"finding": f.ID, "state": out.State, "trials": out.Trials,
		"rate": out.Rate, "divergent": out.Divergent,
	})
	return out, nil
}

// stateFor maps a verification report onto a stored triage state.
//
// The report's own State is the answer except in one case it does not consider:
// a reproducer that fails every time but not always the same way. That is a
// race, and calling it "verified" would promise a determinism it does not have.
func stateFor(rep triage.VerifyReport) string {
	if len(rep.Divergent) > 0 && rep.Reproduced > 0 {
		return store.TriageFlaky
	}
	return rep.State()
}

// MinimizeReport is what a minimisation achieved.
type MinimizeReport struct {
	OriginalSize  int     `json:"original_size"`
	MinimizedSize int     `json:"minimized_size"`
	Reduction     float64 `json:"reduction"`
	Runs          int     `json:"runs"`
	Digest        string  `json:"digest"`
	State         string  `json:"triage_state"`
}

// Minimize reduces a finding's reproducer, keeping the failure class.
//
// The class, not merely "it still crashes": a minimiser free to land on any
// crash will happily hand back a reproducer for a different bug, and a smaller
// reproducer for the wrong bug is worse than the original (ASR-0011).
func (c *Campaign) Minimize(ctx context.Context, id int64, budget int) (*MinimizeReport, error) {
	tr, st := c.triage, c.store
	if tr == nil {
		return nil, ErrNoTriage
	}
	f, err := st.Finding(ctx, id)
	if err != nil {
		return nil, err
	}
	// From the input as the engine found it, not from whatever an earlier pass
	// reduced it to. Asking to minimise again is asking for a better job, and
	// the existing reproducer is a local optimum the last pass already reached
	// — starting there with a larger budget mostly re-derives it. It also makes
	// the report legible: "2000 bytes to 19" is the number somebody wants, and
	// "2 bytes to 2, 0% smaller" reads like a failure when it is a re-run.
	payload, err := st.Blobs().Get(f.Digest)
	if err != nil {
		return nil, fmt.Errorf("daemon: finding %d has no stored input: %w", f.ID, err)
	}
	if budget <= 0 {
		budget = c.Config.Triage.MinimizeBudget
	}

	small, rep, err := triage.Minimize(ctx, tr, payload, triage.MinimizeOptions{MaxRuns: budget})
	if err != nil {
		return nil, err
	}

	digest, err := st.PutBlob(ctx, small)
	if err != nil {
		return nil, err
	}
	state := store.TriageMinimized
	if f.TriageState == store.TriageUnverified || f.TriageState == store.TriageFlaky {
		// Minimisation does not upgrade a finding that does not reliably
		// reproduce; it only makes the unreliable thing smaller.
		state = f.TriageState
	}
	err = st.UpdateTriage(ctx, f.ID, state, f.ReproTrials, f.ReproRate, digest, len(small), f.Notes)
	if err != nil {
		return nil, err
	}

	out := &MinimizeReport{
		OriginalSize: rep.OriginalSize, MinimizedSize: rep.MinimizedSize,
		Reduction: rep.Reduction(), Runs: rep.Runs, Digest: digest.String(), State: state,
	}
	c.publish(EventTriage, map[string]any{
		"finding": f.ID, "state": state,
		"original_size": out.OriginalSize, "minimized_size": out.MinimizedSize,
		"reduction": out.Reduction,
	})
	return out, nil
}

// reproducerOf fetches the payload a finding should be re-run with: the
// minimised form when there is one, since that is the artefact a person works
// from and the one whose behaviour a replay is being asked about.
func reproducerOf(st *store.Store, f *store.Finding) ([]byte, error) {
	digest := f.Digest
	if !f.Minimized.IsZero() {
		digest = f.Minimized
	}
	payload, err := st.Blobs().Get(digest)
	if err != nil {
		return nil, fmt.Errorf("daemon: finding %d has no stored reproducer: %w", f.ID, err)
	}
	return payload, nil
}
