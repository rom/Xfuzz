package worker

import (
	"context"
	"fmt"
	"strings"

	"github.com/rom/Xfuzz/internal/safety"
	"github.com/rom/Xfuzz/pkg/campaign"
	"github.com/rom/Xfuzz/pkg/executor"
	"github.com/rom/Xfuzz/pkg/state"
)

// buildSession assembles the T6 executor and the state guidance for a stateful
// campaign.
//
// The session block's presence is what makes a campaign stateful, so this is
// the one branch in the worker's construction that distinguishes the two kinds.
// Everything downstream — the corpus, the mutators, the triage — is the same
// machinery, which is ASR-0002's whole point.
func (b *built) buildSession(ctx context.Context, cfg *campaign.Resolved) error {
	sc := cfg.Session

	// Resolved before the sandbox was built, because the sandbox had to know
	// about it. Each worker gets its own address, because each worker starts
	// its own copy of the target — resolved by the worker rather than written
	// per worker in the file, so the file stays the one thing that gets
	// reviewed.
	addr := b.sessionAddr
	network, address, err := campaign.SplitAddress(addr)
	if err != nil {
		return fmt.Errorf("worker: session address: %w", err)
	}

	framing, err := executor.FramingNamed(sc.Framing)
	if err != nil {
		return err
	}
	reset, err := resetPolicyNamed(sc.Reset)
	if err != nil {
		return err
	}

	opts := executor.SessionOptions{
		Network:        network,
		Address:        address,
		Reset:          reset,
		Framing:        framing,
		QuietPeriod:    sc.QuietPeriod.Std(),
		ConnectTimeout: sc.ConnectTimeout.Std(),
		ReadTimeout:    sc.ReadTimeout.Std(),
		SessionTimeout: sc.SessionTimeout.Std(),
		ReadLimit:      sc.ReadLimit,
	}

	// The scope guard is the dialer. Every connection a session makes passes
	// through it, and the architecture lint means the executor has no other way
	// to reach the network (ADR-0012).
	sess := executor.NewSession("session", b.scope, opts)
	sess.Output = b.output
	if b.shm != nil {
		sess.Shm, sess.Backend = b.shm, cfg.Feedback.Coverage
	}

	if sc.Managed != nil && *sc.Managed {
		spawner := safety.NewSpawner()
		spawner.Sandbox = b.sandbox
		sess.Manage(spawner, serverSpecFor(cfg, addr))
	}

	if err := sess.Start(ctx); err != nil {
		return err
	}
	b.executor = sess
	b.tier = "session"
	b.closers = append(b.closers, func() { sess.Close() })

	if cfg.State != nil && cfg.State.Guide != nil && *cfg.State.Guide {
		g, gerr := guidanceFor(cfg)
		if gerr != nil {
			return gerr
		}
		b.state = g
		sess.States = g.Observer
	}
	return nil
}

// serverSpecFor describes the server process to run.
//
// The address is appended to the target's own arguments rather than replacing
// them, so a campaign can pass whatever else its server needs and still have
// the per-worker address substituted. The convention is the same @@-shaped one
// the file tiers use: a campaign that names {address} in its arguments gets it
// substituted there, and one that does not gets --listen appended.
func serverSpecFor(cfg *campaign.Resolved, addr string) executor.ProcSpec {
	t := cfg.Target
	argv := append([]string{t.Path}, t.Args...)

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

	env := make([]string, 0, len(t.Env))
	for k, v := range t.Env {
		env = append(env, k+"="+v)
	}
	return executor.ProcSpec{
		Path: t.Path,
		Args: argv,
		Env:  env,
		Dir:  t.Dir,
		// No Timeout: a server is meant to outlive an execution. Bounding it
		// per execution would kill the target between sessions and turn every
		// campaign into a restart campaign without saying so.
		CaptureOutput: true,
	}
}

// AddressPlaceholder is replaced with the session address in a target's
// arguments.
const AddressPlaceholder = "{address}"

// guidanceFor assembles the state model, observer and scheduler.
func guidanceFor(cfg *campaign.Resolved) (*state.Guidance, error) {
	st := cfg.State

	fn := state.FnNamed(st.Fn)
	if fp, ok := fn.(*state.FingerprintFn); ok && len(st.Normalise) > 0 {
		ns := make([]state.Normaliser, 0, len(st.Normalise))
		for _, name := range st.Normalise {
			n := state.NormaliserNamed(name)
			if n == nil {
				return nil, fmt.Errorf("worker: %q is not a normalisation step", name)
			}
			ns = append(ns, n)
		}
		fp.Normalisers = ns
	}

	g := state.NewGuidance(fn)
	if st.Explore > 0 {
		g.Scheduler.Explore = st.Explore
	}
	if st.TailBias > 0 {
		g.Scheduler.TailBias = st.TailBias
	}

	moves := make([]state.Transition, 0, len(st.Declare))
	for _, d := range st.Declare {
		from, to, err := campaign.ParseTransition(d)
		if err != nil {
			return nil, fmt.Errorf("worker: %w", err)
		}
		moves = append(moves, state.Transition{From: state.Label(from), To: state.Label(to)})
	}
	g.Declare(moves)
	return g, nil
}

// resetPolicyNamed maps the campaign file's reset contract onto the executor's.
func resetPolicyNamed(name string) (executor.ResetPolicy, error) {
	switch name {
	case "none":
		return executor.ResetNone, nil
	case "reconnect", "":
		return executor.ResetReconnect, nil
	case "restart":
		return executor.ResetRestart, nil
	case "snapshot":
		return executor.ResetSnapshot, nil
	}
	return 0, fmt.Errorf("worker: %q is not a reset policy", name)
}
