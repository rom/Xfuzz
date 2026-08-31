package worker

import (
	"context"
	"fmt"

	"github.com/rom/Xfuzz/internal/driver"
	"github.com/rom/Xfuzz/internal/safety"
	"github.com/rom/Xfuzz/pkg/campaign"
	"github.com/rom/Xfuzz/pkg/executor"
	"github.com/rom/Xfuzz/pkg/feedback"
	"github.com/rom/Xfuzz/pkg/state"
)

// buildDriver assembles the T7 tier and the UI-state guidance behind it.
//
// The claim ADR-0013 makes, in code: everything from here on is the machine
// every other tier uses. The corpus is the same corpus, the mutation operators
// are the same operators over an IR Repeat, the feedback is the same feedback,
// and the state model a screen builds is the one a protocol session builds. What
// is different is one backend and one state function.
func (b *built) buildDriver(ctx context.Context, cfg *campaign.Resolved) error {
	d := cfg.Driver
	if d.Kind != campaign.DriverTUI {
		return fmt.Errorf("worker: driver.kind %q is not implemented; only %q is",
			d.Kind, campaign.DriverTUI)
	}
	if !safety.PTYSupported() {
		return fmt.Errorf("worker: this host has no pseudo-terminal support, so a " +
			"terminal program cannot be driven here — over pipes isatty is false, " +
			"the size is unknown and there is no controlling terminal, which is a " +
			"different program from the one the campaign meant to fuzz")
	}

	spawner := safety.NewSpawner()
	spawner.Sandbox = b.sandbox

	t := cfg.Target
	backend := driver.NewTUI(spawner, driver.TUIOptions{
		Path:           t.Path,
		Args:           append([]string{t.Path}, t.Args...),
		Env:            procSpecFor(cfg).Env,
		Dir:            t.Dir,
		Cols:           d.Cols,
		Rows:           d.Rows,
		Settle:         d.Settle.Std(),
		StartTimeout:   d.StartTimeout.Std(),
		MaxOutputBytes: int64(d.MaxOutputBytes),
	})

	reset := executor.ResetRestart
	if d.Reset == "none" {
		reset = executor.ResetNone
	}
	e := executor.NewDriver("tui", backend, executor.DriverOptions{
		Timeout:   d.Timeout.Std(),
		Settle:    d.Settle.Std(),
		MaxEvents: d.MaxEvents,
		Reset:     reset,
	})
	e.Output = b.output

	// The screen is the state, so the state observer is the UI sink. Nothing
	// here is terminal-specific: a widget tree would arrive through the same
	// method and build the same model.
	if d.Guide != nil && *d.Guide {
		fn := state.NewScreenFn()
		if len(d.Normalise) > 0 {
			ns := make([]state.Normaliser, 0, len(d.Normalise))
			for _, name := range d.Normalise {
				n := state.NormaliserNamed(name)
				if n == nil {
					return fmt.Errorf("worker: driver.normalise: %q is not a step", name)
				}
				ns = append(ns, n)
			}
			fn.Normalisers = ns
		}
		g := state.NewGuidance(fn)
		b.state = g
		// The observer the guidance already built is the sink: a screen is a
		// response, and RecordUI is Response under the name the executor knows.
		e.UI = g.Observer
	}

	if err := e.Start(ctx); err != nil {
		return err
	}
	b.executor = e
	b.tier = "tui"
	b.closers = append(b.closers, closer{"terminal driver", e.Close})
	return nil
}

// driverObjectives builds the interface oracles a campaign asked for.
//
// Additive to the ordinary ones, and for a sharper reason than on the API tier:
// an interface fails in three ways that leave the process alive and the exit
// status zero, so crash detection sees a completely ordinary execution.
func driverObjectives(cfg *campaign.Resolved, out *feedback.OutputObserver,
	g *state.Guidance) []feedback.Objective {

	if cfg.Driver == nil {
		return nil
	}
	var objs []feedback.Objective
	for _, name := range cfg.Driver.Oracles {
		switch name {
		case campaign.DriverOracleDiagnostic:
			objs = append(objs, feedback.NewUIDiagnosticObjective("ui-diagnostic", out))
		case campaign.DriverOracleUnresponsive:
			if g == nil || g.Observer == nil {
				continue
			}
			objs = append(objs, feedback.NewUIUnresponsiveObjective("ui-unresponsive", g.Observer))
		case campaign.DriverOracleTrap:
			if g == nil || g.Observer == nil {
				continue
			}
			o := feedback.NewUITrapObjective("ui-trap", g.Observer)
			// So a finding names the screen rather than its hash: a bug filed
			// against state 7 is a bug nobody can act on.
			o.Exemplar = exemplarFrom(g)
			objs = append(objs, o)
		}
	}
	return objs
}

// exemplarFrom returns a lookup from a state label to the screen it stands for.
func exemplarFrom(g *state.Guidance) func(string) (string, bool) {
	if g == nil || g.Model == nil {
		return nil
	}
	model := g.Model
	return func(label string) (string, bool) {
		b, ok := model.Exemplar(state.Label(label))
		return string(b), ok
	}
}
