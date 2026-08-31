package worker

import (
	"context"
	"fmt"
	"strings"

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
	backend, err := b.driverBackend(cfg)
	if err != nil {
		return err
	}

	reset := executor.ResetRestart
	if d.Reset == "none" {
		reset = executor.ResetNone
	}
	e := executor.NewDriver(d.Kind, backend, executor.DriverOptions{
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
	b.tier = d.Kind
	b.closers = append(b.closers, closer{d.Kind + " driver", e.Close})
	return nil
}

// driverBackend builds the one backend the campaign asked for.
//
// The dispatch is here and nowhere else: everything after it — the corpus, the
// mutation operators, the state model, the oracles — is written against
// executor.DriverBackend and never learns which one it got. That is the claim
// ADR-0013 makes about the tier, and a second switch anywhere below would be
// the first sign it had stopped being true.
func (b *built) driverBackend(cfg *campaign.Resolved) (executor.DriverBackend, error) {
	d := cfg.Driver
	spawner := safety.NewSpawner()
	spawner.Sandbox = b.sandbox

	switch d.Kind {
	case campaign.DriverTUI:
		if !safety.PTYSupported() {
			return nil, fmt.Errorf("worker: this host has no pseudo-terminal support, so a " +
				"terminal program cannot be driven here — over pipes isatty is false, " +
				"the size is unknown and there is no controlling terminal, which is a " +
				"different program from the one the campaign meant to fuzz")
		}
		t := cfg.Target
		return driver.NewTUI(spawner, driver.TUIOptions{
			Path:           t.Path,
			Args:           append([]string{t.Path}, t.Args...),
			Env:            procSpecFor(cfg).Env,
			Dir:            t.Dir,
			Cols:           d.Cols,
			Rows:           d.Rows,
			Settle:         d.Settle.Std(),
			StartTimeout:   d.StartTimeout.Std(),
			MaxOutputBytes: int64(d.MaxOutputBytes),
		}), nil

	case campaign.DriverGUIAtspi:
		g := driver.NewGUI(spawner, driver.GUIOptions{
			Path:         cfg.Target.Path,
			Args:         append([]string{cfg.Target.Path}, cfg.Target.Args...),
			Env:          procSpecFor(cfg).Env,
			Dir:          cfg.Target.Dir,
			StartTimeout: d.StartTimeout.Std(),
			Settle:       d.Settle.Std(),
		})
		if !g.Supported() {
			_, detail := driver.DesktopEnvironment()
			return nil, fmt.Errorf("worker: this host cannot drive a desktop "+
				"application: %s", detail)
		}
		return g, nil

	case campaign.DriverWeb:
		// A browser cannot start under an address-space limit, and the limit is
		// not the right instrument for one anyway.
		//
		// A modern JavaScript engine *reserves* address space by the terabyte —
		// the pointer-compression cage alone is gigabytes per isolate — and
		// touches almost none of it. RLIMIT_AS counts the reservation, so a
		// campaign's ordinary 2 GiB cap does not constrain the browser's memory
		// use, it stops the browser from launching: measured here, Chromium
		// under `ulimit -v 2097152` never reaches the point of announcing its
		// debugging endpoint, and the only symptom upstream was a protocol
		// command that never answered.
		//
		// So the browser's spawner gets a sandbox with that one limit dropped.
		// Everything else the campaign asked for stays: the namespaces, the
		// filter, the process cap, the working directory, and the cgroup — and
		// the cgroup is the mechanism that actually bounds a browser's memory,
		// because it counts pages in use rather than address space reserved.
		browserSandbox := b.sandbox.Clone()
		browserSandbox.Limits.AddressSpaceBytes = 0
		if browserSandbox.Limits.Processes > 0 &&
			browserSandbox.Limits.Processes < driver.MinBrowserProcesses {
			// The same argument for the same reason: a campaign's process cap
			// is sized for a parser, and a browser under it starts, announces
			// its endpoint and then cannot fork a renderer. Raised to a floor
			// rather than removed, so a runaway browser is still bounded.
			browserSandbox.Limits.Processes = driver.MinBrowserProcesses
		}
		browserSandbox.Name = b.sandbox.Name + "-browser"
		spawner = safety.NewSpawner()
		spawner.Sandbox = browserSandbox
		b.closers = append(b.closers, closer{"browser sandbox", browserSandbox.Close})

		browser := d.Browser
		if browser == "" {
			// target.path names the browser when it is somewhere no probe would
			// look. It is not the target: for a web campaign the target is
			// whatever answers driver.url.
			browser = cfg.Target.Path
		}
		sandboxBrowser := d.BrowserSandbox == nil || *d.BrowserSandbox
		w := driver.NewWeb(spawner, driver.WebOptions{
			URL:            d.URL,
			Browser:        browser,
			Args:           d.BrowserArgs,
			Env:            procSpecFor(cfg).Env,
			Width:          d.Width,
			Height:         d.Height,
			StartTimeout:   d.StartTimeout.Std(),
			Settle:         d.Settle.Std(),
			Headed:         d.Headed,
			BrowserSandbox: sandboxBrowser,
			// The browser's debugging port, which is the control channel to a
			// harness this fuzzer started rather than traffic the campaign
			// aimed anywhere. It is dialled through the safety layer and
			// audited, and it is loopback or it is refused (ADR-0034).
			Dial: b.scope.DialControl,
		})
		if !w.Supported() {
			_, err := driver.FindBrowser(browser)
			return nil, fmt.Errorf("worker: %w", err)
		}
		return w, nil
	}
	return nil, fmt.Errorf("worker: driver.kind %q is not implemented; one of %s",
		d.Kind, strings.Join(campaign.DriverKinds, ", "))
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
		case campaign.DriverOracleException:
			objs = append(objs, feedback.NewUIExceptionObjective("ui-exception", out))
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
