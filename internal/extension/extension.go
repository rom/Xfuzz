// Package extension resolves a campaign's out-of-process plugins into the
// feedbacks, objectives and mutators the engine runs.
//
// It exists because two rules meet here and neither can be bent. Only
// internal/safety may create a process (ADR-0012), and pkg/ may not import
// internal/ — so pkg/plugin owns the protocol and knows nothing about spawning,
// internal/safety owns spawning and knows nothing about the protocol, and this
// package is where a campaign file turns into a running, confined plugin.
package extension

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/rom/Xfuzz/internal/safety"
	"github.com/rom/Xfuzz/pkg/campaign"
	"github.com/rom/Xfuzz/pkg/executor"
	"github.com/rom/Xfuzz/pkg/feedback"
	"github.com/rom/Xfuzz/pkg/mutate"
	"github.com/rom/Xfuzz/pkg/plugin"
)

// Set is every plugin one campaign uses, and what each supplies.
type Set struct {
	plugins []*loaded

	feedbacks  []feedback.Feedback
	objectives []feedback.Objective
	mutators   []mutate.Mutator

	wantsInput bool
}

type loaded struct {
	label string
	host  *plugin.Host
	peer  *safety.Peer
}

// Load starts every plugin the campaign declares and resolves its extensions.
//
// A plugin that will not start, will not handshake, or does not provide what
// the campaign asked for stops the campaign here, before a single execution.
// The alternative is a campaign that runs for six hours and measured something
// other than what its file says.
func Load(ctx context.Context, spawner *safety.Spawner, cfg *campaign.Resolved, seed uint64, engine string) (*Set, error) {
	if len(cfg.Extensions) == 0 {
		return &Set{}, nil
	}

	s := &Set{}
	for _, e := range cfg.Extensions {
		if err := s.start(ctx, spawner, e, seed, engine); err != nil {
			// Whatever did start is stopped: a half-loaded set would leave
			// plugin processes behind for a campaign that never ran.
			s.Close()
			return nil, err
		}
	}
	return s, nil
}

func (s *Set) start(ctx context.Context, spawner *safety.Spawner, e campaign.Extension, seed uint64, engine string) error {
	peer, err := spawner.StartPeer(ctx, specFor(e))
	if err != nil {
		return fmt.Errorf("extension %s: %w", e.Name, err)
	}

	host, err := plugin.Dial(plugin.Options{
		Label:  e.Name,
		Engine: engine,
		Seed:   seed,
		Config: e.Config,
		Transport: plugin.Transport{
			Stdin:    peer.Stdin(),
			Stdout:   peer.Stdout(),
			Kill:     peer.Kill,
			Diagnose: peer.Diagnose,
		},
		CallTimeout: e.Timeout.Std(),
	})
	if err != nil {
		peer.Kill()
		return err
	}
	l := &loaded{label: e.Name, host: host, peer: peer}
	s.plugins = append(s.plugins, l)

	for _, name := range e.Feedbacks {
		f, err := host.NewFeedback(name)
		if err != nil {
			return err
		}
		s.feedbacks = append(s.feedbacks, f)
	}
	for _, name := range e.Objectives {
		o, err := host.NewObjective(name)
		if err != nil {
			return err
		}
		s.objectives = append(s.objectives, o)
	}
	for _, name := range e.Mutators {
		m, err := host.NewMutator(name)
		if err != nil {
			return err
		}
		m.SetBatch(e.Batch)
		s.mutators = append(s.mutators, m)
	}
	if e.Input {
		s.wantsInput = true
	}
	return nil
}

// specFor turns an extension declaration into a process to spawn.
func specFor(e campaign.Extension) executor.ProcSpec {
	argv := append([]string{e.Command}, e.Args...)

	env := make([]string, 0, len(e.Env))
	for k, v := range e.Env {
		env = append(env, k+"="+v)
	}
	// Sorted, because a plugin that reads its environment should see the same
	// one on every run of a campaign that is supposed to replay (ASR-0008).
	sort.Strings(env)

	return executor.ProcSpec{
		Path: e.Command,
		Args: argv,
		Env:  env,
		Dir:  e.Dir,
		// No Timeout: a plugin is long-lived by definition, and the bound that
		// matters is on a call, which the host enforces.
	}
}

// Feedbacks, Objectives and Mutators are what the campaign's plugins supply.
func (s *Set) Feedbacks() []feedback.Feedback   { return s.feedbacks }
func (s *Set) Objectives() []feedback.Objective { return s.objectives }
func (s *Set) Mutators() []mutate.Mutator       { return s.mutators }

// Empty reports whether the campaign has no plugins at all, which is the
// common case and the one that must cost nothing.
func (s *Set) Empty() bool { return len(s.plugins) == 0 }

// WantsInput reports whether any plugin asked to see the executed bytes. The
// observer that carries them is only wired when something reads it.
func (s *Set) WantsInput() bool { return s.wantsInput }

// Err returns the failure that took a plugin out of service, or nil.
//
// This is what makes a plugin mutator's failure visible: Mutate cannot return
// an error, so the worker asks here once per batch of iterations. Every host is
// an atomic load, so asking is affordable.
func (s *Set) Err() error {
	for _, l := range s.plugins {
		if err := l.host.Err(); err != nil {
			return err
		}
	}
	return nil
}

// Stats reports how many calls were made into plugins and how long was spent
// waiting for them, which ADR-0010 makes a first-class metric: a slow plugin
// should be diagnosable from the campaign's own numbers.
func (s *Set) Stats() (calls int64, inside time.Duration) {
	for _, l := range s.plugins {
		calls += l.host.Calls()
		inside += l.host.Inside()
	}
	return calls, inside
}

// Close settles what each plugin is owed, asks it to exit, and kills it if it
// does not.
func (s *Set) Close() error {
	var errs []error
	for _, l := range s.plugins {
		if err := l.host.Close(); err != nil {
			errs = append(errs, err)
		}
		l.peer.Kill()
	}
	s.plugins = nil
	return errors.Join(errs...)
}
