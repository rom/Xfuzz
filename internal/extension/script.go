package extension

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/rom/Xfuzz/pkg/campaign"
	"github.com/rom/Xfuzz/pkg/plugin/script"
	"github.com/rom/Xfuzz/pkg/state"
)

// loadScripts reads and executes the campaign's Starlark, and resolves the
// functions it named.
//
// At startup, deliberately. A Starlark module's top level is where its
// functions are defined, so executing it is how they come to exist — and a
// syntax error or a missing function should surface here, named with a line
// number, rather than on the four-thousandth execution.
func (s *Set) loadScripts(cfg *campaign.Resolved, seed uint64) error {
	for _, sc := range cfg.Scripts {
		path := sc.Path
		if !filepath.IsAbs(path) && cfg.Path != "" {
			// Relative to the campaign file, not to the worker's working
			// directory: a campaign file is meant to be movable, and a script
			// beside it should still be found after the daemon chdirs.
			path = filepath.Join(filepath.Dir(cfg.Path), path)
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("script %s: %w", sc.Name, err)
		}

		mod, err := script.Load(sc.Name, src, script.Options{
			Seed:   seed,
			Config: sc.Config,
			Limits: script.Limits{Steps: sc.Steps, Allocs: sc.Allocs},
		})
		if err != nil {
			return err
		}
		s.scripts = append(s.scripts, mod)

		for _, fn := range sc.Objectives {
			o, err := mod.NewObjective(fn)
			if err != nil {
				return err
			}
			s.objectives = append(s.objectives, o)
			s.scriptErrs = append(s.scriptErrs, o.Err)
		}
		for _, fn := range sc.Mutators {
			m, err := mod.NewMutator(fn)
			if err != nil {
				return err
			}
			m.SetBatch(sc.Batch)
			s.mutators = append(s.mutators, m)
			s.scriptErrs = append(s.scriptErrs, m.Err)
		}
	}
	return nil
}

// StateFn resolves a "SCRIPT:FUNCTION" reference from the campaign's state
// block.
func (s *Set) StateFn(ref string) (state.StateFn, error) {
	name, fn, ok := strings.Cut(ref, ":")
	if !ok || name == "" || fn == "" {
		return nil, fmt.Errorf(`extension: %q is not a script state function; it is "SCRIPT:FUNCTION"`, ref)
	}
	for _, mod := range s.scripts {
		if mod.Name() != name {
			continue
		}
		f, err := mod.NewStateFn(fn)
		if err != nil {
			return nil, err
		}
		s.scriptErrs = append(s.scriptErrs, f.Err)
		return f, nil
	}
	return nil, fmt.Errorf("extension: no script named %q for the state function", name)
}
