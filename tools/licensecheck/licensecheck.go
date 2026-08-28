// Package licensecheck enforces the dependency license policy of ADR-0018.
//
// The policy is only meaningful if it is applied at the moment a dependency is
// added, not audited before a release when removing it is expensive. Every
// module in go.mod must carry a NOTICE entry with a license from the allowed
// set; anything else fails the build.
package licensecheck

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Allowed licenses may be used freely with attribution in NOTICE.
var Allowed = map[string]bool{
	"Apache-2.0": true, "MIT": true, "BSD-2-Clause": true, "BSD-3-Clause": true,
	"ISC": true, "Unlicense": true, "Zlib": true, "BSD-3-Clause-Clear": true,
}

// Conditional licenses are permitted only under the stated restriction.
var Conditional = map[string]string{
	"MPL-2.0": "permitted only as an unmodified library",
}

// Forbidden licenses may never be used. Listed explicitly so that the failure
// message can name the policy rather than merely saying "unknown".
var Forbidden = map[string]bool{
	"GPL-2.0": true, "GPL-3.0": true, "AGPL-3.0": true, "LGPL-2.1": true,
	"LGPL-3.0": true, "SSPL-1.0": true, "BUSL-1.1": true, "CC-BY-NC-4.0": true,
}

// Problem is a single policy breach.
type Problem struct {
	Module string
	Msg    string
}

func (p Problem) String() string {
	if p.Module == "" {
		return p.Msg
	}
	return p.Module + ": " + p.Msg
}

// Component is one row of the NOTICE Components table.
type Component struct {
	Module  string
	Version string
	License string
	UsedFor string
}

var componentRowRe = regexp.MustCompile(`^\|\s*([^|]+?)\s*\|\s*([^|]*?)\s*\|\s*([^|]*?)\s*\|\s*([^|]*?)\s*\|$`)

// Check verifies the repository's go.mod against its NOTICE inventory.
func Check(dir string) ([]Problem, error) {
	mods, err := ParseGoMod(filepath.Join(dir, "go.mod"))
	if err != nil {
		return nil, err
	}
	comps, err := ParseNotice(filepath.Join(dir, "NOTICE"))
	if err != nil {
		return nil, err
	}

	byModule := make(map[string]Component, len(comps))
	var ps []Problem
	for _, c := range comps {
		if _, dup := byModule[c.Module]; dup {
			ps = append(ps, Problem{c.Module, "listed more than once in NOTICE"})
		}
		byModule[c.Module] = c

		switch {
		case Forbidden[c.License]:
			ps = append(ps, Problem{c.Module, fmt.Sprintf(
				"license %s is forbidden by ADR-0018; this dependency cannot be used", c.License)})
		case Allowed[c.License]:
		default:
			if note, ok := Conditional[c.License]; ok {
				ps = append(ps, Problem{c.Module, fmt.Sprintf(
					"license %s is conditional (%s); confirm the condition holds and move the entry to the allowed set",
					c.License, note)})
				continue
			}
			ps = append(ps, Problem{c.Module, fmt.Sprintf(
				"license %q is not in the ADR-0018 allowed set", c.License)})
		}
	}

	for _, m := range mods {
		c, ok := byModule[m.Path]
		if !ok {
			ps = append(ps, Problem{m.Path, "required by go.mod but missing from NOTICE; add a Components row in the same commit"})
			continue
		}
		if c.Version != "" && c.Version != m.Version {
			ps = append(ps, Problem{m.Path, fmt.Sprintf(
				"NOTICE records version %s but go.mod requires %s", c.Version, m.Version)})
		}
	}

	required := make(map[string]bool, len(mods))
	for _, m := range mods {
		required[m.Path] = true
	}
	for _, c := range comps {
		if !required[c.Module] {
			ps = append(ps, Problem{c.Module, "listed in NOTICE but no longer required by go.mod; remove the stale entry"})
		}
	}

	sort.Slice(ps, func(i, j int) bool {
		if ps[i].Module != ps[j].Module {
			return ps[i].Module < ps[j].Module
		}
		return ps[i].Msg < ps[j].Msg
	})
	return ps, nil
}

// Module is a go.mod requirement.
type Module struct {
	Path    string
	Version string
}

// ParseGoMod extracts the require directives from a go.mod file. It reads the
// file directly rather than shelling out to the toolchain so that the check is
// hermetic and runs offline.
func ParseGoMod(path string) ([]Module, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var mods []Module
	inBlock := false
	for _, raw := range strings.Split(string(b), "\n") {
		line := strings.TrimSpace(raw)
		if i := strings.Index(line, "//"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line == "" {
			continue
		}
		switch {
		case inBlock && line == ")":
			inBlock = false
		case inBlock:
			if m, ok := parseRequire(line); ok {
				mods = append(mods, m)
			}
		case line == "require (":
			inBlock = true
		case strings.HasPrefix(line, "require "):
			if m, ok := parseRequire(strings.TrimPrefix(line, "require ")); ok {
				mods = append(mods, m)
			}
		}
	}
	sort.Slice(mods, func(i, j int) bool { return mods[i].Path < mods[j].Path })
	return mods, nil
}

func parseRequire(s string) (Module, bool) {
	f := strings.Fields(s)
	if len(f) < 2 {
		return Module{}, false
	}
	return Module{Path: f[0], Version: f[1]}, true
}

// ParseNotice extracts the Components table from a NOTICE file.
func ParseNotice(path string) ([]Component, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	_, after, found := strings.Cut(string(b), "## Components")
	if !found {
		return nil, fmt.Errorf("%s: no '## Components' section", path)
	}
	var comps []Component
	for _, raw := range strings.Split(after, "\n") {
		line := strings.TrimSpace(raw)
		if !strings.HasPrefix(line, "|") {
			continue
		}
		m := componentRowRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		mod := m[1]
		if mod == "Module" || strings.HasPrefix(mod, "---") {
			continue
		}
		comps = append(comps, Component{
			Module: mod, Version: m[2], License: m[3], UsedFor: m[4],
		})
	}
	return comps, nil
}

// FindRepoRoot walks up from start until it finds the directory holding go.mod.
func FindRepoRoot(start string) (string, error) {
	d, err := filepath.Abs(start)
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(d, "go.mod")); err == nil {
			return d, nil
		}
		parent := filepath.Dir(d)
		if parent == d {
			return "", fmt.Errorf("no go.mod found above %s", start)
		}
		d = parent
	}
}
