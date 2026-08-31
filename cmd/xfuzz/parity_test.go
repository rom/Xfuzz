package main

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/rom/Xfuzz/internal/api"
	"github.com/rom/Xfuzz/internal/daemon"
	"github.com/rom/Xfuzz/tools/docslint"
)

// The CLI/API parity test (ASR-0005).
//
// ADR-0003 says every capability is defined once as an API method, and that CLI
// commands and console views are both defined against that surface. Parity by
// construction rather than by discipline is only true if something checks it —
// otherwise the CLI grows a command the console cannot offer, or the API grows
// a route nobody can reach from a terminal, and the divergence is discovered by
// a user rather than by a test.

func apiRoutes(t *testing.T) map[string]api.Route {
	t.Helper()
	d, err := daemon.New(daemon.Options{DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close(t.Context())

	out := map[string]api.Route{}
	for _, r := range api.NewServer(d).Routes() {
		out[r.Name] = r
	}
	return out
}

func TestEveryAPIRouteIsReachableFromTheCLI(t *testing.T) {
	routes := apiRoutes(t)

	used := map[string][]string{}
	for _, c := range commands {
		for _, r := range c.API {
			used[r] = append(used[r], c.Name)
		}
	}

	var missing []string
	for name := range routes {
		if len(used[name]) == 0 {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		t.Errorf("the API has capabilities the CLI cannot reach:\n  %s",
			strings.Join(missing, "\n  "))
	}
}

func TestEveryCLICommandMapsToTheAPI(t *testing.T) {
	routes := apiRoutes(t)

	// Commands with no API calls are local by design, and each is listed here
	// so that "local" is a decision rather than an omission.
	local := map[string]string{
		"init":    "writes a campaign file; no daemon is involved in writing one",
		"version": "reports the running binary, which no daemon can answer about this process",
		"capture": "turns a recorded session into files; the credentials it separates out " +
			"must not travel over an API, and nothing about the translation needs a daemon",
	}

	for _, c := range commands {
		if len(c.API) == 0 {
			if _, ok := local[c.Name]; !ok {
				t.Errorf("command %q calls no API route and is not declared local; "+
					"either give it its routes or say why it has none", c.Name)
			}
			continue
		}
		if _, isLocal := local[c.Name]; isLocal {
			t.Errorf("command %q is declared local but names API routes", c.Name)
		}
		for _, r := range c.API {
			if _, ok := routes[r]; !ok {
				t.Errorf("command %q names API route %q, which does not exist", c.Name, r)
			}
		}
	}
}

func TestEveryCommandIsDescribed(t *testing.T) {
	// The command list is the help output. A command with no group or summary
	// is a command nobody discovers.
	for _, c := range commands {
		if c.Short == "" {
			t.Errorf("command %q has no summary", c.Name)
		}
		if c.Group == "" {
			t.Errorf("command %q has no group, so it does not appear under any heading", c.Name)
		}
		if c.Usage == "" {
			t.Errorf("command %q has no usage line", c.Name)
		}
		if c.Run == nil {
			t.Errorf("command %q does nothing", c.Name)
		}
		if !strings.HasPrefix(c.Usage, c.Name) {
			t.Errorf("command %q has usage %q, which does not start with the command", c.Name, c.Usage)
		}
	}
}

func TestMutatingRoutesAreReachedByAnActionCommand(t *testing.T) {
	// A mutating route reached only by an inspection command would mean a
	// command that reads also writes, which is not what anybody expects from
	// `xfuzz status`.
	routes := apiRoutes(t)
	inspection := map[string]bool{
		"corpus": true, "findings": true, "metrics": true, "watch": true,
		"workers": true, "safety": true, "audit": true, "info": true,
		"schema": true, "status": true, "list": true, "validate": true, "explain": true,
	}

	for _, c := range commands {
		if !inspection[c.Name] {
			continue
		}
		for _, name := range c.API {
			r, ok := routes[name]
			if !ok {
				continue
			}
			// corpus import and export mutate and belong to the corpus command
			// by nature; they are the exception and are named as one.
			if r.Mutating && !strings.HasPrefix(name, "corpus.") {
				t.Errorf("inspection command %q calls the mutating route %q", c.Name, name)
			}
		}
	}
}

func TestCommandNamesAreUnique(t *testing.T) {
	seen := map[string]bool{}
	for key, c := range commands {
		if key != c.Name {
			t.Errorf("command registered as %q calls itself %q", key, c.Name)
		}
		if seen[c.Name] {
			t.Errorf("two commands are named %q", c.Name)
		}
		seen[c.Name] = true
	}
}

func TestEveryCommandIsInTheGuide(t *testing.T) {
	// docs/GUIDE.md carries a reference table of every command. A table that
	// is merely written by hand is a table that is right on the day it is
	// written: the v0.1 audit found nine commands the guide had never heard
	// of, all of them added after the section around them was.
	//
	// The direction matters in both senses. A command missing from the table
	// is undiscoverable to anyone who does not already know it exists; a row
	// for a command that no longer exists sends a reader to an error message.
	root, err := docslint.FindRepoRoot(".")
	if err != nil {
		t.Fatal(err)
	}
	guide, err := os.ReadFile(filepath.Join(root, "docs", "GUIDE.md"))
	if err != nil {
		t.Fatal(err)
	}

	rowRe := regexp.MustCompile("(?m)^\\| `xfuzz ([a-z-]+)` \\| (.+?) \\|$")
	listed := map[string]string{}
	for _, m := range rowRe.FindAllStringSubmatch(string(guide), -1) {
		listed[m[1]] = m[2]
	}
	if len(listed) == 0 {
		t.Fatal("docs/GUIDE.md has no command reference table; the section was removed or its shape changed")
	}

	for _, c := range commands {
		summary, ok := listed[c.Name]
		if !ok {
			t.Errorf("command %q is not in the guide's command table", c.Name)
			continue
		}
		// The summary is the one the help output prints, so a reader sees the
		// same sentence in both places.
		if summary != c.Short {
			t.Errorf("guide describes %q as %q, but its help says %q", c.Name, summary, c.Short)
		}
	}
	for name := range listed {
		if _, ok := commands[name]; !ok {
			t.Errorf("the guide's command table lists %q, which is not a command", name)
		}
	}
}
