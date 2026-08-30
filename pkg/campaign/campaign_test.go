package campaign

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// target writes an executable stub, so validation has something real to stat.
func target(t *testing.T, dir string) string {
	t.Helper()
	p := filepath.Join(dir, "target")
	if err := os.WriteFile(p, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func write(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func minimal(t *testing.T, dir string) string {
	t.Helper()
	target(t, dir)
	return write(t, dir, "c.yaml", `
name: minimal
target:
  path: ./target
seeds:
  inline: ["seed"]
`)
}

func TestLoadFillsInDefaults(t *testing.T) {
	dir := t.TempDir()
	r, err := Load(minimal(t, dir))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if r.Target.Executor != ExecutorAuto || r.Target.Input != InputStdin {
		t.Fatalf("target defaults not applied: %+v", r.Target)
	}
	if r.Target.Timeout != Duration(5*time.Second) {
		t.Fatalf("timeout = %v", r.Target.Timeout)
	}
	if r.Workers.Count < 1 {
		t.Fatalf("worker count = %d", r.Workers.Count)
	}
	if r.Feedback.MapSize != 1<<16 || len(r.Feedback.Objectives) != 4 {
		t.Fatalf("feedback defaults not applied: %+v", r.Feedback)
	}
	if r.Triage.Enabled == nil || !*r.Triage.Enabled {
		t.Fatal("triage is off by default; a campaign would report one bug ten thousand times")
	}
	if r.Safety.Scope.Loopback == nil || !*r.Safety.Scope.Loopback {
		t.Fatal("loopback is denied by default; local experimentation would need an allowlist")
	}
	if r.Version != FormatVersion {
		t.Fatalf("version = %d", r.Version)
	}
}

func TestLoadResolvesPathsAgainstTheFile(t *testing.T) {
	dir := t.TempDir()
	target(t, dir)
	write(t, dir, "grammar.xfg", "format f { a: u8 }\n")
	if err := os.MkdirAll(filepath.Join(dir, "seeds"), 0o755); err != nil {
		t.Fatal(err)
	}
	path := write(t, dir, "c.yaml", `
name: paths
target:
  path: ./target
format:
  grammar: ./grammar.xfg
seeds:
  dirs: [./seeds]
`)

	// Loaded from a different working directory, which is the case the relative
	// paths have to survive: `xfuzz run ../campaigns/x.yaml` must mean the same
	// thing as running it from beside the file.
	r, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	for name, got := range map[string]string{
		"target.path":    r.Target.Path,
		"format.grammar": r.Format.Grammar,
		"seeds.dirs[0]":  r.Seeds.Dirs[0],
	} {
		if !filepath.IsAbs(got) {
			t.Errorf("%s = %q, which is still relative", name, got)
		}
		if !strings.HasPrefix(got, dir) {
			t.Errorf("%s = %q, which is not under the campaign file's directory", name, got)
		}
	}
}

func TestIncludesAreMergedUnderTheIncludingFile(t *testing.T) {
	dir := t.TempDir()
	target(t, dir)
	write(t, dir, "base.yaml", `
workers:
  count: 2
safety:
  isolation: strong
  memory_limit: 1024
format:
  max_input_bytes: 999
`)
	path := write(t, dir, "c.yaml", `
name: including
include: [./base.yaml]
target:
  path: ./target
seeds:
  inline: ["s"]
safety:
  isolation: moderate
`)

	r, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	// The including file wins where they disagree. An include that silently
	// overrode the file that asked for it is the behaviour nobody expects.
	if r.Safety.Isolation != "moderate" {
		t.Errorf("isolation = %q, want the including file's value", r.Safety.Isolation)
	}
	// And it inherits where it says nothing. Setting one key of a block must
	// not erase the rest of the block.
	if r.Safety.MemoryLimit != 1024 {
		t.Errorf("memory_limit = %d, want the included value 1024", r.Safety.MemoryLimit)
	}
	if r.Workers.Count != 2 {
		t.Errorf("workers.count = %d, want 2", r.Workers.Count)
	}
	if r.Format.MaxInputBytes != 999 {
		t.Errorf("max_input_bytes = %d, want 999", r.Format.MaxInputBytes)
	}
}

func TestIncludePathsResolveAgainstTheIncludedFile(t *testing.T) {
	dir := t.TempDir()
	target(t, dir)
	if err := os.MkdirAll(filepath.Join(dir, "shared", "seeds"), 0o755); err != nil {
		t.Fatal(err)
	}
	write(t, dir, "shared/base.yaml", "seeds:\n  dirs: [./seeds]\n")
	path := write(t, dir, "c.yaml", `
name: nested
include: [./shared/base.yaml]
target:
  path: ./target
`)

	r, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	want := filepath.Join(dir, "shared", "seeds")
	if r.Seeds.Dirs[0] != want {
		t.Fatalf("seeds.dirs[0] = %q, want %q; a shared fragment's own paths must "+
			"resolve against it, or it could only be included from a sibling directory",
			r.Seeds.Dirs[0], want)
	}
}

func TestIncludeCycleIsRefused(t *testing.T) {
	dir := t.TempDir()
	target(t, dir)
	write(t, dir, "a.yaml", "include: [./b.yaml]\n")
	write(t, dir, "b.yaml", "include: [./a.yaml]\n")
	path := write(t, dir, "c.yaml", "name: cycle\ninclude: [./a.yaml]\ntarget:\n  path: ./target\n")

	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "cycle") {
		t.Fatalf("err = %v, want an include cycle", err)
	}
}

func TestProfilesOverlayAndAreConsumed(t *testing.T) {
	dir := t.TempDir()
	target(t, dir)
	path := write(t, dir, "c.yaml", `
name: profiled
target:
  path: ./target
seeds:
  inline: ["s"]
workers:
  count: 1
mutation:
  weights:
    bit-flip: 1
    byte-flip: 2
profiles:
  ci:
    workers:
      count: 4
    stop:
      execs: 100000
    mutation:
      weights:
        bit-flip: 9
`)

	r, err := Load(path, "ci")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if r.Workers.Count != 4 {
		t.Errorf("workers.count = %d, want the profile's 4", r.Workers.Count)
	}
	if r.Stop.Execs != 100000 {
		t.Errorf("stop.execs = %d", r.Stop.Execs)
	}
	// A map of overrides merges key by key: adjusting one weight must not
	// require restating the others.
	if r.Mutation.Weights["bit-flip"] != 9 {
		t.Errorf("bit-flip weight = %d, want the profile's 9", r.Mutation.Weights["bit-flip"])
	}
	if r.Mutation.Weights["byte-flip"] != 2 {
		t.Errorf("byte-flip weight = %d, want the base's 2", r.Mutation.Weights["byte-flip"])
	}
	if len(r.Profiles) != 1 || r.Profiles[0] != "ci" {
		t.Errorf("applied profiles = %v", r.Profiles)
	}
	if r.File.Profiles != nil {
		t.Error("the resolved config still carries its profiles; they no longer apply")
	}
}

func TestUnknownProfileIsNamed(t *testing.T) {
	dir := t.TempDir()
	path := minimal(t, dir)
	_, err := Load(path, "nope")
	if err == nil {
		t.Fatal("an unknown profile was accepted")
	}
	if !strings.Contains(err.Error(), "nope") {
		t.Fatalf("err = %v", err)
	}
}

func TestSlicesReplaceRatherThanAppend(t *testing.T) {
	dir := t.TempDir()
	target(t, dir)
	path := write(t, dir, "c.yaml", `
name: slices
target:
  path: ./target
seeds:
  inline: ["s"]
feedback:
  objectives: [crash, hang, oom, sanitizer]
profiles:
  crash-only:
    feedback:
      objectives: [crash]
`)
	r, err := Load(path, "crash-only")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	// Appending would make it impossible to narrow a list, which is the main
	// thing a profile wants to do to one.
	if len(r.Feedback.Objectives) != 1 || r.Feedback.Objectives[0] != "crash" {
		t.Fatalf("objectives = %v, want exactly [crash]", r.Feedback.Objectives)
	}
}

func TestUnknownFieldsAreRejected(t *testing.T) {
	dir := t.TempDir()
	target(t, dir)
	path := write(t, dir, "c.yaml", `
name: typo
target:
  path: ./target
  timeuot: 10s
`)
	_, err := Load(path)
	if err == nil {
		t.Fatal("a misspelled key was accepted; it would have silently done nothing")
	}
	if !strings.Contains(err.Error(), "timeuot") {
		t.Fatalf("the error does not name the offending key: %v", err)
	}
}

func TestMissingFileIsNotFound(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "absent.yaml")); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestValidationReportsEverythingAtOnce(t *testing.T) {
	dir := t.TempDir()
	path := write(t, dir, "c.yaml", `
target:
  path: /nonexistent/target
  executor: teleport
  input: telepathy
format:
  codec: jpeg2000
feedback:
  coverage: guessing
  map_size: 1000
triage:
  trials: 0
  strategy: vibes
`)
	_, err := Load(path)
	if err == nil {
		t.Fatal("a file with nine problems was accepted")
	}
	var inv *Invalid
	if !errors.As(err, &inv) {
		t.Fatalf("err = %T, want *Invalid", err)
	}
	// The point is the list. A validator that stops at the first problem turns
	// one edit into five round trips.
	if len(inv.Problems) < 8 {
		t.Fatalf("reported %d problems, want at least 8:\n%v", len(inv.Problems), err)
	}
	for _, want := range []string{
		"name", "target.path", "target.executor", "target.input",
		"format.codec", "feedback.coverage", "feedback.map_size",
		"triage.trials", "triage.strategy", "seeds",
	} {
		found := false
		for _, p := range inv.Problems {
			if p.Field == want {
				found = true
			}
		}
		if !found {
			t.Errorf("no problem reported for %s:\n%v", want, err)
		}
	}
}

func TestValidationCatchesTheInputFileMismatch(t *testing.T) {
	dir := t.TempDir()
	target(t, dir)

	// file mode with no @@ produces a campaign where every execution reads an
	// empty file and nothing is ever found.
	path := write(t, dir, "a.yaml", `
name: a
target:
  path: ./target
  input: file
  args: ["--parse"]
seeds:
  inline: ["s"]
`)
	err := mustInvalid(t, path)
	if !hasField(err, "target.args") {
		t.Errorf("file input without @@ was accepted:\n%v", err)
	}

	// And the reverse.
	path = write(t, dir, "b.yaml", `
name: b
target:
  path: ./target
  input: stdin
  args: ["--parse", "@@"]
seeds:
  inline: ["s"]
`)
	err = mustInvalid(t, path)
	if !hasField(err, "target.input") {
		t.Errorf("@@ with stdin input was accepted:\n%v", err)
	}
}

func TestRemoteCampaignRequiresScopeAndAuthorization(t *testing.T) {
	dir := t.TempDir()
	target(t, dir)
	path := write(t, dir, "c.yaml", `
name: remote
target:
  path: ./target
seeds:
  inline: ["s"]
safety:
  network: true
`)
	err := mustInvalid(t, path)
	if !hasField(err, "safety.scope.allow") {
		t.Errorf("a campaign that leaves the host was accepted with no allowlist:\n%v", err)
	}
	if !hasField(err, "safety.authorization") {
		t.Errorf("a campaign that leaves the host was accepted with no authorization:\n%v", err)
	}
}

func TestNoTerminationConditionIsAllowedButVisible(t *testing.T) {
	dir := t.TempDir()
	r, err := Load(minimal(t, dir))
	if err != nil {
		t.Fatalf("an interactive campaign with no stop condition was refused: %v", err)
	}
	if !r.Stop.IsZero() {
		t.Fatal("Stop should be zero")
	}
	if !strings.Contains(r.ExplainString(), "runs until interrupted") {
		t.Fatalf("explain does not mention the missing termination condition:\n%s", r.ExplainString())
	}
}

func TestExplainDistinguishesDefaultsFromChoices(t *testing.T) {
	dir := t.TempDir()
	target(t, dir)
	path := write(t, dir, "c.yaml", `
name: explained
target:
  path: ./target
  timeout: 90s
seeds:
  inline: ["s"]
`)
	r, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	out := r.ExplainString()

	for _, want := range []string{"name", "target.path", "target.timeout", "feedback.map_size"} {
		if !strings.Contains(out, want) {
			t.Errorf("explain omits %s:\n%s", want, out)
		}
	}
	for _, line := range strings.Split(out, "\n") {
		switch {
		case strings.HasPrefix(line, "target.timeout"):
			if strings.Contains(line, "(default)") {
				t.Errorf("a value set in the file is marked as a default: %q", line)
			}
			if !strings.Contains(line, "1m30s") {
				t.Errorf("timeout line = %q", line)
			}
		case strings.HasPrefix(line, "feedback.map_size"):
			if !strings.Contains(line, "(default)") {
				t.Errorf("a defaulted value is not marked: %q", line)
			}
		}
	}
}

func TestExplainYAMLRoundTrips(t *testing.T) {
	dir := t.TempDir()
	target(t, dir)
	path := write(t, dir, "c.yaml", `
name: roundtrip
target:
  path: ./target
  timeout: 30s
seeds:
  inline: ["a", "b"]
workers:
  count: 3
stop:
  execs: 5000
`)
	r, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	b, err := r.YAML()
	if err != nil {
		t.Fatalf("YAML: %v", err)
	}

	// Pinning a run to an artefact after the fact is the point: the rendered
	// file has to run the same campaign.
	again, err := Parse(b, "explained.yaml")
	if err != nil {
		t.Fatalf("the rendered configuration does not parse: %v\n%s", err, b)
	}
	if again.Workers.Count != 3 || again.Stop.Execs != 5000 ||
		again.Target.Timeout != Duration(30*time.Second) || len(again.Seeds.Inline) != 2 {
		t.Fatalf("round trip lost settings:\n%s", b)
	}
}

func TestParseRefusesIncludes(t *testing.T) {
	// A document that arrived over the API must not be able to name a path on
	// the daemon's filesystem.
	_, err := Parse([]byte("name: x\ninclude: [/etc/passwd]\n"), "api")
	if err == nil || !strings.Contains(err.Error(), "include") {
		t.Fatalf("err = %v, want a refusal of include", err)
	}
}

func TestDurationSyntax(t *testing.T) {
	for in, want := range map[string]time.Duration{
		"30s":  30 * time.Second,
		"10m":  10 * time.Minute,
		"2h":   2 * time.Hour,
		"7d":   7 * 24 * time.Hour,
		"1.5d": 36 * time.Hour,
		"":     0,
	} {
		got, err := ParseDuration(in)
		if err != nil || got.Std() != want {
			t.Errorf("ParseDuration(%q) = %v, %v; want %v", in, got.Std(), err, want)
		}
	}
	if _, err := ParseDuration("soon"); err == nil {
		t.Error("a nonsense duration was accepted")
	}
	if got := Duration(7 * 24 * time.Hour).String(); got != "7d" {
		t.Errorf("7 days renders as %q", got)
	}
}

func TestBareNumberDurationIsRejectedWithAHint(t *testing.T) {
	dir := t.TempDir()
	target(t, dir)
	path := write(t, dir, "c.yaml", "name: d\ntarget:\n  path: ./target\n  timeout: 30\n")
	_, err := Load(path)
	if err == nil {
		t.Fatal("a bare number was accepted as a duration; seconds or milliseconds is a coin flip")
	}
	if !strings.Contains(err.Error(), "30s") {
		t.Fatalf("the error does not suggest the fix: %v", err)
	}
}

func TestParseAllow(t *testing.T) {
	cases := map[string]struct {
		dest  string
		ports int
		bad   bool
	}{
		"example.test":          {dest: "example.test"},
		"10.0.0.0/8":            {dest: "10.0.0.0/8"},
		"10.0.0.0/8:80":         {dest: "10.0.0.0/8", ports: 1},
		"10.0.0.1:80,8000-8999": {dest: "10.0.0.1", ports: 2},
		"[fd00::1]:443":         {dest: "fd00::1", ports: 1},
		"fd00::1":               {dest: "fd00::1"},
		"10.0.0.1:0":            {bad: true},
		"10.0.0.1:99999":        {bad: true},
		"10.0.0.1:900-100":      {bad: true},
		"":                      {bad: true},
	}
	for in, want := range cases {
		dest, ports, err := ParseAllow(in)
		if want.bad {
			if err == nil {
				t.Errorf("ParseAllow(%q) was accepted", in)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseAllow(%q): %v", in, err)
			continue
		}
		if dest != want.dest || len(ports) != want.ports {
			t.Errorf("ParseAllow(%q) = %q, %v; want %q with %d ports", in, dest, ports, want.dest, want.ports)
		}
	}
}

func mustInvalid(t *testing.T, path string) error {
	t.Helper()
	_, err := Load(path)
	if err == nil {
		t.Fatalf("%s was accepted", path)
	}
	return err
}

func hasField(err error, field string) bool {
	var inv *Invalid
	if !errors.As(err, &inv) {
		return false
	}
	for _, p := range inv.Problems {
		if p.Field == field {
			return true
		}
	}
	return false
}

func TestExplicitZeroIsNotSilentlyDefaulted(t *testing.T) {
	// Zero is a value somebody can mean. A file asking for no verification runs
	// must be told that is rejected, not quietly given five — and the only way
	// to tell "0" from "absent" is to know which keys the file contained.
	dir := t.TempDir()
	target(t, dir)
	path := write(t, dir, "c.yaml", `
name: zeroes
target:
  path: ./target
seeds:
  inline: ["s"]
triage:
  trials: 0
`)
	err := mustInvalid(t, path)
	if !hasField(err, "triage.trials") {
		t.Fatalf("an explicit trials: 0 was silently replaced with the default:\n%v", err)
	}
}

func TestExplicitZeroIsAllowedWhereItMeansSomething(t *testing.T) {
	// trim_budget: 0 means "do not trim", which is a legitimate thing to ask
	// for and must survive defaulting.
	dir := t.TempDir()
	target(t, dir)
	path := write(t, dir, "c.yaml", `
name: notrim
target:
  path: ./target
seeds:
  inline: ["s"]
mutation:
  trim_budget: 0
`)
	r, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if r.Mutation.TrimBudget != 0 {
		t.Fatalf("trim_budget = %d; the file asked for 0", r.Mutation.TrimBudget)
	}
}

func TestExplainMarksAValueThatMatchesItsDefaultAsChosen(t *testing.T) {
	// Writing the same number the tool would have chosen is still choosing it,
	// and reporting that as a default is the confusion explain exists to end.
	dir := t.TempDir()
	target(t, dir)
	path := write(t, dir, "c.yaml", `
name: same
target:
  path: ./target
seeds:
  inline: ["s"]
feedback:
  map_size: 65536
`)
	r, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(r.ExplainString(), "\n") {
		if strings.HasPrefix(line, "feedback.map_size") && strings.Contains(line, "(default)") {
			t.Fatalf("a value written in the file is reported as a default: %q", line)
		}
	}
}

func TestKeySetSurvivesIncludesAndProfiles(t *testing.T) {
	dir := t.TempDir()
	target(t, dir)
	write(t, dir, "base.yaml", "mutation:\n  stack: 7\n")
	path := write(t, dir, "c.yaml", `
name: keys
include: [./base.yaml]
target:
  path: ./target
seeds:
  inline: ["s"]
profiles:
  p:
    workers:
      count: 6
`)
	r, err := Load(path, "p")
	if err != nil {
		t.Fatal(err)
	}
	if !r.WasSet("mutation.stack") {
		t.Error("a key set by an included file is not recorded as set")
	}
	if !r.WasSet("workers.count") {
		t.Error("a key set by an applied profile is not recorded as set")
	}
	if r.WasSet("feedback.map_size") {
		t.Error("a key nothing set is recorded as set")
	}
}

func TestAScriptStateFunctionMustNameAScriptTheCampaignDeclares(t *testing.T) {
	for _, tc := range []struct {
		name, body, want string
	}{
		{
			name: "no script named",
			body: "name: c\ntarget:\n  path: /bin/true\nseeds:\n  inline: [\"a\"]\nsession:\n  address: tcp:127.0.0.1:9\nstate:\n  fn: script\n  script: nope:label\n",
			want: "no script named",
		},
		{
			name: "no reference at all",
			body: "name: c\ntarget:\n  path: /bin/true\nseeds:\n  inline: [\"a\"]\nsession:\n  address: tcp:127.0.0.1:9\nstate:\n  fn: script\n",
			want: "is required when state.fn is script",
		},
		{
			name: "not a reference",
			body: "name: c\ntarget:\n  path: /bin/true\nseeds:\n  inline: [\"a\"]\nsession:\n  address: tcp:127.0.0.1:9\nstate:\n  fn: script\n  script: label\n" +
				"scripts:\n  - name: s\n    path: s.star\n    objectives: [check]\n",
			want: "is not a script reference",
		},
		{
			name: "set without the function",
			body: "name: c\ntarget:\n  path: /bin/true\nseeds:\n  inline: [\"a\"]\nsession:\n  address: tcp:127.0.0.1:9\nstate:\n  fn: status\n  script: s:label\n" +
				"scripts:\n  - name: s\n    path: s.star\n    objectives: [check]\n",
			want: "is set but state.fn is",
		},
		{
			name: "a script nothing uses",
			body: "name: c\ntarget:\n  path: /bin/true\nseeds:\n  inline: [\"a\"]\nsession:\n  address: tcp:127.0.0.1:9\n" +
				"scripts:\n  - name: s\n    path: s.star\n",
			want: "names no objectives or mutators",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateBody(t, tc.body)
			if err == nil {
				t.Fatalf("accepted:\n%s", tc.body)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error does not mention %q: %v", tc.want, err)
			}
		})
	}
}

func TestAScriptStateFunctionIsAcceptedWhenItsScriptExists(t *testing.T) {
	body := "name: c\ntarget:\n  path: /bin/true\nseeds:\n  inline: [\"a\"]\nsession:\n  address: tcp:127.0.0.1:9\nstate:\n  fn: script\n  script: s:label\n" +
		"scripts:\n  - name: s\n    path: s.star\n"
	if err := validateBody(t, body); err != nil {
		t.Fatalf("a campaign whose state function comes from a declared script was refused: %v", err)
	}
}

// validateBody loads a campaign from a literal and returns its validation error.
func validateBody(t *testing.T, body string) error {
	t.Helper()
	path := filepath.Join(t.TempDir(), "c.yaml")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		return err
	}
	return cfg.Validate()
}

func TestASizeMayBeWrittenWithAUnit(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want int64
	}{
		{"4096", 4096},
		{"4096B", 4096},
		{"512KB", 512 << 10},
		{"512K", 512 << 10},
		{"64MB", 64 << 20},
		{"2GB", 2 << 30},
		{"1TB", 1 << 40},
		{"1.5GB", 3 << 29},
		{" 8 MB ", 8 << 20},
		{"", 0},
	} {
		got, err := ParseSize(tc.in)
		if err != nil {
			t.Errorf("ParseSize(%q): %v", tc.in, err)
			continue
		}
		if got.Bytes() != tc.want {
			t.Errorf("ParseSize(%q) = %d, want %d", tc.in, got.Bytes(), tc.want)
		}
	}

	for _, bad := range []string{"lots", "2GBB", "-", "MB", "2.2.2MB"} {
		if got, err := ParseSize(bad); err == nil {
			t.Errorf("ParseSize(%q) = %d, want an error", bad, got.Bytes())
		}
	}
}

func TestASizeRoundTripsThroughTheFileInTheUnitItWasWritten(t *testing.T) {
	// A campaign file is edited by people. A size that went in as 2GB and came
	// back as 2147483648 would make `xfuzz edit` rewrite a line nobody touched.
	for _, tc := range []struct {
		bytes int64
		want  string
	}{
		{2 << 30, "2GB"}, {64 << 20, "64MB"}, {512 << 10, "512KB"}, {4096, "4KB"},
		{4097, "4097"}, {0, "0"},
	} {
		if got := Size(tc.bytes).String(); got != tc.want {
			t.Errorf("Size(%d) = %q, want %q", tc.bytes, got, tc.want)
		}
	}
}

func TestAPlainByteCountStillWorks(t *testing.T) {
	// Every campaign file written before sizes had units keeps working, which
	// is the reason a bare number is still accepted.
	body := "name: c\ntarget:\n  path: /bin/true\nseeds:\n  inline: [\"a\"]\n" +
		"safety:\n  memory_limit: 2147483648\nstorage:\n  max_corpus_bytes: 1GB\n"
	path := filepath.Join(t.TempDir(), "c.yaml")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("loading: %v", err)
	}
	if got := cfg.Safety.MemoryLimit.Bytes(); got != 2<<30 {
		t.Errorf("memory_limit = %d, want %d", got, 2<<30)
	}
	if got := cfg.Storage.MaxCorpusBytes.Bytes(); got != 1<<30 {
		t.Errorf("max_corpus_bytes = %d, want %d", got, 1<<30)
	}
}
