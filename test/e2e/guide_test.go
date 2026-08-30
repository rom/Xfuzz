//go:build integration

// The definition of done's tenth clause: "a new user can install one binary,
// run `xfuzz init`, and reach a first finding without reading source".
//
// A guide is a claim about the tool, and a claim nobody checks stops being
// true. This walks docs/GUIDE.md's first-campaign section literally — the same
// commands in the same order, with no flags the guide does not mention — and
// asserts what the guide says will happen.
//
// It has already earned its place. On its first run `xfuzz init` produced a
// file that `xfuzz validate` rejected: the template wrote `workers.count: 0`
// with a comment saying "one per core by default", and validation refuses an
// explicit zero. Two commands into the documented path, and it did not work.

package e2e

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rom/Xfuzz/internal/testenv"
)

func TestTheGuideTakesANewUserToAFirstFinding(t *testing.T) {
	e := newEnv(t)

	// Step 1: a target. The guide says to build one with xfuzz-cc; newEnv has
	// done exactly that.
	testenv.BuildBinary(t, e.binDir, "xfuzz-cc")

	// Step 2: seeds. The guide is emphatic that these matter more than
	// anything else in the file, so the walk provides them the way it says to:
	// a few small, valid, different files.
	seeds := filepath.Join(e.dataDir, "seeds")
	if err := os.MkdirAll(seeds, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{
		"a": "Axx", "b": "B\x01\x02", "c": "CCCC", "d": "Zz",
	} {
		if err := os.WriteFile(filepath.Join(seeds, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	// Step 3: xfuzz init.
	path := filepath.Join(e.dataDir, "first.yaml")
	e.mustRun(30*time.Second, "init", "--target", e.target, "--name", "first", "-o", path)

	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// The guide tells the reader to point seeds.dirs at their corpus and to
	// shorten the budget; everything else is left as init wrote it, because
	// what is under test is what init wrote.
	edited := strings.ReplaceAll(string(body), "dirs: [./seeds]", "dirs: ["+seeds+"]")
	edited = strings.ReplaceAll(edited, "after: 1h", "after: 45s")
	if edited == string(body) {
		t.Fatalf("the generated file does not contain the lines the guide tells a reader to edit:\n%s", body)
	}
	if err := os.WriteFile(path, []byte(edited), 0o644); err != nil {
		t.Fatal(err)
	}

	// Step 4: validate and explain, exactly as the guide says to before running.
	out := e.mustRun(30*time.Second, "validate", path)
	if !strings.Contains(out, "valid") {
		t.Fatalf("the file `xfuzz init` wrote is not valid:\n%s", out)
	}
	if explained := e.mustRun(30*time.Second, "explain", path); !strings.Contains(explained, "target.path") {
		t.Fatalf("explain did not render the resolved configuration:\n%s", explained)
	}

	// Step 5: run it.
	if out, err := e.xfuzz(240*time.Second, "run", path); err != nil {
		t.Fatalf("the documented first campaign failed: %v\n%s", err, out)
	}

	final := e.status("first")
	t.Logf("%d execs (%.0f/s), %d corpus entries, %d finding(s) in %d bucket(s)",
		final.Metrics.Execs, final.Metrics.ExecsPerS, final.Metrics.CorpusSize,
		final.Metrics.Findings, final.Metrics.Buckets)

	// Step 6: read the findings. The guide's promise is a *first finding*.
	if final.Metrics.Findings == 0 {
		t.Fatal("the documented path reached no finding in a target with three planted bugs")
	}
	if final.Metrics.Buckets == 0 {
		t.Fatal("findings were recorded but none was bucketed")
	}

	listed := e.mustRun(60*time.Second, "findings", "first")
	for _, want := range []string{"ID", "KIND", "TRIAGE", "JUDGED", "REPRO", "SUMMARY"} {
		if !strings.Contains(listed, want) {
			t.Errorf("the findings table has no %s column, which the guide shows:\n%s", want, listed)
		}
	}

	buckets := e.mustRun(60*time.Second, "findings", "buckets", "first")
	if strings.HasPrefix(strings.TrimSpace(buckets), "{") {
		t.Errorf("`xfuzz findings buckets` answered in JSON without being asked:\n%s", buckets)
	}
	if !strings.Contains(buckets, "bucket(s)") {
		t.Errorf("the buckets listing does not say how many there are:\n%s", buckets)
	}

	// The reproducer, written to a file, as the guide shows.
	repro := filepath.Join(e.dataDir, "repro")
	e.mustRun(60*time.Second, "findings", "get", "first", "1", "-o", repro)
	if fi, err := os.Stat(repro); err != nil || fi.Size() == 0 {
		t.Fatalf("the reproducer was not written: %v", err)
	}

	// Step 7: reproduce it, and record a judgement — the last two things the
	// guide's first-campaign section asks a reader to do.
	if out := e.mustRun(120*time.Second, "replay", "first", "1"); out == "" {
		t.Error("replay said nothing")
	}
	e.mustRun(60*time.Second, "triage", "first", "1", "--as", "confirmed", "--note", "walked the guide")

	judged := e.mustRun(60*time.Second, "findings", "get", "first", "1")
	if !strings.Contains(judged, "confirmed") || !strings.Contains(judged, "walked the guide") {
		t.Errorf("the judgement the guide tells a reader to record is not shown back:\n%s", judged)
	}
}

// Every campaign file the guide shows must be one the tool accepts.
//
// A guide with a YAML block that does not validate teaches a reader something
// false, and they find out by pasting it.
func TestEveryCampaignFileInTheGuideValidates(t *testing.T) {
	e := newEnv(t)
	fixtures := docFixtures(t, e)

	root := testenv.RepoRoot(t)
	for _, doc := range []string{"GUIDE.md", "GRAMMAR.md"} {
		body, err := os.ReadFile(filepath.Join(root, "docs", doc))
		if err != nil {
			t.Fatal(err)
		}
		for i, block := range yamlBlocks(string(body)) {
			// The guide shows fragments — a safety block, a session block —
			// rather than whole files, so each is completed with the minimum a
			// campaign needs before it is checked.
			path := filepath.Join(fixtures, "doc.yaml")
			if err := os.WriteFile(path, []byte(completeCampaign(block)), 0o644); err != nil {
				t.Fatal(err)
			}
			out, err := e.xfuzz(30*time.Second, "validate", path)
			if err != nil {
				t.Errorf("%s: yaml block %d does not validate: %v\n%s\n--- as written ---\n%s",
					doc, i+1, err, out, block)
			}
		}
	}
}

// docFixtures materialises every file the documentation's examples name.
//
// The blocks are illustrations, so they point at ./target, ./seeds, ./format.xfg
// and so on. Validation checks that those paths exist — correctly, since a
// campaign naming a target that is not there should fail before it runs — so
// the fixtures have to exist for the *shape* of each block to be what is under
// test. Paths in a campaign file resolve against the file, so everything lands
// in one directory beside it.
//
// A block that names a file not listed here fails with "cannot be read", which
// is the right outcome: whoever added the example adds the fixture.
func docFixtures(t *testing.T, e *env) string {
	t.Helper()
	dir := testenv.ReachableDir(t)

	for _, name := range []string{"target", "vendor-binary", "server", "my-plugin"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	seeds := filepath.Join(dir, "seeds")
	if err := os.MkdirAll(seeds, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(seeds, "a"), []byte("seed"), 0o644); err != nil {
		t.Fatal(err)
	}

	grammar := "format m {\n  tag: magic \"MSG\"\n  body: bytes<0..64>\n}\n"
	files := map[string]string{
		"format.xfg":  grammar,
		"chunked.xfg": grammar,
		"tokens.dict": "kw_a=\"IHDR\"\n",
		"oracle.star": "def leaked_secret(x):\n    return None\n",
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// yamlBlocks returns the fenced ```yaml blocks of a markdown document.
func yamlBlocks(md string) []string {
	var out []string
	for rest := md; ; {
		open := strings.Index(rest, "```yaml\n")
		if open < 0 {
			return out
		}
		rest = rest[open+len("```yaml\n"):]
		end := strings.Index(rest, "```")
		if end < 0 {
			return out
		}
		out = append(out, rest[:end])
		rest = rest[end+3:]
	}
}

// completeCampaign fills in whatever a fragment does not declare.
func completeCampaign(block string) string {
	full := block
	if !strings.HasPrefix(full, "name:") && !strings.Contains(full, "\nname:") {
		full = "name: docs\n" + full
	}
	if !strings.Contains(full, "target:") {
		full += "\ntarget:\n  path: ./target\n"
	}
	if !strings.Contains(full, "seeds:") {
		full += "\nseeds:\n  inline: [\"seed\"]\n"
	}
	return full
}
