package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/rom/Xfuzz/internal/api"
	"github.com/rom/Xfuzz/internal/client"
	"github.com/rom/Xfuzz/internal/daemon"
	"github.com/rom/Xfuzz/internal/metrics"
	"github.com/rom/Xfuzz/internal/store"
	"github.com/rom/Xfuzz/internal/testenv"
	"github.com/rom/Xfuzz/pkg/campaign"
	"github.com/rom/Xfuzz/pkg/corpus"
	"github.com/rom/Xfuzz/pkg/feedback"
)

// The commands, run. The parity tests prove every command names a route;
// these prove the commands work — against a real daemon behind a real
// listener, with the token the CLI would send, reading what they print.
//
// The daemon is in-process and the listener is loopback TCP, which is the
// same path `--addr` takes in the field. Nothing is stubbed between the
// command and the store.

type cli struct {
	t      *testing.T
	daemon *daemon.Daemon
	server *api.Server
	addr   string
	dir    string
}

func newCLI(t *testing.T) *cli {
	t.Helper()
	dir := testenv.ReachableDir(t)
	d, err := daemon.New(daemon.Options{DataDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close(context.Background()) })

	s := api.NewServer(d)
	s.Token = "tok"
	ts := httptest.NewServer(s)
	t.Cleanup(ts.Close)

	return &cli{t: t, daemon: d, server: s, addr: strings.TrimPrefix(ts.URL, "http://"), dir: dir}
}

// run executes a command as `xfuzz NAME ARGS...` would, against the harness's
// daemon, and returns what it printed.
func (c *cli) run(name string, args ...string) (string, error) {
	c.t.Helper()
	return c.runCtx(context.Background(), name, args...)
}

func (c *cli) runCtx(ctx context.Context, name string, args ...string) (string, error) {
	c.t.Helper()
	cmd, ok := commands[name]
	if !ok {
		c.t.Fatalf("no command %q", name)
	}
	full := append(append([]string{}, args...), "--addr", c.addr, "--token", "tok", "--no-start")
	var err error
	out := captureStdout(c.t, func() { err = cmd.Run(ctx, full) })
	return out, err
}

// ok runs a command that must succeed.
func (c *cli) ok(name string, args ...string) string {
	c.t.Helper()
	out, err := c.run(name, args...)
	if err != nil {
		c.t.Fatalf("xfuzz %s %s: %v\n%s", name, strings.Join(args, " "), err, out)
	}
	return out
}

// campaignFile writes a valid campaign whose target exists.
func (c *cli) campaignFile(name string) string {
	c.t.Helper()
	target := testenv.StubTarget(c.t, c.dir)
	doc := "name: " + name + "\ntarget:\n  path: " + target + "\nseeds:\n  inline: [\"alpha\"]\nworkers:\n  count: 1\nstop:\n  execs: 1000\n"
	path := filepath.Join(c.dir, name+".yaml")
	if err := os.WriteFile(path, []byte(doc), 0o644); err != nil {
		c.t.Fatal(err)
	}
	return path
}

// created loads a campaign into the daemon without starting it.
func (c *cli) created(name string) {
	c.t.Helper()
	path := c.campaignFile(name)
	cfg, err := campaign.Load(path)
	if err != nil {
		c.t.Fatal(err)
	}
	if _, err := c.daemon.Create(context.Background(), cfg); err != nil {
		c.t.Fatalf("creating %s: %v", name, err)
	}
}

// finding files one by hand, the way the store tests do: the API's finding
// routes and the CLI's rendering of them do not need a crash to have happened.
func (c *cli) finding(campaignName string, payload []byte) int64 {
	c.t.Helper()
	camp, err := c.daemon.Campaign(campaignName)
	if err != nil {
		c.t.Fatal(err)
	}
	f := &store.Finding{
		CampaignID:   camp.ID(),
		Digest:       corpus.DigestOf(payload),
		OriginalSize: len(payload),
		Finding: feedback.Finding{
			Kind: "crash", Signal: 11, Summary: "fatal signal SIGSEGV",
			Detail: "the target said so", Frames: []string{"parse+0x10", "main+0x4"},
		},
	}
	f.SetBucket(camp.Config.Triage.Strategy, "parse+0x10")
	if err := camp.Store().SaveFinding(context.Background(), f, payload); err != nil {
		c.t.Fatal(err)
	}
	return f.ID
}

// captureStdout runs fn with os.Stdout redirected and returns what it wrote.
//
// A pipe rather than a buffer, because the commands write through fmt.Print
// and json.Encoder to os.Stdout itself; the reader runs concurrently so a
// command whose output exceeds the pipe's buffer — the schema does — cannot
// block on its own test.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	saved := os.Stdout
	os.Stdout = w
	done := make(chan string)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()
	func() {
		defer func() { os.Stdout = saved; w.Close() }()
		fn()
	}()
	return <-done
}

func TestVersionNamesTheBinary(t *testing.T) {
	c := newCLI(t)
	out := c.ok("version")
	if !strings.HasPrefix(out, "xfuzz ") {
		t.Errorf("version printed %q", out)
	}
}

func TestInitWritesAStarterThatValidates(t *testing.T) {
	// The starter file is the first thing a new user runs. It has to be a
	// campaign the daemon accepts, not a sketch of one — with a real target
	// and the seeds directory it names.
	c := newCLI(t)
	target := testenv.StubTarget(t, c.dir)
	path := filepath.Join(c.dir, "first.yaml")
	if err := os.MkdirAll(filepath.Join(c.dir, "seeds"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(c.dir, "seeds", "one"), []byte("seed"), 0o644); err != nil {
		t.Fatal(err)
	}

	out := c.ok("init", "--target", target, "--name", "first", "-o", path)
	if out != "" {
		t.Errorf("init -o printed %q; the file was the output", out)
	}
	doc, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(doc), "name: first") || !strings.Contains(string(doc), "path: "+target) {
		t.Errorf("the starter does not carry the name and target it was given:\n%s", doc)
	}

	// Refused rather than overwritten: a campaign file is somebody's work.
	if _, err := c.run("init", "-o", path); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Errorf("init overwrote an existing file, or failed for another reason: %v", err)
	}

	// Without -o it is the output.
	if out := c.ok("init"); !strings.Contains(out, "name: campaign") {
		t.Errorf("init to stdout printed:\n%s", out)
	}

	valid := c.ok("validate", path)
	if !strings.Contains(valid, "valid") {
		t.Errorf("the starter did not validate:\n%s", valid)
	}
}

func TestValidateReportsEveryProblemInTheError(t *testing.T) {
	c := newCLI(t)
	path := filepath.Join(c.dir, "bad.yaml")
	os.WriteFile(path, []byte("target:\n  path: /nonexistent\n  executor: teleport\n"), 0o644)

	_, err := c.run("validate", path)
	if err == nil {
		t.Fatal("an invalid file validated")
	}
	for _, want := range []string{"name", "target.path", "target.executor"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error does not mention %s:\n%v", want, err)
		}
	}
	var apiErr *client.APIError
	if !errors.As(err, &apiErr) {
		t.Errorf("err = %T, want the daemon's own error", err)
	}
}

func TestValidateAndExplainOutputs(t *testing.T) {
	c := newCLI(t)
	path := c.campaignFile("plain")

	if out := c.ok("validate", path); !strings.HasSuffix(strings.TrimSpace(out), ": valid") {
		t.Errorf("validate printed %q", out)
	}
	var v struct{ Valid bool }
	if err := json.Unmarshal([]byte(c.ok("validate", path, "--json")), &v); err != nil || !v.Valid {
		t.Errorf("validate --json: %v", err)
	}

	// Explain marks defaults, because "what will this actually do" is the
	// question it answers; --yaml gives back a file that runs the same thing.
	if out := c.ok("explain", path); !strings.Contains(out, "(default)") {
		t.Errorf("explain does not mark defaults:\n%s", out)
	}
	if out := c.ok("explain", path, "--yaml"); !strings.Contains(out, "name: plain") {
		t.Errorf("explain --yaml:\n%s", out)
	}
	var e struct{ Text, YAML string }
	if err := json.Unmarshal([]byte(c.ok("explain", path, "--json")), &e); err != nil || e.Text == "" || e.YAML == "" {
		t.Errorf("explain --json: %v", err)
	}
}

func TestAMissingFileIsAnError(t *testing.T) {
	c := newCLI(t)
	for _, cmd := range []string{"validate", "explain", "run", "edit"} {
		if _, err := c.run(cmd, filepath.Join(c.dir, "nope.yaml")); err == nil {
			t.Errorf("%s of a missing file succeeded", cmd)
		}
		if _, err := c.run(cmd); err == nil || !strings.Contains(err.Error(), "exactly one") {
			t.Errorf("%s with no file: %v", cmd, err)
		}
	}
}

func TestListAndStatus(t *testing.T) {
	c := newCLI(t)
	if out := c.ok("list"); !strings.Contains(out, "no campaigns loaded") {
		t.Errorf("an empty list printed %q", out)
	}
	c.created("nightly")

	out := c.ok("list")
	if !strings.Contains(out, "NAME") || !strings.Contains(out, "nightly") || !strings.Contains(out, "created") {
		t.Errorf("list:\n%s", out)
	}
	var listed struct{ Campaigns []daemon.Status }
	if err := json.Unmarshal([]byte(c.ok("list", "--json")), &listed); err != nil || len(listed.Campaigns) != 1 {
		t.Errorf("list --json: %v %+v", err, listed)
	}

	st := c.ok("status", "nightly")
	for _, want := range []string{"campaign  nightly", "state     created", "seed      ", "isolation ", "corpus    0 entries", "findings  0 in 0 bucket(s)"} {
		if !strings.Contains(st, want) {
			t.Errorf("status lacks %q:\n%s", want, st)
		}
	}
	var s daemon.Status
	if err := json.Unmarshal([]byte(c.ok("status", "nightly", "--json")), &s); err != nil || s.Name != "nightly" {
		t.Errorf("status --json: %v", err)
	}

	_, err := c.run("status", "absent")
	var apiErr *client.APIError
	if !errors.As(err, &apiErr) || !apiErr.NotFound() {
		t.Errorf("status of an absent campaign: %v", err)
	}
	if _, err := c.run("status"); err == nil {
		t.Error("status with no name succeeded")
	}
}

func TestActionsOnAnUnstartedCampaignAreRefused(t *testing.T) {
	// The daemon answers 409 for a state that does not allow the action, and
	// the CLI has to surface that rather than a success line.
	c := newCLI(t)
	c.created("idle")
	for _, action := range []string{"pause", "resume", "stop"} {
		out, err := c.run(action, "idle")
		if err == nil {
			t.Errorf("%s of an unstarted campaign succeeded: %q", action, out)
		}
	}
}

func TestStartStopAndForget(t *testing.T) {
	c := newCLI(t)
	c.created("go")

	out := c.ok("start", "go")
	if !strings.HasPrefix(out, "go: ") {
		t.Errorf("start printed %q", out)
	}
	// Workers may or may not survive on this host — there is no worker binary
	// beside the test — but the campaign is the daemon's to stop either way,
	// and what stop prints is its state and the reason it was given.
	out, err := c.run("stop", "go", "--reason", "test over")
	if err == nil && !strings.Contains(out, "go: ") {
		t.Errorf("stop printed %q", out)
	}

	// Forgotten only once it is not running; the daemon refuses otherwise,
	// and the CLI reports the refusal rather than pretending.
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := c.run("forget", "go"); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the campaign never became forgettable")
		}
		time.Sleep(50 * time.Millisecond)
	}
	if _, err := c.run("status", "go"); err == nil {
		t.Error("a forgotten campaign still answers")
	}

	// And a store survives forgetting: load brings it back by name.
	loaded := c.ok("load", "go")
	if !strings.Contains(loaded, "campaign go loaded") {
		t.Errorf("load printed %q", loaded)
	}
	var s daemon.Status
	if err := json.Unmarshal([]byte(c.ok("load", "go", "--json")), &s); err != nil || s.Name != "go" {
		t.Errorf("load --json: %v", err)
	}
	if _, err := c.run("load", "never-existed"); err == nil {
		t.Error("loading a campaign with no store succeeded")
	}
	if _, err := c.run("load"); err == nil {
		t.Error("load with no name succeeded")
	}
}

func TestRunDetachedStartsAndReturns(t *testing.T) {
	c := newCLI(t)
	path := c.campaignFile("detached")
	out := c.ok("run", path, "--detach")
	if !strings.Contains(out, "campaign detached started") || !strings.Contains(out, "running in the background") {
		t.Errorf("run --detach printed:\n%s", out)
	}
	if out := c.ok("list"); !strings.Contains(out, "detached") {
		t.Errorf("the campaign is not listed after run:\n%s", out)
	}
}

func TestFindingsAreListedShownAndBucketed(t *testing.T) {
	c := newCLI(t)
	c.created("bugs")
	if out := c.ok("findings", "list", "bugs"); !strings.Contains(out, "no findings") {
		t.Errorf("an empty listing printed %q", out)
	}
	if out := c.ok("findings", "buckets", "bugs"); !strings.Contains(out, "no buckets") {
		t.Errorf("an empty bucket listing printed %q", out)
	}

	id := c.finding("bugs", []byte("crash\x00input\xff"))

	list := c.ok("findings", "list", "bugs")
	for _, want := range []string{"ID", "BUG", "crash", "fatal signal SIGSEGV", "not checked", "1 findings"} {
		if !strings.Contains(list, want) {
			t.Errorf("findings list lacks %q:\n%s", want, list)
		}
	}
	// The default subcommand is list, and a name after the verb is a name.
	if out := c.ok("findings", "bugs"); out != list {
		t.Errorf("`findings NAME` differs from `findings list NAME`:\n%s\n---\n%s", out, list)
	}

	get := c.ok("findings", "get", "bugs", itoa(id))
	for _, want := range []string{"finding " + itoa(id) + ": crash fatal signal SIGSEGV", "bug ", "parse+0x10", "the target said so", "reproducer (12 bytes)", "63 72 61 73 68 00", "crash.input."} {
		if !strings.Contains(get, want) {
			t.Errorf("findings get lacks %q:\n%s", want, get)
		}
	}
	repro := filepath.Join(c.dir, "repro.bin")
	c.ok("findings", "get", "bugs", itoa(id), "-o", repro)
	if b, _ := os.ReadFile(repro); string(b) != "crash\x00input\xff" {
		t.Errorf("-o wrote %q", b)
	}
	var full struct {
		ID         int64  `json:"id"`
		Reproducer []byte `json:"reproducer"`
	}
	if err := json.Unmarshal([]byte(c.ok("findings", "get", "bugs", itoa(id), "--json")), &full); err != nil || full.ID != id || len(full.Reproducer) != 12 {
		t.Errorf("findings get --json: %v %+v", err, full)
	}

	buckets := c.ok("findings", "buckets", "bugs")
	if !strings.Contains(buckets, "FINDINGS") || !strings.Contains(buckets, "parse+0x10") || !strings.Contains(buckets, "1 bucket(s)") {
		t.Errorf("findings buckets:\n%s", buckets)
	}

	if _, err := c.run("findings", "get", "bugs", "999"); err == nil {
		t.Error("an absent finding was shown")
	}
	if _, err := c.run("findings", "get", "bugs"); err == nil {
		t.Error("findings get with one argument succeeded")
	}
	// A word that is not a verb is taken as a campaign name — `findings
	// nightly` is the common case — so an extra word is one argument too many.
	if _, err := c.run("findings", "teleport", "bugs"); err == nil || !strings.Contains(err.Error(), "exactly one") {
		t.Errorf("an unknown word before the name: %v", err)
	}
}

func TestTriageRecordsAJudgement(t *testing.T) {
	c := newCLI(t)
	c.created("judged")
	id := c.finding("judged", []byte("x"))

	out := c.ok("triage", "judged", itoa(id), "--as", "confirmed", "--note", "reported upstream")
	if !strings.Contains(out, "finding "+itoa(id)+": confirmed") || !strings.Contains(out, "reported upstream") {
		t.Errorf("triage printed %q", out)
	}
	// The judgement shows in the listing's own column.
	if list := c.ok("findings", "list", "judged"); !strings.Contains(list, "confirmed") {
		t.Errorf("the judgement is not in the listing:\n%s", list)
	}
	// "pending" clears it, and prints as pending rather than as nothing.
	if out := c.ok("triage", "judged", itoa(id), "--as", "pending"); !strings.Contains(out, ": pending") {
		t.Errorf("clearing a judgement printed %q", out)
	}
	var f struct{ Disposition string }
	if err := json.Unmarshal([]byte(c.ok("triage", "judged", itoa(id), "--as", "invalid", "--json")), &f); err != nil || f.Disposition != "invalid" {
		t.Errorf("triage --json: %v %+v", err, f)
	}
	if _, err := c.run("triage", "judged"); err == nil {
		t.Error("triage with one argument succeeded")
	}
}

func TestReplayAndMinimizeRunTheReproducer(t *testing.T) {
	// A created campaign can replay: the reproducer runs through its own
	// sandbox against the stub target. The report's numbers are the daemon's;
	// what the CLI owes is to print them as a sentence, and to check its
	// arguments before asking.
	c := newCLI(t)
	c.created("tri")
	id := c.finding("tri", []byte("crash input"))

	out := c.ok("replay", "tri", itoa(id), "--trials", "2")
	if !strings.Contains(out, "finding "+itoa(id)+": ") || !strings.Contains(out, " of 2 runs reproduced (") {
		t.Errorf("replay printed %q", out)
	}
	var rep struct{ Trials int }
	if err := json.Unmarshal([]byte(c.ok("replay", "tri", itoa(id), "--json")), &rep); err != nil || rep.Trials <= 0 {
		t.Errorf("replay --json: %v %+v", err, rep)
	}

	// The stub target does not fail on this input, and a minimiser given an
	// input that does not fail has nothing to preserve: it refuses, in the
	// daemon's words, rather than handing back a smaller input for no bug.
	if !strings.Contains(out, " 0 of 2 runs reproduced (0%)") {
		t.Errorf("the stub reproduced a crash it cannot have: %q", out)
	}
	if _, err := c.run("minimize", "tri", itoa(id), "--budget", "20"); err == nil || !strings.Contains(err.Error(), "does not fail") {
		t.Errorf("minimising an input that does not fail: %v", err)
	}

	for _, cmd := range []string{"replay", "minimize"} {
		if _, err := c.run(cmd, "tri", "notanumber"); err == nil || !strings.Contains(err.Error(), "not a finding id") {
			t.Errorf("%s with a bad id: %v", cmd, err)
		}
		if _, err := c.run(cmd, "tri"); err == nil {
			t.Errorf("%s with one argument succeeded", cmd)
		}
		if _, err := c.run(cmd, "tri", "999"); err == nil {
			t.Errorf("%s of an absent finding succeeded", cmd)
		}
	}
}

func TestCorpusCommands(t *testing.T) {
	c := newCLI(t)
	c.created("corp")

	if out := c.ok("corpus", "list", "corp"); !strings.Contains(out, "DIGEST") || !strings.Contains(out, "0 entries") {
		t.Errorf("an empty corpus listed as:\n%s", out)
	}

	in := filepath.Join(c.dir, "in")
	os.MkdirAll(in, 0o755)
	os.WriteFile(filepath.Join(in, "a"), []byte("alpha"), 0o644)
	os.WriteFile(filepath.Join(in, "b"), []byte("beta"), 0o644)
	os.WriteFile(filepath.Join(in, "a-again"), []byte("alpha"), 0o644)

	var imp struct {
		Imported  int
		Duplicate int
		Format    string
	}
	if err := json.Unmarshal([]byte(c.ok("corpus", "import", "corp", "--dir", in, "--format", "raw")), &imp); err != nil {
		t.Fatal(err)
	}
	if imp.Imported != 2 || imp.Duplicate != 1 || imp.Format != "raw" {
		t.Errorf("import = %+v", imp)
	}

	list := c.ok("corpus", "list", "corp", "--limit", "10", "--order", "size")
	if !strings.Contains(list, "2 entries") {
		t.Errorf("after import:\n%s", list)
	}
	var entries struct {
		Entries []struct{ Digest string }
	}
	json.Unmarshal([]byte(c.ok("corpus", "list", "corp", "--json", "--favoured")), &entries)
	if len(entries.Entries) == 0 {
		// Nothing is favoured until an engine measures coverage; the plain
		// listing still names every entry.
		json.Unmarshal([]byte(c.ok("corpus", "list", "corp", "--json")), &entries)
	}
	if len(entries.Entries) == 0 {
		t.Fatal("no entries to fetch")
	}
	got := c.ok("corpus", "get", "corp", entries.Entries[0].Digest)
	if got != "alpha" && got != "beta" {
		t.Errorf("corpus get printed %q", got)
	}
	saved := filepath.Join(c.dir, "entry.bin")
	c.ok("corpus", "get", "corp", entries.Entries[0].Digest, "-o", saved)
	if b, _ := os.ReadFile(saved); string(b) != got {
		t.Errorf("-o wrote %q, stdout gave %q", b, got)
	}

	outDir := filepath.Join(c.dir, "out")
	var exp struct{ Written int }
	if err := json.Unmarshal([]byte(c.ok("corpus", "export", "corp", "--dir", outDir, "--format", "raw")), &exp); err != nil {
		t.Fatal(err)
	}
	if exp.Written != 2 {
		t.Errorf("export = %+v", exp)
	}
	if _, err := c.run("corpus", "export", "corp", "--dir", outDir, "--format", "raw"); err == nil {
		t.Error("a second export into a non-empty directory was not refused")
	}
	c.ok("corpus", "export", "corp", "--dir", outDir, "--format", "raw", "--overwrite", "--favoured")

	if _, err := c.run("corpus", "import", "corp"); err == nil || !strings.Contains(err.Error(), "--dir is required") {
		t.Errorf("import without --dir: %v", err)
	}
	if _, err := c.run("corpus", "get", "corp"); err == nil {
		t.Error("corpus get with one argument succeeded")
	}
	if _, err := c.run("corpus", "vanish", "corp"); err == nil || !strings.Contains(err.Error(), "exactly one") {
		t.Errorf("an unknown word before the name: %v", err)
	}
}

func TestInspectionCommandsAnswer(t *testing.T) {
	c := newCLI(t)
	c.created("insp")

	var m map[string]any
	if err := json.Unmarshal([]byte(c.ok("metrics", "insp")), &m); err != nil {
		t.Errorf("metrics: %v", err)
	}
	if _, ok := m["execs"]; !ok {
		t.Errorf("metrics carries no execs: %v", m)
	}
	var h map[string]any
	if err := json.Unmarshal([]byte(c.ok("metrics", "insp", "--history")), &h); err != nil {
		t.Errorf("metrics --history: %v", err)
	}

	if out := c.ok("workers", "insp"); !strings.Contains(out, "EXECUTOR") || !strings.Contains(out, "ISOLATION") {
		t.Errorf("workers:\n%s", out)
	}
	var w struct{ Workers []daemon.WorkerStatus }
	if err := json.Unmarshal([]byte(c.ok("workers", "insp", "--json")), &w); err != nil {
		t.Errorf("workers --json: %v", err)
	}

	safety := c.ok("safety", "insp")
	for _, want := range []string{"isolation", "network scope:", "connections:"} {
		if !strings.Contains(safety, want) {
			t.Errorf("safety lacks %q:\n%s", want, safety)
		}
	}
	var sj struct{ Isolation string }
	if err := json.Unmarshal([]byte(c.ok("safety", "insp", "--json")), &sj); err != nil || sj.Isolation == "" {
		t.Errorf("safety --json: %v", err)
	}

	if out := c.ok("states", "insp"); !strings.Contains(out, "no protocol states recorded") {
		t.Errorf("states on a file campaign:\n%s", out)
	}
	var stj struct{ States []any }
	if err := json.Unmarshal([]byte(c.ok("states", "insp", "--json", "--transitions")), &stj); err != nil {
		t.Errorf("states --json: %v", err)
	}

	audit := c.ok("audit")
	if !strings.Contains(audit, "hash chain verified over") {
		t.Errorf("audit:\n%s", audit)
	}
	var aj struct{ Intact bool }
	if err := json.Unmarshal([]byte(c.ok("audit", "--json")), &aj); err != nil || !aj.Intact {
		t.Errorf("audit --json: %v %+v", err, aj)
	}

	var info map[string]any
	if err := json.Unmarshal([]byte(c.ok("info")), &info); err != nil {
		t.Errorf("info: %v", err)
	}
	if _, ok := info["daemon"]; !ok {
		t.Errorf("info carries no daemon block: %v", info)
	}

	var schema map[string]any
	if err := json.Unmarshal([]byte(c.ok("schema")), &schema); err != nil {
		t.Errorf("schema: %v", err)
	}
	if _, ok := schema["properties"]; !ok {
		t.Error("the schema has no properties")
	}
	var openapi map[string]any
	if err := json.Unmarshal([]byte(c.ok("schema", "--openapi")), &openapi); err != nil {
		t.Errorf("schema --openapi: %v", err)
	}
	if _, ok := openapi["paths"]; !ok {
		t.Error("the OpenAPI document has no paths")
	}

	doctor := c.ok("doctor")
	for _, want := range []string{"platform", "version", "isolation", "shared-memory", "xfuzz-worker"} {
		if !strings.Contains(doctor, want) {
			t.Errorf("doctor lacks %q:\n%s", want, doctor)
		}
	}
	var dj struct{ Capabilities []struct{ Name string } }
	if err := json.Unmarshal([]byte(c.ok("doctor", "--json")), &dj); err != nil || len(dj.Capabilities) < 10 {
		t.Errorf("doctor --json: %v, %d capabilities", err, len(dj.Capabilities))
	}

	for _, cmd := range []string{"metrics", "workers", "safety", "states"} {
		if _, err := c.run(cmd, "absent"); err == nil {
			t.Errorf("%s of an absent campaign succeeded", cmd)
		}
	}
}

func TestWatchStopsWhenTheContextDoes(t *testing.T) {
	c := newCLI(t)
	c.created("watched")
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := c.runCtx(ctx, "watch", "watched", "--kinds", "metrics,log"); err != nil {
		t.Errorf("watch returned %v; a cancelled watch is not an error", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Error("watch did not stop when its context ended")
	}
}

func TestEditKeepsTheFileAndTypesTheValue(t *testing.T) {
	c := newCLI(t)
	path := c.campaignFile("edited")
	// A comment the edit must keep, and a number that must stay a number.
	os.WriteFile(path, []byte("# house style\n"+mustRead(t, path)), 0o644)

	out := c.ok("edit", path, "--set", "workers.count=8", "--set", "description=hand edited", "--unset", "stop.execs")
	for _, want := range []string{"# house style", "count: 8", "description: hand edited"} {
		if !strings.Contains(out, want) {
			t.Errorf("edit lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "execs:") {
		t.Errorf("--unset left the field:\n%s", out)
	}
	// Written to a file rather than printed, and in place.
	dest := filepath.Join(c.dir, "edited-copy.yaml")
	if printed := c.ok("edit", path, "--set", "workers.count=2", "-o", dest); printed != "" {
		t.Errorf("edit -o printed %q", printed)
	}
	if !strings.Contains(mustRead(t, dest), "count: 2") {
		t.Error("-o did not write the edited document")
	}
	c.ok("edit", path, "--set", "workers.count=3", "-i")
	if !strings.Contains(mustRead(t, path), "count: 3") {
		t.Error("-i did not write the file back")
	}
	var r struct {
		Document string
		Valid    bool
	}
	if err := json.Unmarshal([]byte(c.ok("edit", path, "--set", "workers.count=4", "--json")), &r); err != nil || !r.Valid {
		t.Errorf("edit --json: %v %+v", err, r)
	}
	if _, err := c.run("edit", path, "--set", "noequals"); err == nil || !strings.Contains(err.Error(), "not path=value") {
		t.Errorf("a malformed --set: %v", err)
	}
}

func mustRead(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestGrammarSampleAndImport(t *testing.T) {
	c := newCLI(t)
	grammar := filepath.Join(c.dir, "msg.xfg")
	os.WriteFile(grammar, []byte("format message {\n  magic:  magic \"MSG\"\n  length: u16be = len(^body)\n  body:   bytes<1..8>\n}\n"), 0o644)

	out := c.ok("grammar", "sample", grammar, "-n", "2", "--seed", "7")
	if !strings.Contains(out, "type(s), root message") || !strings.Contains(out, "sample 1 (") || !strings.Contains(out, "sample 2 (") {
		t.Errorf("grammar sample:\n%s", out)
	}
	// The default subcommand, with the file where the verb would be.
	if again := c.ok("grammar", grammar, "-n", "2", "--seed", "7"); again != out {
		t.Errorf("`grammar FILE` differs from `grammar sample FILE`")
	}
	raw := c.ok("grammar", "sample", grammar, "-n", "1", "--seed", "7", "--raw")
	if !strings.HasPrefix(raw, "MSG") {
		t.Errorf("--raw did not print the bytes: %q", raw)
	}
	var sj struct {
		Valid   bool
		Samples []struct{ Size int }
	}
	if err := json.Unmarshal([]byte(c.ok("grammar", "sample", grammar, "-n", "3", "--json")), &sj); err != nil || !sj.Valid || len(sj.Samples) != 3 {
		t.Errorf("grammar --json: %v %+v", err, sj)
	}

	broken := filepath.Join(c.dir, "broken.xfg")
	os.WriteFile(broken, []byte("format { nonsense"), 0o644)
	if _, err := c.run("grammar", "sample", broken); err == nil || !strings.Contains(err.Error(), "does not compile") {
		t.Errorf("a broken grammar: %v", err)
	}
	if _, err := c.run("grammar", "teleport", grammar); err == nil || !strings.Contains(err.Error(), "exactly one") {
		t.Errorf("an unknown word before the file: %v", err)
	}

	// Import is local: a foreign description in, an Xfuzz grammar out, and
	// the report of what could not be translated on standard error.
	abnf := filepath.Join(c.dir, "req.abnf")
	os.WriteFile(abnf, []byte("request = method SP \"/\" CRLF\nmethod  = %s\"GET\" / %s\"HEAD\"\n"), 0o644)
	imported := c.ok("grammar", "import", abnf, "--quiet")
	if !strings.Contains(imported, "format ") {
		t.Errorf("import printed no grammar:\n%s", imported)
	}
	dest := filepath.Join(c.dir, "req.xfg")
	c.ok("grammar", "import", abnf, "-o", dest, "--quiet")
	if !strings.Contains(mustRead(t, dest), "format ") {
		t.Error("import -o wrote no grammar")
	}
	c.ok("grammar", "sample", dest, "-n", "1")
	if _, err := c.run("grammar", "import", abnf, "--as", "nonsense"); err == nil || !strings.Contains(err.Error(), "nothing imports") {
		t.Errorf("an unknown importer: %v", err)
	}
	unknown := filepath.Join(c.dir, "what.xyz")
	os.WriteFile(unknown, []byte("?"), 0o644)
	if _, err := c.run("grammar", "import", unknown); err == nil {
		t.Error("an undetectable file was imported")
	}
	if _, err := c.run("grammar", "import"); err == nil {
		t.Error("import with no file succeeded")
	}
}

func TestCaptureSeparatesTheSecrets(t *testing.T) {
	c := newCLI(t)
	har := filepath.Join(c.dir, "session.har")
	os.WriteFile(har, []byte(`{"log":{"version":"1.2","entries":[{"startedDateTime":"2026-03-01T10:00:02Z","time":1,
"request":{"method":"GET","url":"https://api.example.com/me","httpVersion":"HTTP/1.1",
"headers":[{"name":"Host","value":"api.example.com"},{"name":"Authorization","value":"Bearer secret-token"}]},
"response":{"status":200,"httpVersion":"HTTP/1.1","headers":[{"name":"Content-Type","value":"application/json"}],
"content":{"size":9,"mimeType":"application/json","text":"{\"id\":1}"}}}]}}`), 0o644)

	session := c.ok("capture", har)
	if !strings.Contains(session, "GET /me") {
		t.Errorf("the session does not carry the request:\n%s", session)
	}
	if strings.Contains(session, "secret-token") {
		t.Error("the credential was printed in the session")
	}

	out := filepath.Join(c.dir, "session.http")
	secrets := filepath.Join(c.dir, "secrets")
	if printed := c.ok("capture", har, "-o", out, "--secrets", secrets, "--links"); printed != "" {
		t.Errorf("capture -o printed %q", printed)
	}
	if !strings.Contains(mustRead(t, out), "GET /me") {
		t.Error("-o did not write the session")
	}
	fi, err := os.Stat(secrets)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("the secrets file is mode %o, want 0600", fi.Mode().Perm())
	}
	if s := mustRead(t, secrets); !strings.Contains(s, "=secret-token") {
		t.Errorf("the secrets file does not hold the credential:\n%s", s)
	}
	if _, err := c.run("capture"); err == nil {
		t.Error("capture with no file succeeded")
	}
	garbage := filepath.Join(c.dir, "garbage")
	os.WriteFile(garbage, []byte("\x00\x01not http"), 0o644)
	if _, err := c.run("capture", garbage); err == nil {
		t.Error("garbage was read as a capture")
	}
}

func TestNoStartRefusesRatherThanStarting(t *testing.T) {
	// --no-start against nothing: the message names where it looked, and no
	// daemon is spawned to look again.
	t.Setenv("PATH", t.TempDir())
	cmd := commands["info"]
	var err error
	captureStdout(t, func() { err = cmd.Run(context.Background(), []string{"--addr", "127.0.0.1:1", "--no-start"}) })
	if err == nil || !strings.Contains(err.Error(), "no daemon is answering on 127.0.0.1:1") {
		t.Errorf("err = %v", err)
	}
	if got := describe("", "1.2.3.4:5"); got != "1.2.3.4:5" {
		t.Errorf("describe prefers the address: %q", got)
	}
	if got := describe("/tmp/x.sock", ""); got != "/tmp/x.sock" {
		t.Errorf("describe with only a socket: %q", got)
	}
}

func TestUsageListsEveryCommandOnce(t *testing.T) {
	text := captureStdout(t, func() { usage(os.Stdout) })
	for name := range commands {
		if strings.Count(text, "    "+name+" ") != 1 && strings.Count(text, "    "+name+"\n") != 1 {
			t.Errorf("usage names %q %d times", name, strings.Count(text, "    "+name))
		}
	}
	if !strings.Contains(text, "--help") {
		t.Error("usage does not say how to get a command's own flags")
	}
	if got := nameList([]string{"b", "a", "c"}); got != "a, b, c" {
		t.Errorf("nameList = %q", got)
	}
}

func TestParsePermutesFlagsBehindPositionals(t *testing.T) {
	// `xfuzz validate campaign.yaml --json` is what people type, and Go's
	// flag package would treat --json as a second file.
	mk := func() (*flag.FlagSet, *bool, *string) {
		fs := flag.NewFlagSet("t", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		j := fs.Bool("json", false, "")
		s := fs.String("store", "", "")
		return fs, j, s
	}

	fs, j, s := mk()
	if err := parse(fs, []string{"file.yaml", "--json", "--store", "dir"}); err != nil {
		t.Fatal(err)
	}
	if !*j || *s != "dir" || strings.Join(fs.Args(), ",") != "file.yaml" {
		t.Errorf("json=%v store=%q args=%v", *j, *s, fs.Args())
	}

	// --name=value consumes nothing after it; a bool flag consumes nothing.
	fs, j, s = mk()
	if err := parse(fs, []string{"--store=dir", "--json", "file.yaml"}); err != nil {
		t.Fatal(err)
	}
	if !*j || *s != "dir" || strings.Join(fs.Args(), ",") != "file.yaml" {
		t.Errorf("json=%v store=%q args=%v", *j, *s, fs.Args())
	}

	// -- ends flags, so a file whose name starts with a dash is reachable,
	// and a lone "-" is a positional.
	fs, j, _ = mk()
	if err := parse(fs, []string{"--", "--json", "-"}); err != nil {
		t.Fatal(err)
	}
	if *j || strings.Join(fs.Args(), ",") != "--json,-" {
		t.Errorf("after --: json=%v args=%v", *j, fs.Args())
	}

	// An unknown flag is assumed to take a value, so the argument after it is
	// not mistaken for a file — and flag then reports it.
	fs, _, _ = mk()
	if err := parse(fs, []string{"--bogus", "file.yaml"}); err == nil {
		t.Error("an unknown flag was accepted")
	}
	if !takesValue(fs, "--bogus") || !takesValue(fs, "-store") || takesValue(fs, "--json") {
		t.Error("takesValue is wrong about a flag")
	}
}

func TestSmallHelpers(t *testing.T) {
	if s, r := subcommand(nil, "list"); s != "list" || r != nil {
		t.Errorf("subcommand(nil) = %q %v", s, r)
	}
	if s, r := subcommand([]string{"--json", "x"}, "list"); s != "list" || len(r) != 2 {
		t.Errorf("a flag first: %q %v", s, r)
	}
	if s, r := subcommand([]string{"get", "x"}, "list"); s != "get" || len(r) != 1 {
		t.Errorf("a verb first: %q %v", s, r)
	}
	if s, r := subcommand([]string{"nightly"}, "list"); s != "list" || len(r) != 1 {
		t.Errorf("a name first: %q %v", s, r)
	}

	if got := hexDump([]byte("AB\x00\xff")); !strings.Contains(got, "41 42 00 ff") || !strings.Contains(got, "AB..") || !strings.HasPrefix(got, "  00000000  ") {
		t.Errorf("hexDump:\n%s", got)
	}
	if got := hexDump(make([]byte, 17)); strings.Count(got, "\n") != 2 {
		t.Errorf("17 bytes should be two lines:\n%s", got)
	}
	if hexDump(nil) != "" {
		t.Error("hexDump(nil) is not empty")
	}
	if spaced("aabbcc") != "aa bb cc" || printable([]byte("a\tb")) != "a.b" {
		t.Error("spaced or printable is wrong")
	}
	if dash("") != "-" || dash("x") != "x" {
		t.Error("dash is wrong")
	}
	if short("0123456789abcdef0123") != "0123456789abcdef" || short("ab") != "ab" {
		t.Error("short is wrong")
	}
	if got := shortBucket("crash|XFUZZ-BUG-1-with-a-long-tail-2"); len([]rune(got)) != 28 || !strings.HasSuffix(got, "tail-2") || !strings.HasPrefix(got, "crash|") {
		t.Errorf("shortBucket keeps both ends: %q", got)
	}
	if shortBucket("short") != "short" {
		t.Error("a short bucket was shortened")
	}
	if urlEscape(`a b"c&d#e`) != "a%20b%22c%26d%23e" {
		t.Errorf("urlEscape = %q", urlEscape(`a b"c&d#e`))
	}
	for in, want := range map[string]any{"true": true, "false": false, "null": nil, "~": nil, "8": 8, "1.5": 1.5, "8s": "8s"} {
		if got := scalarOf(in); got != want {
			t.Errorf("scalarOf(%q) = %v (%T), want %v", in, got, got, want)
		}
	}
	var sl stringList
	sl.Set("a")
	sl.Set("b")
	var pl profileList
	pl.Set("p")
	if sl.String() != "a,b" || pl.String() != "p" {
		t.Error("the list flags are wrong")
	}
	if _, err := onePath(nil); err == nil {
		t.Error("onePath(nil) succeeded")
	}
	if p, err := onePath([]string{"rel.yaml"}); err != nil || !filepath.IsAbs(p) {
		t.Errorf("onePath does not absolutise: %q %v", p, err)
	}
	if _, _, err := nameAndID([]string{"c", "0"}); err == nil {
		t.Error("a zero id was accepted")
	}
	if n, id, err := nameAndID([]string{"c", "12"}); err != nil || n != "c" || id != 12 {
		t.Errorf("nameAndID = %q %d %v", n, id, err)
	}

	empty := daemon.Status{}
	if worstOf(empty) != "ok" {
		t.Error("a healthy campaign is not ok")
	}
	sick := daemon.Status{Health: []metrics.Diagnostic{{Severity: metrics.SeverityWarn, Name: "stall"}}}
	if worstOf(sick) != "warn: stall" {
		t.Errorf("worstOf = %q", worstOf(sick))
	}
	fixed := daemon.Status{Started: time.Unix(100, 0), Stopped: time.Unix(160, 0)}
	if elapsedOf(fixed) != time.Minute {
		t.Errorf("elapsedOf a finished campaign = %v", elapsedOf(fixed))
	}
	if elapsedOf(daemon.Status{Started: time.Now().Add(-time.Hour)}) < 59*time.Minute {
		t.Error("elapsedOf a running campaign is not measured to now")
	}
}

func TestPrintEventRendersEachKind(t *testing.T) {
	// Not a terminal, so progress lines end in a newline rather than a
	// carriage return — which is what `xfuzz run > log` needs.
	out := captureStdout(t, func() {
		printEvent("metrics", []byte(`{"data":{"execs":1200,"execs_per_second":40,"coverage":31,"corpus_size":4,"buckets":1,"states":3,"transitions":5}}`))
		printEvent("finding", []byte(`{"data":{"kind":"crash","summary":"SIGSEGV","bucket":"crash|XFUZZ-BUG-1","new_bucket":true}}`))
		printEvent("finding", []byte(`{"data":{"kind":"crash","summary":"again","new_bucket":false}}`))
		printEvent("log", []byte(`{"data":{"level":"warn","text":"a worker restarted"}}`))
		printEvent("log", []byte(`{"data":{"level":"info","text":"quiet"}}`))
		printEvent("dropped", nil)
		printEvent("worker", []byte(`{}`))
		if !printEvent("campaign", []byte(`{"data":{"state":"running"}}`)) {
			t.Error("a running campaign stopped the follow")
		}
		if printEvent("campaign", []byte(`{"data":{"state":"finished","reason":"budget"}}`)) {
			t.Error("a finished campaign did not stop the follow")
		}
	})
	for _, want := range []string{"1200 execs", "40/s", "31 edges", "3 states", "5 moves", "finding: crash SIGSEGV [crash|XFUZZ-BUG-1]", "warn: a worker restarted", "events were dropped", "campaign running", "campaign finished: budget"} {
		if !strings.Contains(out, want) {
			t.Errorf("printEvent output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "again") || strings.Contains(out, "quiet") || strings.Contains(out, "\r") {
		t.Errorf("printEvent printed what it should not have:\n%s", out)
	}
}

func TestPrintStatusShowsProtocolAndWorkers(t *testing.T) {
	s := daemon.Status{Name: "p", State: daemon.StateRunning, Reason: "", Seed: 42, Isolation: "strong",
		Started: time.Now().Add(-time.Minute)}
	s.Metrics.States, s.Metrics.Transitions, s.Metrics.IllegalMoves = 3, 4, 1
	s.Metrics.Workers, s.Metrics.WorkersHealthy = 2, 1
	s.Health = []metrics.Diagnostic{{Severity: metrics.SeverityWarn, Summary: "slow", Remedy: "add cores"}}
	out := captureStdout(t, func() { printStatus(s) })
	for _, want := range []string{"protocol  3 states, 4 transitions (1 outside the declared model)", "workers   1 of 2 healthy", "[warn] slow", "add cores", "running   "} {
		if !strings.Contains(out, want) {
			t.Errorf("printStatus lacks %q:\n%s", want, out)
		}
	}
	s.State = daemon.StateFinished
	s.Reason = "budget"
	out = captureStdout(t, func() { printStatus(s) })
	if !strings.Contains(out, "state     finished (budget)") || !strings.Contains(out, "workers   2, stopped") {
		t.Errorf("a finished campaign:\n%s", out)
	}
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }
