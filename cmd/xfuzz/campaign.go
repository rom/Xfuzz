package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/rom/Xfuzz/internal/client"
	"github.com/rom/Xfuzz/internal/daemon"
)

func init() {
	register(&Command{
		Name: "init", Group: "campaign files", Short: "Write a starter campaign file",
		Usage: "init [--target PATH] [--name NAME]",
		Run:   runInit,
	})
	register(&Command{
		Name: "validate", Group: "campaign files", Short: "Check a campaign file without running it",
		Usage: "validate FILE [--profile NAME]...",
		API:   []string{"campaign.validate"},
		Run:   runValidate,
	})
	register(&Command{
		Name: "explain", Group: "campaign files",
		Short: "Print the fully resolved configuration, including every default",
		Usage: "explain FILE [--profile NAME]... [--yaml]",
		API:   []string{"campaign.explain"},
		Run:   runExplain,
	})
	register(&Command{
		Name: "run", Group: "campaigns", Short: "Create and start a campaign, following its progress",
		Usage: "run FILE [--profile NAME]... [--detach]",
		API:   []string{"campaign.create", "campaign.start", "event.stream", "campaign.get"},
		Run:   runRun,
	})
	register(&Command{
		Name: "list", Group: "campaigns", Short: "List campaigns the daemon has loaded",
		Usage: "list", API: []string{"campaign.list"}, Run: runList,
	})
	register(&Command{
		Name: "status", Group: "campaigns", Short: "Show one campaign's state, counters and health",
		Usage: "status NAME", API: []string{"campaign.get", "metrics.health"}, Run: runStatus,
	})
	register(&Command{
		Name: "pause", Group: "campaigns", Short: "Pause a campaign without losing its state",
		Usage: "pause NAME", API: []string{"campaign.pause"}, Run: actionCommand("pause"),
	})
	register(&Command{
		Name: "resume", Group: "campaigns", Short: "Resume a paused campaign",
		Usage: "resume NAME", API: []string{"campaign.resume"}, Run: actionCommand("resume"),
	})
	register(&Command{
		Name: "stop", Group: "campaigns", Short: "Stop a campaign",
		Usage: "stop NAME [--reason TEXT]", API: []string{"campaign.stop"}, Run: runStop,
	})
	register(&Command{
		Name: "start", Group: "campaigns", Short: "Start a campaign the daemon already holds",
		Usage: "start NAME", API: []string{"campaign.start"}, Run: actionCommand("start"),
	})
	register(&Command{
		Name: "forget", Group: "campaigns", Short: "Forget a finished campaign, keeping its store",
		Usage: "forget NAME", API: []string{"campaign.forget"}, Run: runForget,
	})
}

// runInit writes the annotated starter file.
//
// Local by design: it produces a file, and a daemon is not involved in writing
// one. It is also the only command that does not need a daemon at all, which is
// what makes "install one binary and reach a first finding" possible.
func runInit(ctx context.Context, args []string) error {
	fs, _ := flags(commands["init"])
	target := fs.String("target", "./target", "path to the target executable")
	cname := fs.String("name", "campaign", "campaign name")
	out := fs.String("o", "", "write to this file instead of standard output")
	if err := parse(fs, args); err != nil {
		return err
	}

	doc := starterCampaign(*cname, *target)
	if *out == "" {
		fmt.Print(doc)
		return nil
	}
	if _, err := os.Stat(*out); err == nil {
		return fmt.Errorf("%s already exists; refusing to overwrite a campaign file", *out)
	}
	return os.WriteFile(*out, []byte(doc), 0o644)
}

func runValidate(ctx context.Context, args []string) error {
	fs, opts := flags(commands["validate"])
	var profiles profileList
	fs.Var(&profiles, "profile", "profile to apply (repeatable)")
	if err := parse(fs, args); err != nil {
		return err
	}
	path, err := onePath(fs.Args())
	if err != nil {
		return err
	}
	doc, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	c, err := opts.connect(ctx)
	if err != nil {
		return err
	}
	var resp struct {
		Valid    bool     `json:"valid"`
		Name     string   `json:"name"`
		Warnings []string `json:"warnings"`
	}
	err = c.Do(ctx, "POST", "/v1/campaigns/validate", map[string]any{
		"document": string(doc), "name": path, "profiles": []string(profiles),
	}, &resp)
	if err != nil {
		return err
	}
	if opts.jsonOut {
		return printJSON(resp)
	}
	fmt.Printf("%s: valid\n", path)
	for _, w := range resp.Warnings {
		fmt.Printf("  warning: %s\n", w)
	}
	return nil
}

func runExplain(ctx context.Context, args []string) error {
	fs, opts := flags(commands["explain"])
	var profiles profileList
	fs.Var(&profiles, "profile", "profile to apply (repeatable)")
	asYAML := fs.Bool("yaml", false, "print the resolved configuration as a campaign file")
	if err := parse(fs, args); err != nil {
		return err
	}
	path, err := onePath(fs.Args())
	if err != nil {
		return err
	}
	doc, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	c, err := opts.connect(ctx)
	if err != nil {
		return err
	}
	var resp struct {
		Name     string   `json:"name"`
		Profiles []string `json:"profiles"`
		Text     string   `json:"text"`
		YAML     string   `json:"yaml"`
	}
	err = c.Do(ctx, "POST", "/v1/campaigns/explain", map[string]any{
		"document": string(doc), "name": path, "profiles": []string(profiles),
	}, &resp)
	if err != nil {
		return err
	}
	switch {
	case opts.jsonOut:
		return printJSON(resp)
	case *asYAML:
		fmt.Print(resp.YAML)
	default:
		fmt.Print(resp.Text)
	}
	return nil
}

func runRun(ctx context.Context, args []string) error {
	fs, opts := flags(commands["run"])
	var profiles profileList
	fs.Var(&profiles, "profile", "profile to apply (repeatable)")
	detach := fs.Bool("detach", false, "start the campaign and return immediately")
	if err := parse(fs, args); err != nil {
		return err
	}
	path, err := onePath(fs.Args())
	if err != nil {
		return err
	}
	doc, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	c, err := opts.connect(ctx)
	if err != nil {
		return err
	}

	var created daemon.Status
	err = c.Do(ctx, "POST", "/v1/campaigns", map[string]any{
		"document": string(doc), "name": path, "profiles": []string(profiles),
	}, &created)
	if err != nil {
		return err
	}

	var started daemon.Status
	if err := c.Do(ctx, "POST", "/v1/campaigns/"+created.Name+"/start", nil, &started); err != nil {
		return err
	}

	fmt.Printf("campaign %s started: %d worker(s), seed %d, isolation %s\n",
		started.Name, len(started.Workers), started.Seed, started.Isolation)
	if *detach {
		// The campaign outlives this command, which is the point of the daemon
		// owning it (ADR-0003).
		fmt.Printf("running in the background; follow it with '%s status %s'\n", name, started.Name)
		return nil
	}
	return follow(ctx, c, started.Name, opts)
}

// follow prints progress until the campaign finishes or the user interrupts.
func follow(ctx context.Context, c *client.Client, campaignName string, opts *connOptions) error {
	fmt.Printf("following; ctrl-c stops watching, not the campaign\n\n")

	streamed := make(chan error, 1)
	go func() {
		streamed <- c.Stream(ctx, []string{"metrics", "finding", "campaign", "worker", "log"},
			campaignName, func(kind string, data []byte) bool {
				return printEvent(kind, data)
			})
	}()

	select {
	case <-ctx.Done():
		fmt.Printf("\nstopped following; the campaign is still running\n")
		return nil
	case err := <-streamed:
		if err != nil && ctx.Err() == nil {
			return err
		}
	}

	var final daemon.Status
	if err := c.Do(context.WithoutCancel(ctx), "GET", "/v1/campaigns/"+campaignName, nil, &final); err != nil {
		return err
	}
	printStatus(final)
	return nil
}

func runList(ctx context.Context, args []string) error {
	fs, opts := flags(commands["list"])
	if err := parse(fs, args); err != nil {
		return err
	}
	c, err := opts.connect(ctx)
	if err != nil {
		return err
	}
	var resp struct {
		Campaigns []daemon.Status `json:"campaigns"`
	}
	if err := c.Do(ctx, "GET", "/v1/campaigns", nil, &resp); err != nil {
		return err
	}
	if opts.jsonOut {
		return printJSON(resp)
	}
	if len(resp.Campaigns) == 0 {
		fmt.Println("no campaigns loaded")
		return nil
	}
	fmt.Printf("%-24s %-10s %10s %9s %8s  %s\n", "NAME", "STATE", "EXECS", "COVERAGE", "BUCKETS", "HEALTH")
	for _, s := range resp.Campaigns {
		fmt.Printf("%-24s %-10s %10d %9d %8d  %s\n",
			s.Name, s.State, s.Metrics.Execs, s.Metrics.Coverage, s.Metrics.Buckets, worstOf(s))
	}
	return nil
}

func runStatus(ctx context.Context, args []string) error {
	fs, opts := flags(commands["status"])
	if err := parse(fs, args); err != nil {
		return err
	}
	target, err := oneName(fs.Args())
	if err != nil {
		return err
	}
	c, err := opts.connect(ctx)
	if err != nil {
		return err
	}
	var s daemon.Status
	if err := c.Do(ctx, "GET", "/v1/campaigns/"+target, nil, &s); err != nil {
		return err
	}
	if opts.jsonOut {
		return printJSON(s)
	}
	printStatus(s)
	return nil
}

func actionCommand(action string) func(context.Context, []string) error {
	return func(ctx context.Context, args []string) error {
		fs, opts := flags(commands[action])
		if err := parse(fs, args); err != nil {
			return err
		}
		target, err := oneName(fs.Args())
		if err != nil {
			return err
		}
		c, err := opts.connect(ctx)
		if err != nil {
			return err
		}
		var s daemon.Status
		if err := c.Do(ctx, "POST", "/v1/campaigns/"+target+"/"+action, nil, &s); err != nil {
			return err
		}
		if opts.jsonOut {
			return printJSON(s)
		}
		fmt.Printf("%s: %s\n", s.Name, s.State)
		return nil
	}
}

func runStop(ctx context.Context, args []string) error {
	fs, opts := flags(commands["stop"])
	reason := fs.String("reason", "", "why the campaign is being stopped, for the audit log")
	if err := parse(fs, args); err != nil {
		return err
	}
	target, err := oneName(fs.Args())
	if err != nil {
		return err
	}
	c, err := opts.connect(ctx)
	if err != nil {
		return err
	}
	path := "/v1/campaigns/" + target + "/stop"
	if *reason != "" {
		path += "?reason=" + urlEscape(*reason)
	}
	var s daemon.Status
	if err := c.Do(ctx, "POST", path, nil, &s); err != nil {
		return err
	}
	if opts.jsonOut {
		return printJSON(s)
	}
	fmt.Printf("%s: %s (%s)\n", s.Name, s.State, s.Reason)
	return nil
}

func runForget(ctx context.Context, args []string) error {
	fs, opts := flags(commands["forget"])
	if err := parse(fs, args); err != nil {
		return err
	}
	target, err := oneName(fs.Args())
	if err != nil {
		return err
	}
	c, err := opts.connect(ctx)
	if err != nil {
		return err
	}
	if err := c.Do(ctx, "DELETE", "/v1/campaigns/"+target, nil, nil); err != nil {
		return err
	}
	fmt.Printf("%s: forgotten; its store is untouched\n", target)
	return nil
}

// printStatus renders a campaign the way somebody checking on it wants to read
// it: what it is doing, then what is wrong with it.
func printStatus(s daemon.Status) {
	fmt.Printf("campaign  %s\n", s.Name)
	fmt.Printf("state     %s", s.State)
	if s.Reason != "" {
		fmt.Printf(" (%s)", s.Reason)
	}
	fmt.Println()
	fmt.Printf("seed      %d\n", s.Seed)
	fmt.Printf("isolation %s\n", s.Isolation)
	if !s.Started.IsZero() {
		fmt.Printf("running   %s\n", elapsedOf(s).Round(time.Second))
	}

	m := s.Metrics
	fmt.Printf("\nexecs     %d (%.0f/s)\n", m.Execs, m.ExecsPerS)
	fmt.Printf("coverage  %d edges (%.1f%% of the map)\n", m.Coverage, 100*m.MapDensity)
	fmt.Printf("corpus    %d entries\n", m.CorpusSize)
	fmt.Printf("findings  %d in %d bucket(s)\n", m.Findings, m.Buckets)
	if m.Workers > 0 {
		// "0 of 2 healthy" on a campaign that ended on its budget reads as a
		// failure. Once it has stopped, the workers being gone is the expected
		// state and the count is history, not health.
		if s.State == daemon.StateRunning {
			fmt.Printf("workers   %d of %d healthy\n", m.WorkersHealthy, m.Workers)
		} else {
			fmt.Printf("workers   %d, stopped\n", m.Workers)
		}
	}

	if len(s.Health) > 0 {
		fmt.Println("\nhealth")
		for _, d := range s.Health {
			fmt.Printf("  [%s] %s\n", d.Severity, d.Summary)
			if d.Remedy != "" {
				fmt.Printf("        %s\n", d.Remedy)
			}
		}
	}
}

func printEvent(kind string, data []byte) bool {
	switch kind {
	case "metrics":
		// The payload is the event envelope; the snapshot is its data field.
		// Unmarshalling the envelope directly reads every counter as zero,
		// which looks exactly like a campaign that is not running.
		var e struct {
			Data struct {
				Execs      uint64  `json:"execs"`
				ExecsPerS  float64 `json:"execs_per_second"`
				Coverage   int     `json:"coverage"`
				CorpusSize int     `json:"corpus_size"`
				Buckets    int     `json:"buckets"`
			} `json:"data"`
		}
		if json.Unmarshal(data, &e) == nil {
			progress("%10d execs  %7.0f/s  %6d edges  %4d corpus  %3d buckets",
				e.Data.Execs, e.Data.ExecsPerS, e.Data.Coverage, e.Data.CorpusSize, e.Data.Buckets)
		}
	case "finding":
		var e struct {
			Data struct {
				Kind      string `json:"kind"`
				Summary   string `json:"summary"`
				Bucket    string `json:"bucket"`
				NewBucket bool   `json:"new_bucket"`
			} `json:"data"`
		}
		if json.Unmarshal(data, &e) == nil && e.Data.NewBucket {
			fmt.Printf("\n  finding: %s %s [%s]\n", e.Data.Kind, e.Data.Summary, short(e.Data.Bucket))
		}
	case "campaign":
		var e struct {
			Data struct {
				State  string `json:"state"`
				Reason string `json:"reason"`
			} `json:"data"`
		}
		if json.Unmarshal(data, &e) == nil {
			fmt.Printf("\n  campaign %s", e.Data.State)
			if e.Data.Reason != "" {
				fmt.Printf(": %s", e.Data.Reason)
			}
			fmt.Println()
			if e.Data.State == string(daemon.StateFinished) {
				return false
			}
		}
	case "log":
		var e struct {
			Data struct {
				Level string `json:"level"`
				Text  string `json:"text"`
			} `json:"data"`
		}
		if json.Unmarshal(data, &e) == nil && e.Data.Level != "info" {
			fmt.Printf("\n  %s: %s\n", e.Data.Level, e.Data.Text)
		}
	case "dropped":
		// The stream is lossy by design and says so, rather than quietly
		// showing an incomplete picture.
		fmt.Printf("\n  (events were dropped: this client fell behind; the campaign was not slowed)\n")
	}
	return true
}

// progress writes a line that a terminal overwrites in place.
//
// Redirected output gets one line per update instead, because a file full of
// carriage returns is a file nobody can read — and `xfuzz run > log` is what
// anybody scripting this will write.
func progress(format string, args ...any) {
	if isTerminal(os.Stdout) {
		fmt.Printf("\r"+format, args...)
		return
	}
	fmt.Printf(format+"\n", args...)
}

func worstOf(s daemon.Status) string {
	if len(s.Health) == 0 {
		return "ok"
	}
	return fmt.Sprintf("%s: %s", s.Health[0].Severity, s.Health[0].Name)
}

func elapsedOf(s daemon.Status) time.Duration {
	end := time.Now()
	if !s.Stopped.IsZero() {
		end = s.Stopped
	}
	return end.Sub(s.Started)
}

func short(s string) string {
	if len(s) > 16 {
		return s[:16]
	}
	return s
}

// starterCampaign is what `xfuzz init` writes.
func starterCampaign(cname, target string) string {
	return fmt.Sprintf(`# An Xfuzz campaign. This file is the only interface: what it says is what
# runs, and 'xfuzz explain' prints the whole resolved configuration including
# every default.

name: %s

target:
  path: %s
  # How the input reaches the target. For a program that takes a file, set
  # input: file and put @@ in the arguments where the path belongs.
  input: stdin
  timeout: 5s

seeds:
  # Real files the target accepts. A corpus is what gives mutation something
  # worth preserving; without one a campaign spends its first hours rediscovering
  # the file format.
  dirs: [./seeds]

format:
  codec: raw
  # A grammar makes mutation structural: lengths and checksums are recomputed
  # after every change, so a mutated input still parses far enough to be
  # interesting.
  # grammar: ./format.xfg
  # dictionary: ./tokens.dict

feedback:
  # sancov needs a target built with xfuzz-cc. For a binary you cannot rebuild,
  # set coverage: none and novelty: true.
  coverage: sancov
  objectives: [crash, hang, oom, sanitizer]

workers:
  # One per core by default.
  count: 0

safety:
  # The campaign refuses to start if the host cannot provide this much.
  # Raise it to 'strong' for a target you do not trust.
  isolation: minimal

stop:
  # A campaign should be able to end. Remove this to run until interrupted.
  after: 1h
`, cname, target)
}

func onePath(args []string) (string, error) {
	if len(args) != 1 {
		return "", errors.New("expected exactly one campaign file")
	}
	return args[0], nil
}

func oneName(args []string) (string, error) {
	if len(args) != 1 {
		return "", errors.New("expected exactly one campaign name")
	}
	return args[0], nil
}

func printJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func urlEscape(s string) string {
	return strings.NewReplacer(" ", "%20", "\"", "%22", "&", "%26", "#", "%23").Replace(s)
}

// profileList collects a repeatable flag.
type profileList []string

func (p *profileList) String() string     { return strings.Join(*p, ",") }
func (p *profileList) Set(v string) error { *p = append(*p, v); return nil }
