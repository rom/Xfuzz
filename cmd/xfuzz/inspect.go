package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"github.com/rom/Xfuzz/internal/daemon"
)

func init() {
	register(&Command{
		Name: "corpus", Group: "inspection", Short: "Browse, fetch, import and export the corpus",
		Usage: "corpus list|get|import|export NAME [args]",
		API:   []string{"corpus.list", "corpus.get", "corpus.import", "corpus.export"},
		Run:   runCorpus,
	})
	register(&Command{
		Name: "findings", Group: "inspection", Short: "List findings and fetch their reproducers",
		Usage: "findings list|get|buckets NAME [args]",
		API:   []string{"finding.list", "finding.get", "finding.buckets"},
		Run:   runFindings,
	})
	register(&Command{
		Name: "metrics", Group: "inspection", Short: "Show counters, history, and health diagnostics",
		Usage: "metrics NAME [--history]",
		API:   []string{"metrics.get", "metrics.history"},
		Run:   runMetrics,
	})
	register(&Command{
		Name: "watch", Group: "inspection", Short: "Follow a campaign's live event stream",
		Usage: "watch [NAME] [--kinds metrics,finding,...]",
		API:   []string{"event.stream"},
		Run:   runWatch,
	})
	register(&Command{
		Name: "workers", Group: "inspection", Short: "Show each worker's state",
		Usage: "workers NAME", API: []string{"admin.workers"}, Run: runWorkers,
	})
	register(&Command{
		Name: "safety", Group: "inspection",
		Short: "Show the isolation in force, and why it is not higher",
		Usage: "safety NAME", API: []string{"admin.safety"}, Run: runSafety,
	})
	register(&Command{
		Name: "audit", Group: "inspection", Short: "Print the audit log and verify its hash chain",
		Usage: "audit", API: []string{"admin.audit"}, Run: runAudit,
	})
	register(&Command{
		Name: "info", Group: "daemon", Short: "Show the daemon's version and status",
		Usage: "info", API: []string{"admin.info"}, Run: runInfo,
	})
	register(&Command{
		Name: "schema", Group: "daemon", Short: "Print the campaign file JSON Schema",
		Usage: "schema [--openapi]", API: []string{"admin.schema", "admin.openapi"}, Run: runSchema,
	})
}

func runCorpus(ctx context.Context, args []string) error {
	sub, rest := subcommand(args, "list")
	switch sub {
	case "list":
		return corpusList(ctx, rest)
	case "get":
		return corpusGet(ctx, rest)
	case "import":
		return corpusTransfer(ctx, rest, "import")
	case "export":
		return corpusTransfer(ctx, rest, "export")
	default:
		return fmt.Errorf("unknown corpus subcommand %q (want list, get, import, or export)", sub)
	}
}

func corpusList(ctx context.Context, args []string) error {
	fs, opts := flags(commands["corpus"])
	limit := fs.Int("limit", 50, "how many entries to show")
	order := fs.String("order", "coverage", "coverage, size, or discovered")
	favoured := fs.Bool("favoured", false, "only the minimal covering set")
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

	path := fmt.Sprintf("/v1/campaigns/%s/corpus?limit=%d&order=%s", target, *limit, *order)
	if *favoured {
		path += "&favoured=true"
	}
	var resp struct {
		Entries []struct {
			Digest   string `json:"digest"`
			Size     int    `json:"size"`
			Coverage int    `json:"coverage"`
			Favoured bool   `json:"favoured"`
			Origin   string `json:"origin"`
		} `json:"entries"`
		Count int `json:"count"`
	}
	if err := c.Do(ctx, "GET", path, nil, &resp); err != nil {
		return err
	}
	if opts.jsonOut {
		return printJSON(resp)
	}
	fmt.Printf("%-16s %8s %9s %4s  %s\n", "DIGEST", "SIZE", "COVERAGE", "FAV", "ORIGIN")
	for _, e := range resp.Entries {
		fav := ""
		if e.Favoured {
			fav = "*"
		}
		fmt.Printf("%-16s %8d %9d %4s  %s\n", short(e.Digest), e.Size, e.Coverage, fav, e.Origin)
	}
	fmt.Printf("\n%d entries\n", resp.Count)
	return nil
}

func corpusGet(ctx context.Context, args []string) error {
	fs, opts := flags(commands["corpus"])
	out := fs.String("o", "", "write the payload to this file instead of standard output")
	if err := parse(fs, args); err != nil {
		return err
	}
	if fs.NArg() != 2 {
		return fmt.Errorf("expected a campaign name and a digest")
	}
	c, err := opts.connect(ctx)
	if err != nil {
		return err
	}
	var e struct {
		Digest  string `json:"digest"`
		Payload []byte `json:"payload"`
	}
	if err := c.Do(ctx, "GET", "/v1/campaigns/"+fs.Arg(0)+"/corpus/"+fs.Arg(1), nil, &e); err != nil {
		return err
	}
	return emit(*out, e.Payload, opts.jsonOut, e)
}

func corpusTransfer(ctx context.Context, args []string, direction string) error {
	fs, opts := flags(commands["corpus"])
	dir := fs.String("dir", "", "directory to read from or write to")
	format := fs.String("format", "auto", "afl, libfuzzer, raw, or auto")
	favoured := fs.Bool("favoured", false, "export only the minimal covering set")
	overwrite := fs.Bool("overwrite", false, "export into a directory that already holds files")
	if err := parse(fs, args); err != nil {
		return err
	}
	target, err := oneName(fs.Args())
	if err != nil {
		return err
	}
	if *dir == "" {
		return fmt.Errorf("--dir is required")
	}
	c, err := opts.connect(ctx)
	if err != nil {
		return err
	}

	body := map[string]any{"dir": *dir, "format": *format}
	if direction == "export" {
		body["favoured_only"] = *favoured
		body["overwrite"] = *overwrite
	}
	var resp map[string]any
	if err := c.Do(ctx, "POST", "/v1/campaigns/"+target+"/corpus/"+direction, body, &resp); err != nil {
		return err
	}
	return printJSON(resp)
}

func runFindings(ctx context.Context, args []string) error {
	sub, rest := subcommand(args, "list")
	switch sub {
	case "list":
		return findingsList(ctx, rest)
	case "get":
		return findingsGet(ctx, rest)
	case "buckets":
		return findingsBuckets(ctx, rest)
	default:
		return fmt.Errorf("unknown findings subcommand %q (want list, get, or buckets)", sub)
	}
}

func findingsList(ctx context.Context, args []string) error {
	fs, opts := flags(commands["findings"])
	state := fs.String("state", "", "only findings in this triage state")
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
	path := "/v1/campaigns/" + target + "/findings"
	if *state != "" {
		path += "?state=" + *state
	}
	var resp struct {
		Findings []struct {
			ID          int64   `json:"id"`
			Kind        string  `json:"kind"`
			Signal      int     `json:"signal"`
			Summary     string  `json:"summary"`
			TriageState string  `json:"triage_state"`
			ReproTrials int     `json:"repro_trials"`
			ReproRate   float64 `json:"repro_rate"`
			Reduction   float64 `json:"reduction"`
		} `json:"findings"`
		Count int `json:"count"`
	}
	if err := c.Do(ctx, "GET", path, nil, &resp); err != nil {
		return err
	}
	if opts.jsonOut {
		return printJSON(resp)
	}
	if resp.Count == 0 {
		fmt.Println("no findings")
		return nil
	}
	fmt.Printf("%6s %-10s %-12s %10s  %s\n", "ID", "KIND", "TRIAGE", "REPRO", "SUMMARY")
	for _, f := range resp.Findings {
		repro := "not checked"
		if f.ReproTrials > 0 {
			repro = fmt.Sprintf("%.0f%% of %d", 100*f.ReproRate, f.ReproTrials)
		}
		fmt.Printf("%6d %-10s %-12s %10s  %s\n", f.ID, f.Kind, f.TriageState, repro, f.Summary)
	}
	fmt.Printf("\n%d findings\n", resp.Count)
	return nil
}

func findingsGet(ctx context.Context, args []string) error {
	fs, opts := flags(commands["findings"])
	out := fs.String("o", "", "write the reproducer to this file")
	if err := parse(fs, args); err != nil {
		return err
	}
	if fs.NArg() != 2 {
		return fmt.Errorf("expected a campaign name and a finding id")
	}
	c, err := opts.connect(ctx)
	if err != nil {
		return err
	}
	// Re-marshalled rather than passed through, so that --json here is the
	// reproducer and its account of itself rather than the whole record. The
	// signal is part of that account: the summary names it only for the
	// signals that have names, and for the rest the number is the information.
	var f struct {
		ID         int64    `json:"id"`
		Kind       string   `json:"kind"`
		Signal     int      `json:"signal"`
		Summary    string   `json:"summary"`
		Detail     string   `json:"detail"`
		Frames     []string `json:"frames"`
		Reproducer []byte   `json:"reproducer"`
	}
	if err := c.Do(ctx, "GET", "/v1/campaigns/"+fs.Arg(0)+"/findings/"+fs.Arg(1), nil, &f); err != nil {
		return err
	}
	if *out != "" || opts.jsonOut {
		return emit(*out, f.Reproducer, opts.jsonOut, f)
	}
	fmt.Printf("finding %d: %s %s\n", f.ID, f.Kind, f.Summary)
	for _, fr := range f.Frames {
		fmt.Printf("  %s\n", fr)
	}
	if f.Detail != "" {
		fmt.Printf("\n%s\n", f.Detail)
	}
	fmt.Printf("\nreproducer (%d bytes):\n%s\n", len(f.Reproducer), hexDump(f.Reproducer))
	return nil
}

func findingsBuckets(ctx context.Context, args []string) error {
	fs, opts := flags(commands["findings"])
	strategy := fs.String("strategy", "", "bucketing strategy (default: the campaign's)")
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
	path := "/v1/campaigns/" + target + "/buckets"
	if *strategy != "" {
		path += "?strategy=" + *strategy
	}
	var resp map[string]any
	if err := c.Do(ctx, "GET", path, nil, &resp); err != nil {
		return err
	}
	return printJSON(resp)
}

func runMetrics(ctx context.Context, args []string) error {
	fs, opts := flags(commands["metrics"])
	history := fs.Bool("history", false, "print the downsampled series instead of the current values")
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
	path := "/v1/campaigns/" + target + "/metrics"
	if *history {
		path += "/history"
	}
	var resp map[string]any
	if err := c.Do(ctx, "GET", path, nil, &resp); err != nil {
		return err
	}
	return printJSON(resp)
}

func runWatch(ctx context.Context, args []string) error {
	fs, opts := flags(commands["watch"])
	kinds := fs.String("kinds", "metrics,finding,campaign,worker,log", "event kinds to follow")
	if err := parse(fs, args); err != nil {
		return err
	}
	campaignName := ""
	if fs.NArg() == 1 {
		campaignName = fs.Arg(0)
	}
	c, err := opts.connect(ctx)
	if err != nil {
		return err
	}
	err = c.Stream(ctx, strings.Split(*kinds, ","), campaignName, printEvent)
	if ctx.Err() != nil {
		fmt.Println()
		return nil
	}
	return err
}

func runWorkers(ctx context.Context, args []string) error {
	fs, opts := flags(commands["workers"])
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
	var resp struct {
		Workers []daemon.WorkerStatus `json:"workers"`
	}
	if err := c.Do(ctx, "GET", "/v1/campaigns/"+target+"/workers", nil, &resp); err != nil {
		return err
	}
	if opts.jsonOut {
		return printJSON(resp)
	}
	fmt.Printf("%4s %-10s %8s %9s  %s\n", "ID", "STATE", "PID", "RESTARTS", "STRATEGY")
	for _, w := range resp.Workers {
		fmt.Printf("%4d %-10s %8d %9d  %s", w.ID, w.State, w.Pid, w.Restarts, w.Strategy)
		if w.Err != "" {
			fmt.Printf("  (%s)", w.Err)
		}
		fmt.Println()
	}
	return nil
}

func runSafety(ctx context.Context, args []string) error {
	fs, opts := flags(commands["safety"])
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
	var resp struct {
		Isolation   string            `json:"isolation"`
		Explanation string            `json:"explanation"`
		Scope       string            `json:"scope"`
		Connections map[string]uint64 `json:"connections"`
	}
	if err := c.Do(ctx, "GET", "/v1/campaigns/"+target+"/safety", nil, &resp); err != nil {
		return err
	}
	if opts.jsonOut {
		return printJSON(resp)
	}
	fmt.Println(resp.Explanation)
	fmt.Printf("\nnetwork scope: %s\n", resp.Scope)
	fmt.Printf("connections:   %d allowed, %d refused\n",
		resp.Connections["allowed"], resp.Connections["denied"])
	return nil
}

func runAudit(ctx context.Context, args []string) error {
	fs, opts := flags(commands["audit"])
	if err := parse(fs, args); err != nil {
		return err
	}
	c, err := opts.connect(ctx)
	if err != nil {
		return err
	}
	var resp struct {
		Entries []struct {
			ID     int64  `json:"ID"`
			At     string `json:"At"`
			Actor  string `json:"Actor"`
			Action string `json:"Action"`
			Detail string `json:"Detail"`
		} `json:"entries"`
		Verified  int    `json:"verified"`
		Intact    bool   `json:"intact"`
		Tampering string `json:"tampering"`
	}
	if err := c.Do(ctx, "GET", "/v1/audit", nil, &resp); err != nil {
		return err
	}
	if opts.jsonOut {
		return printJSON(resp)
	}
	for _, e := range resp.Entries {
		fmt.Printf("%4d %s %-20s %s %s\n", e.ID, e.At, e.Action, e.Actor, e.Detail)
	}
	fmt.Println()
	if resp.Intact {
		fmt.Printf("hash chain verified over %d entries\n", resp.Verified)
	} else {
		fmt.Printf("TAMPERING DETECTED after %d entries: %s\n", resp.Verified, resp.Tampering)
		os.Exit(1)
	}
	return nil
}

func runInfo(ctx context.Context, args []string) error {
	fs, opts := flags(commands["info"])
	if err := parse(fs, args); err != nil {
		return err
	}
	c, err := opts.connect(ctx)
	if err != nil {
		return err
	}
	var resp map[string]any
	if err := c.Do(ctx, "GET", "/v1/info", nil, &resp); err != nil {
		return err
	}
	return printJSON(resp)
}

func runSchema(ctx context.Context, args []string) error {
	fs, opts := flags(commands["schema"])
	openapi := fs.Bool("openapi", false, "print the API's OpenAPI description instead")
	if err := parse(fs, args); err != nil {
		return err
	}
	c, err := opts.connect(ctx)
	if err != nil {
		return err
	}
	path := "/v1/schema"
	if *openapi {
		path = "/v1/openapi.json"
	}
	var raw map[string]any
	if err := c.Do(ctx, "GET", path, nil, &raw); err != nil {
		return err
	}
	return printJSON(raw)
}

// subcommand splits a verb's first argument off, defaulting when the next
// argument is a flag or a name.
func subcommand(args []string, def string) (string, []string) {
	if len(args) == 0 {
		return def, nil
	}
	first := args[0]
	if strings.HasPrefix(first, "-") {
		return def, args
	}
	switch first {
	case "list", "get", "import", "export", "buckets":
		return first, args[1:]
	}
	return def, args
}

// emit writes a payload to a file or to standard output.
func emit(path string, payload []byte, asJSON bool, full any) error {
	if asJSON {
		return printJSON(full)
	}
	if path != "" {
		if err := os.WriteFile(path, payload, 0o644); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "wrote %d bytes to %s\n", len(payload), path)
		return nil
	}
	_, err := os.Stdout.Write(payload)
	return err
}

// hexDump renders a reproducer the way somebody reading a bug report wants it.
func hexDump(b []byte) string {
	const perLine = 16
	var sb strings.Builder
	for i := 0; i < len(b); i += perLine {
		end := min(i+perLine, len(b))
		fmt.Fprintf(&sb, "  %08x  %-48s  %s\n", i,
			spaced(hex.EncodeToString(b[i:end])), printable(b[i:end]))
	}
	return sb.String()
}

func spaced(h string) string {
	var sb strings.Builder
	for i := 0; i < len(h); i += 2 {
		if i > 0 {
			sb.WriteByte(' ')
		}
		sb.WriteString(h[i : i+2])
	}
	return sb.String()
}

func printable(b []byte) string {
	out := make([]byte, len(b))
	for i, c := range b {
		if c >= 0x20 && c < 0x7f {
			out[i] = c
		} else {
			out[i] = '.'
		}
	}
	return string(out)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
