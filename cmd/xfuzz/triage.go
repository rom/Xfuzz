package main

import (
	"context"
	"errors"
	"fmt"

	"github.com/rom/Xfuzz/internal/api"
)

func init() {
	register(&Command{
		Name: "replay", Group: "inspection",
		Short: "Re-run a finding's reproducer and report whether it still fails",
		Usage: "replay NAME ID [--trials N]",
		API:   []string{"finding.replay"},
		Run:   runReplay,
	})
	register(&Command{
		Name: "minimize", Group: "inspection",
		Short: "Reduce a finding's reproducer, preserving its failure class",
		Usage: "minimize NAME ID [--budget N]",
		API:   []string{"finding.minimize"},
		Run:   runMinimize,
	})
	register(&Command{
		Name: "doctor", Group: "daemon",
		Short: "Report what this host can do, and why anything is missing",
		Usage: "doctor",
		API:   []string{"admin.capabilities"},
		Run:   runDoctor,
	})
}

// runReplay asks the daemon to re-run a reproducer.
//
// The daemon rather than the client, even though the client could exec the
// target itself. A reproducer is the input that made a hostile program
// misbehave, so re-running it needs the campaign's sandbox — and the campaign's
// sandbox lives where the campaign does (ADR-0012, ADR-0003).
func runReplay(ctx context.Context, args []string) error {
	fs, opts := flags(commands["replay"])
	trials := fs.Int("trials", 0, "how many times to run it (default: the campaign's triage.trials)")
	if err := parse(fs, args); err != nil {
		return err
	}
	target, id, err := nameAndID(fs.Args())
	if err != nil {
		return err
	}
	c, err := opts.connect(ctx)
	if err != nil {
		return err
	}

	var rep struct {
		Trials     int     `json:"trials"`
		Reproduced int     `json:"reproduced"`
		Rate       float64 `json:"rate"`
		Kind       string  `json:"kind"`
		Signal     int     `json:"signal"`
		Marker     string  `json:"marker"`
		Divergent  bool    `json:"divergent"`
		State      string  `json:"triage_state"`
	}
	err = c.Do(ctx, "POST", fmt.Sprintf("/v1/campaigns/%s/findings/%d/replay", target, id),
		api.TriageRequest{Trials: *trials}, &rep)
	if err != nil {
		return err
	}
	if opts.jsonOut {
		return printJSON(rep)
	}

	fmt.Printf("finding %d: %d of %d runs reproduced (%.0f%%) — %s\n",
		id, rep.Reproduced, rep.Trials, 100*rep.Rate, rep.State)
	if rep.Kind != "" {
		fmt.Printf("  failure   %s", rep.Kind)
		if rep.Signal != 0 {
			fmt.Printf(" signal %d", rep.Signal)
		}
		fmt.Println()
	}
	if rep.Marker != "" {
		fmt.Printf("  marker    %s\n", rep.Marker)
	}
	if rep.Divergent {
		// Worth a line of its own: a reproducer that fails in more than one way
		// is a race, and that is more interesting than either failure.
		fmt.Println("  note      it did not always fail the same way, which usually means a race")
	}
	return nil
}

func runMinimize(ctx context.Context, args []string) error {
	fs, opts := flags(commands["minimize"])
	budget := fs.Int("budget", 0,
		"how many executions to spend (default: the campaign's triage.minimize_budget)")
	if err := parse(fs, args); err != nil {
		return err
	}
	target, id, err := nameAndID(fs.Args())
	if err != nil {
		return err
	}
	c, err := opts.connect(ctx)
	if err != nil {
		return err
	}

	var rep struct {
		OriginalSize  int     `json:"original_size"`
		MinimizedSize int     `json:"minimized_size"`
		Reduction     float64 `json:"reduction"`
		Runs          int     `json:"runs"`
		Digest        string  `json:"digest"`
		State         string  `json:"triage_state"`
	}
	err = c.Do(ctx, "POST", fmt.Sprintf("/v1/campaigns/%s/findings/%d/minimize", target, id),
		api.TriageRequest{Budget: *budget}, &rep)
	if err != nil {
		return err
	}
	if opts.jsonOut {
		return printJSON(rep)
	}

	fmt.Printf("finding %d: %d bytes to %d (%.0f%% smaller) in %d runs\n",
		id, rep.OriginalSize, rep.MinimizedSize, 100*rep.Reduction, rep.Runs)
	fmt.Printf("  reproducer %s\n", short(rep.Digest))
	fmt.Printf("  state      %s\n", rep.State)
	return nil
}

// runDoctor reports the host's capabilities.
//
// Through the daemon, because the daemon is the process that runs targets and
// therefore the one whose capabilities matter. A client reporting its own would
// answer for the wrong machine the moment --addr points elsewhere.
func runDoctor(ctx context.Context, args []string) error {
	fs, opts := flags(commands["doctor"])
	if err := parse(fs, args); err != nil {
		return err
	}
	c, err := opts.connect(ctx)
	if err != nil {
		return err
	}

	var rep api.CapabilitiesResponse
	if err := c.Do(ctx, "GET", "/v1/capabilities", nil, &rep); err != nil {
		return err
	}
	if opts.jsonOut {
		return printJSON(rep)
	}

	fmt.Printf("platform   %s\n", rep.Platform)
	fmt.Printf("version    %s (%s)\n", rep.Version.Version, rep.Version.Go)
	fmt.Printf("isolation  %s\n\n", rep.Isolation)

	for _, cap := range rep.Capabilities {
		mark := "no "
		if cap.Available {
			mark = "yes"
		}
		fmt.Printf("  %-3s %-18s %s\n", mark, cap.Name, cap.Detail)
	}
	if len(rep.Notes) > 0 {
		fmt.Println("\nnotes")
		for _, n := range rep.Notes {
			fmt.Printf("  - %s\n", n)
		}
	}
	return nil
}

// nameAndID reads a campaign name and a finding id.
func nameAndID(args []string) (string, int64, error) {
	if len(args) != 2 {
		return "", 0, errors.New("expected a campaign name and a finding id")
	}
	var id int64
	if _, err := fmt.Sscanf(args[1], "%d", &id); err != nil || id <= 0 {
		return "", 0, fmt.Errorf("%q is not a finding id; `xfuzz findings list %s` shows them",
			args[1], args[0])
	}
	return args[0], id, nil
}
