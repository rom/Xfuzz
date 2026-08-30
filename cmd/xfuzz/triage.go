package main

import (
	"context"
	"errors"
	"fmt"

	"github.com/rom/Xfuzz/internal/api"
)

func init() {
	register(&Command{
		Name: "triage", Group: "triage",
		Short: "Record a judgement of a finding, and a note",
		Usage: "triage NAME ID [--as JUDGEMENT] [--note TEXT]",
		API:   []string{"finding.triage"},
		Run:   runTriage,
	})
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
		Name: "states", Group: "inspection",
		Short: "Show the protocol state machine a stateful campaign has explored",
		Usage: "states NAME [--transitions]",
		API:   []string{"metrics.states"},
		Run:   runStates,
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

// runStates renders the protocol state machine.
//
// With the exemplars, because a state label is a hash of a normalised response
// and a hash explains nothing. Seeing what the target actually said beside the
// label it produced is how somebody decides whether the clustering is right —
// which is the difference between a campaign reporting four hundred states and
// a person being able to do anything about it (ADR-0006).
func runStates(ctx context.Context, args []string) error {
	fs, opts := flags(commands["states"])
	showMoves := fs.Bool("transitions", false, "list every transition as well as every state")
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

	var rep struct {
		Fn     string `json:"fn"`
		States []struct {
			Label    string `json:"label"`
			Count    int    `json:"count"`
			Exemplar string `json:"exemplar"`
			Variants int    `json:"variants"`
		} `json:"states"`
		Transitions []struct {
			From  string `json:"from"`
			To    string `json:"to"`
			Count int    `json:"count"`
		} `json:"transitions"`
		Illegal []struct {
			From  string `json:"from"`
			To    string `json:"to"`
			Count int    `json:"count"`
		} `json:"illegal"`
	}
	if err := c.Do(ctx, "GET", "/v1/campaigns/"+target+"/states", nil, &rep); err != nil {
		return err
	}
	if opts.jsonOut {
		return printJSON(rep)
	}

	if len(rep.States) == 0 {
		fmt.Println("no protocol states recorded; this is not a stateful campaign, " +
			"or it has not run long enough to see a reply")
		return nil
	}

	fmt.Printf("state function  %s\n", rep.Fn)
	fmt.Printf("states          %d\n", len(rep.States))
	fmt.Printf("transitions     %d\n\n", len(rep.Transitions))

	fmt.Printf("%-14s %9s  %s\n", "STATE", "VISITS", "WHAT THE TARGET SAID")
	for _, st := range rep.States {
		fmt.Printf("%-14s %9d  %s", st.Label, st.Count, st.Exemplar)
		if st.Variants > 1 {
			// Said here rather than left to be discovered, because a label
			// covering several responses is why aiming at it may not take a
			// campaign anywhere new.
			fmt.Printf("  (+%d more)", st.Variants-1)
		}
		fmt.Println()
	}

	if *showMoves {
		fmt.Printf("\n%-30s %9s\n", "TRANSITION", "COUNT")
		for _, t := range rep.Transitions {
			fmt.Printf("%-30s %9d\n", t.From+" -> "+t.To, t.Count)
		}
	}
	if len(rep.Illegal) > 0 {
		// Its own section: the target accepted a move its own declared protocol
		// forbids, which is a result rather than a statistic.
		fmt.Printf("\noutside the declared model\n")
		for _, t := range rep.Illegal {
			fmt.Printf("  %-28s %9d\n", t.From+" -> "+t.To, t.Count)
		}
	}
	return nil
}

// runTriage records a judgement and a note against a finding.
//
// The machine's verdict — does it reproduce, how small does it get — is written
// by triage and is not settable here. What this writes is the other half: what
// a person decided about it, which nothing else can supply and which a re-run
// must not erase.
func runTriage(ctx context.Context, args []string) error {
	fs, opts := flags(commands["triage"])
	as := fs.String("as", "", "judgement: confirmed, duplicate, wontfix, invalid, or pending to clear it")
	note := fs.String("note", "", "note to record with it")
	if err := parse(fs, args); err != nil {
		return err
	}
	if fs.NArg() != 2 {
		return errors.New("expected a campaign name and a finding id")
	}
	disposition := *as
	if disposition == "pending" {
		disposition = ""
	}

	c, err := opts.connect(ctx)
	if err != nil {
		return err
	}
	var f struct {
		ID          int64  `json:"id"`
		Summary     string `json:"summary"`
		Disposition string `json:"disposition"`
		Notes       string `json:"notes"`
	}
	err = c.Do(ctx, "POST",
		"/v1/campaigns/"+fs.Arg(0)+"/findings/"+fs.Arg(1)+"/triage",
		map[string]any{"disposition": disposition, "notes": *note}, &f)
	if err != nil {
		return err
	}
	if opts.jsonOut {
		return printJSON(f)
	}
	state := f.Disposition
	if state == "" {
		state = "pending"
	}
	fmt.Printf("finding %d: %s — %s\n", f.ID, state, f.Summary)
	if f.Notes != "" {
		fmt.Printf("  %s\n", f.Notes)
	}
	return nil
}
