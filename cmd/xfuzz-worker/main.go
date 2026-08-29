// Command xfuzz-worker runs one worker of a campaign.
//
// It is started by the daemon, not by hand, and speaks the daemon's protocol
// over the descriptors it is given. Run without them it fuzzes standalone and
// prints to stderr, which is what a developer checking a campaign file wants
// before involving a daemon at all.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strconv"

	"github.com/rom/Xfuzz/internal/daemon"
	"github.com/rom/Xfuzz/internal/platform"
	"github.com/rom/Xfuzz/internal/version"
	"github.com/rom/Xfuzz/internal/worker"
	"github.com/rom/Xfuzz/pkg/campaign"
)

const name = "xfuzz-worker"

func main() {
	var (
		campaignPath = flag.String("campaign", "", "campaign file to run")
		workerID     = flag.Int("worker", -1, "worker index (default: $"+daemon.EnvWorkerID+")")
		storeDir     = flag.String("store", "", "store directory (default: the campaign's)")
		showVersion  = flag.Bool("version", false, "print version and exit")
		profiles     profileList
	)
	flag.Var(&profiles, "profile", "campaign profile to apply (repeatable)")
	flag.Usage = usage
	flag.Parse()

	if *showVersion {
		fmt.Printf("%s %s\n", name, version.Get())
		return
	}
	if *campaignPath == "" {
		fmt.Fprintln(os.Stderr, name+": --campaign is required")
		flag.Usage()
		os.Exit(2)
	}

	cfg, err := campaign.Load(*campaignPath, profiles...)
	if err != nil {
		fail("%v", err)
	}

	id := *workerID
	if id < 0 {
		id = envInt(daemon.EnvWorkerID, 0)
	}

	opts := worker.Options{
		Config:   cfg,
		ID:       id,
		Seed:     uint64(envInt(daemon.EnvCampaignSeed, 0)),
		Strategy: os.Getenv(daemon.EnvStrategy),
		StoreDir: *storeDir,
	}

	// The daemon passes the protocol on descriptors it opened before exec.
	// Absent, the worker runs standalone.
	if ctl := os.Getenv(daemon.EnvControlFD); ctl != "" {
		control := os.NewFile(uintptr(envInt(daemon.EnvControlFD, daemon.WorkerControlFD)), "control")
		status := os.NewFile(uintptr(envInt(daemon.EnvStatusFD, daemon.WorkerStatusFD)), "status")
		if control == nil || status == nil {
			fail("the daemon named descriptors %s and %s but they are not open",
				os.Getenv(daemon.EnvControlFD), os.Getenv(daemon.EnvStatusFD))
		}
		opts.Control, opts.Status = control, status
	}

	ctx, stop := signal.NotifyContext(context.Background(), platform.TerminationSignals()...)
	defer stop()

	w := worker.New(opts)
	defer w.Close()

	if err := w.Run(ctx); err != nil {
		fail("%v", err)
	}
}

func usage() {
	fmt.Fprintf(flag.CommandLine.Output(), `%s runs one worker of a campaign.

usage: %s --campaign FILE [--worker N] [--profile NAME]...

It is normally started by xfuzzd, which passes the protocol on descriptors and
sets %s, %s and %s. Run by hand it fuzzes standalone and reports to stderr.

flags:
`, name, name, daemon.EnvWorkerID, daemon.EnvCampaignSeed, daemon.EnvStrategy)
	flag.PrintDefaults()
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, name+": "+format+"\n", args...)
	os.Exit(1)
}

func envInt(key string, def int) int {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	n, err := strconv.ParseUint(v, 10, 64)
	if err != nil {
		return def
	}
	return int(n)
}

// profileList collects a repeatable flag.
type profileList []string

func (p *profileList) String() string     { return fmt.Sprint(*p) }
func (p *profileList) Set(v string) error { *p = append(*p, v); return nil }
