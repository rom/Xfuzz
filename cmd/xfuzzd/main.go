// Command xfuzzd is the Xfuzz daemon.
//
// It owns campaign lifecycle, worker supervision, the store, the safety layer,
// and the event bus. The CLI and the web console are both clients of its API and
// have no privileged path (ADR-0003).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"time"

	"github.com/rom/Xfuzz/internal/api"
	"github.com/rom/Xfuzz/internal/daemon"
	"github.com/rom/Xfuzz/internal/platform"
	"github.com/rom/Xfuzz/internal/version"
)

const name = "xfuzzd"

func main() {
	var (
		dataDir     = flag.String("data", "", "data directory (default: the user's config directory)")
		socket      = flag.String("socket", "", "Unix socket to listen on (default: within the data directory)")
		addr        = flag.String("addr", "", "TCP address to listen on instead; requires --token")
		token       = flag.String("token", "", "bearer token required on every request")
		workerBin   = flag.String("worker", "", "xfuzz-worker binary (default: beside this one, then PATH)")
		maxCampaign = flag.Int("max-campaigns", 0, "how many campaigns may run at once")
		showVersion = flag.Bool("version", false, "print version and exit")
	)
	flag.Usage = usage
	flag.Parse()

	if *showVersion {
		fmt.Printf("%s %s\n", name, version.Get())
		return
	}

	d, err := daemon.New(daemon.Options{
		DataDir:      *dataDir,
		WorkerBinary: *workerBin,
		MaxCampaigns: *maxCampaign,
	})
	if err != nil {
		fail("%v", err)
	}

	listener := api.Listener{Socket: *socket, Addr: *addr, Token: *token}
	if listener.Socket == "" && listener.Addr == "" {
		listener.Socket = api.DefaultSocket(d.DataDir())
	}

	ctx, stop := signal.NotifyContext(context.Background(), platform.TerminationSignals()...)
	defer stop()

	srv := api.NewServer(d)
	where := listener.Socket
	if listener.Addr != "" {
		where = listener.Addr
	}
	fmt.Fprintf(os.Stderr, "%s %s listening on %s (data %s)\n",
		name, version.Get().Version, where, d.DataDir())
	// Said here rather than left to be worked out: the console is the one
	// client that cannot reach a Unix socket, and the token is the one thing
	// it will ask for.
	if listener.Addr != "" && api.ConsoleBuilt() {
		fmt.Fprintf(os.Stderr, "%s console at %s (it asks for the token once per browser session)\n",
			name, consoleURL(listener.Addr))
	}

	err = api.Serve(ctx, srv, listener)

	// Shutdown runs on a context of its own: the one that was cancelled is why
	// we are shutting down, and using it would cancel the campaign stops and
	// the final checkpoints that shutdown exists to perform.
	shutdown, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if cerr := d.Close(shutdown); cerr != nil && err == nil {
		err = cerr
	}

	switch {
	case errors.Is(err, api.ErrAlreadyRunning):
		fail("%v", err)
	case errors.Is(err, api.ErrTCPNeedsToken):
		fail("%v", err)
	case err != nil:
		fail("%v", err)
	}
	fmt.Fprintf(os.Stderr, "%s: stopped\n", name)
}

func usage() {
	fmt.Fprintf(flag.CommandLine.Output(), `%s is the Xfuzz daemon.

usage: %s [flags]

It listens on a Unix socket by default, where filesystem permissions are the
access control. Serving over TCP requires a token: a campaign file names a
binary to execute, so an unauthenticated daemon on a network address is a remote
code execution service.

xfuzz starts a private daemon automatically when none is running, so this
command is for running one deliberately — as a service, or with a listener of
your own choosing.

flags:
`, name, name)
	flag.PrintDefaults()
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, name+": "+format+"\n", args...)
	os.Exit(1)
}
