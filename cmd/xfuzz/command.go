package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/rom/Xfuzz/internal/api"
	"github.com/rom/Xfuzz/internal/client"
	"github.com/rom/Xfuzz/internal/daemon"
)

// Command is one CLI verb.
//
// Commands are values, like API routes, and for the same reason: the parity
// test walks both lists and asserts neither side has a capability the other
// lacks (ASR-0005). A command declared only as a switch case could not be
// checked against anything.
type Command struct {
	Name  string
	Group string
	Short string
	Usage string

	// API names the routes this command calls. Empty means the command is
	// local — `init` writes a file, `version` prints a string — and the parity
	// test needs to know the difference between "local by design" and
	// "forgotten".
	API []string

	Run func(ctx context.Context, args []string) error
}

var commands = map[string]*Command{}

func register(c *Command) { commands[c.Name] = c }

// flags builds a flag set carrying the shared connection options.
func flags(c *Command) (*flag.FlagSet, *connOptions) {
	fs := flag.NewFlagSet(name+" "+c.Name, flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "%s\n\nusage: %s %s\n\nflags:\n", c.Short, name, c.Usage)
		fs.PrintDefaults()
	}

	opts := &connOptions{}
	fs.StringVar(&opts.socket, "socket", "", "daemon socket (default: within the data directory)")
	fs.StringVar(&opts.addr, "addr", "", "daemon TCP address instead of a socket")
	fs.StringVar(&opts.token, "token", "", "bearer token (default: $XFUZZ_TOKEN)")
	fs.BoolVar(&opts.jsonOut, "json", false, "print the raw JSON response")
	fs.BoolVar(&opts.noStart, "no-start", false, "fail rather than starting a private daemon")
	return fs, opts
}

type connOptions struct {
	socket  string
	addr    string
	token   string
	jsonOut bool
	noStart bool
}

// connect returns a client, starting a private daemon if none is running.
//
// The single-user case should need no service management: `xfuzz run` on a fresh
// machine has to work. It is not a bypass — the daemon is still the engine, and
// starting one is exactly that, done for the user (ADR-0003).
func (o *connOptions) connect(ctx context.Context) (*client.Client, error) {
	socket := o.socket
	if socket == "" && o.addr == "" {
		dir, err := daemon.DefaultDataDir()
		if err != nil {
			return nil, err
		}
		socket = api.DefaultSocket(dir)
	}
	token := o.token
	if token == "" {
		token = os.Getenv("XFUZZ_TOKEN")
	}

	opts := client.Options{Socket: socket, Addr: o.addr, Token: token, Timeout: 60 * time.Second}
	if o.noStart {
		c, err := client.New(opts)
		if err != nil {
			return nil, err
		}
		if err := c.Ping(ctx); err != nil {
			return nil, fmt.Errorf("no daemon is answering on %s", describe(socket, o.addr))
		}
		return c, nil
	}
	return client.AutoStart(ctx, opts)
}

func describe(socket, addr string) string {
	if addr != "" {
		return addr
	}
	return socket
}
