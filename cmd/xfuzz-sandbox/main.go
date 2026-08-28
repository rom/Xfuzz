// Command xfuzz-sandbox applies confinement to itself and then becomes the
// target.
//
// It exists because two of the mechanisms ADR-0012 requires — resource limits
// and a seccomp filter — can only be installed by the process that will run the
// target, between fork and exec. Go gives no hook there: os/exec forks and execs
// in one step, and running arbitrary Go between the two is not safe in a
// process with a garbage collector and threads.
//
// So the confinement is applied by a process that is *already* the child. This
// helper sets its own limits, installs its own filter, and then execs the
// target, which inherits both. It is the same shape as every other sandbox
// launcher — bwrap, runc's init, AFL's own forkserver child — for the same
// reason.
//
// It is deliberately small and does nothing that could fail silently. Every
// mechanism it is asked for either applies or the helper exits non-zero before
// the target runs, because a sandbox that quietly did not happen is worse than
// no sandbox: the campaign would report itself as confined.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"syscall"

	"github.com/rom/Xfuzz/internal/platform"
)

func main() {
	var (
		chdir    = flag.String("chdir", "", "working directory for the target")
		fsize    = flag.Uint64("limit-fsize", 0, "maximum file size in bytes (0: unlimited)")
		cpu      = flag.Uint64("limit-cpu", 0, "maximum CPU seconds (0: unlimited)")
		nproc    = flag.Uint64("limit-nproc", 0, "maximum processes for the user (0: unlimited)")
		nofile   = flag.Uint64("limit-nofile", 0, "maximum open descriptors (0: unlimited)")
		noCore   = flag.Bool("no-core", true, "suppress core dumps")
		seccomp  = flag.Bool("seccomp", true, "install the syscall denylist")
		roRoot   = flag.Bool("ro-root", false, "make the filesystem read-only except for -rw paths")
		uid      = flag.Int("uid", 0, "become this user before executing the target (0: keep the current one)")
		gid      = flag.Int("gid", 0, "become this group before executing the target (0: keep the current one)")
		showCaps = flag.Bool("capabilities", false, "print what this host can enforce and exit")
		rw       pathList
	)
	flag.Var(&rw, "rw", "a path that stays writable under -ro-root (repeatable)")
	flag.Usage = usage
	flag.Parse()

	if *showCaps {
		caps := platform.DetectSandbox()
		fmt.Println(caps)
		for _, n := range caps.Notes {
			fmt.Println("note:", n)
		}
		return
	}

	argv := flag.Args()
	if len(argv) == 0 {
		usage()
		os.Exit(2)
	}

	// The filesystem first, because it is the only step that needs the mount
	// syscall — which the seccomp filter installed further down denies.
	if *roRoot {
		if err := platform.ConfineFilesystem(rw); err != nil {
			fail("%v", err)
		}
	}

	if *chdir != "" {
		if err := os.Chdir(*chdir); err != nil {
			fail("entering the working directory: %v", err)
		}
	}

	// The identity drop comes after the mounts, which need privilege, and
	// before everything else, so that nothing below runs with more authority
	// than the target will have.
	if *uid > 0 {
		g := *gid
		if g <= 0 {
			g = *uid
		}
		if err := platform.DropPrivileges(*uid, g); err != nil {
			fail("%v", err)
		}
	}

	// Limits before the filter: setrlimit is not on the denylist, but ordering
	// the irreversible step last means a failure to apply a limit is reported
	// while the process can still report anything.
	//
	// RLIMIT_AS is deliberately absent. This helper is a Go program and the Go
	// runtime reserves on the order of a gigabyte of address space before main
	// runs, so any address-space limit small enough to be useful would kill the
	// helper rather than the target. Memory is capped by the cgroup instead,
	// which is both stronger and measured against real pages.
	if err := platform.ApplyLimits(platform.Limits{
		FileSizeBytes: *fsize,
		CPUSeconds:    *cpu,
		Processes:     *nproc,
		OpenFiles:     *nofile,
		DisableCore:   *noCore,
	}); err != nil {
		fail("%v", err)
	}

	if *seccomp {
		prog, err := platform.BuildSeccompFilter(platform.DefaultSeccompNumbers(), platform.SeccompDenyErrno)
		switch {
		case errors.Is(err, platform.ErrSeccompUnsupported):
			fail("seccomp was requested but is unavailable on this platform: %v", err)
		case err != nil:
			fail("building the seccomp filter: %v", err)
		}
		if err := platform.ApplySeccomp(prog); err != nil {
			fail("installing the seccomp filter: %v", err)
		}
	} else if err := platform.SetNoNewPrivs(); err != nil {
		// Even without a filter, a target that cannot gain privileges through
		// exec is a target that cannot escape through a setuid binary.
		fail("%v", err)
	}

	path := argv[0]
	if err := syscall.Exec(path, argv, os.Environ()); err != nil {
		fail("executing %s: %v", path, err)
	}
}

// pathList collects a repeatable path flag.
type pathList []string

func (p *pathList) String() string     { return strings.Join(*p, ",") }
func (p *pathList) Set(v string) error { *p = append(*p, v); return nil }

func usage() {
	fmt.Fprintf(os.Stderr, `xfuzz-sandbox applies confinement and then becomes the target.

usage: xfuzz-sandbox [flags] -- program [args...]

It is invoked by Xfuzz, not by hand. The namespaces and the cgroup are applied
by the parent at clone time; what this helper adds is what can only be set from
inside the child: resource limits, no_new_privs, and the seccomp denylist.

flags:
`)
	flag.PrintDefaults()
}

func fail(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	if !strings.HasSuffix(msg, "\n") {
		msg += "\n"
	}
	fmt.Fprint(os.Stderr, "xfuzz-sandbox: "+msg)
	os.Exit(ExitSandboxFailed)
}

// ExitSandboxFailed is what the helper exits with when confinement could not be
// applied.
//
// It is distinct so the spawner can tell "the sandbox refused" from "the target
// crashed", which are different things and must never be confused: reporting a
// sandbox failure as a finding would fill a campaign with bugs that are not in
// the target.
const ExitSandboxFailed = 125
