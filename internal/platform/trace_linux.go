//go:build linux

package platform

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// TraceSupported reports whether this host can trace a target by breakpoint.
//
// Three things can stop it. Yama's ptrace scope, when set above one, restricts
// tracing to processes with an explicit permission grant even for a parent —
// value 2 needs CAP_SYS_PTRACE and value 3 disables ptrace outright. A container
// can also drop CAP_SYS_PTRACE from its bounding set, and then the attach fails
// with EPERM at run time rather than here.
//
// Probing rather than trying and reporting: a campaign that discovers this after
// starting has already told the operator it was fuzzing.
func TraceSupported() bool {
	if !traceArchSupported {
		// The third thing, and the one that is not about permission: this
		// architecture has no breakpoint implementation, and could not use one
		// if it had, because the blocks come from an x86-64 decoder.
		return false
	}
	b, err := os.ReadFile("/proc/sys/kernel/yama/ptrace_scope")
	if err != nil {
		// No Yama at all, which is the common case outside Ubuntu and its
		// derivatives.
		return true
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil {
		return true
	}
	// 0 and 1 both permit tracing a direct child, which is the only relationship
	// this backend uses.
	return n <= 1
}

// EnableTrace marks a command to be stopped at its first exec under ptrace.
//
// The child calls PTRACE_TRACEME between fork and exec, so the tracer is the
// thread that started it. Everything that follows must therefore happen on that
// same thread, which is why the caller locks it.
func EnableTrace(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Ptrace = true
	// A traced process must not also be put in its own process group by the
	// generic configuration: the tracer waits on the pid directly, and a killed
	// group would reap it out from under the wait.
	cmd.SysProcAttr.Setpgid = false
}

// TraceRun drives a tracee that is already stopped at its first exec, and
// returns the blocks it entered.
//
// It must run on the same locked OS thread that started the process. Every
// ptrace request is addressed to the tracer *thread*, not the tracer process,
// and Go will otherwise move the goroutine to whichever thread is free and every
// request will fail with ESRCH.
func TraceRun(pid int, opt TraceOptions) (TraceOutcome, error) {
	var out TraceOutcome

	// Wait for the stop the child raises when its exec completes.
	//
	// Starting a process with PTRACE_TRACEME does not wait for it: the fork
	// returns as soon as the child exists, and the child reaches its trap some
	// microseconds later. Every ptrace request before that trap fails with
	// ESRCH, because there is no *stopped* tracee to address yet — and the
	// failure is timing-dependent, so it looks like a flake rather than a
	// missing wait. Found exactly that way: the first execution of a target
	// worked and the third did not.
	var first syscall.WaitStatus
	for {
		if _, err := syscall.Wait4(pid, &first, 0, nil); err != nil {
			if errors.Is(err, syscall.EINTR) {
				continue
			}
			return out, fmt.Errorf("platform: waiting for %d to stop at exec: %w", pid, err)
		}
		break
	}
	if first.Exited() {
		out.ExitCode = first.ExitStatus()
		return out, nil
	}
	if first.Signaled() {
		out.Signal = int(first.Signal())
		return out, nil
	}

	// Ask for exec events by name and for the kernel to kill the tracee if this
	// process dies: a fuzzer that crashes must not leave a stopped, un-reaped
	// target behind holding the workdir open.
	if err := unix.PtraceSetOptions(pid, unix.PTRACE_O_TRACEEXEC|unix.PTRACE_O_EXITKILL); err != nil {
		return out, fmt.Errorf("platform: setting trace options on %d: %w", pid, err)
	}

	var killed atomic.Bool
	if opt.Timeout > 0 {
		t := time.AfterFunc(opt.Timeout, func() {
			killed.Store(true)
			_ = syscall.Kill(pid, syscall.SIGKILL)
		})
		defer t.Stop()
	}

	exe, err := filepath.EvalSymlinks(opt.Exe)
	if err != nil {
		exe = opt.Exe
	}

	planted := make(map[uintptr]byte, len(opt.Blocks))
	var base uint64
	armed := false

	// arm plants the breakpoints once the tracee has become the program whose
	// blocks were analysed.
	arm := func() {
		if armed {
			return
		}
		cur, err := filepath.EvalSymlinks(fmt.Sprintf("/proc/%d/exe", pid))
		if err != nil || cur != exe {
			return
		}
		armed = true
		if opt.PIE {
			b, ok := loadBase(pid, cur)
			out.Base = b
			if !ok {
				// Without the base, every address would be planted somewhere
				// arbitrary. Planting nothing is the safe failure: the execution
				// still runs and simply reports no coverage.
				return
			}
			base = b
		}
		for _, blk := range opt.Blocks {
			addr := uintptr(base + blk)
			var orig [1]byte
			if _, err := syscall.PtracePeekText(pid, addr, orig[:]); err != nil {
				continue
			}
			if orig[0] == traceTrap {
				// Already a trap in the original program — a debugger check or a
				// deliberate abort. Leaving it alone keeps the program's own
				// behaviour; claiming it as a breakpoint would report a hit that
				// this backend did not cause and would restore the wrong byte.
				continue
			}
			if _, err := syscall.PtracePokeText(pid, addr, []byte{traceTrap}); err != nil {
				continue
			}
			planted[addr] = orig[0]
		}
		out.Planted = len(planted)
	}

	arm() // in case the traced program is already the target

	sig := 0
	for {
		if err := syscall.PtraceCont(pid, sig); err != nil {
			if errors.Is(err, syscall.ESRCH) {
				break
			}
			return out, fmt.Errorf("platform: continuing %d: %w", pid, err)
		}
		sig = 0

		var ws syscall.WaitStatus
		if _, err := syscall.Wait4(pid, &ws, 0, nil); err != nil {
			if errors.Is(err, syscall.EINTR) {
				continue
			}
			return out, fmt.Errorf("platform: waiting on %d: %w", pid, err)
		}

		switch {
		case ws.Exited():
			out.ExitCode = ws.ExitStatus()
			return finish(&out, &killed), nil

		case ws.Signaled():
			out.Signal = int(ws.Signal())
			return finish(&out, &killed), nil

		case ws.Stopped():
			st := ws.StopSignal()
			if st != syscall.SIGTRAP {
				// Something the program itself received: a fault, a timer, a
				// signal it installed a handler for. Pass it through so the
				// program behaves as it would untraced, and so a segmentation
				// fault produces a real crash status rather than a stopped
				// process the fuzzer has to interpret.
				sig = int(st)
				continue
			}
			// A SIGTRAP is either an exec event, one of these breakpoints, or
			// the program's own trap instruction.
			if ws.TrapCause() == unix.PTRACE_EVENT_EXEC {
				arm()
				continue
			}
			if hit(pid, base, planted, &out) {
				continue
			}
			// Not a breakpoint this backend planted: the program trapped on its
			// own. Deliver it, which for the default disposition ends the
			// process and reports it as the crash it is.
			sig = int(syscall.SIGTRAP)
		}
	}
	return finish(&out, &killed), nil
}

// finish converts a watchdog kill into a timeout rather than a crash. A target
// killed for running too long has not found a bug, and recording it as SIGKILL
// would put every slow input in the findings.
func finish(out *TraceOutcome, killed *atomic.Bool) TraceOutcome {
	if killed.Load() {
		out.TimedOut = true
		out.Signal = 0
	}
	return *out
}

// hit handles a stop that may be one of the planted breakpoints, and reports
// whether it was.
//
// The trap instruction has already executed, so the instruction pointer sits one
// byte past it. Restoring the original byte and rewinding by one is what lets
// the program continue as though the breakpoint had never been there; removing
// the entry is what makes it one-shot.
func hit(pid int, base uint64, planted map[uintptr]byte, out *TraceOutcome) bool {
	var regs syscall.PtraceRegs
	if err := syscall.PtraceGetRegs(pid, &regs); err != nil {
		return false
	}
	addr := trapAddr(&regs)
	orig, ok := planted[addr]
	if !ok {
		return false
	}
	if _, err := syscall.PtracePokeText(pid, addr, []byte{orig}); err != nil {
		return false
	}
	delete(planted, addr)
	rewindToTrap(&regs)
	if err := syscall.PtraceSetRegs(pid, &regs); err != nil {
		return false
	}
	// Recorded as a link-time address, which is the only form that means the
	// same thing twice. Address-space layout randomisation gives the image a
	// different base on every execution, so a runtime address is unique to one
	// run: a corpus keyed on them would find every input interesting exactly
	// once and would never reproduce (ASR-0008).
	out.Hits = append(out.Hits, uint64(addr)-base)
	return true
}

// loadBase finds where the kernel mapped a position-independent executable.
//
// The first mapping of the file is its base, and every link-time address in the
// image is that base plus itself. Reading it from the process rather than
// assuming a value is not optional: address-space layout randomisation picks a
// different one on every execution, which is the entire reason this cannot be
// computed ahead of time.
func loadBase(pid int, exe string) (uint64, bool) {
	f, err := os.Open(fmt.Sprintf("/proc/%d/maps", pid))
	if err != nil {
		return 0, false
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		i := strings.LastIndexByte(line, ' ')
		if i < 0 || i+1 >= len(line) {
			continue
		}
		if strings.TrimSpace(line[i+1:]) != exe {
			continue
		}
		dash := strings.IndexByte(line, '-')
		if dash < 0 {
			continue
		}
		v, err := strconv.ParseUint(line[:dash], 16, 64)
		if err != nil {
			continue
		}
		return v, true
	}
	return 0, false
}

// LockTracingThread pins the calling goroutine to its OS thread and returns the
// function that releases it.
//
// Exported because the lock has to span the spawn as well as the trace: the
// thread that forks the child is the one the kernel records as its tracer, and
// a goroutine that migrates between the two ends up issuing every ptrace request
// from a thread that is not permitted to.
func LockTracingThread() func() {
	runtime.LockOSThread()
	return runtime.UnlockOSThread
}
