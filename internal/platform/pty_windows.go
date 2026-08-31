//go:build windows

package platform

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The Windows pseudo-terminal, which is a pseudo-console.
//
// It is the same idea as a Unix pair reached by a different route, and the
// route is why this file is long. There is no single device to open and no
// descriptor to hand the child: the console is created around two pipes, and it
// reaches the child as a process attribute in an extended startup structure.
// os/exec cannot carry one — SysProcAttr has no field for an attribute list —
// so this is the one place in Xfuzz that calls CreateProcess itself.
//
// That does not put the target outside the sandbox. The command it starts is
// the *exec.Cmd internal/safety prepared: the path, the argument vector, the
// working directory, the environment and the creation flags are read off it
// rather than rebuilt, so every decision the safety layer made still applies.
// What is missing on this platform is missing from the sandbox itself and is
// reported by DetectSandbox, not quietly skipped here.
//
// ConPTY needs Windows 10 1809 or later. On anything older CreatePseudoConsole
// is not exported by kernel32 and the call fails, which PTYSupported reports as
// no terminal rather than as a broken target.

// PTYSupported reports whether this host can allocate a pseudo-console.
//
// Probed by creating one, for the same reason the Unix side opens a pair: the
// build says nothing about whether this Windows can do it, and discovering it
// after a campaign has started means having told the operator it was fuzzing a
// terminal program when it was not.
func PTYSupported() bool {
	t, err := OpenTTY(DefaultPTYCols, DefaultPTYRows)
	if err != nil {
		return false
	}
	t.Close()
	return true
}

// TTY is a pseudo-console and the two pipes that reach it.
//
// The pipes are not symmetric with a Unix master: a console reads one handle
// and writes another, so what the fuzzer holds is the write end of the one it
// reads and the read end of the one it writes.
type TTY struct {
	hpc windows.Handle
	in  *os.File // the fuzzer writes here: typing
	out *os.File // the fuzzer reads here: what the target drew

	mu      sync.Mutex
	started bool
	closed  bool
}

// OpenTTY allocates a pseudo-console of the given size.
func OpenTTY(cols, rows int) (*TTY, error) {
	cols, rows = clampTTYSize(cols, rows)

	var inRead, inWrite windows.Handle
	if err := windows.CreatePipe(&inRead, &inWrite, nil, 0); err != nil {
		return nil, fmt.Errorf("platform: creating the console input pipe: %w", err)
	}
	var outRead, outWrite windows.Handle
	if err := windows.CreatePipe(&outRead, &outWrite, nil, 0); err != nil {
		windows.CloseHandle(inRead)
		windows.CloseHandle(inWrite)
		return nil, fmt.Errorf("platform: creating the console output pipe: %w", err)
	}

	var hpc windows.Handle
	err := windows.CreatePseudoConsole(
		windows.Coord{X: int16(cols), Y: int16(rows)}, inRead, outWrite, 0, &hpc)

	// The console duplicates the two handles it was given, so these copies go
	// now whether it succeeded or not. The write end of the output pipe matters
	// most: held open here, a read would never report end-of-file, so a drain
	// loop would wait for ever after the target exited. It is the same mistake
	// as holding the Unix slave open, with the same symptom.
	windows.CloseHandle(inRead)
	windows.CloseHandle(outWrite)

	if err != nil {
		windows.CloseHandle(inWrite)
		windows.CloseHandle(outRead)
		return nil, fmt.Errorf("platform: creating a pseudo-console: %w (ConPTY needs "+
			"Windows 10 1809 or later)", err)
	}
	return &TTY{
		hpc: hpc,
		in:  os.NewFile(uintptr(inWrite), "conpty-in"),
		out: os.NewFile(uintptr(outRead), "conpty-out"),
	}, nil
}

// Start runs a prepared command on the pseudo-console.
func (t *TTY) Start(cmd *exec.Cmd) (TTYProcess, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.started {
		return nil, errors.New("platform: the console has already started a target")
	}
	if len(cmd.ExtraFiles) > 0 {
		// os/exec refuses these on Windows too. Saying so here rather than
		// silently dropping them keeps a fork-server-style target from starting
		// with its control descriptors missing and hanging on the handshake.
		return nil, errors.New("platform: extra descriptors cannot be passed to a " +
			"target on a pseudo-console")
	}

	appName, err := windows.UTF16PtrFromString(cmd.Path)
	if err != nil {
		return nil, fmt.Errorf("platform: %s is not a usable program path: %w", cmd.Path, err)
	}
	argv := cmd.Args
	if len(argv) == 0 {
		argv = []string{cmd.Path}
	}
	cmdLine := windows.ComposeCommandLine(argv)
	if cmd.SysProcAttr != nil && cmd.SysProcAttr.CmdLine != "" {
		// The safety layer may have written the command line itself, for a
		// target whose arguments do not survive Windows quoting.
		cmdLine = cmd.SysProcAttr.CmdLine
	}
	cmdLine16, err := windows.UTF16PtrFromString(cmdLine)
	if err != nil {
		return nil, fmt.Errorf("platform: the command line is not usable: %w", err)
	}

	var dir16 *uint16
	if cmd.Dir != "" {
		if dir16, err = windows.UTF16PtrFromString(cmd.Dir); err != nil {
			return nil, fmt.Errorf("platform: %s is not a usable directory: %w", cmd.Dir, err)
		}
	}
	env, err := envBlock(cmd.Env)
	if err != nil {
		return nil, err
	}

	attrs, err := windows.NewProcThreadAttributeList(1)
	if err != nil {
		return nil, fmt.Errorf("platform: allocating the process attribute list: %w", err)
	}
	defer attrs.Delete()
	if err := attrs.Update(windows.PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE,
		handleAsValue(t.hpc), unsafe.Sizeof(t.hpc)); err != nil {
		return nil, fmt.Errorf("platform: attaching the pseudo-console to the target: %w", err)
	}

	si := &windows.StartupInfoEx{
		StartupInfo:             windows.StartupInfo{Cb: uint32(unsafe.Sizeof(windows.StartupInfoEx{}))},
		ProcThreadAttributeList: attrs.List(),
	}
	flags := uint32(windows.EXTENDED_STARTUPINFO_PRESENT | windows.CREATE_UNICODE_ENVIRONMENT)
	if cmd.SysProcAttr != nil {
		flags |= cmd.SysProcAttr.CreationFlags
	}

	pi := new(windows.ProcessInformation)
	// Handles are not inherited: the console is the only thing the target needs
	// from this process and it arrives through the attribute list. Inheriting
	// would hand the target the fuzzer's own descriptors, which is the opposite
	// of what a sandbox is for.
	if err := windows.CreateProcess(appName, cmdLine16, nil, nil, false,
		flags, env, dir16, &si.StartupInfo, pi); err != nil {
		return nil, fmt.Errorf("platform: starting %s on a pseudo-console: %w", cmd.Path, err)
	}
	windows.CloseHandle(pi.Thread)
	t.started = true
	return &conptyProcess{pid: int(pi.ProcessId), h: pi.Process}, nil
}

// Read returns whatever the target has drawn.
func (t *TTY) Read(b []byte) (int, error) { return t.out.Read(b) }

// Write types into the target.
func (t *TTY) Write(b []byte) (int, error) { return t.in.Write(b) }

// Resize changes the console's window size.
//
// Unlike the Unix ioctl this sends no signal, because Windows has none to send:
// a program learns its new size from a console event or by asking. A program
// that only redraws on SIGWINCH therefore does not redraw here, which is a real
// difference between the platforms and not something this layer can paper over.
func (t *TTY) Resize(cols, rows int) error {
	cols, rows = clampTTYSize(cols, rows)
	if err := windows.ResizePseudoConsole(t.hpc,
		windows.Coord{X: int16(cols), Y: int16(rows)}); err != nil {
		return fmt.Errorf("platform: resizing the console to %dx%d: %w", cols, rows, err)
	}
	return nil
}

// Close releases the console and its pipes.
//
// The console first: closing it is what unblocks a read on the output pipe,
// which is where a drain goroutine is sitting. Closing the pipe under that
// goroutine instead would be a close during a blocking read, which Windows does
// not interrupt.
func (t *TTY) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return nil
	}
	t.closed = true
	windows.ClosePseudoConsole(t.hpc)
	err := t.out.Close()
	if cerr := t.in.Close(); cerr != nil && err == nil {
		err = cerr
	}
	return err
}

// conptyProcess is a target started with CreateProcess.
type conptyProcess struct {
	pid int
	h   windows.Handle

	once sync.Once
	exit TTYExit
	err  error
}

func (p *conptyProcess) Pid() int { return p.pid }

func (p *conptyProcess) Wait() (TTYExit, error) {
	p.once.Do(func() {
		ev, err := windows.WaitForSingleObject(p.h, windows.INFINITE)
		if err != nil {
			p.err = fmt.Errorf("platform: waiting for target %d: %w", p.pid, err)
			return
		}
		if ev != windows.WAIT_OBJECT_0 {
			p.err = fmt.Errorf("platform: waiting for target %d returned %#x", p.pid, ev)
			return
		}
		var code uint32
		if err := windows.GetExitCodeProcess(p.h, &code); err != nil {
			p.err = fmt.Errorf("platform: reading the exit code of target %d: %w", p.pid, err)
			return
		}
		windows.CloseHandle(p.h)
		p.h = 0
		// Widened rather than sign-extended, so the code reads the same
		// way it does from os.ProcessState on this platform: 3221225477
		// rather than -1073741819 for an access violation.
		p.exit = TTYExit{ExitCode: int(code), Signal: ExceptionSignal(code)}
	})
	return p.exit, p.err
}

// envBlock turns an environment into the block CreateProcess wants.
//
// A nil slice returns nil, which means the child inherits this process's
// environment — the same meaning exec.Cmd gives a nil Env, so a spec that did
// not set one behaves identically whether it went through os/exec or through
// here.
func envBlock(env []string) (*uint16, error) {
	if env == nil {
		return nil, nil
	}
	var b strings.Builder
	for _, e := range env {
		if strings.IndexByte(e, 0) >= 0 {
			return nil, fmt.Errorf("platform: an environment entry contains a NUL byte")
		}
		if e == "" {
			// An empty entry would terminate the block early and silently drop
			// every variable after it.
			continue
		}
		b.WriteString(e)
		b.WriteByte(0)
	}
	// The block ends with an empty entry, so a block with no variables is two
	// NULs rather than none.
	b.WriteByte(0)
	// Encoded by hand: the standard helpers reject a string with interior NUL
	// bytes, and interior NUL bytes are what an environment block is made of.
	u := utf16Block(b.String())
	return &u[0], nil
}

// utf16Block encodes a NUL-separated environment block, which the standard
// helpers refuse because they treat the first NUL as the end of the string.
func utf16Block(s string) []uint16 {
	u := utf16.Encode([]rune(s))
	if len(u) == 0 || u[len(u)-1] != 0 {
		u = append(u, 0)
	}
	return u
}

// handleAsValue passes a console handle where an attribute value is expected.
//
// UpdateProcThreadAttribute takes the value of a pseudo-console attribute *by
// value* — the documentation and every sample pass the HPCON itself, not a
// pointer to it — while the Go binding types that parameter as unsafe.Pointer,
// because most other attributes are pointers. Converting the handle directly
// would be a uintptr-to-pointer conversion, which is the pattern that hides
// real lifetime bugs and which vet is right to reject.
//
// Reinterpreting the bits through a pointer-to-pointer conversion says what is
// actually happening: a pointer-sized value is being placed in a pointer-sized
// field. It is the same technique x/sys/windows uses to pass a COORD where the
// system call wants a DWORD.
func handleAsValue(h windows.Handle) unsafe.Pointer {
	return *(*unsafe.Pointer)(unsafe.Pointer(&h))
}
