// Package testenv builds the fixtures that integration tests need.
//
// It exists because those fixtures are subtle enough to get wrong. A target
// runs under an unprivileged identity of its own, so the directory it is built
// in has to be one that identity can enter — which t.TempDir's is not. Three
// packages had grown their own version of that rule and they had already
// drifted apart, each fixing a different subset of the problem.
//
// Nothing outside a test imports this: every function here takes a testing.TB,
// which is the compiler's way of saying so.
package testenv

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// ReachableDir returns a temporary directory a confined target can enter.
//
// Not t.TempDir. That returns a subdirectory of a 0700 parent created for the
// test, and it is the parent that blocks the traversal, so making the returned
// directory world-executable fixes nothing. A campaign refuses to start on an
// unreachable target — deliberately, because the alternative is a campaign that
// reports two live workers and completes no executions — so a fixture that got
// this wrong would test the refusal rather than the campaign.
//
// The directory is removed when the test ends.
func ReachableDir(t testing.TB) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "xfuzz-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	// The system temporary directory is traversable on every platform Xfuzz
	// supports, but a host can be configured otherwise and the failure that
	// causes is confusing enough to be worth naming here instead.
	if fi, err := os.Stat(os.TempDir()); err == nil && fi.Mode().Perm()&0o001 == 0 {
		t.Skipf("%s is not traversable by other users, so no target built under it can run confined", os.TempDir())
	}
	return dir
}

// RepoRoot returns the directory holding go.mod.
func RepoRoot(t testing.TB) string {
	t.Helper()
	dir, err := filepath.Abs(".")
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("no go.mod above the test directory")
		}
		dir = parent
	}
}

// BuildTarget compiles testdata/targets/<name>.c with coverage instrumentation
// and returns the path to the executable.
//
// Skips rather than fails where clang is missing: an instrumented target cannot
// be built without it, and a test that cannot build its subject has not found a
// defect.
func BuildTarget(t testing.TB, name string) string {
	t.Helper()
	if _, err := exec.LookPath("clang"); err != nil {
		t.Skip("clang is not installed; instrumented targets cannot be built here")
	}
	out := filepath.Join(ReachableDir(t), name)
	cmd := exec.Command("go", "run", "./cmd/xfuzz-cc", "-O1", "-o", out,
		filepath.Join("testdata", "targets", name+".c"))
	cmd.Dir = RepoRoot(t)
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("building %s: %v\n%s", name, err, b)
	}
	if err := os.Chmod(out, 0o755); err != nil {
		t.Fatal(err)
	}
	return out
}

// BuildGoTarget compiles a Go planted-bug target with Xfuzz instrumentation.
//
// Through xfuzz-cc's Go mode rather than `go build`, because the claim under
// test is that the tool produces a target the fuzzer can read coverage from —
// and reproducing its flags here would be testing a copy of them.
func BuildGoTarget(t testing.TB, name string) string {
	t.Helper()
	if _, err := exec.LookPath("clang"); err != nil {
		if _, err := exec.LookPath("gcc"); err != nil {
			t.Skip("no C compiler; the runtime object cannot be built")
		}
	}
	dir := ReachableDir(t)
	cc := BuildBinary(t, dir, "xfuzz-cc")
	out := filepath.Join(dir, name)
	cmd := exec.Command(cc, "--go", "-o", out, "./testdata/targets/go/"+name)
	cmd.Dir = RepoRoot(t)
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("building the Go target %s: %v\n%s", name, err, b)
	}
	if err := os.Chmod(out, 0o755); err != nil {
		t.Fatal(err)
	}
	return out
}

// BuildAt compiles the package in src to out and returns out.
//
// For fixtures a test writes on the fly, which is how the fault-injection
// cases get a plugin that dies on purpose: the misbehaviour is the point, so
// it does not belong in examples/ where someone might copy it.
func BuildAt(t testing.TB, out, src string) string {
	t.Helper()
	out = exePath(out)
	cmd := exec.Command("go", "build", "-o", out, src)
	cmd.Dir = RepoRoot(t)
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("building %s: %v\n%s", src, err, b)
	}
	if err := os.Chmod(out, 0o755); err != nil {
		t.Fatal(err)
	}
	return out
}

// BuildPlugin compiles one of the example plugins into dir and returns its
// path.
//
// Built rather than faked, because the claim under test is that a *process*
// speaking the protocol works — spawned through the safety layer, confined,
// talking over its own standard input and output. A fake would test the
// framing, which the unit tests already do, and nothing that only a real
// process can get wrong.
func BuildPlugin(t testing.TB, dir, name string) string {
	t.Helper()
	out := filepath.Join(dir, ExeName(name))
	cmd := exec.Command("go", "build", "-o", out, "./examples/plugins/"+name)
	cmd.Dir = RepoRoot(t)
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("building the %s plugin: %v\n%s", name, err, b)
	}
	if err := os.Chmod(out, 0o755); err != nil {
		t.Fatal(err)
	}
	return out
}

// ExeName is command with whatever this platform puts on the end of an
// executable.
//
// Windows will not run a file without one. `go build -o xfuzz` writes exactly
// `xfuzz`, and exec then reports "executable file not found in %PATH%" for a
// file that is sitting right there — which is how every Windows e2e test in
// this project failed, from the first one written to the first CI run that
// could compile.
// exePath gives a built binary the extension its platform requires to run it.
//
// Windows decides what may be executed by exactly that, so a build written to a
// name without one produces a file that exists and cannot be started — and the
// error says only that it was not found, which reads as a build that never
// happened rather than as a name that cannot be run.
func exePath(out string) string {
	if runtime.GOOS == "windows" && filepath.Ext(out) == "" {
		return out + ".exe"
	}
	return out
}

// SkipPOSIXTarget skips a test whose fixture target is a POSIX program.
//
// Several fixtures here put a terminal into raw mode, resize on SIGWINCH, or
// name a syscall the way Unix does; they are written against x/sys/unix and do
// not build for Windows. Whether that particular program has been ported is a
// different question from the one the test asks — whether a driver drives, a
// sandbox holds, a spawner spawns — and a build error naming a missing constant
// answers neither.
func SkipPOSIXTarget(t testing.TB, what string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skipf("%s is a POSIX program and does not build for this platform", what)
	}
}

// TargetName is what an executable stub must be called on this platform, for
// the tests that write one rather than build one.
func TargetName() string { return ExeName("target") }

// ForThisPlatform rewrites a campaign fixture's target path to the name an
// executable can have here.
//
// Campaign validation decides executability by extension on Windows, because
// that is how the platform decides it, so a fixture naming ./target describes a
// file that cannot be run and is refused before any of the campaign under test
// happens.
func ForThisPlatform(body string) string {
	if TargetName() == "target" {
		return body
	}
	return strings.ReplaceAll(body, "./target", "./"+TargetName())
}

// StubTarget writes an executable target into dir and returns its path.
//
// A real program rather than a shell script, because a campaign file names a
// target and something eventually tries to start it. A script is a program
// where there is a shell to read it and a file the loader refuses where there
// is not, so naming one with an executable extension does not make it one — it
// only moves the failure from the campaign's validation to the moment it runs.
//
// It reads a line and repeats it behind a marker, which is an exit status to
// classify and a line of output to attribute. Built once per test binary and
// copied, so a fixture directory costs a copy rather than a compile.
func StubTarget(t testing.TB, dir string) string {
	t.Helper()
	stubOnce.Do(func() {
		d, err := os.MkdirTemp("", "xfuzz-stub-")
		if err != nil {
			stubErr = err
			return
		}
		stubDir = d
		stubPath = BuildAt(t, filepath.Join(d, "stub"), "./testdata/targets/go/echoer")
	})
	if stubErr != nil {
		t.Fatalf("building the stub target: %v", stubErr)
	}
	b, err := os.ReadFile(stubPath)
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, TargetName())
	if err := os.WriteFile(out, b, 0o755); err != nil {
		t.Fatal(err)
	}
	return out
}

var (
	stubOnce sync.Once
	stubPath string
	stubDir  string
	stubErr  error
)

// ReadDoc reads a documentation file with its line endings normalised.
//
// A checkout on Windows has CRLF, and a multi-line pattern anchored with $
// matches nothing against it: the carriage return is still there, before the
// newline the anchor is looking for. A test that parses a table out of the
// documentation then reports that the table is missing, which is true of no
// file in the repository.
func ReadDoc(t testing.TB, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	b = bytes.ReplaceAll(b, []byte("\r\n"), []byte("\n"))
	return bytes.ReplaceAll(b, []byte("\r"), []byte("\n"))
}

// Sleeper builds a target that will not finish on its own, for the tests that
// measure what stops one.
func Sleeper(t testing.TB, dir string) string {
	t.Helper()
	return BuildAt(t, filepath.Join(dir, "sleeper"), "./testdata/targets/go/sleeper")
}

func ExeName(command string) string {
	if runtime.GOOS == "windows" {
		return command + ".exe"
	}
	return command
}

// BuildBinary compiles one of Xfuzz's own commands into dir and returns its
// path.
func BuildBinary(t testing.TB, dir, command string) string {
	t.Helper()
	out := filepath.Join(dir, ExeName(command))
	cmd := exec.Command("go", "build", "-o", out, "./cmd/"+command)
	cmd.Dir = RepoRoot(t)
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("building %s: %v\n%s", command, err, b)
	}
	return out
}

// BuildStrippedTarget compiles a planted-bug target with no instrumentation and
// removes its symbol table, which is the shape the binary-only tier exists for.
//
// The ordinary compiler, not xfuzz-cc: the point of a T5 campaign is that the
// target was never built for fuzzing, so building it with the fuzzer's own
// wrapper would test something else entirely. Stripped for the same reason —
// what remains is a program with no symbols, no coverage runtime, and nothing
// the fuzzer can ask it.
func BuildStrippedTarget(t testing.TB, name string) string {
	t.Helper()
	cc, err := exec.LookPath("clang")
	if err != nil {
		if cc, err = exec.LookPath("gcc"); err != nil {
			t.Skip("no C compiler; a binary-only target cannot be built here")
		}
	}
	out := filepath.Join(ReachableDir(t), name)
	src := filepath.Join(RepoRoot(t), "testdata", "targets", name+".c")
	cmd := exec.Command(cc, "-O1", "-o", out, src)
	cmd.Dir = RepoRoot(t)
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("building %s without instrumentation: %v\n%s", name, err, b)
	}
	if strip, err := exec.LookPath("strip"); err == nil {
		if b, err := exec.Command(strip, out).CombinedOutput(); err != nil {
			t.Logf("strip failed on %s (%v): %s; continuing with symbols", name, err, b)
		}
	}
	if err := os.Chmod(out, 0o755); err != nil {
		t.Fatal(err)
	}
	return out
}

// Browser returns a browser to drive, or skips the test.
//
// The probe is wider than the product's, on purpose. internal/driver looks on
// PATH and at XFUZZ_BROWSER, because that is where an operator's browser is;
// a CI image often unpacks one somewhere else entirely, and a test that skipped
// there would leave the web driver unexercised on the only machine that runs
// the suite.
func Browser(t testing.TB) string {
	t.Helper()
	path := findBrowser(t)

	// And it has to be a browser that will actually be driven. Installed is not
	// the same as drivable: measured on a macOS runner, the browser starts,
	// spends its time waking an updater, and never announces a debugging
	// endpoint — so every web test failed after its own start timeout, eleven
	// of them, for a reason that was about the machine rather than the code.
	//
	// The probe is deliberately not this driver: it is a plain command line
	// with the two switches the protocol needs. A regression in internal/driver
	// therefore still fails these tests rather than skipping them, and only a
	// host that cannot run a debuggable browser at all steps aside — saying so,
	// with what the browser said.
	browserProbeOnce.Do(func() { browserProbeErr = probeBrowser(path) })
	if browserProbeErr != nil {
		t.Skipf("%s is installed but cannot be driven here: %v", path, browserProbeErr)
	}
	return path
}

func findBrowser(t testing.TB) string {
	t.Helper()
	if p := os.Getenv("XFUZZ_BROWSER"); p != "" {
		if _, err := exec.LookPath(p); err == nil {
			return p
		}
		t.Skipf("XFUZZ_BROWSER is set to %s, which is not executable", p)
	}
	for _, c := range []string{
		"chromium", "chromium-browser", "google-chrome", "google-chrome-stable", "chrome",
	} {
		if p, err := exec.LookPath(c); err == nil {
			return p
		}
	}
	for _, p := range []string{
		"/opt/pw-browsers/chromium",
		"/usr/lib/chromium/chromium",
		"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
	} {
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			return p
		}
	}
	t.Skip("no browser found: the web driver needs one, and this host has none")
	return ""
}

var (
	browserProbeOnce sync.Once
	browserProbeErr  error
)

// browserProbeTimeout is how long a browser has to announce its endpoint.
//
// Generous, because a cold browser on a shared runner takes seconds to start
// and this decides whether a whole suite runs. It is spent once per test
// binary, and only where a browser was found.
const browserProbeTimeout = 45 * time.Second

// probeBrowser starts a browser and waits for it to announce a debugging
// endpoint, then kills it.
func probeBrowser(path string) error {
	dir, err := os.MkdirTemp("", "xfuzz-browser-probe-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)

	ctx, cancel := context.WithTimeout(context.Background(), browserProbeTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, path,
		"--headless=new", "--disable-gpu", "--no-sandbox",
		"--remote-debugging-port=0",
		"--user-data-dir="+dir,
		"--no-first-run", "--no-default-browser-check",
		"--disable-background-networking", "--disable-component-update",
		"about:blank")
	cmd.Env = append(os.Environ(), "TMPDIR="+dir)
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()

	// A bounded tail, so a browser that talks for the whole timeout without
	// announcing anything still produces a message somebody can act on.
	var said strings.Builder
	sc := bufio.NewScanner(stderr)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if strings.Contains(line, "DevTools listening on") {
			return nil
		}
		if said.Len() < 4<<10 {
			said.WriteString(line)
			said.WriteByte('\n')
		}
	}
	return fmt.Errorf("it announced no debugging endpoint in %s; what it said instead:\n%s",
		browserProbeTimeout, said.String())
}

// Desktop returns a Python interpreter with GTK bindings, or skips the test.
//
// A desktop campaign needs a display, a session bus, an accessibility bus and
// an application with an accessibility bridge. That is four things a CI image
// usually has none of, so this skips rather than fails — the same treatment the
// browser and the binary-only tools get.
func Desktop(t testing.TB) string {
	t.Helper()
	if os.Getenv("DISPLAY") == "" && os.Getenv("WAYLAND_DISPLAY") == "" {
		t.Skip("no display: a desktop campaign has nothing to draw on")
	}
	if os.Getenv("DBUS_SESSION_BUS_ADDRESS") == "" {
		t.Skip("no session bus: there is no accessibility bus to publish a tree on")
	}
	if p := os.Getenv("XFUZZ_PYTHON_GTK"); p != "" {
		if _, err := exec.LookPath(p); err == nil {
			return p
		}
		t.Skipf("XFUZZ_PYTHON_GTK is set to %s, which is not executable", p)
	}
	for _, c := range []string{"python3", "python3.12", "python3.11", "python3.13"} {
		p, err := exec.LookPath(c)
		if err != nil {
			continue
		}
		cmd := exec.Command(p, "-c",
			"import gi; gi.require_version('Gtk','3.0'); from gi.repository import Gtk")
		if cmd.Run() == nil {
			return p
		}
	}
	t.Skip("no Python with GTK bindings: the desktop driver's test target needs one")
	return ""
}
