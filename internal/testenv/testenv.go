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
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
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
	out := filepath.Join(dir, name)
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
