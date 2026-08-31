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
