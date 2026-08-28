package safety

import (
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
)

var (
	helperOnce sync.Once
	helperPath string
	helperDir  string
	helperErr  error
)

// TestMain removes the directories of binaries the tests build.
func TestMain(m *testing.M) {
	code := m.Run()
	if helperDir != "" {
		os.RemoveAll(helperDir)
	}
	if targetDir != "" {
		os.RemoveAll(targetDir)
	}
	os.Exit(code)
}

func repoRoot(t testing.TB) string {
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

var (
	targetOnce sync.Once
	targetPath string
	targetDir  string
	targetErr  error
)

// escapeTarget compiles the escape-attempt program, once per test binary.
//
// It is plain C with no instrumentation: what these tests measure is whether
// the sandbox holds, and a coverage map would only slow them down.
func escapeTarget(t testing.TB) string {
	t.Helper()
	cc, err := exec.LookPath("cc")
	if err != nil {
		if cc, err = exec.LookPath("clang"); err != nil {
			t.Skip("no C compiler; the escape tests need a target that tries to escape")
		}
	}
	targetOnce.Do(func() {
		dir, err := os.MkdirTemp("", "xfuzz-escape-")
		if err != nil {
			targetErr = err
			return
		}
		targetDir = dir
		// World-traversable and the binary world-executable: the target runs
		// as a different, unprivileged user, and a 0700 build directory would
		// make every escape test fail at exec rather than at the thing it is
		// measuring. A real target binary is readable too.
		if err := os.Chmod(dir, 0o755); err != nil {
			targetErr = err
			return
		}
		out := filepath.Join(dir, "escape")
		src := filepath.Join(repoRoot(t), "testdata", "targets", "escape.c")
		if b, err := exec.Command(cc, "-O0", "-o", out, src).CombinedOutput(); err != nil {
			targetErr = &buildError{string(b), err}
			return
		}
		if err := os.Chmod(out, 0o755); err != nil {
			targetErr = err
			return
		}
		targetPath = out
	})
	if targetErr != nil {
		t.Fatalf("building the escape target: %v", targetErr)
	}
	return targetPath
}

type buildError struct {
	output string
	err    error
}

func (e *buildError) Error() string { return e.err.Error() + "\n" + e.output }
