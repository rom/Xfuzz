package engine

import (
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"

	"github.com/rom/Xfuzz/pkg/feedback"
)

// TestMain removes the directory of compiled targets once every test in this
// package has finished. It lives here rather than beside the campaign tests
// because those are behind a build tag, and a package must have exactly one
// TestMain in every build configuration.
func TestMain(m *testing.M) {
	code := m.Run()
	buildDirMu.Lock()
	if buildDir != "" {
		os.RemoveAll(buildDir)
	}
	buildDirMu.Unlock()
	os.Exit(code)
}

// Building an instrumented target needs clang. Where it is absent the
// integration tests skip with a reason rather than failing: a missing toolchain
// is an environment gap, and a suite that fails for environmental reasons is a
// suite people learn to ignore (docs/TESTS.md section 10).

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

func haveClang() bool {
	_, err := exec.LookPath("clang")
	return err == nil
}

var (
	buildOnce  sync.Map // target name -> *sync.Once
	buildPaths sync.Map // target name -> string
	buildErrs  sync.Map // target name -> error
	buildDir   string
	buildDirMu sync.Mutex
)

// buildTarget compiles a planted-bug target with instrumentation, once per test
// binary.
func buildTarget(t testing.TB, name string) string {
	t.Helper()
	if !haveClang() {
		t.Skip("clang is not installed; instrumented targets cannot be built here")
	}

	onceAny, _ := buildOnce.LoadOrStore(name, &sync.Once{})
	onceAny.(*sync.Once).Do(func() {
		root := repoRoot(t)

		buildDirMu.Lock()
		if buildDir == "" {
			d, err := os.MkdirTemp("", "xfuzz-targets-")
			if err != nil {
				buildErrs.Store(name, err)
				buildDirMu.Unlock()
				return
			}
			buildDir = d
		}
		dir := buildDir
		buildDirMu.Unlock()

		out := filepath.Join(dir, name)
		src := filepath.Join(root, "testdata", "targets", name+".c")

		// Through xfuzz-cc rather than clang directly, so the wrapper is
		// exercised by every integration test that uses a target.
		cmd := exec.Command("go", "run", "./cmd/xfuzz-cc", "-O1", "-o", out, src)
		cmd.Dir = root
		if b, err := cmd.CombinedOutput(); err != nil {
			buildErrs.Store(name, err)
			buildPaths.Store(name, string(b))
			return
		}
		buildPaths.Store(name, out)
	})

	if err, bad := buildErrs.Load(name); bad {
		detail, _ := buildPaths.Load(name)
		t.Fatalf("building %s: %v\n%s", name, err, detail)
	}
	p, _ := buildPaths.Load(name)
	return p.(string)
}

// countCovered reports how many entries of a coverage map were touched.
func countCovered(m *feedback.CoverageMap) int { return m.Covered() }
