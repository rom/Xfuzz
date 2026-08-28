package archlint

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestRepositoryLayering is the gate: the repository must satisfy every rule
// declared in docs/ARCHITECTURE.md section 2.
func TestRepositoryLayering(t *testing.T) {
	root, err := FindRepoRoot(".")
	if err != nil {
		t.Fatal(err)
	}
	vs, err := Check(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range vs {
		t.Errorf("%s", v)
	}
	if len(vs) > 0 {
		t.Logf("%d layering violation(s); see docs/ARCHITECTURE.md section 2", len(vs))
	}
}

// TestRulesFire proves the linter can fail. A lint that only ever passes is
// indistinguishable from one that checks nothing, so every rule is exercised
// against a fixture that deliberately breaks it.
func TestRulesFire(t *testing.T) {
	files := map[string]string{
		"pkg/corpus/bad.go": `package corpus
import _ "` + ModulePath + `/internal/store"
`,
		"pkg/ir/bad.go": `package ir
import _ "` + ModulePath + `/pkg/executor"
`,
		"internal/engine/bad.go": `package engine
import _ "` + ModulePath + `/cmd/xfuzz"
`,
		"internal/daemon/bad.go": `package daemon
import _ "os/exec"
`,
		"pkg/plugin/bad.go": `package plugin
import _ "plugin"
`,
		"internal/engine/bad_linux.go": `package engine
`,
		"internal/store/bad.go": `//go:build linux

package store
`,
		"internal/api/bad.go": `package api
import "net"
func dial() { net.Dial("tcp", "example.com:80") }
`,
	}
	want := map[string]string{
		"pkg/corpus/bad.go":            "pkg-no-internal",
		"pkg/ir/bad.go":                "core-no-executor",
		"internal/engine/bad.go":       "no-cmd-import",
		"internal/daemon/bad.go":       "spawn-confinement",
		"pkg/plugin/bad.go":            "no-stdlib-plugin",
		"internal/engine/bad_linux.go": "platform-build-tags",
		"internal/store/bad.go":        "platform-build-tags",
		"internal/api/bad.go":          "dial-confinement",
	}

	dir := t.TempDir()
	for name, src := range files {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	vs, err := Check(dir)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, v := range vs {
		got[v.File] = v.Rule
	}
	for file, rule := range want {
		if got[file] != rule {
			t.Errorf("%s: expected rule %q to fire, got %q", file, rule, got[file])
		}
	}
}

// TestAllowlistsAreHonoured checks that the documented exceptions actually
// exempt their directories, so the allowlist is real rather than decorative.
func TestAllowlistsAreHonoured(t *testing.T) {
	files := map[string]string{
		"internal/safety/ok.go":   "package safety\nimport _ \"os/exec\"\n",
		"internal/platform/ok.go": "//go:build linux\n\npackage platform\n",
		"cmd/xfuzz-cc/ok.go":      "package main\nimport _ \"os/exec\"\n",
		"tools/x/ok.go":           "package x\nimport _ \"os/exec\"\n",
		"cmd/xfuzz/ok.go":         "package main\nimport _ \"" + ModulePath + "/pkg/corpus\"\n",
		"internal/version/ok.go":  "//go:build cgo\n\npackage version\n",
	}
	dir := t.TempDir()
	for name, src := range files {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	vs, err := Check(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range vs {
		t.Errorf("allowlisted file flagged: %s", v)
	}
}

// TestSpawnConfinementExemptsTests documents the one rule that does not apply
// to test files, and checks it still applies to everything else.
func TestSpawnConfinementExemptsTests(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{
		"internal/engine/helper_test.go": "package engine\nimport _ \"os/exec\"\n",
		"internal/engine/real.go":        "package engine\nimport _ \"os/exec\"\n",
	}
	for name, src := range files {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	vs, err := Check(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(vs) != 1 {
		t.Fatalf("expected exactly one violation, the non-test file, got %v", vs)
	}
	if vs[0].File != "internal/engine/real.go" {
		t.Errorf("the violation is on %s; production code must still be caught", vs[0].File)
	}
}

// TestSkipsGeneratedAndVendorTrees keeps the linter from reporting on trees the
// project does not author.
func TestSkipsGeneratedAndVendorTrees(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"vendor/x/bad.go", "pkg/ir/testdata/bad.go"} {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		src := "package x\nimport _ \"" + ModulePath + "/internal/store\"\n"
		if err := os.WriteFile(p, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	vs, err := Check(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(vs) != 0 {
		t.Errorf("expected skipped trees to produce no violations, got %v", vs)
	}
}

func TestFindRepoRoot(t *testing.T) {
	root, err := FindRepoRoot(".")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Errorf("FindRepoRoot returned %s, which has no go.mod", root)
	}
	if !strings.HasSuffix(filepath.ToSlash(root), "Xfuzz") {
		t.Logf("repo root resolved to %s", root)
	}
}
