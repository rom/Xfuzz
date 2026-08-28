// Package archlint enforces the layering rules declared in
// docs/ARCHITECTURE.md section 2.
//
// These rules are the difference between an architecture and a diagram. Each
// one is stated in ARCHITECTURE.md and checked here; an exception must be added
// to an explicit allowlist below, where it is visible in review, rather than
// being silently possible.
package archlint

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// ModulePath is the module under analysis.
const ModulePath = "github.com/rom/Xfuzz"

// Violation is a single breach of a layering rule.
type Violation struct {
	File string // repo-relative, slash-separated
	Line int
	Rule string
	Msg  string
}

func (v Violation) String() string {
	return fmt.Sprintf("%s:%d: [%s] %s", v.File, v.Line, v.Rule, v.Msg)
}

// rule describes an import restriction: files under a directory may not import
// packages matching a prefix, unless they sit under an allowed prefix.
type rule struct {
	name    string
	reason  string
	applyTo []string // repo-relative dir prefixes the rule governs ("" = all)
	forbid  []string // import path prefixes that are forbidden
	allow   []string // dir prefixes exempted from the rule

	// allowTests exempts _test.go files. Use it only where the rule protects
	// runtime behaviour rather than structure, since test files never reach a
	// shipped binary.
	allowTests bool
}

// importRules are checked against every .go file in the repository.
var importRules = []rule{
	{
		name:    "pkg-no-internal",
		reason:  "pkg/ is the public API surface and must not depend on internal/",
		applyTo: []string{"pkg/"},
		forbid:  []string{ModulePath + "/internal/"},
	},
	{
		name:    "core-no-executor",
		reason:  "the engine core must not know how inputs are delivered",
		applyTo: []string{"pkg/ir/", "pkg/feedback/", "pkg/corpus/"},
		forbid:  []string{ModulePath + "/pkg/executor"},
	},
	{
		name:    "no-cmd-import",
		reason:  "cmd/ holds entry points; nothing may import them",
		applyTo: []string{""},
		forbid:  []string{ModulePath + "/cmd/"},
		allow:   []string{"cmd/"},
	},
	{
		name:    "spawn-confinement",
		reason:  "only internal/safety may spawn processes (ADR-0012); it delegates OS specifics to internal/platform",
		applyTo: []string{""},
		forbid:  []string{"os/exec", "syscall", "golang.org/x/sys/"},
		allow: []string{
			"internal/safety/",
			"internal/platform/",
			"tools/",        // repo tooling shells out to the Go toolchain
			"bench/",        // the benchmark harness drives external processes
			"cmd/xfuzz-cc/", // the compiler wrapper execs a compiler by definition
		},
		// Test files are exempt. The rule protects runtime behaviour — every
		// target a campaign runs must pass through the safety layer — and a
		// _test.go file is not part of any shipped binary, so it cannot carry
		// that behaviour into production. Integration tests legitimately
		// compile fixtures and invoke the toolchain. The layering that keeps
		// executors away from the safety layer is pkg-no-internal, which does
		// apply to tests, and which is why those tests live under internal/ at
		// all.
		allowTests: true,
	},
	{
		name:    "no-stdlib-plugin",
		reason:  "ADR-0010 rejects Go's plugin package: Linux-only, toolchain-locked, no isolation",
		applyTo: []string{""},
		forbid:  []string{"plugin"},
	},
}

// dialFuncs are package-qualified calls that open an outbound connection.
// Listening (http.ListenAndServe, net.Listen) is not restricted: the daemon
// serves an API. What is restricted is reaching *out*, which must pass the
// scope guard (ADR-0012).
var dialFuncs = map[string][]string{
	"net":  {"Dial", "DialTimeout", "DialIP", "DialTCP", "DialUDP", "DialUnix"},
	"http": {"Get", "Head", "Post", "PostForm"},
}

// dialAllow lists the directories permitted to dial directly.
var dialAllow = []string{
	"internal/safety/",
	"internal/platform/",
	"tools/",
	"bench/",
}

var knownGOOS = map[string]bool{
	"aix": true, "android": true, "darwin": true, "dragonfly": true,
	"freebsd": true, "hurd": true, "illumos": true, "ios": true, "js": true,
	"linux": true, "nacl": true, "netbsd": true, "openbsd": true, "plan9": true,
	"solaris": true, "wasip1": true, "windows": true, "zos": true, "unix": true,
}

var knownGOARCH = map[string]bool{
	"386": true, "amd64": true, "arm": true, "arm64": true, "loong64": true,
	"mips": true, "mips64": true, "mips64le": true, "mipsle": true,
	"ppc64": true, "ppc64le": true, "riscv64": true, "s390x": true,
	"wasm": true,
}

// platformTagAllow lists directories permitted to carry GOOS/GOARCH build
// constraints. Everything else must reach platform differences through
// internal/platform.
var platformTagAllow = []string{"internal/platform/"}

var skipDirs = map[string]bool{
	".git": true, "node_modules": true, "vendor": true,
	"dist": true, "testdata": true,
}

// Check walks the repository rooted at dir and returns every layering
// violation, sorted by file and line.
func Check(dir string) ([]Violation, error) {
	var vs []Violation
	fset := token.NewFileSet()

	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skipDirs[d.Name()] {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)

		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		f, err := parser.ParseFile(fset, path, src, parser.ParseComments)
		if err != nil {
			return fmt.Errorf("parse %s: %w", rel, err)
		}

		vs = append(vs, checkImports(fset, f, rel)...)
		vs = append(vs, checkPlatformTags(fset, f, rel)...)
		vs = append(vs, checkDials(fset, f, rel)...)
		return nil
	})
	if err != nil {
		return nil, err
	}

	sort.Slice(vs, func(i, j int) bool {
		if vs[i].File != vs[j].File {
			return vs[i].File < vs[j].File
		}
		return vs[i].Line < vs[j].Line
	})
	return vs, nil
}

func checkImports(fset *token.FileSet, f *ast.File, rel string) []Violation {
	var vs []Violation
	for _, r := range importRules {
		if !underAny(rel, r.applyTo) || underAny(rel, r.allow) {
			continue
		}
		if r.allowTests && strings.HasSuffix(rel, "_test.go") {
			continue
		}
		for _, spec := range f.Imports {
			p := strings.Trim(spec.Path.Value, `"`)
			for _, bad := range r.forbid {
				if p == bad || (strings.HasSuffix(bad, "/") && strings.HasPrefix(p, bad)) {
					vs = append(vs, Violation{
						File: rel,
						Line: fset.Position(spec.Pos()).Line,
						Rule: r.name,
						Msg:  fmt.Sprintf("imports %q: %s", p, r.reason),
					})
				}
			}
		}
	}
	return vs
}

func checkPlatformTags(fset *token.FileSet, f *ast.File, rel string) []Violation {
	if underAny(rel, platformTagAllow) {
		return nil
	}
	var vs []Violation

	// Filename suffix form: foo_linux.go, foo_windows_amd64.go
	base := strings.TrimSuffix(filepath.Base(rel), ".go")
	base = strings.TrimSuffix(base, "_test")
	for _, part := range strings.Split(base, "_")[1:] {
		if knownGOOS[part] || knownGOARCH[part] {
			vs = append(vs, Violation{
				File: rel, Line: 1, Rule: "platform-build-tags",
				Msg: fmt.Sprintf("filename implies a %q build constraint; OS differences belong in internal/platform", part),
			})
			break
		}
	}

	// //go:build form. A bare "cgo" constraint is fine (ADR-0017); a GOOS or
	// GOARCH term is not.
	for _, cg := range f.Comments {
		for _, c := range cg.List {
			text, ok := strings.CutPrefix(c.Text, "//go:build ")
			if !ok {
				continue
			}
			for _, tok := range strings.FieldsFunc(text, func(r rune) bool {
				return !('a' <= r && r <= 'z' || '0' <= r && r <= '9')
			}) {
				if knownGOOS[tok] || knownGOARCH[tok] {
					vs = append(vs, Violation{
						File: rel, Line: fset.Position(c.Pos()).Line,
						Rule: "platform-build-tags",
						Msg:  fmt.Sprintf("//go:build constrains on %q; OS differences belong in internal/platform", tok),
					})
				}
			}
		}
	}
	return vs
}

func checkDials(fset *token.FileSet, f *ast.File, rel string) []Violation {
	if underAny(rel, dialAllow) || strings.HasSuffix(rel, "_test.go") {
		return nil
	}
	// Map local import names for the packages we care about.
	local := map[string]string{}
	for _, spec := range f.Imports {
		p := strings.Trim(spec.Path.Value, `"`)
		name := p[strings.LastIndex(p, "/")+1:]
		if spec.Name != nil {
			name = spec.Name.Name
		}
		if _, ok := dialFuncs[name]; ok && (p == "net" || p == "net/http") {
			local[name] = p
		}
	}
	if len(local) == 0 {
		return nil
	}

	var vs []Violation
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		pkg, ok := sel.X.(*ast.Ident)
		if !ok {
			return true
		}
		if _, imported := local[pkg.Name]; !imported {
			return true
		}
		for _, fn := range dialFuncs[pkg.Name] {
			if sel.Sel.Name == fn {
				vs = append(vs, Violation{
					File: rel,
					Line: fset.Position(call.Pos()).Line,
					Rule: "dial-confinement",
					Msg: fmt.Sprintf("calls %s.%s: outbound connections must pass the scope guard in internal/safety (ADR-0012)",
						pkg.Name, fn),
				})
			}
		}
		return true
	})
	return vs
}

func underAny(rel string, prefixes []string) bool {
	for _, p := range prefixes {
		if p == "" || strings.HasPrefix(rel, p) {
			return true
		}
	}
	return false
}

// FindRepoRoot walks up from start until it finds the directory holding go.mod.
func FindRepoRoot(start string) (string, error) {
	dir, err := filepath.Abs(start)
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("no go.mod found above %s", start)
		}
		dir = parent
	}
}
