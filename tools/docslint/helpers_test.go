package docslint

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func mustCopyTree(t *testing.T, src, dst string) {
	t.Helper()
	err := filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, b, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
}

func mustWrite(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func appendToFile(t *testing.T, path, extra string) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	mustWrite(t, path, string(b)+extra)
}

func replaceInFile(t *testing.T, path, old, new string) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if !strings.Contains(s, old) {
		t.Fatalf("%s: fixture text %q not found", path, old)
	}
	mustWrite(t, path, strings.Replace(s, old, new, 1))
}

// crlfTree rewrites every markdown file under dir with CRLF line endings, which
// is what a git checkout on Windows produces.
func crlfTree(t *testing.T, dir string) {
	t.Helper()
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".md") {
			return err
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		body := strings.ReplaceAll(string(b), "\r\n", "\n")
		return os.WriteFile(path, []byte(strings.ReplaceAll(body, "\n", "\r\n")), 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
}
