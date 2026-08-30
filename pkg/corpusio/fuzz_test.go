package corpusio

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// FuzzImport fuzzes the AFL and libFuzzer corpus importers.
//
// Untrusted because a corpus is the thing people download: "here is a corpus
// for PNG" is a link, and the filenames in it carry structure the importer
// reads — AFL's `id:000000,src:000001,op:havoc` is parsed, not just listed.
//
// The name and the content are fuzzed together because they are separate
// parsers that meet: one decides what a file is, the other decides what is in
// it, and a disagreement between them is exactly the sort of thing a corpus
// from a stranger would exercise.
func FuzzImport(f *testing.F) {
	f.Add("id:000000,src:000000,op:havoc,rep:2", []byte("seed"))
	f.Add("id_000001", []byte(""))
	f.Add("da39a3ee5e6b4b0d3255bfef95601890afd80709", []byte("libfuzzer entry"))
	f.Add("README.txt", []byte("not a seed"))
	f.Add(".hidden", []byte("dot file"))
	f.Add("id:99999999999999999999", []byte("overflowing index"))
	f.Add("", []byte("no name at all"))

	f.Fuzz(func(t *testing.T, name string, body []byte) {
		// The importer is under test, not the filesystem: a name that escapes
		// the directory would be testing os.WriteFile. Rejecting those here
		// keeps the fuzzer's attention on the parsers.
		if name == "" || strings.ContainsAny(name, "/\\\x00") || name == "." || name == ".." {
			return
		}
		if len(name) > 200 {
			return
		}

		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, name), body, 0o600); err != nil {
			return // the name was not one this filesystem accepts
		}

		for _, format := range []Format{FormatAuto, FormatAFL, FormatLibFuzzer, FormatRaw} {
			tcs, rep, err := Import(dir, ImportOptions{Format: format})
			if err != nil {
				if strings.TrimSpace(err.Error()) == "" {
					t.Fatalf("format %s refused the corpus with an empty message", format)
				}
				continue
			}
			// The report must add up. A partial success that says nothing is
			// the failure mode this package's report exists to prevent: a
			// directory where forty of a thousand files were skipped looks
			// exactly like one where none were.
			if rep.Imported != len(tcs) {
				t.Fatalf("format %s reported %d imported but returned %d entries",
					format, rep.Imported, len(tcs))
			}
			for _, tc := range tcs {
				if tc == nil {
					t.Fatalf("format %s returned a nil entry", format)
				}
				if len(tc.Bytes) == 0 && rep.Imported > 0 {
					// An empty seed is legal input to a target and must not be
					// silently turned into one; what must not happen is an
					// entry whose payload was lost between read and return.
					continue
				}
			}
		}
	})
}
