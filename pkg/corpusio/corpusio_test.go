package corpusio

import (
	"crypto/sha1"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rom/Xfuzz/pkg/corpus"
)

func write(t *testing.T, dir, name, content string) {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestImportAFLQueue(t *testing.T) {
	out := t.TempDir()
	write(t, out, "queue/id:000000,orig:seed", "alpha")
	write(t, out, "queue/id:000001,src:000000,op:havoc,+cov", "beta")
	write(t, out, "queue/README.txt", "this directory holds the queue")
	write(t, out, "queue/.state/deterministic_done/id:000000", "bookkeeping")
	write(t, out, "fuzzer_stats", "start_time : 0")
	write(t, out, "crashes/id:000000,sig:11", "boom")

	// The output directory is given, not the queue: that is the path afl-fuzz
	// prints, so it is the path a person pastes.
	tcs, rep, err := Import(out, ImportOptions{})
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	if rep.Format != FormatAFL {
		t.Fatalf("format = %v, want afl", rep.Format)
	}
	if !strings.HasSuffix(rep.Dir, "queue") {
		t.Fatalf("resolved dir = %s, want the queue subdirectory", rep.Dir)
	}
	if rep.Imported != 2 {
		t.Fatalf("imported %d entries, want 2: %s", rep.Imported, rep)
	}
	got := map[string]bool{}
	for _, tc := range tcs {
		got[string(tc.Bytes)] = true
	}
	if !got["alpha"] || !got["beta"] {
		t.Fatalf("payloads = %v", got)
	}
	if got["boom"] {
		t.Fatal("a crash was imported as a seed")
	}
	if got["bookkeeping"] {
		t.Fatal("the .state directory was imported")
	}
}

func TestImportLibFuzzerCorpus(t *testing.T) {
	dir := t.TempDir()
	for _, s := range []string{"one", "two", "three"} {
		sum := sha1.Sum([]byte(s))
		write(t, dir, hex.EncodeToString(sum[:]), s)
	}
	_, rep, err := Import(dir, ImportOptions{})
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	if rep.Format != FormatLibFuzzer {
		t.Fatalf("format = %v, want libfuzzer", rep.Format)
	}
	if rep.Imported != 3 {
		t.Fatalf("imported %d, want 3", rep.Imported)
	}
}

func TestImportDeduplicatesByContent(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "a", "same content")
	write(t, dir, "b", "same content")
	write(t, dir, "c", "different")

	tcs, rep, err := Import(dir, ImportOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(tcs) != 2 || rep.Imported != 2 || rep.Duplicate != 1 {
		t.Fatalf("imported %d, duplicates %d; want 2 and 1", rep.Imported, rep.Duplicate)
	}
}

func TestImportSkipsEmptyAndOversized(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "empty", "")
	write(t, dir, "huge", strings.Repeat("x", 200))
	write(t, dir, "fine", "ok")

	_, rep, err := Import(dir, ImportOptions{MaxFileSize: 100})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Imported != 1 {
		t.Fatalf("imported %d, want 1: %s", rep.Imported, rep)
	}
	if rep.Reasons["empty"] != 1 || rep.Reasons["too-large"] != 1 {
		t.Fatalf("reasons = %v", rep.Reasons)
	}
	if !strings.Contains(rep.String(), "skipped") {
		t.Fatalf("the report does not mention the skips: %s", rep)
	}
}

func TestImportIsNotRecursiveByDefault(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "top", "top level")
	write(t, dir, "nested/deep", "nested")

	_, rep, err := Import(dir, ImportOptions{Format: FormatRaw})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Imported != 1 {
		t.Fatalf("imported %d, want 1", rep.Imported)
	}
	_, rep, err = Import(dir, ImportOptions{Format: FormatRaw, Recursive: true})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Imported != 2 {
		t.Fatalf("recursive import got %d, want 2", rep.Imported)
	}
}

func TestImportOrderIsStable(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 30; i++ {
		write(t, dir, string(rune('a'+i%26))+string(rune('0'+i/26)), strings.Repeat("x", i+1))
	}
	first, _, err := Import(dir, ImportOptions{Format: FormatRaw})
	if err != nil {
		t.Fatal(err)
	}
	second, _, err := Import(dir, ImportOptions{Format: FormatRaw})
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != len(second) {
		t.Fatalf("%d vs %d entries", len(first), len(second))
	}
	for i := range first {
		if first[i].ID != second[i].ID {
			t.Fatalf("import order differs at %d", i)
		}
	}
}

func TestImportRecordsOrigin(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "sample.png", "not really a png")
	tcs, _, err := Import(dir, ImportOptions{Format: FormatRaw})
	if err != nil {
		t.Fatal(err)
	}
	if tcs[0].Prov.Origin != "raw:sample.png" {
		t.Fatalf("origin = %q", tcs[0].Prov.Origin)
	}
	tcs, _, err = Import(dir, ImportOptions{Format: FormatRaw, Origin: "customer-samples"})
	if err != nil {
		t.Fatal(err)
	}
	if tcs[0].Prov.Origin != "customer-samples" {
		t.Fatalf("explicit origin ignored: %q", tcs[0].Prov.Origin)
	}
}

func corpusOf(payloads ...string) []*corpus.Testcase {
	out := make([]*corpus.Testcase, 0, len(payloads))
	for _, p := range payloads {
		out = append(out, corpus.NewTestcase(nil, []byte(p)))
	}
	return out
}

func TestExportRefusesNonEmptyDirectory(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "existing", "someone else's corpus")

	if _, err := Export(dir, corpusOf("a"), ExportOptions{Format: FormatRaw}); err == nil {
		t.Fatal("exporting into a non-empty directory was allowed")
	}
	if _, err := Export(dir, corpusOf("a"), ExportOptions{Format: FormatRaw, Overwrite: true}); err != nil {
		t.Fatalf("Overwrite did not permit it: %v", err)
	}
}

func TestExportLibFuzzerNaming(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "out")
	tcs := corpusOf("hello", "world")
	if _, err := Export(dir, tcs, ExportOptions{Format: FormatLibFuzzer}); err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"hello", "world"} {
		sum := sha1.Sum([]byte(s))
		p := filepath.Join(dir, hex.EncodeToString(sum[:]))
		got, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("libFuzzer name missing for %q: %v", s, err)
		}
		if string(got) != s {
			t.Fatalf("content = %q", got)
		}
	}
}

func TestExportAFLNaming(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "out")
	tcs := corpusOf("a", "b")
	tcs[0].Meta.Favoured = true
	if _, err := Export(dir, tcs, ExportOptions{Format: FormatAFL}); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 2 {
		t.Fatalf("wrote %d files", len(entries))
	}
	var covMarked int
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), "id:") {
			t.Fatalf("filename %q is not an AFL queue name", e.Name())
		}
		if strings.HasSuffix(e.Name(), ",+cov") {
			covMarked++
		}
	}
	if covMarked != 1 {
		t.Fatalf("%d entries marked +cov, want 1", covMarked)
	}
}

func TestExportFavouredOnly(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "out")
	tcs := corpusOf("a", "b", "c")
	tcs[1].Meta.Favoured = true
	rep, err := Export(dir, tcs, ExportOptions{Format: FormatRaw, FavouredOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Written != 1 {
		t.Fatalf("wrote %d entries, want 1", rep.Written)
	}
}

func TestExportIsStable(t *testing.T) {
	tcs := corpusOf("one", "two", "three", "four")
	names := func() []string {
		dir := filepath.Join(t.TempDir(), "out")
		if _, err := Export(dir, tcs, ExportOptions{Format: FormatAFL}); err != nil {
			t.Fatal(err)
		}
		entries, _ := os.ReadDir(dir)
		var out []string
		for _, e := range entries {
			b, _ := os.ReadFile(filepath.Join(dir, e.Name()))
			out = append(out, e.Name()+"="+string(b))
		}
		return out
	}
	a, b := names(), names()
	if len(a) != len(b) {
		t.Fatal("different file counts")
	}
	for i := range a {
		if a[i] != b[i] {
			t.Fatalf("two exports of one corpus differ at %d: %q vs %q", i, a[i], b[i])
		}
	}
}

func TestRoundTripThroughEveryFormat(t *testing.T) {
	original := corpusOf("first payload", "second payload", "third payload")
	want := map[string]bool{}
	for _, tc := range original {
		want[string(tc.Bytes)] = true
	}

	for _, format := range []Format{FormatAFL, FormatLibFuzzer, FormatRaw} {
		t.Run(format.String(), func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "out")
			if _, err := Export(dir, original, ExportOptions{Format: format}); err != nil {
				t.Fatalf("Export: %v", err)
			}
			back, rep, err := Import(dir, ImportOptions{})
			if err != nil {
				t.Fatalf("Import: %v", err)
			}
			if rep.Imported != len(original) {
				t.Fatalf("round trip lost entries: %d of %d (%s)", rep.Imported, len(original), rep)
			}
			for _, tc := range back {
				if !want[string(tc.Bytes)] {
					t.Fatalf("round trip produced an unexpected payload %q", tc.Bytes)
				}
			}
		})
	}
}

func TestExportSkipsEntriesWithoutPayload(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "out")
	tcs := corpusOf("real")
	tcs = append(tcs, &corpus.Testcase{ID: corpus.DigestOf([]byte("absent"))})
	rep, err := Export(dir, tcs, ExportOptions{Format: FormatRaw})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Written != 1 || rep.Skipped != 1 {
		t.Fatalf("wrote %d, skipped %d; want 1 and 1", rep.Written, rep.Skipped)
	}
}

func TestParseFormat(t *testing.T) {
	for in, want := range map[string]Format{
		"": FormatAuto, "auto": FormatAuto, "AFL": FormatAFL, "afl++": FormatAFL,
		"libfuzzer": FormatLibFuzzer, "raw": FormatRaw,
	} {
		got, err := ParseFormat(in)
		if err != nil || got != want {
			t.Fatalf("ParseFormat(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	if _, err := ParseFormat("honggfuzz"); err == nil {
		t.Fatal("an unknown format was accepted")
	}
}
