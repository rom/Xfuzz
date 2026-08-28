package store

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/rom/Xfuzz/pkg/corpus"
	"github.com/rom/Xfuzz/pkg/corpusio"
)

func TestImportCorpusIntoCampaign(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	c, _ := s.CreateCampaign(ctx, "c", "", 1)

	src := t.TempDir()
	for name, content := range map[string]string{"a": "alpha", "b": "beta", "c": "alpha"} {
		if err := os.WriteFile(filepath.Join(src, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	rep, err := s.ImportCorpus(ctx, c.ID, src, corpusio.ImportOptions{Format: corpusio.FormatRaw})
	if err != nil {
		t.Fatalf("ImportCorpus: %v", err)
	}
	if rep.Imported != 2 || rep.Duplicate != 1 {
		t.Fatalf("report = %s", rep)
	}
	n, _, err := s.CountTestcases(ctx, c.ID)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("stored %d entries, want 2", n)
	}
	if !s.Blobs().Has(corpus.DigestOf([]byte("alpha"))) {
		t.Fatal("the payload was not stored")
	}

	// Re-importing the same directory must not grow the corpus.
	if _, err := s.ImportCorpus(ctx, c.ID, src, corpusio.ImportOptions{Format: corpusio.FormatRaw}); err != nil {
		t.Fatal(err)
	}
	if n, _, _ := s.CountTestcases(ctx, c.ID); n != 2 {
		t.Fatalf("re-import grew the corpus to %d", n)
	}

	entries, err := s.AuditLog(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("audit entries = %d, want one per import", len(entries))
	}
	if entries[0].Action != AuditCorpusImport {
		t.Fatalf("action = %q", entries[0].Action)
	}
	if _, err := s.VerifyAudit(ctx); err != nil {
		t.Fatalf("VerifyAudit: %v", err)
	}
}

func TestExportCorpusFromCampaign(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	c, _ := s.CreateCampaign(ctx, "c", "", 1)

	if err := s.SaveTestcases(ctx, c.ID, []*corpus.Testcase{
		testcase("keep me", 30, true),
		testcase("also here", 10, false),
	}); err != nil {
		t.Fatal(err)
	}

	dst := filepath.Join(t.TempDir(), "out")
	rep, err := s.ExportCorpus(ctx, c.ID, dst, corpusio.ExportOptions{Format: corpusio.FormatLibFuzzer})
	if err != nil {
		t.Fatalf("ExportCorpus: %v", err)
	}
	if rep.Written != 2 {
		t.Fatalf("wrote %d entries, want 2", rep.Written)
	}

	fav := filepath.Join(t.TempDir(), "fav")
	rep, err = s.ExportCorpus(ctx, c.ID, fav,
		corpusio.ExportOptions{Format: corpusio.FormatAFL, FavouredOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Written != 1 {
		t.Fatalf("favoured export wrote %d entries, want 1", rep.Written)
	}
}

func TestCorpusRoundTripThroughStore(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	c, _ := s.CreateCampaign(ctx, "c", "", 1)

	payloads := []string{"first", "second", "third", "fourth"}
	var batch []*corpus.Testcase
	for _, p := range payloads {
		batch = append(batch, testcase(p, len(p), false))
	}
	if err := s.SaveTestcases(ctx, c.ID, batch); err != nil {
		t.Fatal(err)
	}

	dst := filepath.Join(t.TempDir(), "out")
	if _, err := s.ExportCorpus(ctx, c.ID, dst, corpusio.ExportOptions{Format: corpusio.FormatAFL}); err != nil {
		t.Fatal(err)
	}

	other, _ := s.CreateCampaign(ctx, "other", "", 2)
	rep, err := s.ImportCorpus(ctx, other.ID, dst, corpusio.ImportOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Imported != len(payloads) {
		t.Fatalf("round trip imported %d of %d: %s", rep.Imported, len(payloads), rep)
	}
	got, err := s.Testcases(ctx, other.ID, TestcaseQuery{WithPayload: true})
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, tc := range got {
		seen[string(tc.Bytes)] = true
	}
	for _, p := range payloads {
		if !seen[p] {
			t.Fatalf("payload %q did not survive the round trip", p)
		}
	}
}
