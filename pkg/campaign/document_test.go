package campaign

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const annotated = `# The campaign we run in CI.
version: 1
name: nightly

target:
  # Built by make release; the timeout is what the slowest input took, doubled.
  path: ./target
  timeout: 5s

seeds:
  dirs: [./corpus]

workers:
  count: 2  # one per core we are allowed

stop:
  after: 30m
`

// An edit has to come back as the same file with one thing changed. Anything
// else is the console rewriting a file somebody else owns.
func TestDocumentEditsPreserveCommentsOrderAndParagraphs(t *testing.T) {
	d, err := ParseDocument([]byte(annotated))
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Set("workers.count", 8); err != nil {
		t.Fatal(err)
	}
	out, err := d.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	got := string(out)

	if !strings.Contains(got, "count: 8") {
		t.Errorf("the edit did not take:\n%s", got)
	}
	if strings.Contains(got, "count: \"8\"") {
		t.Error("a number was written as a string; touching a field changed its type")
	}
	for _, comment := range []string{
		"# The campaign we run in CI.",
		"# Built by make release; the timeout is what the slowest input took, doubled.",
		"# one per core we are allowed",
	} {
		if !strings.Contains(got, comment) {
			t.Errorf("comment lost: %q\n%s", comment, got)
		}
	}

	// Key order is the file's, not the struct's.
	for _, pair := range [][2]string{
		{"version:", "name:"}, {"name:", "target:"}, {"target:", "seeds:"},
		{"seeds:", "workers:"}, {"workers:", "stop:"},
	} {
		if strings.Index(got, pair[0]) > strings.Index(got, pair[1]) {
			t.Errorf("%s now comes after %s:\n%s", pair[0], pair[1], got)
		}
	}

	// Paragraphs: every block that had a blank line before it still does.
	for _, key := range []string{"target:", "seeds:", "workers:", "stop:"} {
		if !strings.Contains(got, "\n\n"+key) {
			t.Errorf("the blank line before %s was lost; the file was reflowed:\n%s", key, got)
		}
	}

	// Indentation is the file's two spaces, not the encoder's four.
	if !strings.Contains(got, "\n  path: ./target") {
		t.Errorf("the file was reindented:\n%s", got)
	}

	// And what comes out is still a campaign.
	if _, err := ParseDocument(out); err != nil {
		t.Fatalf("the edited document does not parse: %v\n%s", err, got)
	}
}

// Saving is idempotent: the second save of a file changes nothing.
//
// Not byte-identity with the source, which would be a claim this cannot make —
// the encoder normalises the spacing before an inline comment, so a file
// written with two spaces there comes back with one. That is a single
// normalisation on first save. What matters for a file kept in git is that it
// settles: if every save produced a slightly different file, no diff would ever
// be only the change somebody made.
func TestSavingADocumentIsIdempotent(t *testing.T) {
	d, err := ParseDocument([]byte(annotated))
	if err != nil {
		t.Fatal(err)
	}
	once, err := d.Bytes()
	if err != nil {
		t.Fatal(err)
	}

	again, err := ParseDocument(once)
	if err != nil {
		t.Fatal(err)
	}
	twice, err := again.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if string(twice) != string(once) {
		t.Errorf("the second save differs from the first, so no diff is ever just the edit:\n"+
			"--- first ---\n%s\n--- second ---\n%s", once, twice)
	}

	// And the normalisation really is only that one thing.
	if strings.Count(string(once), "\n") != strings.Count(annotated, "\n") {
		t.Errorf("the file gained or lost lines on the way through:\n%s", once)
	}
}

func TestDocumentSetCreatesAndUnsetRemoves(t *testing.T) {
	d, err := ParseDocument([]byte("name: c\n"))
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Set("workers.count", 4); err != nil {
		t.Fatal(err)
	}
	if err := d.Set("target.path", "./t"); err != nil {
		t.Fatal(err)
	}
	if got, ok := d.Get("workers.count"); !ok || got != "4" {
		t.Errorf("workers.count = %q, %v", got, ok)
	}

	if !d.Unset("workers.count") {
		t.Error("removing a key that exists reported nothing removed")
	}
	if _, ok := d.Get("workers.count"); ok {
		t.Error("the key survived being removed")
	}
	if d.Unset("nothing.here") {
		t.Error("removing a key that does not exist reported a removal")
	}

	out, err := d.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "path: ./t") {
		t.Errorf("created key missing:\n%s", out)
	}
}

// Editing a document and resolving it has to agree with parsing the file it
// produces, or the console would be launching something other than what it
// showed.
func TestEditedDocumentsResolveAsThemselves(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	src := "name: nightly\n\ntarget:\n  # why this timeout\n  path: " + target +
		"\n\nseeds:\n  inline: [\"a\"]\n\nworkers:\n  count: 2\n"

	d, err := ParseDocument([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Set("workers.count", 6); err != nil {
		t.Fatal(err)
	}
	r, err := d.Resolved("nightly")
	if err != nil {
		t.Fatal(err)
	}
	if r.Workers.Count != 6 {
		t.Errorf("resolved worker count is %d, want 6", r.Workers.Count)
	}
	if r.Name != "nightly" {
		t.Errorf("resolved name is %q", r.Name)
	}
}
