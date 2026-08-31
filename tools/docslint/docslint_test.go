package docslint

import "testing"

// TestDocumentationIsConsistent is the gate described in docs/TESTS.md
// section 11.
func TestDocumentationIsConsistent(t *testing.T) {
	root, err := FindRepoRoot(".")
	if err != nil {
		t.Fatal(err)
	}
	ps, err := Check(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range ps {
		t.Errorf("%s", p)
	}
}

// TestDocumentationIsConsistentWithWindowsLineEndings runs the same checks
// against the same documents, checked out the way git checks them out on
// Windows.
//
// Every check here is a line-anchored regular expression, and $ in Go's
// multi-line mode knows nothing about a carriage return, so a CRLF checkout
// made every pattern that ends in $ match nothing: the lint reported that every
// ADR was missing from the index that lists it, and every ASR row missing from
// the matrix that has it. The invariants are about the text, not about how a
// platform ends its lines, so the same tree must pass either way — and this
// runs everywhere rather than only on Windows, because a check that only the
// Windows job can fail is a check that fails after the change that broke it.
func TestDocumentationIsConsistentWithWindowsLineEndings(t *testing.T) {
	root, err := FindRepoRoot(".")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	mustCopyTree(t, root+"/docs", dir+"/docs")
	mustWrite(t, dir+"/go.mod", "module example.test\n")
	crlfTree(t, dir)

	ps, err := Check(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range ps {
		t.Errorf("%s", p)
	}
}

// TestDetectsDrift proves the checks can fail. Traceability drift is silent by
// nature, so a lint that cannot demonstrate a failure is not evidence of
// anything.
func TestDetectsDrift(t *testing.T) {
	root, err := FindRepoRoot(".")
	if err != nil {
		t.Fatal(err)
	}

	// A record set that is internally inconsistent must be reported.
	dir := t.TempDir()
	mustCopyTree(t, root+"/docs", dir+"/docs")
	mustWrite(t, dir+"/go.mod", "module example.test\n")

	// Break the bidirectional link: ADR-0001 stops serving ASR-0001, while
	// ASR-0001 still claims it does.
	replaceInFile(t, dir+"/docs/adr/ADR-0001-novel-engine-no-ecosystem-runtime-dependency.md",
		"- **Serves:** ASR-0001,", "- **Serves:**")

	ps, err := Check(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(ps) == 0 {
		t.Fatal("expected traceability drift to be detected, got no problems")
	}

	// And a broken link must be reported.
	dir2 := t.TempDir()
	mustCopyTree(t, root+"/docs", dir2+"/docs")
	mustWrite(t, dir2+"/go.mod", "module example.test\n")
	appendToFile(t, dir2+"/docs/DESIGN.md", "\n[dangling](nope-does-not-exist.md)\n")
	ps2, err := Check(dir2)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, p := range ps2 {
		if p.File == "docs/DESIGN.md" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a broken link in docs/DESIGN.md to be reported, got %v", ps2)
	}
}
