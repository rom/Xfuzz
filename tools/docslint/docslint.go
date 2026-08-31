// Package docslint checks the documentation invariants that docs/TESTS.md
// section 11 promises are enforced in CI.
//
// The decision records are only useful if they stay consistent with each other.
// Traceability drifts silently: an ADR gains an ASR in its header, the index and
// the matrix are not updated, and the claim that "every ASR is satisfied by at
// least one ADR" quietly stops being true. These checks make that drift a build
// failure.
package docslint

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Problem is a single documentation inconsistency.
type Problem struct {
	File string
	Msg  string
}

func (p Problem) String() string { return p.File + ": " + p.Msg }

var (
	linkRe    = regexp.MustCompile(`\[([^\]]*)\]\(([^)\s]+)\)`)
	servesRe  = regexp.MustCompile(`(?m)^- \*\*Serves:\*\* (.+)$`)
	satisfyRe = regexp.MustCompile(`(?s)## Satisfied by\s*\n\s*\n(.*?)(?:\n\n|\n*$)`)
	adrIDRe   = regexp.MustCompile(`ADR-\d{4}`)
	asrIDRe   = regexp.MustCompile(`ASR-\d{4}`)
	adrRowRe  = regexp.MustCompile(`(?m)^\| \[(ADR-\d{4})\][^|]*\|[^|]*\|[^|]*\| (.+?) \|$`)
	asrRowRe  = regexp.MustCompile(`(?m)^\| \[(ASR-\d{4})\]`)
	matrixRe  = regexp.MustCompile(`(?m)^\| (ASR-\d{4})[^|]*\| (.+?) \|$`)
	statusRe  = regexp.MustCompile(`(?m)^- \*\*Status:\*\* (.+)$`)
)

// Check runs every documentation invariant against the repository at dir.
func Check(dir string) ([]Problem, error) {
	var ps []Problem

	links, err := checkLinks(dir)
	if err != nil {
		return nil, err
	}
	ps = append(ps, links...)

	trace, err := checkTraceability(dir)
	if err != nil {
		return nil, err
	}
	ps = append(ps, trace...)

	sort.Slice(ps, func(i, j int) bool {
		if ps[i].File != ps[j].File {
			return ps[i].File < ps[j].File
		}
		return ps[i].Msg < ps[j].Msg
	})
	return ps, nil
}

// checkLinks verifies that every relative markdown link resolves to a file that
// exists. Broken cross-references are the most common way a decision record set
// rots.
func checkLinks(dir string) ([]Problem, error) {
	var ps []Problem
	err := walkMarkdown(dir, func(rel string, body []byte) error {
		for _, m := range linkRe.FindAllStringSubmatch(string(body), -1) {
			target := m[2]
			switch {
			case strings.HasPrefix(target, "http://"),
				strings.HasPrefix(target, "https://"),
				strings.HasPrefix(target, "mailto:"),
				strings.HasPrefix(target, "#"):
				continue
			}
			path, _, _ := strings.Cut(target, "#")
			if path == "" {
				continue
			}
			abs := filepath.Join(dir, filepath.FromSlash(filepath.Dir(rel)), filepath.FromSlash(path))
			if _, err := os.Stat(abs); err != nil {
				ps = append(ps, Problem{rel, fmt.Sprintf("broken link [%s](%s)", m[1], target)})
			}
		}
		return nil
	})
	return ps, err
}

// checkTraceability enforces the bidirectional ASR/ADR relationship and its
// three representations: the record headers, the two indexes, and the matrix in
// ARCHITECTURE.md. All three must agree.
func checkTraceability(dir string) ([]Problem, error) {
	var ps []Problem

	adrDir := filepath.Join(dir, "docs", "adr")
	asrDir := filepath.Join(dir, "docs", "asr")

	adrServes, err := readRecords(adrDir, "ADR-", func(body string) []string {
		m := servesRe.FindStringSubmatch(body)
		if m == nil {
			return nil
		}
		return asrIDRe.FindAllString(m[1], -1)
	}, func(rel, body string) []Problem {
		var out []Problem
		if !servesRe.MatchString(body) {
			out = append(out, Problem{rel, "missing '- **Serves:**' header line"})
		}
		if !statusRe.MatchString(body) {
			out = append(out, Problem{rel, "missing '- **Status:**' header line"})
		}
		return out
	}, &ps)
	if err != nil {
		return nil, err
	}

	asrSatisfied, err := readRecords(asrDir, "ASR-", func(body string) []string {
		m := satisfyRe.FindStringSubmatch(body)
		if m == nil {
			return nil
		}
		return adrIDRe.FindAllString(m[1], -1)
	}, func(rel, body string) []Problem {
		var out []Problem
		if !satisfyRe.MatchString(body) {
			out = append(out, Problem{rel, "missing '## Satisfied by' section"})
		}
		if !statusRe.MatchString(body) {
			out = append(out, Problem{rel, "missing '- **Status:**' header line"})
		}
		return out
	}, &ps)
	if err != nil {
		return nil, err
	}

	// Every ASR must be satisfied by at least one ADR.
	for id, adrs := range asrSatisfied {
		if len(adrs) == 0 {
			ps = append(ps, Problem{"docs/asr/" + id, "no satisfying ADR: every requirement must be answered by a decision"})
		}
	}

	// Bidirectional consistency between record headers.
	for adr, asrs := range adrServes {
		for _, asr := range asrs {
			if !contains(asrSatisfied[asr], adr) {
				ps = append(ps, Problem{"docs/asr/" + asr,
					fmt.Sprintf("%s claims to serve it, but its 'Satisfied by' section omits %s", adr, adr)})
			}
		}
	}
	for asr, adrs := range asrSatisfied {
		for _, adr := range adrs {
			if _, known := adrServes[adr]; !known {
				ps = append(ps, Problem{"docs/asr/" + asr, fmt.Sprintf("names %s, which does not exist", adr)})
				continue
			}
			if !contains(adrServes[adr], asr) {
				ps = append(ps, Problem{"docs/adr/" + adr,
					fmt.Sprintf("%s lists it as satisfying, but its 'Serves' header omits %s", asr, asr)})
			}
		}
	}

	// The ADR index's Serves column must match the record headers.
	adrIndex, err := readDoc(filepath.Join(adrDir, "README.md"))
	if err != nil {
		return nil, err
	}
	indexed := map[string]bool{}
	for _, row := range adrRowRe.FindAllStringSubmatch(string(adrIndex), -1) {
		id := row[1]
		indexed[id] = true
		got := asrIDRe.FindAllString(row[2], -1)
		want := adrServes[id]
		if !sameSet(got, want) {
			ps = append(ps, Problem{"docs/adr/README.md",
				fmt.Sprintf("%s index row lists %v but the record's Serves header says %v", id, got, want)})
		}
	}
	for id := range adrServes {
		if !indexed[id] {
			ps = append(ps, Problem{"docs/adr/README.md", id + " is not listed in the index"})
		}
	}

	// The ASR index must list every ASR.
	asrIndex, err := readDoc(filepath.Join(asrDir, "README.md"))
	if err != nil {
		return nil, err
	}
	asrIndexed := map[string]bool{}
	for _, row := range asrRowRe.FindAllStringSubmatch(string(asrIndex), -1) {
		asrIndexed[row[1]] = true
	}
	for id := range asrSatisfied {
		if !asrIndexed[id] {
			ps = append(ps, Problem{"docs/asr/README.md", id + " is not listed in the index"})
		}
	}

	// The ARCHITECTURE.md matrix must match the ASR records.
	arch, err := readDoc(filepath.Join(dir, "docs", "ARCHITECTURE.md"))
	if err != nil {
		return nil, err
	}
	inMatrix := map[string]bool{}
	for _, row := range matrixRe.FindAllStringSubmatch(string(arch), -1) {
		id := row[1]
		inMatrix[id] = true
		got := adrIDRe.FindAllString(row[2], -1)
		if !sameSet(got, asrSatisfied[id]) {
			ps = append(ps, Problem{"docs/ARCHITECTURE.md",
				fmt.Sprintf("traceability matrix row %s lists %v but the record says %v", id, got, asrSatisfied[id])})
		}
	}
	for id := range asrSatisfied {
		if !inMatrix[id] {
			ps = append(ps, Problem{"docs/ARCHITECTURE.md", "traceability matrix is missing a row for " + id})
		}
	}

	return ps, nil
}

// readRecords loads every record file with the given prefix, extracting its
// cross-references and running per-file structural checks.
func readRecords(dir, prefix string, extract func(string) []string,
	validate func(rel, body string) []Problem, ps *[]Problem) (map[string][]string, error) {

	out := map[string][]string{}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasPrefix(name, prefix) || !strings.HasSuffix(name, ".md") {
			continue
		}
		body, err := readDoc(filepath.Join(dir, name))
		if err != nil {
			return nil, err
		}
		rel := filepath.ToSlash(filepath.Join(filepath.Base(dir), name))
		*ps = append(*ps, validate("docs/"+rel, string(body))...)
		out[name[:8]] = extract(string(body))
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no %s records found in %s", prefix, dir)
	}
	return out, nil
}

// readDoc reads a documentation file with its line endings normalised.
//
// Every check here is a line-anchored regular expression, and Go's ^ and $ in
// multi-line mode anchor around \n and know nothing about \r. A checkout with
// CRLF endings — which is what git gives on Windows by default — therefore
// leaves a \r at the end of every line, so a pattern ending in $ matches
// nothing and every ADR is reported as missing from an index that lists it.
// The invariants are about the text, not about how a platform ends its lines.
func readDoc(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return normaliseEndings(b), nil
}

// normaliseEndings turns CRLF and a lone CR into LF.
func normaliseEndings(b []byte) []byte {
	b = bytes.ReplaceAll(b, []byte("\r\n"), []byte("\n"))
	return bytes.ReplaceAll(b, []byte("\r"), []byte("\n"))
}

func walkMarkdown(dir string, fn func(rel string, body []byte) error) error {
	return filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "vendor", "dist":
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".md") {
			return nil
		}
		body, err := readDoc(path)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		return fn(filepath.ToSlash(rel), body)
	})
}

func contains(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

func sameSet(a, b []string) bool {
	as, bs := append([]string(nil), a...), append([]string(nil), b...)
	sort.Strings(as)
	sort.Strings(bs)
	if len(as) != len(bs) {
		return false
	}
	for i := range as {
		if as[i] != bs[i] {
			return false
		}
	}
	return true
}

// FindRepoRoot walks up from start until it finds the directory holding go.mod.
func FindRepoRoot(start string) (string, error) {
	d, err := filepath.Abs(start)
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(d, "go.mod")); err == nil {
			return d, nil
		}
		parent := filepath.Dir(d)
		if parent == d {
			return "", fmt.Errorf("no go.mod found above %s", start)
		}
		d = parent
	}
}
