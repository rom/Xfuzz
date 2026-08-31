package schemaio

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/rom/Xfuzz/pkg/schema"
)

// Importer reads a foreign format description.
type Importer interface {
	// Name is what a campaign file and the command line call it.
	Name() string

	// Extensions are the file suffixes this importer claims, for Detect.
	Extensions() []string

	// Import translates a description into a schema, and reports what it could
	// not translate.
	//
	// A schema and a report, always both. An importer that returned only a
	// schema would be telling the caller that the translation was complete,
	// which for every one of these languages is a claim nobody can make.
	Import(src []byte, filename string) (*schema.Schema, *Report, error)
}

// Note is one thing an importer could not translate.
type Note struct {
	// Where locates the construct in the source, as precisely as the importer
	// can manage.
	Where string

	// What names the construct: "prose-val", "oneof", "instance".
	What string

	// Why explains what the schema language cannot express, in terms of the
	// grammar rather than of the code. Somebody reading this is deciding
	// whether to hand-write the missing part.
	Why string
}

func (n Note) String() string {
	s := n.What
	if n.Where != "" {
		s = n.Where + ": " + s
	}
	if n.Why != "" {
		s += " — " + n.Why
	}
	return s
}

// Report is what an import produced and what it left behind.
type Report struct {
	// Source names the importer.
	Source string

	// File is the description that was read.
	File string

	// Types is how many types the schema ended up with, and Fields how many
	// fields across them.
	Types  int
	Fields int

	// Notes are the constructs that did not survive the translation.
	Notes []Note
}

// Add records something that could not be translated.
func (r *Report) Add(where, what, why string) {
	if r == nil {
		return
	}
	r.Notes = append(r.Notes, Note{Where: where, What: what, Why: why})
}

// Complete reports whether everything in the source was translated.
func (r *Report) Complete() bool { return r == nil || len(r.Notes) == 0 }

// Summarise groups the notes by construct, so a report on a large document says
// "142 prose-val" rather than listing them.
func (r *Report) Summarise() []string {
	if r == nil || len(r.Notes) == 0 {
		return nil
	}
	counts := map[string]int{}
	why := map[string]string{}
	for _, n := range r.Notes {
		counts[n.What]++
		if why[n.What] == "" {
			why[n.What] = n.Why
		}
	}
	kinds := make([]string, 0, len(counts))
	for k := range counts {
		kinds = append(kinds, k)
	}
	sort.Strings(kinds)
	out := make([]string, 0, len(kinds))
	for _, k := range kinds {
		line := fmt.Sprintf("%s (%d)", k, counts[k])
		if why[k] != "" {
			line += ": " + why[k]
		}
		out = append(out, line)
	}
	return out
}

func (r *Report) String() string {
	if r == nil {
		return ""
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s: %d types, %d fields", r.Source, r.Types, r.Fields)
	if len(r.Notes) == 0 {
		b.WriteString("; everything in the source was translated\n")
		return b.String()
	}
	fmt.Fprintf(&b, "; %d constructs not translated:\n", len(r.Notes))
	for _, line := range r.Summarise() {
		b.WriteString("  " + line + "\n")
	}
	return b.String()
}

// registry holds the importers, in the order a report should list them.
var registry = []Importer{
	ABNF{}, Kaitai{},
}

// Importers lists every importer.
func Importers() []Importer { return append([]Importer(nil), registry...) }

// Names lists the importers by name, sorted.
func Names() []string {
	out := make([]string, 0, len(registry))
	for _, imp := range registry {
		out = append(out, imp.Name())
	}
	sort.Strings(out)
	return out
}

// For returns the importer with a given name.
func For(name string) (Importer, bool) {
	for _, imp := range registry {
		if imp.Name() == name {
			return imp, true
		}
	}
	return nil, false
}

// Detect guesses which importer a file needs.
//
// By extension first, because that is what the author of the file meant. Only
// where the extension is ambiguous — .yaml and .json are used by three of these
// — does it look inside, and then only for a key that is diagnostic rather than
// merely present.
func Detect(filename string, src []byte) (Importer, bool) {
	ext := strings.ToLower(filepath.Ext(filename))
	var candidates []Importer
	for _, imp := range registry {
		for _, e := range imp.Extensions() {
			if e == ext {
				candidates = append(candidates, imp)
			}
		}
	}
	switch len(candidates) {
	case 1:
		return candidates[0], true
	case 0:
		return nil, false
	}
	head := string(src)
	if len(head) > 4096 {
		head = head[:4096]
	}
	for _, imp := range candidates {
		if s, ok := imp.(sniffer); ok && s.sniff(head) {
			return imp, true
		}
	}
	return candidates[0], true
}

// sniffer is an importer that can recognise its own content, for the file
// extensions more than one of them claims.
type sniffer interface{ sniff(head string) bool }

// ImportFile reads a description with whichever importer its name implies.
func ImportFile(filename string, src []byte) (*schema.Schema, *Report, error) {
	imp, ok := Detect(filename, src)
	if !ok {
		return nil, nil, fmt.Errorf("schemaio: nothing imports %q; known importers are %s",
			filepath.Ext(filename), strings.Join(Names(), ", "))
	}
	return imp.Import(src, filename)
}
