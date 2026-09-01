package corpusio

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/rom/Xfuzz/pkg/corpus"
)

// ExportOptions configures writing a corpus directory.
type ExportOptions struct {
	// Format is the layout to write. FormatAuto is treated as FormatRaw:
	// exporting must never guess, because the guess would be made from the
	// destination directory, which is usually empty.
	Format Format

	// Overwrite permits writing into a directory that already holds files.
	// Without it, a non-empty destination is refused: merging a corpus into an
	// unrelated one by accident is easy, and undoing it is not.
	Overwrite bool

	// FavouredOnly writes just the minimal covering set. That is what a corpus
	// handed to someone else should usually be — it reaches everything the full
	// corpus reaches and is a fraction of the size.
	FavouredOnly bool
}

// ExportReport says what was written.
type ExportReport struct {
	Format  Format
	Dir     string
	Written int
	Bytes   int64
	Skipped int
}

func (r ExportReport) String() string {
	return fmt.Sprintf("%d entries (%d bytes) written to %s as %s",
		r.Written, r.Bytes, r.Dir, r.Format)
}

// Export writes a corpus to a directory in another fuzzer's layout.
//
// Entries must carry their payload in Bytes; an entry loaded from the store
// without one is skipped and counted rather than written empty.
func Export(dir string, tcs []*corpus.Testcase, opts ExportOptions) (ExportReport, error) {
	format := opts.Format
	if format == FormatAuto {
		format = FormatRaw
	}
	rep := ExportReport{Format: format, Dir: dir}

	if format == FormatAFL && !AFLNamesSupported() {
		// Named here rather than discovered on the first file. AFL calls its
		// queue entries `id:000000,orig:...`, a colon is not a character a
		// Windows filename may contain, and the alternative — writing them
		// under some other name — produces a directory that is not an AFL
		// corpus: afl-cmin would not read it and the importer here keys on the
		// same prefix. The interoperation is the whole point of the format, so
		// it is refused rather than approximated.
		return rep, fmt.Errorf("corpusio: the AFL layout names its entries " +
			"`id:000000,orig:...` and this platform's filenames cannot contain " +
			"a colon, so an AFL corpus cannot be written here; export as " +
			"libfuzzer or raw, which name their files portably")
	}

	if err := os.MkdirAll(dir, 0o755); err != nil {
		return rep, fmt.Errorf("corpusio: creating %s: %w", dir, err)
	}
	if !opts.Overwrite {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return rep, fmt.Errorf("corpusio: %w", err)
		}
		if len(entries) > 0 {
			return rep, fmt.Errorf(
				"corpusio: %s already holds %d files; pass Overwrite to merge into it",
				dir, len(entries))
		}
	}

	// Sorted by digest so the export is a function of the corpus and not of the
	// order the caller happened to load it in. An AFL layout numbers its files,
	// and unstable numbering would make two exports of one corpus look like
	// different corpora.
	ordered := make([]*corpus.Testcase, 0, len(tcs))
	for _, tc := range tcs {
		if opts.FavouredOnly && !tc.Meta.Favoured {
			continue
		}
		ordered = append(ordered, tc)
	}
	sort.Slice(ordered, func(i, j int) bool {
		return ordered[i].ID.String() < ordered[j].ID.String()
	})

	for i, tc := range ordered {
		if len(tc.Bytes) == 0 {
			rep.Skipped++
			continue
		}
		name := exportName(format, i, tc)
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, tc.Bytes, 0o644); err != nil {
			return rep, fmt.Errorf("corpusio: writing %s: %w", p, err)
		}
		rep.Written++
		rep.Bytes += int64(len(tc.Bytes))
	}
	return rep, nil
}

// exportName renders one entry's filename in the target layout.
func exportName(format Format, index int, tc *corpus.Testcase) string {
	switch format {
	case FormatAFL:
		// AFL reads only the id field; the rest is informational, and matching
		// its vocabulary means afl-cmin and a person reading the directory both
		// see what they expect. "+cov" is AFL's own marker for an entry that
		// brought new coverage, which is what Favoured means here.
		var b strings.Builder
		fmt.Fprintf(&b, "id:%06d,orig:%s", index, tc.ID.Short())
		if tc.Meta.Favoured {
			b.WriteString(",+cov")
		}
		return b.String()

	case FormatLibFuzzer:
		// libFuzzer names a corpus file after the SHA-1 of its contents. This
		// is not a security use of SHA-1 — it is that tool's filename
		// convention, and a corpus written under any other name is one
		// libFuzzer's own merge will duplicate rather than recognise.
		sum := sha1.Sum(tc.Bytes)
		return hex.EncodeToString(sum[:])

	default:
		return tc.ID.String() + ".bin"
	}
}

// AFLNamesSupported reports whether this platform allows a colon in a
// filename, which is what the AFL layout requires.
//
// Probed rather than assumed from the operating system's name: the answer
// belongs to the filesystem, and a Unix host with a mounted share behaves like
// the share.
func AFLNamesSupported() bool {
	dir, err := os.MkdirTemp("", "xfuzz-name-probe-")
	if err != nil {
		return true // Not the question being asked; let the write report it.
	}
	defer os.RemoveAll(dir)

	p := filepath.Join(dir, "id:000000,orig:probe")
	if err := os.WriteFile(p, nil, 0o644); err != nil {
		return false
	}
	return true
}
