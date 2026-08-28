package corpusio

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/rom/Xfuzz/pkg/corpus"
)

// DefaultMaxFileSize caps what import will read from a single file.
//
// An imported corpus is not trusted input in the security sense, but it is
// unvetted: a stray core dump or a video file in a seed directory should be
// skipped with a reason, not loaded into memory and then mutated for a week.
const DefaultMaxFileSize = 16 << 20

// NoLimit disables a limit.
const NoLimit = -1

// ImportOptions configures reading a corpus directory.
type ImportOptions struct {
	// Format is the layout to expect. FormatAuto detects it.
	Format Format

	// MaxFileSize caps individual files. Zero means DefaultMaxFileSize,
	// NoLimit means no cap.
	MaxFileSize int64

	// MaxFiles caps how many entries are imported. Zero means no cap.
	MaxFiles int

	// Recursive descends into subdirectories. Off by default, because the
	// layouts this package understands are flat and a recursive walk of an AFL
	// output directory would sweep up crashes and hangs as if they were seeds.
	Recursive bool

	// Origin is recorded in each entry's provenance. Empty means the format
	// name and the source file, which is what makes an imported entry traceable
	// back to where it came from months later.
	Origin string
}

// ImportReport says what happened, entry by entry.
//
// Import is one of the few places where a silent partial success is likely: a
// directory of a thousand files where forty were skipped looks exactly like one
// where none were, unless somebody counts. So the counts are returned, with the
// reasons.
type ImportReport struct {
	// Format is what was used, after detection.
	Format Format

	// Dir is the directory actually read, which may be a subdirectory of the
	// one given — an AFL output directory contains the queue rather than being
	// it.
	Dir string

	// Imported is how many distinct entries were produced.
	Imported int

	// Duplicate counts files whose content matched an entry already imported.
	// On a merged corpus this is often most of them, and it is the number that
	// tells a person the merge was worth doing.
	Duplicate int

	// Skipped counts files not imported, by reason.
	Skipped int
	Reasons map[string]int

	// Bytes is the total imported payload size.
	Bytes int64
}

func (r *ImportReport) skip(reason string) {
	r.Skipped++
	if r.Reasons == nil {
		r.Reasons = map[string]int{}
	}
	r.Reasons[reason]++
}

// String renders the report as one line, for a CLI.
func (r ImportReport) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%d imported (%d bytes) from %s as %s", r.Imported, r.Bytes, r.Dir, r.Format)
	if r.Duplicate > 0 {
		fmt.Fprintf(&b, ", %d duplicates", r.Duplicate)
	}
	if r.Skipped > 0 {
		reasons := make([]string, 0, len(r.Reasons))
		for k, v := range r.Reasons {
			reasons = append(reasons, fmt.Sprintf("%s×%d", k, v))
		}
		sort.Strings(reasons)
		fmt.Fprintf(&b, ", %d skipped (%s)", r.Skipped, strings.Join(reasons, ", "))
	}
	return b.String()
}

// aflEntryRe matches an AFL queue filename.
var aflEntryRe = regexp.MustCompile(`^id[:_]\d+`)

// hexNameRe matches a libFuzzer corpus filename: the SHA-1 of the content.
var hexNameRe = regexp.MustCompile(`^[0-9a-f]{40}$`)

// Import reads a corpus directory.
//
// Entries are de-duplicated by content, which is the whole point of importing
// several corpora into one campaign: three AFL runs of the same target share
// most of their queue, and keeping three copies would triple the scheduling cost
// of the same coverage.
func Import(dir string, opts ImportOptions) ([]*corpus.Testcase, ImportReport, error) {
	rep := ImportReport{Format: opts.Format}

	root, err := resolveDir(dir, opts.Format)
	if err != nil {
		return nil, rep, err
	}
	rep.Dir = root

	if opts.Format == FormatAuto {
		rep.Format, err = detectFormat(root)
		if err != nil {
			return nil, rep, err
		}
	}
	maxSize := opts.MaxFileSize
	switch {
	case maxSize == 0:
		maxSize = DefaultMaxFileSize
	case maxSize == NoLimit:
		maxSize = 0
	}

	paths, err := listFiles(root, rep.Format, opts.Recursive, &rep)
	if err != nil {
		return nil, rep, err
	}
	// Sorted so that importing the same directory twice produces the same
	// corpus in the same order. Directory order is not defined, and a corpus
	// whose scheduling order depends on the filesystem is not reproducible
	// (ASR-0008).
	sort.Strings(paths)

	seen := make(map[corpus.Digest]bool, len(paths))
	out := make([]*corpus.Testcase, 0, len(paths))

	for _, p := range paths {
		if opts.MaxFiles > 0 && len(out) >= opts.MaxFiles {
			rep.skip("over-file-limit")
			continue
		}
		fi, err := os.Stat(p)
		if err != nil {
			rep.skip("unreadable")
			continue
		}
		if fi.Size() == 0 {
			// An empty seed is not a seed. It carries no structure to mutate
			// and every fuzzer that writes one is writing a placeholder.
			rep.skip("empty")
			continue
		}
		if maxSize > 0 && fi.Size() > maxSize {
			rep.skip("too-large")
			continue
		}
		data, err := os.ReadFile(p)
		if err != nil {
			rep.skip("unreadable")
			continue
		}
		d := corpus.DigestOf(data)
		if seen[d] {
			rep.Duplicate++
			continue
		}
		seen[d] = true

		tc := corpus.NewTestcase(nil, data)
		tc.Prov.Origin = originFor(opts.Origin, rep.Format, root, p)
		out = append(out, tc)
		rep.Imported++
		rep.Bytes += int64(len(data))
	}
	return out, rep, nil
}

// resolveDir finds the directory that actually holds the inputs.
//
// People pass the AFL output directory, not the queue inside it, because that
// is the path afl-fuzz printed. Following the convention here is the difference
// between "imported 0 entries" and the thing working.
func resolveDir(dir string, format Format) (string, error) {
	fi, err := os.Stat(dir)
	if err != nil {
		return "", fmt.Errorf("corpusio: %w", err)
	}
	if !fi.IsDir() {
		return "", fmt.Errorf("corpusio: %s is not a directory", dir)
	}
	if format == FormatLibFuzzer || format == FormatRaw {
		return dir, nil
	}
	for _, candidate := range []string{
		filepath.Join(dir, "queue"),
		filepath.Join(dir, "default", "queue"),
	} {
		if fi, err := os.Stat(candidate); err == nil && fi.IsDir() {
			return candidate, nil
		}
	}
	return dir, nil
}

// detectFormat guesses a layout from its filenames.
//
// It is a guess and it is treated as one: every layout here is "a directory of
// files", so guessing wrong costs only the provenance label and which
// bookkeeping files get skipped, never the payloads.
func detectFormat(dir string) (Format, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return FormatRaw, fmt.Errorf("corpusio: %w", err)
	}
	var afl, hex, total int
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		total++
		switch {
		case aflEntryRe.MatchString(e.Name()):
			afl++
		case hexNameRe.MatchString(e.Name()):
			hex++
		}
	}
	switch {
	case total == 0:
		return FormatRaw, nil
	case afl*2 > total:
		return FormatAFL, nil
	case hex*2 > total:
		return FormatLibFuzzer, nil
	}
	return FormatRaw, nil
}

// aflBookkeeping are files an AFL queue directory contains that are not inputs.
var aflBookkeeping = map[string]bool{
	"README.txt": true, ".state": true, "fuzzer_stats": true,
	"fuzz_bitmap": true, "plot_data": true, "cmdline": true, "fuzzer_setup": true,
}

func listFiles(root string, format Format, recursive bool, rep *ImportReport) ([]string, error) {
	var out []string
	err := filepath.WalkDir(root, func(p string, e fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		name := e.Name()
		if e.IsDir() {
			if p == root {
				return nil
			}
			if format == FormatAFL && aflBookkeeping[name] {
				return fs.SkipDir
			}
			if !recursive {
				return fs.SkipDir
			}
			return nil
		}
		if format == FormatAFL && aflBookkeeping[name] {
			return nil
		}
		if strings.HasPrefix(name, ".") {
			return nil
		}
		if !e.Type().IsRegular() {
			rep.skip("not-a-regular-file")
			return nil
		}
		out = append(out, p)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("corpusio: walking %s: %w", root, err)
	}
	return out, nil
}

func originFor(explicit string, format Format, root, path string) string {
	if explicit != "" {
		return explicit
	}
	rel, err := filepath.Rel(root, path)
	if err != nil {
		rel = filepath.Base(path)
	}
	return format.String() + ":" + filepath.ToSlash(rel)
}
