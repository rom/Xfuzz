// Package corpusio moves corpora between Xfuzz and the on-disk layouts other
// fuzzers use.
//
// Interoperating at the level of a directory of files is deliberate. It is the
// one thing every fuzzer in the ecosystem agrees on, it carries no licence
// obligation (ADR-0001), and it means a corpus built over weeks by AFL++ or
// libFuzzer is usable here without anybody rewriting it — and, just as
// importantly, that a corpus built here is not trapped.
package corpusio

import (
	"fmt"
	"strings"
)

// Format is an on-disk corpus layout.
type Format int

// The layouts understood.
const (
	// FormatAuto inspects the directory and picks. Import only.
	FormatAuto Format = iota

	// FormatAFL is an AFL/AFL++ queue directory: files named
	// "id:000123,src:000045,op:havoc,+cov", with a .state subdirectory and a
	// README.txt that are bookkeeping rather than inputs.
	FormatAFL

	// FormatLibFuzzer is a libFuzzer corpus directory: a flat directory whose
	// filenames are the SHA-1 of their contents.
	FormatLibFuzzer

	// FormatRaw is a flat directory of files with no naming convention. It is
	// what a person has when they have collected sample files by hand.
	FormatRaw
)

var formatNames = map[Format]string{
	FormatAuto: "auto", FormatAFL: "afl", FormatLibFuzzer: "libfuzzer", FormatRaw: "raw",
}

func (f Format) String() string {
	if n, ok := formatNames[f]; ok {
		return n
	}
	return fmt.Sprintf("Format(%d)", int(f))
}

// ParseFormat resolves a format name.
func ParseFormat(s string) (Format, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "auto":
		return FormatAuto, nil
	case "afl", "afl++", "aflplusplus":
		return FormatAFL, nil
	case "libfuzzer", "libfuzz", "lf":
		return FormatLibFuzzer, nil
	case "raw", "dir", "files":
		return FormatRaw, nil
	}
	return FormatAuto, fmt.Errorf("corpusio: unknown corpus format %q (want afl, libfuzzer, or raw)", s)
}
