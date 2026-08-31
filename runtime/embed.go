// Package xfuzzrt carries the C coverage runtime that gets compiled into
// instrumented targets.
//
// The source is embedded so that xfuzz-cc is a single self-contained binary: an
// operator installing Xfuzz on a build host should not also have to place a C
// file somewhere and keep the two versions in step.
//
// The runtime is compiled into the target, never into Xfuzz. Xfuzz itself stays
// pure Go (ADR-0017).
//
// The C source sits in csrc/ rather than beside this file because the Go
// toolchain refuses a .c file in a package directory unless cgo is enabled, and
// enabling cgo here would defeat the point.
package xfuzzrt

import (
	_ "embed"
	"strings"
)

//go:embed csrc/xfuzz-rt.c
var source string

// Source returns the C runtime, for compilation and for audit. Anyone asked to
// link this into their software is entitled to read it first, which is why
// xfuzz-cc can print it.
func Source() string { return source }

// MapSize is the coverage map size the runtime uses. It must match
// feedback.DefaultMapSize; a mismatch means the fuzzer reads a different map
// than the target writes, and coverage silently disappears.
const MapSize = 1 << 16

// Environment variables the runtime reads.
const (
	// EnvShmID names the file backing the shared coverage map.
	EnvShmID = "XFUZZ_SHM_ID"
	// EnvForkServer, when set, makes the target start a fork server.
	EnvForkServer = "XFUZZ_FORKSERVER"
	// EnvControlFD and EnvStatusFD override the fork server's descriptors.
	EnvControlFD = "XFUZZ_CTL_FD"
	EnvStatusFD  = "XFUZZ_ST_FD"
	// EnvDeferInit suppresses the automatic constructor so a target can start
	// the fork server itself, after its own initialisation.
	EnvDeferInit = "XFUZZ_DEFER_INIT"
	// EnvCmpID names the file backing the comparison table. A target that is not
	// given it records no comparisons, which is how a campaign that does not
	// want them avoids paying for them.
	EnvCmpID = "XFUZZ_CMP_ID"
)

// Hello is the handshake word a live runtime writes on startup.
//
// It must match XFUZZ_HELLO in the C source and forkServerHello in
// pkg/executor. It read XFZ1 here while the runtime and the fork server had both
// moved to XFZ2: nothing used this copy, so nothing broke, and the first caller
// to reach for it would have rejected every working target as not carrying a
// runtime at all.
const Hello uint32 = 0x58465A32 // "XFZ2"

// CmpRegionSize is the size of the comparison table the runtime writes, matching
// XFUZZ_CMP_SIZE. It must equal feedback.CmpRegionSize.
const CmpRegionSize = 1 << 18

// InstrumentFlags are the compiler flags that install the coverage callbacks.
//
// The "bb" level matters and is easy to get wrong. Without an explicit level
// clang defaults to "func", one guard per function, which reports which
// functions ran and nothing about which paths through them — a coverage signal
// that cannot distinguish two inputs taking different branches of the same
// function, so coverage-guided fuzzing degrades to random.
//
// "bb" rather than "edge" because the runtime derives edges itself, by XOR-ing
// consecutive block identifiers. Clang's "edge" level prunes blocks whose
// coverage it considers implied, which measurably loses discrimination here:
// on the planted-bug targets it reported identical coverage for inputs taking
// visibly different paths, while "bb" separated them.
//
// "no-prune" keeps blocks clang would otherwise drop as redundant. Its pruning
// is sound for answering "was this code reached", which is what coverage
// reporting needs, and lossy for answering "did this input go somewhere new",
// which is what a fuzzer needs. On the planted-bug targets it roughly doubled
// the coverage signal: 8 entries against 15 across the same inputs.
var InstrumentFlags = []string{"-fsanitize-coverage=bb,no-prune,trace-pc-guard,trace-cmp"}

// CmpFlag is the part of the instrumentation that logs comparison operands.
//
// Included by default, and removable with XFUZZ_NO_CMPLOG, because it is what
// gets a campaign past a magic number and a checksum — the comparisons a fuzzer
// cannot guess (ADR-0007). The callbacks are inert unless the fuzzer attached
// the comparison region, so a target built with it and fuzzed without it pays
// one predictable branch per comparison rather than a write.
//
// Separable rather than always-on because the branch is not free on a target
// whose hot loop is comparisons, and because someone auditing what Xfuzz asks
// their compiler to do should be able to turn each piece off by name.
const CmpFlag = "trace-cmp"

// InstrumentFlagsWithout returns the instrumentation flags with one feature
// removed.
func InstrumentFlagsWithout(feature string) []string {
	out := make([]string, 0, len(InstrumentFlags))
	for _, f := range InstrumentFlags {
		out = append(out, removeFeature(f, feature))
	}
	return out
}

// removeFeature drops one comma-separated feature from a -fsanitize-coverage
// argument, leaving the rest as they were.
func removeFeature(flag, feature string) string {
	const prefix = "-fsanitize-coverage="
	if !strings.HasPrefix(flag, prefix) {
		return flag
	}
	parts := strings.Split(flag[len(prefix):], ",")
	kept := parts[:0]
	for _, p := range parts {
		if p != feature {
			kept = append(kept, p)
		}
	}
	return prefix + strings.Join(kept, ",")
}
