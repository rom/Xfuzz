package triage

import (
	"strings"
	"testing"

	"github.com/rom/Xfuzz/pkg/feedback"
)

// FuzzClassify fuzzes the sanitizer-output parser and the bucketing built on
// it.
//
// A target's output is the most reliably hostile input Xfuzz handles: it is
// produced by a program the fuzzer is deliberately driving into undefined
// behaviour, with bytes the fuzzer itself chose. A sanitizer report is
// something to be parsed *because* the program producing it has already lost
// control, and half of one is the normal case rather than the exception.
//
// Classification and bucketing together, because they are the pair that
// decides whether two crashes are the same bug. A panic here loses a campaign's
// findings at the last step, after the executions that earned them.
func FuzzClassify(f *testing.F) {
	f.Add("==1234==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000018\n"+
		"    #0 0x4f1a2b in parse /src/parse.c:42\n"+
		"    #1 0x4f2c3d in main /src/main.c:10\n", 11, 1)
	f.Add("panic: runtime error: index out of range [5] with length 3\n\ngoroutine 1 [running]:\n"+
		"main.parse(...)\n\t/src/main.go:12 +0x1d\n", 0, 0)
	f.Add("Assertion failed: (n < len), function parse, file parse.c, line 42.\n", 6, 0)
	f.Add("thread 'main' panicked at 'index out of bounds', src/main.rs:12:5\n", 6, 0)
	f.Add("    #0 \n    #1 \n    #2 \n", 11, 1)
	f.Add("==ERROR: ", 11, 1)
	f.Add("", 0, 4)

	f.Fuzz(func(t *testing.T, output string, signal int, exit int) {
		// Bounded, because the fuzzer explores length before shape and a
		// megabyte of one repeated byte teaches nothing that a kilobyte does
		// not.
		if len(output) > 1<<16 {
			return
		}
		kinds := []feedback.ExitKind{
			feedback.ExitOK, feedback.ExitCrash, feedback.ExitTimeout,
			feedback.ExitOOM, feedback.ExitError,
		}
		o := Outcome{
			Exit:   kinds[((exit%len(kinds))+len(kinds))%len(kinds)],
			Signal: signal,
			Output: output,
		}

		c := Classify(o)
		if c.Kind == "" {
			t.Fatal("classification produced no kind; every outcome has one, including ok")
		}
		// A marker is the target's own words about its failure, and it ends up
		// in a bucket key and a finding summary. An unbounded one would make
		// both unreadable and the bucket effectively unique per crash.
		if len(c.Marker) > maxMarkerBytes {
			t.Fatalf("marker is %d bytes; it is a bucket key, not a transcript", len(c.Marker))
		}
		if strings.ContainsAny(c.Marker, "\n\r") {
			t.Fatalf("marker spans lines: %q", c.Marker)
		}

		for _, name := range []string{"signal", "marker", "frames", "coverage", "chain"} {
			strategy, sig := Bucket(StrategyNamed(name), o, c)
			if strategy == "" || sig == "" {
				t.Fatalf("strategy %q produced an empty bucket (%q, %q); "+
					"an empty signature merges every unclassifiable finding with every other",
					name, strategy, sig)
			}
		}
	})
}

// maxMarkerBytes is the ceiling a marker must respect. It is a bucket key and a
// summary line, so it has to fit on one.
const maxMarkerBytes = 512
