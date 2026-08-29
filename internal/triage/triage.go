// Package triage turns crashes into findings.
//
// A fuzzer that reports every crashing input reports the same bug ten thousand
// times, in inputs too large to read, some of which do not crash again. Triage
// is what makes that output usable: it verifies that a reproducer reproduces,
// shrinks it to something a person can look at, and groups the survivors so the
// count on the screen is a count of bugs rather than of executions.
//
// It is asynchronous by construction. Every operation here re-runs the target —
// minimisation runs it hundreds of times — and none of it may happen on the
// fuzz loop's thread (ARCHITECTURE section 4). The engine records a finding and
// moves on; a worker in this package picks it up.
package triage

import (
	"context"
	"fmt"
	"strings"

	"github.com/rom/Xfuzz/pkg/feedback"
)

// Outcome is one execution of a candidate input, as triage sees it.
//
// Triage owns no executor. It is handed something that can run an input, which
// keeps this package free of the delivery mechanism and lets the same code
// triage a file target, a network session, or a fake in a test.
type Outcome struct {
	// Exit is how the execution ended.
	Exit feedback.ExitKind

	// Signal is the fatal signal, when there was one.
	Signal int

	// Output is the target's combined stdout and stderr.
	Output string

	// Coverage is a snapshot of the coverage map for this execution, or nil
	// when the target is not instrumented. Bucketing uses it when frames are
	// not available, which on a black-box target is always.
	Coverage []byte

	// Finding is what the objectives reported, if the caller ran them.
	Finding feedback.Finding
}

// Crashed reports whether the outcome is one worth triaging.
func (o Outcome) Crashed() bool {
	switch o.Exit {
	case feedback.ExitCrash, feedback.ExitTimeout, feedback.ExitOOM:
		return true
	}
	// A sanitizer can report without a fatal signal: LeakSanitizer and UBSan
	// both do. Treating a clean exit as uninteresting would lose them.
	return o.Finding.Kind != "" && o.Finding.Kind != "ok"
}

// Runner executes a candidate input.
//
// Implementations must be safe to call repeatedly with the same input and must
// not retain the slice.
type Runner interface {
	Run(ctx context.Context, input []byte) (Outcome, error)
}

// RunnerFunc adapts a function to Runner.
type RunnerFunc func(ctx context.Context, input []byte) (Outcome, error)

// Run implements Runner.
func (f RunnerFunc) Run(ctx context.Context, input []byte) (Outcome, error) { return f(ctx, input) }

// Class is the identity of a crash, at the coarsest level that is still a fact
// rather than a guess.
//
// It answers "is this the same kind of failure", which is what minimisation has
// to preserve. It deliberately does not answer "is this the same bug" — that is
// bucketing's question, it is a judgement, and conflating the two would let a
// minimiser wander from one bug to another while believing it had preserved the
// crash.
type Class struct {
	Kind   string
	Signal int

	// Marker is a distinguishing line from the target's own output. Planted-bug
	// targets print one; so do assertion failures, panics, and sanitizer
	// summaries in real programs.
	Marker string
}

// String renders the class.
func (c Class) String() string {
	var b strings.Builder
	b.WriteString(c.Kind)
	if c.Signal != 0 {
		fmt.Fprintf(&b, "/sig%d", c.Signal)
	}
	if c.Marker != "" {
		b.WriteString("/" + c.Marker)
	}
	return b.String()
}

// Equal reports whether two outcomes are the same kind of failure.
func (c Class) Equal(o Class) bool {
	return c.Kind == o.Kind && c.Signal == o.Signal && c.Marker == o.Marker
}

// Classifier turns outcomes into classes.
//
// The marker prefixes are configurable because a program that names its own
// failures is giving better evidence than any signal number, and every codebase
// names them differently. The default set is generic and deliberately short: a
// line wrongly taken for a failure marker splits one bug across many buckets,
// which is worse than not recognising it at all.
type Classifier struct {
	MarkerPrefixes []string
}

// DefaultClassifier recognises the failure markers common to C, C++, and Go.
var DefaultClassifier = &Classifier{MarkerPrefixes: genericMarkerPrefixes}

// NewClassifier returns a classifier that also recognises a campaign's own
// markers.
//
// The generic set is kept rather than replaced. A target that prints its own
// diagnostic can still die of an assertion in a library it did not write, and a
// campaign that named one marker should not thereby stop recognising the other.
func NewClassifier(extra ...string) *Classifier {
	if len(extra) == 0 {
		return DefaultClassifier
	}
	prefixes := make([]string, 0, len(genericMarkerPrefixes)+len(extra))
	prefixes = append(prefixes, extra...)
	prefixes = append(prefixes, genericMarkerPrefixes...)
	return &Classifier{MarkerPrefixes: prefixes}
}

// Classify reduces an outcome to its class, using the default classifier.
func Classify(o Outcome) Class { return DefaultClassifier.Classify(o) }

// Classify reduces an outcome to its class.
func (cl *Classifier) Classify(o Outcome) Class {
	c := Class{Signal: o.Signal}
	switch {
	case o.Finding.Kind != "":
		c.Kind = o.Finding.Kind
	case o.Exit == feedback.ExitTimeout:
		c.Kind = "hang"
	case o.Exit == feedback.ExitOOM:
		c.Kind = "oom"
	case o.Exit == feedback.ExitCrash:
		c.Kind = "crash"
	case o.Exit == feedback.ExitError:
		c.Kind = "error"
	default:
		c.Kind = "ok"
	}
	c.Marker = extractMarker(o.Output, cl.MarkerPrefixes)
	return c
}

// genericMarkerPrefixes are the line shapes that identify a failure in a
// program's own words, across the languages a target is likely to be written
// in.
//
// This is not pattern-matching for its own sake. When a target says which
// assertion failed, that is better evidence of which bug this is than any
// signal number, and it is available on a black-box target where frames are
// not.
var genericMarkerPrefixes = []string{
	"Assertion failed:",
	"assertion failed:",
	"panic:",
	"FATAL:",
	"terminate called after throwing",
}

func extractMarker(out string, prefixes []string) string {
	if out == "" || len(prefixes) == 0 {
		return ""
	}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		for _, p := range prefixes {
			if idx := strings.Index(line, p); idx >= 0 {
				return normaliseMarker(line[idx:])
			}
		}
	}
	return ""
}

// normaliseMarker strips what varies between runs of the same bug.
//
// An assertion message carrying a line number is stable; one carrying an
// address or a pid is not, and leaving those in would give every execution of
// one bug its own bucket. Short numbers survive on purpose: a line number, an
// error code or the index of a planted bug is part of what the message says,
// and collapsing those merges bugs the target went to the trouble of telling
// apart. The engine applies the same rule while a campaign runs, so a finding's
// live bucket and its triaged bucket agree.
func normaliseMarker(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		if s[i] == '0' && i+1 < len(s) && (s[i+1] == 'x' || s[i+1] == 'X') {
			j := i + 2
			for j < len(s) && isHexDigit(s[j]) {
				j++
			}
			if j > i+2 {
				b.WriteString("0xADDR")
				i = j
				continue
			}
		}
		if s[i] >= '0' && s[i] <= '9' {
			j := i
			for j < len(s) && s[j] >= '0' && s[j] <= '9' {
				j++
			}
			if j-i >= volatileDigits {
				b.WriteByte('#')
				i = j
				continue
			}
		}
		b.WriteByte(s[i])
		i++
	}
	const maxMarker = 160
	out := strings.TrimSpace(b.String())
	if len(out) > maxMarker {
		out = out[:maxMarker]
	}
	return out
}

// volatileDigits is how long a digit run has to be before it is treated as
// varying rather than as part of the message. Five, because pids, offsets and
// counters reach it and line numbers, error codes and bug indices rarely do.
const volatileDigits = 5

func isHexDigit(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}
