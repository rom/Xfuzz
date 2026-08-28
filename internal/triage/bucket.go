package triage

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash/fnv"
	"strings"
)

// Strategy groups findings believed to share a root cause.
//
// Bucketing is a judgement, and every strategy is wrong in a different
// direction: signals merge unrelated bugs, frames need symbols, coverage
// splits one bug across many buckets when the path in varies. So a strategy is
// a named, replaceable thing whose output is stored alongside the name that
// produced it (ADR-0008), and a campaign can be graded on more than one.
type Strategy interface {
	// Name identifies the strategy in the store and in reports.
	Name() string

	// Signature returns the bucket key, and false when this strategy has no
	// evidence to work from. Returning false is not a failure: it is how a
	// chain falls through to a strategy that does.
	Signature(o Outcome, c Class) (string, bool)
}

// SignalStrategy buckets on the failure kind and fatal signal.
//
// It is the crudest strategy and the only one that always works. A segfault and
// a division by zero land in different buckets; two unrelated segfaults land in
// the same one. Its value is as the last link in a chain, where "one bucket per
// signal" beats "no bucket at all".
type SignalStrategy struct{}

// Name implements Strategy.
func (SignalStrategy) Name() string { return "signal" }

// Signature implements Strategy.
func (SignalStrategy) Signature(_ Outcome, c Class) (string, bool) {
	if c.Signal != 0 {
		return fmt.Sprintf("%s/sig%d", c.Kind, c.Signal), true
	}
	return c.Kind, true
}

// MarkerStrategy buckets on the failure marker the target printed.
//
// When a program names its own failure — a failed assertion, a panic message —
// that name is the best bucket key available, because it is what the program's
// authors already use to tell their bugs apart. It yields nothing on a target
// that says nothing, which is most of them.
type MarkerStrategy struct{}

// Name implements Strategy.
func (MarkerStrategy) Name() string { return "marker" }

// Signature implements Strategy.
func (MarkerStrategy) Signature(_ Outcome, c Class) (string, bool) {
	if c.Marker == "" {
		return "", false
	}
	return c.Marker, true
}

// FrameStrategy buckets on the top stack frames of a sanitizer report.
//
// This is the industry default and the best strategy when it applies. Depth is
// a trade: too shallow and every crash inside memcpy is one bug; too deep and
// two paths into one bug are two buckets. Five is the conventional compromise.
type FrameStrategy struct {
	// Depth is how many frames to consider. Zero means five.
	Depth int

	// Skip drops frames whose function name has one of these prefixes. Frames
	// inside the allocator or the sanitizer's own interceptors are noise: they
	// are the same for every heap bug in the program.
	Skip []string
}

// DefaultFrameSkip are the frame prefixes that carry no information about which
// bug this is.
var DefaultFrameSkip = []string{
	"__asan", "__msan", "__tsan", "__ubsan", "__sanitizer",
	"__interceptor", "operator new", "operator delete",
	"malloc", "calloc", "realloc", "free", "memcpy", "memmove", "memset",
	"abort", "__libc_", "raise", "__GI_",
}

// Name implements Strategy.
func (FrameStrategy) Name() string { return "frames" }

// Signature implements Strategy.
func (s FrameStrategy) Signature(o Outcome, _ Class) (string, bool) {
	depth := s.Depth
	if depth <= 0 {
		depth = 5
	}
	skip := s.Skip
	if skip == nil {
		skip = DefaultFrameSkip
	}

	kept := make([]string, 0, depth)
	for _, f := range o.Finding.Frames {
		name := frameFunction(f)
		if hasAnyPrefix(name, skip) {
			continue
		}
		kept = append(kept, name)
		if len(kept) == depth {
			break
		}
	}
	if len(kept) == 0 {
		return "", false
	}
	return strings.Join(kept, ";"), true
}

// frameFunction reduces a frame to its function name.
//
// A frame from a sanitizer report is "func /path/to/file.c:12:3". The path and
// the line move when the file is edited, and a bucket that changes when an
// unrelated line is inserted above the bug is not a bucket.
func frameFunction(frame string) string {
	if i := strings.IndexByte(frame, ' '); i > 0 {
		return frame[:i]
	}
	return frame
}

func hasAnyPrefix(s string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

// CoverageStrategy buckets on the set of edges the crashing execution reached.
//
// It is the only strategy that works on a black-box target with no symbols, and
// it is the reason two bugs that both abort do not have to share a bucket. Its
// weakness is well known and worth stating plainly: the tuple set includes the
// whole path in, not just the crash site, so two inputs that reach one bug by
// different routes get different buckets. That is why triage minimises before
// it buckets — a minimised input has almost no path left to vary — and why the
// grading criterion is "approximately the right number of buckets" rather than
// exactly.
//
// Hitcounts are deliberately ignored. Whether a loop ran nine times or eleven
// says nothing about which bug this is, and including it would give one bug a
// bucket per iteration count.
type CoverageStrategy struct{}

// Name implements Strategy.
func (CoverageStrategy) Name() string { return "coverage" }

// Signature implements Strategy.
func (CoverageStrategy) Signature(o Outcome, _ Class) (string, bool) {
	if len(o.Coverage) == 0 {
		return "", false
	}
	h := fnv.New64a()
	var buf [4]byte
	any := false
	for i, v := range o.Coverage {
		if v == 0 {
			continue
		}
		any = true
		binary.LittleEndian.PutUint32(buf[:], uint32(i))
		h.Write(buf[:])
	}
	if !any {
		return "", false
	}
	var sum [8]byte
	binary.LittleEndian.PutUint64(sum[:], h.Sum64())
	return hex.EncodeToString(sum[:]), true
}

// Chain tries strategies in order and uses the first with evidence.
//
// The order encodes what counts as better evidence: what the program said about
// itself, then where it was when it died, then how it died. The name reported is
// the chain's own, so two findings bucketed by different links are still
// comparable — and the link that produced each signature is recoverable from the
// signature's prefix.
type Chain []Strategy

// DefaultChain is the strategy used when a campaign does not choose one.
func DefaultChain() Chain {
	return Chain{FrameStrategy{}, MarkerStrategy{}, CoverageStrategy{}, SignalStrategy{}}
}

// Name implements Strategy.
func (Chain) Name() string { return "chain" }

// Signature implements Strategy.
func (c Chain) Signature(o Outcome, cl Class) (string, bool) {
	for _, s := range c {
		if sig, ok := s.Signature(o, cl); ok {
			return s.Name() + ":" + sig, true
		}
	}
	return "", false
}

// Bucket computes a finding's bucket under a strategy.
func Bucket(s Strategy, o Outcome, c Class) (strategy, signature string) {
	sig, ok := s.Signature(o, c)
	if !ok {
		// No strategy had evidence. Saying so explicitly beats returning an
		// empty signature that would silently merge every such finding with
		// every other.
		return s.Name(), "unclassified"
	}
	return s.Name(), sig
}
