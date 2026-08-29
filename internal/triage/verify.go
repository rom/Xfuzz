package triage

import (
	"context"
	"fmt"
	"strings"
)

// DefaultTrials is how many times verification runs a reproducer.
//
// Five is enough to tell "always" from "sometimes" and cheap enough to run on
// every finding. Distinguishing 90% from 95% would need hundreds of runs and
// would not change what anybody does with the finding.
const DefaultTrials = 5

// VerifyReport is the outcome of re-running a reproducer.
type VerifyReport struct {
	// Trials is how many times it was run, and Reproduced how many of those
	// failed the same way.
	Trials     int
	Reproduced int

	// Class is the failure class observed, from the first reproduction.
	Class Class

	// Divergent lists the other classes seen, when a reproducer did not always
	// fail the same way. A crash that is sometimes a segfault and sometimes a
	// hang is one finding with a race in it, and hiding that behind a single
	// class would lose the most useful thing about it.
	Divergent []Class
}

// Rate is the fraction of trials that reproduced.
func (r VerifyReport) Rate() float64 {
	if r.Trials == 0 {
		return 0
	}
	return float64(r.Reproduced) / float64(r.Trials)
}

// State maps the report onto a triage state.
func (r VerifyReport) State() string {
	switch {
	case r.Trials == 0:
		return "new"
	case r.Reproduced == 0:
		return "unverified"
	case r.Reproduced == r.Trials:
		return "verified"
	default:
		return "flaky"
	}
}

func (r VerifyReport) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%d/%d reproduced (%s)", r.Reproduced, r.Trials, r.State())
	if r.Class.Kind != "" {
		fmt.Fprintf(&b, " as %s", r.Class)
	}
	if len(r.Divergent) > 0 {
		names := make([]string, 0, len(r.Divergent))
		for _, c := range r.Divergent {
			names = append(names, c.String())
		}
		fmt.Fprintf(&b, "; also seen as %s", strings.Join(names, ", "))
	}
	return b.String()
}

// Verify re-runs a reproducer to find out whether it reproduces.
//
// This is the first thing triage does and the reason a finding count means
// anything. An input that crashed once and never again is not a bug report; it
// is a note that something non-deterministic happened, and filing it as a bug
// wastes the time of whoever picks it up.
func Verify(ctx context.Context, r Runner, input []byte, trials int) (VerifyReport, error) {
	return DefaultClassifier.Verify(ctx, r, input, trials)
}

// Verify re-runs a reproducer, classifying each run with this classifier.
//
// The classifier matters here and not only at bucketing time: divergence is
// "did this reproduce as the same thing", and a classifier that cannot see the
// target's own marker cannot tell two of its bugs apart to notice.
func (cl *Classifier) Verify(ctx context.Context, r Runner, input []byte, trials int) (VerifyReport, error) {
	if trials <= 0 {
		trials = DefaultTrials
	}
	rep := VerifyReport{}
	seen := map[string]bool{}

	for i := 0; i < trials; i++ {
		if err := ctx.Err(); err != nil {
			return rep, err
		}
		o, err := r.Run(ctx, input)
		if err != nil {
			return rep, err
		}
		rep.Trials++
		if !o.Crashed() {
			continue
		}
		c := cl.Classify(o)
		rep.Reproduced++
		switch {
		case rep.Class.Kind == "":
			rep.Class = c
			seen[c.String()] = true
		case !c.Equal(rep.Class) && !seen[c.String()]:
			seen[c.String()] = true
			rep.Divergent = append(rep.Divergent, c)
		}
	}
	return rep, nil
}
