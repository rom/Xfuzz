package triage

import (
	"context"
	"fmt"
)

// MinimizeOptions bounds a minimisation run.
type MinimizeOptions struct {
	// MaxRuns caps how many executions minimisation may spend. Zero means
	// DefaultMaxRuns.
	//
	// Minimisation is unbounded work on an input nobody has read yet, and the
	// campaign is still running. A budget is what stops one pathological
	// reproducer from consuming a triage worker for an afternoon.
	MaxRuns int

	// Preserve decides whether a candidate still counts as the same failure.
	// Nil means the class must match the original's.
	Preserve func(o Outcome) bool

	// Normalize replaces bytes with a canonical value where doing so does not
	// change the outcome. It shrinks nothing but makes two reproducers of one
	// bug look alike, which is what lets a person see they are the same.
	Normalize bool
}

// DefaultMaxRuns is the execution budget for one minimisation.
const DefaultMaxRuns = 4000

// MinimizeReport says what minimisation achieved.
type MinimizeReport struct {
	OriginalSize  int
	MinimizedSize int
	Runs          int

	// Exhausted is true when the budget ran out before the algorithm converged,
	// so the result is the best found rather than a minimum.
	Exhausted bool
}

// Reduction is the fraction of the input removed.
func (r MinimizeReport) Reduction() float64 {
	if r.OriginalSize <= 0 {
		return 0
	}
	return 1 - float64(r.MinimizedSize)/float64(r.OriginalSize)
}

func (r MinimizeReport) String() string {
	s := fmt.Sprintf("%d -> %d bytes (%.0f%% smaller) in %d runs",
		r.OriginalSize, r.MinimizedSize, 100*r.Reduction(), r.Runs)
	if r.Exhausted {
		s += ", budget exhausted"
	}
	return s
}

// Minimize shrinks a reproducer while it still fails the same way.
//
// The algorithm is delta debugging restricted to deletion: cut the input into n
// blocks, try removing each, and when nothing can be removed at that
// granularity, double n. It converges on an input where no single block of any
// tried size can be deleted, which is not a global minimum but is reached in a
// number of runs proportional to the log of the input size rather than to its
// square.
//
// What it preserves is the *class* — kind, signal, and the failure marker the
// program printed — not the exact coverage. Requiring the same edges would stop
// almost every deletion, since removing bytes changes the path by construction;
// requiring only "it still crashes" lets the minimiser wander from one bug to
// another and hand back a reproducer for a different bug entirely. The class is
// the line between those, and it is checked on every candidate.
func Minimize(ctx context.Context, r Runner, input []byte, opts MinimizeOptions) ([]byte, MinimizeReport, error) {
	rep := MinimizeReport{OriginalSize: len(input), MinimizedSize: len(input)}
	if len(input) <= 1 {
		return append([]byte(nil), input...), rep, nil
	}

	budget := opts.MaxRuns
	if budget <= 0 {
		budget = DefaultMaxRuns
	}

	preserve := opts.Preserve
	if preserve == nil {
		base, err := r.Run(ctx, input)
		if err != nil {
			return nil, rep, err
		}
		rep.Runs++
		if !base.Crashed() {
			return nil, rep, fmt.Errorf("triage: the input to minimise does not fail")
		}
		want := Classify(base)
		preserve = func(o Outcome) bool { return o.Crashed() && Classify(o).Equal(want) }
	}

	best := append([]byte(nil), input...)

	// still reports whether a candidate reproduces, charging the budget.
	still := func(candidate []byte) (bool, error) {
		if rep.Runs >= budget {
			rep.Exhausted = true
			return false, nil
		}
		o, err := r.Run(ctx, candidate)
		rep.Runs++
		if err != nil {
			return false, err
		}
		return preserve(o), nil
	}

	blocks := 2
	for len(best) > 1 && !rep.Exhausted {
		if err := ctx.Err(); err != nil {
			return best, rep, err
		}
		size := len(best) / blocks
		if size == 0 {
			break
		}
		reduced := false

		// Removing from the end first: a truncated tail is the commonest
		// redundancy in a mutated input, and taking it early makes every later
		// run cheaper.
		for start := len(best) - size; start >= 0; start -= size {
			end := start + size
			if end > len(best) {
				end = len(best)
			}
			candidate := make([]byte, 0, len(best)-(end-start))
			candidate = append(candidate, best[:start]...)
			candidate = append(candidate, best[end:]...)
			if len(candidate) == 0 {
				continue
			}
			ok, err := still(candidate)
			if err != nil {
				return best, rep, err
			}
			if ok {
				best = candidate
				reduced = true
				// The block boundaries have moved; restarting at this
				// granularity is cheaper than reasoning about the shift.
				break
			}
			if rep.Exhausted {
				break
			}
		}
		if reduced {
			continue
		}
		if blocks >= len(best) {
			break
		}
		blocks *= 2
	}

	if opts.Normalize && !rep.Exhausted {
		var err error
		best, err = normalize(ctx, best, still, &rep)
		if err != nil {
			return best, rep, err
		}
	}

	rep.MinimizedSize = len(best)
	return best, rep, nil
}

// normalize replaces bytes with a canonical value where the failure survives.
//
// Two reproducers for one bug that differ only in the filler around the
// triggering bytes are the same bug, and a person comparing them should be able
// to see that at a glance. Overwriting rather than deleting is what makes this
// safe on a format with fixed-size fields, where deletion would break the parse
// before it reached the bug.
func normalize(ctx context.Context, in []byte, still func([]byte) (bool, error), rep *MinimizeReport) ([]byte, error) {
	const filler = 0x20 // a printable byte, so a minimised input reads as text where it can

	out := append([]byte(nil), in...)
	for i := range out {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		if out[i] == filler {
			continue
		}
		saved := out[i]
		out[i] = filler
		ok, err := still(out)
		if err != nil {
			return out, err
		}
		if !ok {
			out[i] = saved
		}
		if rep.Exhausted {
			break
		}
	}
	return out, nil
}

// MinimizeSequence shrinks a sequence of messages the same way Minimize shrinks
// bytes: by removing elements while the failure survives.
//
// A stateful finding is a session — a series of messages — and the redundancy in
// one is whole messages rather than bytes inside them. Sharing the algorithm
// rather than the representation is what lets session minimisation arrive in M6
// without a second delta debugger.
func MinimizeSequence(ctx context.Context, run func(context.Context, [][]byte) (Outcome, error),
	session [][]byte, opts MinimizeOptions) ([][]byte, MinimizeReport, error) {

	rep := MinimizeReport{OriginalSize: len(session), MinimizedSize: len(session)}
	if len(session) <= 1 {
		return session, rep, nil
	}
	budget := opts.MaxRuns
	if budget <= 0 {
		budget = DefaultMaxRuns
	}

	preserve := opts.Preserve
	if preserve == nil {
		base, err := run(ctx, session)
		if err != nil {
			return nil, rep, err
		}
		rep.Runs++
		if !base.Crashed() {
			return nil, rep, fmt.Errorf("triage: the session to minimise does not fail")
		}
		want := Classify(base)
		preserve = func(o Outcome) bool { return o.Crashed() && Classify(o).Equal(want) }
	}

	best := session
	for i := len(best) - 1; i >= 0 && !rep.Exhausted; i-- {
		if err := ctx.Err(); err != nil {
			return best, rep, err
		}
		if len(best) == 1 {
			break
		}
		candidate := make([][]byte, 0, len(best)-1)
		candidate = append(candidate, best[:i]...)
		candidate = append(candidate, best[i+1:]...)

		if rep.Runs >= budget {
			rep.Exhausted = true
			break
		}
		o, err := run(ctx, candidate)
		rep.Runs++
		if err != nil {
			return best, rep, err
		}
		if preserve(o) {
			best = candidate
		}
	}
	rep.MinimizedSize = len(best)
	return best, rep, nil
}
