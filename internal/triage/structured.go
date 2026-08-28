package triage

import (
	"context"
	"fmt"

	"github.com/rom/Xfuzz/pkg/ir"
)

// MinimizeStructured shrinks a reproducer through its structure rather than its
// bytes.
//
// Byte-level minimisation cannot reduce a checksum-protected format at all.
// Deleting bytes from a chunk invalidates the length and the checksum that
// cover it, the parser rejects the file before reaching the bug, and the
// minimiser concludes — correctly, from what it can see — that the bytes were
// necessary. It is a real limit, not a tuning problem: the intermediate states
// delta debugging must pass through do not exist in the format.
//
// Working on the tree removes the obstacle rather than climbing it. Dropping an
// element of a repeat removes a whole chunk; the fixup pass then recomputes
// every length and checksum that the removal invalidated, so the candidate is a
// valid file again. This is what the IR is for (ADR-0005), applied to the part
// of the pipeline where its absence is most expensive.
//
// It falls back to nothing: a caller with no tree still has Minimize.
func MinimizeStructured(ctx context.Context, r Runner, root *ir.Node, opts MinimizeOptions) (*ir.Node, []byte, MinimizeReport, error) {
	rep := MinimizeReport{}
	if root == nil {
		return nil, nil, rep, fmt.Errorf("triage: no structure to minimise")
	}

	fixer := ir.NewFixer()
	encode := func(n *ir.Node) ([]byte, error) {
		b, err := fixer.Fix(n, ir.Suppress{})
		if err != nil {
			return nil, err
		}
		return append([]byte(nil), b...), nil
	}

	best := ir.Copy(root)
	encoded, err := encode(best)
	if err != nil {
		return nil, nil, rep, err
	}
	rep.OriginalSize = len(encoded)
	rep.MinimizedSize = len(encoded)

	budget := opts.MaxRuns
	if budget <= 0 {
		budget = DefaultMaxRuns
	}

	preserve := opts.Preserve
	if preserve == nil {
		base, err := r.Run(ctx, encoded)
		if err != nil {
			return nil, nil, rep, err
		}
		rep.Runs++
		if !base.Crashed() {
			return nil, nil, rep, fmt.Errorf("triage: the input to minimise does not fail")
		}
		want := Classify(base)
		preserve = func(o Outcome) bool { return o.Crashed() && Classify(o).Equal(want) }
	}

	try := func(candidate *ir.Node) (bool, []byte, error) {
		if rep.Runs >= budget {
			rep.Exhausted = true
			return false, nil, nil
		}
		b, err := encode(candidate)
		if err != nil {
			// A candidate that cannot be encoded is not a candidate. That is a
			// rejection, not a failure of minimisation: the removal produced a
			// tree the format does not admit.
			return false, nil, nil
		}
		o, err := r.Run(ctx, b)
		rep.Runs++
		if err != nil {
			return false, nil, err
		}
		return preserve(o), b, nil
	}

	// Each pass makes at most one change and then starts again, because a
	// removal renumbers every position after it. Passes stop when a whole walk
	// finds nothing to remove, which is the fixed point.
	for !rep.Exhausted {
		if err := ctx.Err(); err != nil {
			return best, encoded, rep, err
		}
		changed := false

		for _, cand := range removals(best) {
			trial := ir.Copy(best)
			if !cand.apply(trial) {
				continue
			}
			ok, b, err := try(trial)
			if err != nil {
				return best, encoded, rep, err
			}
			if ok {
				best, encoded = trial, b
				changed = true
				break
			}
			if rep.Exhausted {
				break
			}
		}
		if !changed {
			break
		}
	}

	rep.MinimizedSize = len(encoded)
	return best, encoded, rep, nil
}

// removal is one candidate reduction of a tree.
type removal struct {
	// path is the child-index route from the root to the node to change.
	path []int

	// index is the child to drop from a repeat, or -1 for a whole-node change.
	index int

	// shrinkTo is the length to truncate a Bytes node to, or -1.
	shrinkTo int
}

func (c removal) apply(root *ir.Node) bool {
	n := root
	for _, step := range c.path {
		if step >= len(n.Children) {
			return false
		}
		n = n.Children[step]
	}
	switch {
	case c.index >= 0:
		if c.index >= len(n.Children) || len(n.Children)-1 < int(n.MinLen) {
			return false
		}
		n.Children = append(n.Children[:c.index:c.index], n.Children[c.index+1:]...)
		return true
	case c.shrinkTo >= 0:
		if c.shrinkTo >= len(n.Raw) || c.shrinkTo < int(n.MinLen) {
			return false
		}
		n.Raw = append([]byte(nil), n.Raw[:c.shrinkTo]...)
		return true
	case n.Kind == ir.KindOpt:
		if !n.Present() {
			return false
		}
		n.SetPresent(false)
		return true
	}
	return false
}

// removals enumerates every reduction worth trying, largest first.
//
// Ordering by expected saving is what keeps the run count down: removing a
// whole chunk in the first attempt is worth more than a hundred single-byte
// truncations, and once it is gone those bytes never have to be considered.
func removals(root *ir.Node) []removal {
	var out []removal
	var walk func(n *ir.Node, path []int)

	walk = func(n *ir.Node, path []int) {
		switch {
		case n.Kind == ir.KindRepeat:
			// From the end: a trailing element is the commonest redundancy, and
			// removing it does not renumber the elements before it.
			for i := len(n.Children) - 1; i >= 0; i-- {
				out = append(out, removal{path: clonePath(path), index: i, shrinkTo: -1})
			}
		case n.Kind == ir.KindOpt && n.Present():
			out = append(out, removal{path: clonePath(path), index: -1, shrinkTo: -1})
		case n.Kind == ir.KindBytes && len(n.Raw) > int(n.MinLen) && !n.Immutable():
			// Halving first, then quartering, and so on: a geometric ladder
			// reaches the minimum length in a logarithmic number of attempts
			// where stepping down by one byte would take a linear one.
			for size := len(n.Raw) / 2; size > int(n.MinLen); size /= 2 {
				out = append(out, removal{path: clonePath(path), index: -1, shrinkTo: size})
			}
			if int(n.MinLen) < len(n.Raw) {
				out = append(out, removal{path: clonePath(path), index: -1, shrinkTo: int(n.MinLen)})
			}
		}
		for i, kid := range n.Children {
			walk(kid, append(path, i))
		}
	}
	walk(root, nil)
	return out
}

func clonePath(p []int) []int {
	if len(p) == 0 {
		return nil
	}
	return append([]int(nil), p...)
}
