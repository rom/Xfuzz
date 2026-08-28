package mutate

import "github.com/rom/Xfuzz/pkg/ir"

// Crossover. Splicing takes material that already worked in one corpus entry
// and moves it into another. It is how a fuzzer combines two partial
// discoveries — a seed that reached a parser state and a seed that carried an
// interesting payload — into one input that does both.

// SpliceSubtree replaces a node with a same-shaped node from a donor entry.
//
// Candidates are matched on kind and name, so the graft is type-compatible and
// keeps the name that sibling derivations resolve against. The node is
// overwritten in place rather than swapped in its parent, which keeps the
// operator working through the plain Mutator interface.
type SpliceSubtree struct{}

func (SpliceSubtree) Name() string { return "splice-subtree" }
func (SpliceSubtree) Kind() Kind   { return KindSplice }
func (SpliceSubtree) CanApply(c *Ctx, n *ir.Node) bool {
	// Derived nodes are recomputed and Ref nodes carry no content, so grafting
	// either accomplishes nothing. Grafting the root replaces the input
	// wholesale, which is a substitution rather than a crossover.
	return c.Donor != nil && n != nil && n != c.Root && !n.Immutable() &&
		n.Kind != ir.KindDerived && n.Kind != ir.KindRef
}

func (SpliceSubtree) Mutate(c *Ctx, n *ir.Node) bool {
	if c.Donor == nil {
		return false
	}
	donor := pickMatching(c, c.Donor, n)
	if donor == nil || donor == n || ir.Equal(donor, n) {
		return false
	}
	// A graft that violates the target's declared bounds would produce
	// something the format does not allow.
	switch n.Kind {
	case ir.KindBytes, ir.KindStr:
		if !n.FitsLen(len(donor.Raw)) {
			return false
		}
	case ir.KindRepeat:
		if !n.FitsLen(len(donor.Children)) {
			return false
		}
	}
	graft(c, n, donor)
	return true
}

// SpliceBytes copies a run of bytes from a donor payload into this one.
type SpliceBytes struct{}

func (SpliceBytes) Name() string                     { return "splice-bytes" }
func (SpliceBytes) Kind() Kind                       { return KindSplice }
func (SpliceBytes) CanApply(c *Ctx, n *ir.Node) bool { return c.Donor != nil && isPayload(n) }

func (SpliceBytes) Mutate(c *Ctx, n *ir.Node) bool {
	if c.Donor == nil {
		return false
	}
	src := pickPayload(c, c.Donor)
	if src == nil || len(src.Raw) == 0 {
		return false
	}
	from := c.Rand.Intn(len(src.Raw))
	length := c.Rand.IntRange(1, min(len(src.Raw)-from, 256))

	if c.Rand.Bool() {
		at := c.Rand.Intn(len(n.Raw))
		length = min(length, len(n.Raw)-at)
		if length == 0 {
			return false
		}
		copy(n.Raw[at:], src.Raw[from:from+length])
		return true
	}

	length = min(length, c.canGrow(n))
	if length <= 0 {
		return false
	}
	at := c.Rand.Intn(len(n.Raw) + 1)
	n.Raw = insertRun(c, n.Raw, at, length, 0)
	copy(n.Raw[at:], src.Raw[from:from+length])
	return true
}

// graft overwrites dst with a copy of src, keeping dst's name so that sibling
// derivations still resolve.
func graft(c *Ctx, dst, src *ir.Node) {
	name := dst.Name
	clone := c.Arena.Clone(src)
	*dst = *clone
	dst.Name = name
}

// pickMatching selects a node from the donor tree with the same kind and name
// as want, uniformly at random.
//
// Reservoir sampling avoids building a candidate list, so the operator stays
// allocation-free however large the donor is.
func pickMatching(c *Ctx, donor, want *ir.Node) *ir.Node {
	var chosen *ir.Node
	seen := 0
	ir.Walk(donor, func(x *ir.Node) bool {
		if x.Kind == want.Kind && x.Name == want.Name {
			seen++
			if c.Rand.Intn(seen) == 0 {
				chosen = x
			}
		}
		return true
	})
	return chosen
}

// pickPayload selects a byte-bearing node from a tree uniformly at random.
func pickPayload(c *Ctx, root *ir.Node) *ir.Node {
	var chosen *ir.Node
	seen := 0
	ir.Walk(root, func(x *ir.Node) bool {
		if isPayload(x) {
			seen++
			if c.Rand.Intn(seen) == 0 {
				chosen = x
			}
		}
		return true
	})
	return chosen
}
