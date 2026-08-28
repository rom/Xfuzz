package mutate

import "github.com/rom/Xfuzz/pkg/ir"

// Structured operators. These are what a schema buys: instead of perturbing
// bytes and hoping the result still parses, they change a typed value, switch a
// variant, or add and remove elements of a sequence — and the fixup pass then
// restores the lengths and checksums that would otherwise reject the input.
//
// None of them touch KindDerived nodes. A derived value is recomputed during
// fixup, so mutating one is either wasted work or, worse, an operator that
// reports a change the fixup silently reverts and per-operator accounting then
// misattributes. Deliberately wrong derived values come from ir.Suppress, which
// is a campaign-level decision rather than a random operator.

// maxRepeatChildren bounds sequence growth when Ctx.MaxChildren is unset.
const maxRepeatChildren = 4096

// childBudget reports how many elements may be added to a sequence, honouring
// both the node's declared bounds and the context's cap.
func (c *Ctx) childBudget(n *ir.Node) int {
	limit := c.MaxChildren
	if limit <= 0 {
		limit = maxRepeatChildren
	}
	if n.MaxLen > 0 && int(n.MaxLen) < limit {
		limit = int(n.MaxLen)
	}
	return limit - len(n.Children)
}

func isMutableInt(n *ir.Node) bool { return n != nil && !n.Immutable() && n.Kind == ir.KindInt }

// IntArith adds or subtracts a small value from a typed integer.
type IntArith struct{}

func (IntArith) Name() string                     { return "int-arith" }
func (IntArith) Kind() Kind                       { return KindStructural }
func (IntArith) CanApply(c *Ctx, n *ir.Node) bool { return isMutableInt(n) }

func (IntArith) Mutate(c *Ctx, n *ir.Node) bool {
	delta := int64(c.Rand.IntRange(1, arithMax))
	if c.Rand.Bool() {
		delta = -delta
	}
	n.Val += delta
	return true
}

// IntInteresting sets a typed integer to a boundary value for its width.
//
// Working from the declared width rather than guessing one is the advantage
// over the byte-level operator: the value lands exactly on the field's limits
// instead of somewhere inside a neighbouring field.
type IntInteresting struct{}

func (IntInteresting) Name() string                     { return "int-interesting" }
func (IntInteresting) Kind() Kind                       { return KindStructural }
func (IntInteresting) CanApply(c *Ctx, n *ir.Node) bool { return isMutableInt(n) }

func (IntInteresting) Mutate(c *Ctx, n *ir.Node) bool {
	var pool []int64
	switch n.Width {
	case 1:
		pool = interesting8
	case 2:
		pool = interesting16
	case 4:
		pool = interesting32
	default:
		pool = interesting64
	}
	v := pool[c.Rand.Intn(len(pool))]
	if v == n.Val {
		return false
	}
	n.Val = v
	return true
}

// IntRandom replaces a typed integer with a random value of its width.
type IntRandom struct{}

func (IntRandom) Name() string                     { return "int-random" }
func (IntRandom) Kind() Kind                       { return KindStructural }
func (IntRandom) CanApply(c *Ctx, n *ir.Node) bool { return isMutableInt(n) }

func (IntRandom) Mutate(c *Ctx, n *ir.Node) bool {
	v := int64(c.Rand.Uint64())
	if n.Width < 8 {
		v &= 1<<(8*uint(n.Width)) - 1
	}
	if v == n.Val {
		return false
	}
	n.Val = v
	return true
}

// IntBitFlip flips one bit of a typed integer, within its width.
type IntBitFlip struct{}

func (IntBitFlip) Name() string                     { return "int-bitflip" }
func (IntBitFlip) Kind() Kind                       { return KindStructural }
func (IntBitFlip) CanApply(c *Ctx, n *ir.Node) bool { return isMutableInt(n) }

func (IntBitFlip) Mutate(c *Ctx, n *ir.Node) bool {
	n.Val ^= 1 << c.Rand.Intn(int(n.Width)*8)
	return true
}

// ChoiceSwitch selects a different alternative of a tagged union.
//
// This is unreachable by byte-level mutation in any format where the tag and
// the body must agree: flipping the tag alone leaves a body the target rejects.
type ChoiceSwitch struct{}

func (ChoiceSwitch) Name() string { return "choice-switch" }
func (ChoiceSwitch) Kind() Kind   { return KindStructural }
func (ChoiceSwitch) CanApply(c *Ctx, n *ir.Node) bool {
	return n != nil && !n.Immutable() && n.Kind == ir.KindChoice && len(n.Children) > 1
}

func (ChoiceSwitch) Mutate(c *Ctx, n *ir.Node) bool {
	next := c.Rand.Intn(len(n.Children) - 1)
	if int32(next) >= n.Sel {
		next++
	}
	n.Sel = int32(next)
	return true
}

// OptToggle adds or removes an optional subtree.
type OptToggle struct{}

func (OptToggle) Name() string { return "opt-toggle" }
func (OptToggle) Kind() Kind   { return KindStructural }
func (OptToggle) CanApply(c *Ctx, n *ir.Node) bool {
	return n != nil && !n.Immutable() && n.Kind == ir.KindOpt && len(n.Children) == 1
}

func (OptToggle) Mutate(c *Ctx, n *ir.Node) bool {
	n.SetPresent(!n.Present())
	return true
}

func isRepeat(n *ir.Node) bool { return n != nil && !n.Immutable() && n.Kind == ir.KindRepeat }

// RepeatInsert clones an existing element and inserts the copy at a random
// position.
//
// Cloning rather than generating is deliberate: an existing element is already
// valid for the format, so the result usually still parses. Generating a fresh
// element needs a schema and belongs to pkg/generate.
type RepeatInsert struct{}

func (RepeatInsert) Name() string { return "repeat-insert" }
func (RepeatInsert) Kind() Kind   { return KindStructural }
func (RepeatInsert) CanApply(c *Ctx, n *ir.Node) bool {
	return isRepeat(n) && len(n.Children) > 0 && c.childBudget(n) > 0
}

func (RepeatInsert) Mutate(c *Ctx, n *ir.Node) bool {
	if c.childBudget(n) < 1 {
		return false
	}
	src := c.Rand.Intn(len(n.Children))
	clone := c.Arena.Clone(n.Children[src])
	at := c.Rand.Intn(len(n.Children) + 1)
	n.Children = insertChild(c, n.Children, at, clone)
	return true
}

// RepeatDelete removes one element from a sequence.
type RepeatDelete struct{}

func (RepeatDelete) Name() string { return "repeat-delete" }
func (RepeatDelete) Kind() Kind   { return KindStructural }
func (RepeatDelete) CanApply(c *Ctx, n *ir.Node) bool {
	return isRepeat(n) && len(n.Children) > int(n.MinLen)
}

func (RepeatDelete) Mutate(c *Ctx, n *ir.Node) bool {
	at := c.Rand.Intn(len(n.Children))
	n.Children = append(n.Children[:at], n.Children[at+1:]...)
	return true
}

// RepeatDuplicate copies a contiguous run of elements and inserts it directly
// after itself, which is how a fuzzer discovers the limits a target places on
// repetition.
type RepeatDuplicate struct{}

func (RepeatDuplicate) Name() string { return "repeat-duplicate" }
func (RepeatDuplicate) Kind() Kind   { return KindStructural }
func (RepeatDuplicate) CanApply(c *Ctx, n *ir.Node) bool {
	return isRepeat(n) && len(n.Children) > 0 && c.childBudget(n) > 0
}

func (RepeatDuplicate) Mutate(c *Ctx, n *ir.Node) bool {
	room := c.childBudget(n)
	if room < 1 {
		return false
	}
	at := c.Rand.Intn(len(n.Children))
	count := c.Rand.IntRange(1, min(min(len(n.Children)-at, room), 16))

	n.Children = c.Arena.GrowKids(n.Children, count)
	n.Children = n.Children[:len(n.Children)+count]
	copy(n.Children[at+count:], n.Children[at:])
	for i := 0; i < count; i++ {
		// The source run was shifted right by the copy above.
		n.Children[at+i] = c.Arena.Clone(n.Children[at+count+i])
	}
	return true
}

// RepeatSwap exchanges two elements, exploring order dependence without
// changing anything else.
type RepeatSwap struct{}

func (RepeatSwap) Name() string { return "repeat-swap" }
func (RepeatSwap) Kind() Kind   { return KindStructural }
func (RepeatSwap) CanApply(c *Ctx, n *ir.Node) bool {
	return isRepeat(n) && len(n.Children) > 1
}

func (RepeatSwap) Mutate(c *Ctx, n *ir.Node) bool {
	i := c.Rand.Intn(len(n.Children))
	j := c.Rand.Intn(len(n.Children) - 1)
	if j >= i {
		j++
	}
	n.Children[i], n.Children[j] = n.Children[j], n.Children[i]
	return true
}

// RepeatShuffle permutes a whole sequence.
type RepeatShuffle struct{}

func (RepeatShuffle) Name() string { return "repeat-shuffle" }
func (RepeatShuffle) Kind() Kind   { return KindStructural }
func (RepeatShuffle) CanApply(c *Ctx, n *ir.Node) bool {
	return isRepeat(n) && len(n.Children) > 1
}

func (RepeatShuffle) Mutate(c *Ctx, n *ir.Node) bool {
	// A shuffle that happens to be the identity is not a change, and reporting
	// one would inflate the operator's apparent effectiveness. But the reverse
	// error is worse: this originally checked only whether the first element
	// had moved, so a shuffle that permuted everything else reported no change
	// and went unrecorded — an untracked mutation that breaks replay.
	//
	// Fisher-Yates maps each sequence of draws to exactly one permutation, and
	// the identity comes only from drawing j == i every time. So "some draw
	// moved something" is precisely "the permutation is not the identity".
	moved := false
	c.Rand.Shuffle(len(n.Children), func(i, j int) {
		if i != j {
			moved = true
			n.Children[i], n.Children[j] = n.Children[j], n.Children[i]
		}
	})
	return moved
}

// insertChild opens a slot at position at and stores kid there.
func insertChild(c *Ctx, kids []*ir.Node, at int, kid *ir.Node) []*ir.Node {
	kids = c.Arena.GrowKids(kids, 1)
	kids = kids[:len(kids)+1]
	copy(kids[at+1:], kids[at:])
	kids[at] = kid
	return kids
}
