package mutate

import (
	"github.com/rom/Xfuzz/pkg/ir"
	"github.com/rom/Xfuzz/pkg/rng"
)

// Ctx carries everything a mutator needs beyond the node it is changing.
//
// It is passed by pointer and reused across mutations; nothing in it is
// allocated per operation.
type Ctx struct {
	// Rand supplies the operator's parameters. It is the StreamMutatorParam
	// stream, kept separate from operator selection so that changing the
	// operator mix does not shift every parameter draw (ASR-0008).
	Rand *rng.Rand

	// Select chooses which operator to apply, and Nodes chooses which node to
	// apply it to. Three streams rather than one so that adding an operator or
	// changing node weighting perturbs only its own sequence.
	Select *rng.Rand
	Nodes  *rng.Rand

	// Arena owns the tree being mutated. Growth goes through it so that
	// structural mutation stays allocation-free.
	Arena *ir.Arena

	// Root is the tree being mutated, for operators that need whole-tree
	// context.
	Root *ir.Node

	// Dict holds format tokens. May be nil.
	Dict *Dictionary

	// Donor is another corpus entry, for splice. May be nil.
	Donor *ir.Node

	// MaxBytes caps how large a single payload may grow. Zero means unlimited.
	// Without a cap, repeated growth operators inflate an input until execution
	// time is dominated by copying it.
	MaxBytes int

	// MaxChildren caps how long a single sequence may grow. Zero selects a
	// default. Sequences inflate faster than payloads, because duplication
	// copies whole subtrees.
	MaxChildren int
}

// NewCtx builds a context with the three streams derived as ASR-0008 requires.
// Using it rather than assembling a Ctx by hand is what keeps a campaign
// reproducible.
func NewCtx(campaignSeed uint64, workerID uint32, a *ir.Arena) *Ctx {
	return &Ctx{
		Rand:   rng.Derive(campaignSeed, workerID, rng.StreamMutatorParam),
		Select: rng.Derive(campaignSeed, workerID, rng.StreamMutatorSelect),
		Nodes:  rng.Derive(campaignSeed, workerID, rng.StreamStructure),
		Arena:  a,
	}
}

// budget returns how many bytes a payload of the given length may still grow.
func (c *Ctx) budget(cur int) int {
	if c.MaxBytes <= 0 {
		return maxGrowth
	}
	if room := c.MaxBytes - cur; room < maxGrowth {
		return room
	}
	return maxGrowth
}

// maxGrowth bounds a single growth operation regardless of MaxBytes, so one
// mutation cannot turn a small input into a huge one.
const maxGrowth = 4096

// Mutator is one input transformation.
//
// Operators are deliberately small and single-purpose: the scheduler composes
// them, and per-operator accounting only means something when each does one
// identifiable thing.
type Mutator interface {
	// Name identifies the operator in configuration, provenance, and stats.
	Name() string

	// CanApply reports whether the operator is meaningful for a node in this
	// context. It must be cheap: the scheduler calls it for every node while
	// choosing a target.
	//
	// It takes the context, not just the node, so that an operator can decline
	// when its preconditions are absent — no dictionary loaded, no donor entry,
	// nothing to graft. Declining here rather than inside Mutate is what keeps
	// the scheduler from spending its budget on operators that cannot act.
	CanApply(c *Ctx, n *ir.Node) bool

	// Mutate transforms n, reporting whether it changed anything. Returning
	// false is normal — a delete on a one-element sequence, an increment that
	// would exceed a bound — and the scheduler simply tries again.
	Mutate(c *Ctx, n *ir.Node) bool
}

// Kind classifies an operator for weighting and reporting.
type Kind uint8

// Operator classes.
const (
	KindByte       Kind = iota // rewrites raw payload bytes
	KindStructural             // changes tree shape or typed values
	KindSplice                 // copies material from another corpus entry
	KindDictionary             // inserts format tokens
)

func (k Kind) String() string {
	switch k {
	case KindByte:
		return "byte"
	case KindStructural:
		return "structural"
	case KindSplice:
		return "splice"
	case KindDictionary:
		return "dictionary"
	}
	return "unknown"
}

// Classified is implemented by operators that declare their class. Operators
// that do not are treated as KindByte.
type Classified interface {
	Kind() Kind
}

// KindOf returns an operator's class.
func KindOf(m Mutator) Kind {
	if c, ok := m.(Classified); ok {
		return c.Kind()
	}
	return KindByte
}

// isPayload reports whether a node holds raw bytes a byte-level operator can
// rewrite in place.
func isPayload(n *ir.Node) bool {
	return isWritable(n) && len(n.Raw) > 0
}

// isWritable reports whether a node holds bytes at all and is not off-limits.
func isWritable(n *ir.Node) bool {
	return n != nil && !n.Immutable() &&
		(n.Kind == ir.KindBytes || n.Kind == ir.KindStr)
}

// canGrow reports how many bytes may be added to a payload, honouring both the
// node's declared bounds and the context's cap.
func (c *Ctx) canGrow(n *ir.Node) int {
	room := c.budget(len(n.Raw))
	if n.MaxLen > 0 {
		if declared := int(n.MaxLen) - len(n.Raw); declared < room {
			room = declared
		}
	}
	return room
}

// canShrink reports how many bytes may be removed from a payload.
func (c *Ctx) canShrink(n *ir.Node) int {
	return len(n.Raw) - int(n.MinLen)
}

// All returns every built-in operator, in a stable order.
//
// The order is part of the reproducibility contract: operator selection is by
// index, so reordering this list changes what every recorded campaign replays
// to. Append; never insert.
func All() []Mutator {
	return []Mutator{
		BitFlip{}, ByteFlip{}, Arith{}, Interesting{}, RandomByte{},
		InsertBytes{}, DeleteBytes{}, CopyBytes{}, SetBlock{},
		IntArith{}, IntInteresting{}, IntRandom{}, IntBitFlip{},
		ChoiceSwitch{}, OptToggle{},
		RepeatInsert{}, RepeatDelete{}, RepeatDuplicate{}, RepeatSwap{}, RepeatShuffle{},
		DictOverwrite{}, DictInsert{},
		SpliceSubtree{}, SpliceBytes{},
	}
}
