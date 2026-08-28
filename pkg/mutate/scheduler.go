package mutate

import (
	"fmt"
	"sort"
	"strings"

	"github.com/rom/Xfuzz/pkg/ir"
)

// Scheduler composes operators into a mutation round and records what it did.
//
// Two responsibilities that look separable but are not: choosing what to do,
// and accounting for whether it worked. Per-operator yield is the only way to
// tell a productive operator from one burning executions, and it is only
// meaningful if the thing being measured is the thing that was chosen — so
// selection and accounting live together.
type Scheduler struct {
	ops     []Mutator
	weights []int
	stats   []Stats
	index   map[string]int

	// SizeWeighting biases node selection toward larger payloads, so a 40 KB
	// blob receives proportionally more attention than a 4-byte tag. Without it
	// every node is equally likely and byte-level exploration of large payloads
	// starves. It is a heuristic, exposed so a campaign can turn it off.
	SizeWeighting bool

	// MinStack and MaxStack bound how many operators one round applies. Applying
	// several at once — AFL's havoc stacking — reaches combinations that single
	// mutations do not.
	MinStack, MaxStack int

	// scratch, reused across rounds
	path    []int // the walk's current position
	chosen  []int // the selected node's path, kept clear of path
	pathBuf []int
	ops2    []Op

	// node-selection state, held here so the walk can be a method rather than a
	// recursive closure; a closure would allocate on every round.
	pickTotal  int
	pickNodeAt *ir.Node
	pickFor    Mutator
}

// Stats counts one operator's activity.
type Stats struct {
	Attempts    uint64 // selected and asked to mutate
	Applied     uint64 // reported a change
	Interesting uint64 // produced a corpus entry (recorded by the engine)
	Findings    uint64 // produced a finding (recorded by the engine)
}

// Yield is the share of attempts that produced a corpus entry. It is the number
// that says whether an operator earns its place.
func (s Stats) Yield() float64 {
	if s.Attempts == 0 {
		return 0
	}
	return float64(s.Interesting) / float64(s.Attempts)
}

// ApplyRate is the share of attempts that changed anything. A low rate means
// the operator is being offered nodes it cannot use.
func (s Stats) ApplyRate() float64 {
	if s.Attempts == 0 {
		return 0
	}
	return float64(s.Applied) / float64(s.Attempts)
}

// Op records one applied operator, for provenance (ASR-0008).
type Op struct {
	// Mutator is the operator's name.
	Mutator string
	// Path is the child-index route from the root to the mutated node.
	Path []int
	// RandPos is the parameter stream's position before the operator ran.
	// Together with the path, it is enough to reproduce the mutation exactly.
	RandPos uint64
}

func (o Op) String() string {
	var b strings.Builder
	b.WriteString(o.Mutator)
	b.WriteString("@/")
	for i, p := range o.Path {
		if i > 0 {
			b.WriteByte('/')
		}
		fmt.Fprintf(&b, "%d", p)
	}
	fmt.Fprintf(&b, " rng=%d", o.RandPos)
	return b.String()
}

// NewScheduler returns a scheduler over the given operators, each at weight 1.
func NewScheduler(ops ...Mutator) *Scheduler {
	s := &Scheduler{
		index:         make(map[string]int, len(ops)),
		SizeWeighting: true,
		MinStack:      1,
		MaxStack:      8,
	}
	for _, m := range ops {
		s.Add(m, 1)
	}
	return s
}

// Default returns a scheduler over every built-in operator with weights that
// favour cheap byte-level mutation while keeping structural operators frequent
// enough to matter.
func Default() *Scheduler {
	s := NewScheduler()
	for _, m := range All() {
		w := 4
		switch KindOf(m) {
		case KindStructural:
			w = 6 // the reason a schema is worth having
		case KindSplice:
			w = 2 // useful but only with a donor
		case KindDictionary:
			w = 3 // inert without a dictionary
		}
		s.Add(m, w)
	}
	return s
}

// Add registers an operator. A weight of zero disables it without removing it,
// which keeps operator indices stable across campaigns.
func (s *Scheduler) Add(m Mutator, weight int) {
	if i, dup := s.index[m.Name()]; dup {
		s.weights[i] = weight
		return
	}
	s.index[m.Name()] = len(s.ops)
	s.ops = append(s.ops, m)
	s.weights = append(s.weights, weight)
	s.stats = append(s.stats, Stats{})
}

// SetWeight adjusts an operator's weight, reporting whether it is registered.
func (s *Scheduler) SetWeight(name string, weight int) bool {
	i, ok := s.index[name]
	if ok {
		s.weights[i] = weight
	}
	return ok
}

// Operators returns the registered operators in selection order.
func (s *Scheduler) Operators() []Mutator { return s.ops }

// Operator looks an operator up by name, which is how a recorded provenance
// chain is replayed.
func (s *Scheduler) Operator(name string) (Mutator, bool) {
	i, ok := s.index[name]
	if !ok {
		return nil, false
	}
	return s.ops[i], true
}

// maxOperatorRetries bounds how many operators a round will try before giving
// up on a stack slot, when the chosen ones have nowhere applicable to act.
const maxOperatorRetries = 8

// Mutate applies a stack of operators to a tree and returns what it did.
//
// Selection is operator-first: an operator is drawn by weight, then a node it
// can act on is drawn from the tree. The obvious alternative — pick a node,
// then pick among the operators that fit it — was tried first and is wrong,
// because it hands the mix to whichever operator has the broadest
// applicability rather than to the configured weights. In a PNG corpus it gave
// subtree splicing eight times the attempts of every byte operator combined,
// with the weights saying otherwise. Weights only mean something if they decide
// the mix.
//
// The returned slice and the paths inside it are owned by the Scheduler and are
// valid until the next call. Copy them with CloneOps to keep them.
func (s *Scheduler) Mutate(c *Ctx, root *ir.Node) []Op {
	stack := s.MinStack
	if s.MaxStack > s.MinStack {
		stack = s.MinStack + c.Nodes.Intn(s.MaxStack-s.MinStack+1)
	}
	s.ops2 = s.ops2[:0]
	s.pathBuf = s.pathBuf[:0]

	for i := 0; i < stack; i++ {
		for try := 0; try < maxOperatorRetries; try++ {
			op := c.Select.Weighted(s.weights)
			if op < 0 {
				return s.ops2 // every operator is disabled
			}
			node, path := s.pickNodeFor(c, root, s.ops[op])
			if node == nil {
				continue // this operator has nowhere to act in this tree
			}

			pos := c.Rand.Position()
			s.stats[op].Attempts++
			if !s.ops[op].Mutate(c, node) {
				continue
			}
			s.stats[op].Applied++

			start := len(s.pathBuf)
			s.pathBuf = append(s.pathBuf, path...)
			// A three-index slice so a later append cannot write through this
			// one. If the append above reallocated, earlier slices still
			// reference the previous array, which still holds their data.
			s.ops2 = append(s.ops2, Op{
				Mutator: s.ops[op].Name(),
				Path:    s.pathBuf[start:len(s.pathBuf):len(s.pathBuf)],
				RandPos: pos,
			})
			break
		}
	}
	return s.ops2
}

// CloneOps copies a provenance record so it can outlive the next Mutate call.
// The engine does this only for inputs that become corpus entries, which keeps
// the hot path free of the allocation.
func CloneOps(ops []Op) []Op {
	if len(ops) == 0 {
		return nil
	}
	out := make([]Op, len(ops))
	for i, o := range ops {
		out[i] = Op{Mutator: o.Mutator, RandPos: o.RandPos, Path: append([]int(nil), o.Path...)}
	}
	return out
}

// pickNodeFor chooses a node the given operator can act on, returning it with
// the child-index path that reaches it, or nil when the tree has none.
//
// Selection is a single weighted reservoir pass: no candidate list is built, so
// the cost is one walk and no allocation however large the tree. The walk is a
// method rather than a recursive closure because a closure capturing local
// state allocates on every round, and this runs once per stacked operator.
func (s *Scheduler) pickNodeFor(c *Ctx, root *ir.Node, m Mutator) (*ir.Node, []int) {
	s.path = s.path[:0]
	s.chosen = s.chosen[:0]
	s.pickTotal = 0
	s.pickNodeAt = nil
	s.pickFor = m

	s.walkPick(c, root)

	if s.pickNodeAt == nil {
		return nil, nil
	}
	return s.pickNodeAt, s.chosen
}

func (s *Scheduler) walkPick(c *Ctx, n *ir.Node) {
	if s.pickFor.CanApply(c, n) {
		w := s.nodeWeight(n)
		s.pickTotal += w
		// Select with probability w/total: correct weighted sampling in one pass.
		if c.Nodes.Intn(s.pickTotal) < w {
			s.pickNodeAt = n
			// Into its own buffer: appending onto a slice of s.path would be
			// overwritten by the walk as it continues.
			s.chosen = append(s.chosen[:0], s.path...)
		}
	}
	for i, kid := range n.Children {
		s.path = append(s.path, i)
		s.walkPick(c, kid)
		s.path = s.path[:len(s.path)-1]
	}
}

// nodeWeight biases selection toward larger payloads when size weighting is on.
func (s *Scheduler) nodeWeight(n *ir.Node) int {
	if !s.SizeWeighting {
		return 1
	}
	if n.Kind == ir.KindBytes || n.Kind == ir.KindStr {
		// Sub-linear: a 4 KB payload deserves more attention than a 4-byte tag,
		// but not a thousand times more, or structure never gets touched.
		w := 1 + len(n.Raw)/64
		if w > 32 {
			w = 32
		}
		return w
	}
	return 1
}

// RecordOutcome attributes an execution's result to the operators that produced
// it. The engine calls this once feedback has judged the input.
func (s *Scheduler) RecordOutcome(ops []Op, interesting, finding bool) {
	if !interesting && !finding {
		return
	}
	for _, o := range ops {
		i, ok := s.index[o.Mutator]
		if !ok {
			continue
		}
		if interesting {
			s.stats[i].Interesting++
		}
		if finding {
			s.stats[i].Findings++
		}
	}
}

// StatsFor returns one operator's counters.
func (s *Scheduler) StatsFor(name string) (Stats, bool) {
	i, ok := s.index[name]
	if !ok {
		return Stats{}, false
	}
	return s.stats[i], true
}

// NamedStats pairs an operator with its counters.
type NamedStats struct {
	Name string
	Kind Kind
	Stats
}

// Report returns per-operator statistics, most productive first. This is what
// answers "which operators are earning their executions" — the introspection
// ASR-0012 requires.
func (s *Scheduler) Report() []NamedStats {
	out := make([]NamedStats, 0, len(s.ops))
	for i, m := range s.ops {
		out = append(out, NamedStats{Name: m.Name(), Kind: KindOf(m), Stats: s.stats[i]})
	}
	sort.SliceStable(out, func(a, b int) bool {
		if x, y := out[a].Yield(), out[b].Yield(); x != y {
			return x > y
		}
		return out[a].Attempts > out[b].Attempts
	})
	return out
}

// ResetStats zeroes every counter.
func (s *Scheduler) ResetStats() {
	for i := range s.stats {
		s.stats[i] = Stats{}
	}
}
