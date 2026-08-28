package ir

import (
	"errors"
	"fmt"
	"slices"
	"sort"
)

// ErrCyclicDerivation reports derivations that depend on each other's values.
var ErrCyclicDerivation = errors.New("ir: cyclic derivation")

// Fixer recomputes derived values after a tree is mutated.
//
// This is the mechanism that makes structured mutation worth doing: mutate
// freely, then restore the length fields, counts, offsets, and checksums that a
// target validates before it parses anything interesting. Without it, nearly
// every execution dies in the first bounds check.
//
// A Fixer holds reusable scratch state. Keep one per worker and call Fix
// repeatedly; steady-state fixups then allocate nothing.
//
// # How it stays acyclic
//
// The pass exploits a property of the node model: every derived node has a
// fixed width, so no derived *value* can change any node's *size*. Sizes and
// offsets are therefore fully determined by structure alone and can be computed
// once, up front. Length, Count, and Offset read only those, so they can never
// form a cycle. Only Checksum reads other nodes' values, so only checksums need
// ordering — and they are ordered by containment, which is a partial order.
//
// A checksum covering the field that holds it is genuinely circular. Real
// formats resolve it by treating the field as zero (the IPv4 header checksum,
// among others), which Derivation.SelfZero expresses. Without that flag such a
// derivation is reported as a cycle rather than silently producing something
// arbitrary.
type Fixer struct {
	buf    []byte
	length map[*Node]int
	off    map[*Node]int

	tasks []csTask
	byOff []int // task indices sorted by field offset
	indeg []int
	ready []int
	stack []*Node
}

// csTask is one checksum derivation, resolved to byte spans.
type csTask struct {
	node               *Node
	fieldOff, fieldEnd int
	rangeOff, rangeEnd int
	fn                 ChecksumFunc
	selfInclusive      bool
	deps               []int // tasks that must be computed first
}

// NewFixer returns a Fixer with reusable scratch state.
func NewFixer() *Fixer {
	return &Fixer{
		length: make(map[*Node]int),
		off:    make(map[*Node]int),
	}
}

// Fixup recomputes the derived values of a tree. It allocates scratch state on
// every call; on the hot path use a reused Fixer instead.
func Fixup(root *Node, sup Suppress) error {
	_, err := NewFixer().Fix(root, sup)
	return err
}

// Fix recomputes derived values and returns the resulting encoding.
//
// The returned slice aliases the Fixer's buffer and is invalidated by the next
// call to Fix. Copy it if it must outlive that.
func (f *Fixer) Fix(root *Node, sup Suppress) ([]byte, error) {
	if root == nil {
		return nil, nil
	}

	// Sizes and positions first: both are independent of every derived value,
	// so one pass each settles them for the whole fixup.
	clear(f.length)
	clear(f.off)
	f.measure(root)
	f.locate(root, 0)

	// One walk computes every size-dependent derivation and collects the
	// value-dependent ones, which need the ancestor chain to resolve their
	// references.
	f.tasks = f.tasks[:0]
	f.stack = f.stack[:0]
	if err := f.derive(root, root, sup); err != nil {
		return nil, err
	}

	f.buf = AppendEncode(f.buf[:0], root)

	if len(f.tasks) > 0 {
		if err := f.checksums(); err != nil {
			return nil, err
		}
	}
	return f.buf, nil
}

// Encoded returns the encoding produced by the most recent Fix.
func (f *Fixer) Encoded() []byte { return f.buf }

// measure records the encoded length of every node, bottom-up.
func (f *Fixer) measure(n *Node) int {
	var l int
	switch n.Kind {
	case KindBytes, KindStr:
		l = len(n.Raw)
	case KindInt, KindDerived:
		l = int(n.Width)
	case KindRef:
		l = 0
	default:
		for _, c := range n.Children {
			cl := f.measure(c)
			if !contributes(n, c) {
				continue
			}
			l += cl
		}
	}
	f.length[n] = l
	return l
}

// locate records the byte offset of every node that the encoder actually
// writes. Nodes in unselected Choice branches and absent Opt subtrees get no
// entry, so a reference into one is reported rather than silently resolving to
// a position that does not exist in the output.
func (f *Fixer) locate(n *Node, at int) {
	f.off[n] = at
	for _, c := range n.Children {
		if !contributes(n, c) {
			continue
		}
		f.locate(c, at)
		at += f.length[c]
	}
}

// contributes reports whether a child is part of its parent's encoding.
func contributes(parent, child *Node) bool {
	switch parent.Kind {
	case KindChoice:
		return parent.Selected() == child
	case KindOpt:
		return parent.Present()
	}
	return true
}

// derive walks the encoded shape of the tree, computing size-dependent
// derivations in place and queueing checksums for the ordered pass.
func (f *Fixer) derive(root, n *Node, sup Suppress) error {
	if n.Kind == KindDerived {
		if n.Derive == nil {
			return fmt.Errorf("ir: derived node %q has no derivation", n.Name)
		}
		if !sup.suppresses(n) {
			if err := f.computeOne(root, n); err != nil {
				return err
			}
		}
		return nil
	}
	f.stack = append(f.stack, n)
	for _, c := range n.Children {
		if !contributes(n, c) {
			continue
		}
		if err := f.derive(root, c, sup); err != nil {
			return err
		}
	}
	f.stack = f.stack[:len(f.stack)-1]
	return nil
}

func (f *Fixer) computeOne(root, n *Node) error {
	d := n.Derive
	switch d.Kind {
	case DeriveLength:
		start, end, err := f.span(root, n)
		if err != nil {
			return err
		}
		n.Val = truncate(int64(end-start)+d.Addend, n.Width)

	case DeriveCount:
		target, err := d.From.Resolve(root, f.stack, n)
		if err != nil {
			return fmt.Errorf("ir: %s in %q: %w", d, n.Name, err)
		}
		count := len(target.Children)
		if target.Kind == KindOpt && !target.Present() {
			count = 0
		}
		n.Val = truncate(int64(count)+d.Addend, n.Width)

	case DeriveOffset:
		target, err := d.From.Resolve(root, f.stack, n)
		if err != nil {
			return fmt.Errorf("ir: %s in %q: %w", d, n.Name, err)
		}
		at, ok := f.off[target]
		if !ok {
			return fmt.Errorf("ir: %s in %q: target %s is not encoded", d, n.Name, target)
		}
		n.Val = truncate(int64(at)+d.Addend, n.Width)

	case DeriveChecksum:
		fn, ok := Checksum(d.Algo)
		if !ok {
			return fmt.Errorf("ir: %s in %q: unknown checksum algorithm %q (have %v)",
				d, n.Name, d.Algo, ChecksumNames())
		}
		start, end, err := f.span(root, n)
		if err != nil {
			return err
		}
		fieldOff, ok := f.off[n]
		if !ok {
			return fmt.Errorf("ir: %s in %q: the field is not encoded", d, n.Name)
		}
		fieldEnd := fieldOff + int(n.Width)
		self := fieldOff >= start && fieldEnd <= end
		if self && !d.SelfZero {
			return fmt.Errorf("%w: %s in %q covers the field that holds it; set SelfZero to compute it with the field zeroed",
				ErrCyclicDerivation, d, n.Name)
		}
		f.tasks = append(f.tasks, csTask{
			node: n, fieldOff: fieldOff, fieldEnd: fieldEnd,
			rangeOff: start, rangeEnd: end, fn: fn, selfInclusive: self,
		})

	default:
		return fmt.Errorf("ir: unknown derivation class %d in %q", d.Kind, n.Name)
	}
	return nil
}

// span resolves a derivation's From..To range to a byte interval.
func (f *Fixer) span(root, n *Node) (start, end int, err error) {
	d := n.Derive
	from, err := d.From.Resolve(root, f.stack, n)
	if err != nil {
		return 0, 0, fmt.Errorf("ir: %s in %q: from: %w", d, n.Name, err)
	}
	start, ok := f.off[from]
	if !ok {
		return 0, 0, fmt.Errorf("ir: %s in %q: range start %s is not encoded", d, n.Name, from)
	}
	to := from
	if !d.To.IsZero() {
		to, err = d.To.Resolve(root, f.stack, n)
		if err != nil {
			return 0, 0, fmt.Errorf("ir: %s in %q: to: %w", d, n.Name, err)
		}
	}
	toOff, ok := f.off[to]
	if !ok {
		return 0, 0, fmt.Errorf("ir: %s in %q: range end %s is not encoded", d, n.Name, to)
	}
	// Compare the endpoints' positions, not the resulting interval: a range
	// written back-to-front over adjacent fields yields a plausible-looking
	// length of zero rather than an obviously invalid one.
	if toOff < start {
		return 0, 0, fmt.Errorf("ir: %s in %q: range end %s begins at %d, before range start %s at %d; is From..To reversed?",
			d, n.Name, to, toOff, from, start)
	}
	return start, toOff + f.length[to], nil
}

// checksums computes the queued checksums in containment order, patching each
// result back into the encoding buffer so that an enclosing checksum sees the
// finished bytes.
func (f *Fixer) checksums() error {
	f.buildDeps()

	f.indeg = ensureInts(f.indeg, len(f.tasks))
	for i := range f.tasks {
		f.indeg[i] = len(f.tasks[i].deps)
	}

	// Kahn's algorithm, seeded and extended in document order so that the
	// result does not depend on map or visit order.
	f.ready = f.ready[:0]
	for i := range f.tasks {
		if f.indeg[i] == 0 {
			f.ready = append(f.ready, i)
		}
	}

	done := 0
	for head := 0; head < len(f.ready); head++ {
		i := f.ready[head]
		t := &f.tasks[i]

		if t.selfInclusive {
			for b := t.fieldOff; b < t.fieldEnd; b++ {
				f.buf[b] = 0
			}
		}
		v := t.fn(f.buf[t.rangeOff:t.rangeEnd])
		t.node.Val = truncate(int64(v)+t.node.Derive.Addend, t.node.Width)
		putInt(f.buf[t.fieldOff:t.fieldEnd], t.node.Val, t.node.Width, t.node.Endian)
		done++

		// Releasing dependents in ascending index keeps the order deterministic.
		for j := range f.tasks {
			if f.indeg[j] <= 0 {
				continue
			}
			for _, dep := range f.tasks[j].deps {
				if dep == i {
					f.indeg[j]--
					if f.indeg[j] == 0 {
						f.ready = append(f.ready, j)
					}
					break
				}
			}
		}
	}

	if done != len(f.tasks) {
		var stuck []string
		for i := range f.tasks {
			if f.indeg[i] > 0 {
				stuck = append(stuck, f.tasks[i].node.Name)
			}
		}
		return fmt.Errorf("%w: checksums depend on each other: %v", ErrCyclicDerivation, stuck)
	}
	return nil
}

// buildDeps links each checksum to the checksums whose fields fall inside its
// range. Field offsets are sorted once so the search is logarithmic rather than
// quadratic: a format with thousands of chunks has thousands of checksums, and
// comparing every pair would dominate the fixup.
func (f *Fixer) buildDeps() {
	for i := range f.tasks {
		f.tasks[i].deps = f.tasks[i].deps[:0]
	}

	f.byOff = ensureInts(f.byOff, len(f.tasks))
	for i := range f.tasks {
		f.byOff[i] = i
	}
	// Tasks are collected in encoding order, so field offsets are already
	// ascending and the sort is normally a no-op. The check keeps that an
	// optimisation rather than an unstated assumption. slices.SortFunc is used
	// over sort.Slice because the latter allocates a reflect-based swapper, and
	// this runs on the hot path.
	byFieldOff := func(a, b int) int { return f.tasks[a].fieldOff - f.tasks[b].fieldOff }
	if !slices.IsSortedFunc(f.byOff, byFieldOff) {
		slices.SortFunc(f.byOff, byFieldOff)
	}

	for i := range f.tasks {
		t := &f.tasks[i]
		lo := sort.Search(len(f.byOff), func(k int) bool {
			return f.tasks[f.byOff[k]].fieldOff >= t.rangeOff
		})
		for k := lo; k < len(f.byOff); k++ {
			j := f.byOff[k]
			o := &f.tasks[j]
			if o.fieldOff >= t.rangeEnd {
				break
			}
			if j == i || o.fieldEnd > t.rangeEnd {
				continue
			}
			t.deps = append(t.deps, j)
		}
	}
}

func ensureInts(s []int, n int) []int {
	if cap(s) >= n {
		return s[:n]
	}
	return make([]int, n)
}
