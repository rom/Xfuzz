package ir

import "fmt"

// Slab sizes. Nodes are handed out from fixed slabs that are never reallocated,
// because growing a single backing array would invalidate every outstanding
// *Node.
const (
	nodeSlabSize = 512
	kidSlabSize  = 2048
	byteSlabSize = 64 << 10
)

// Arena allocates nodes for one worker's fuzz loop.
//
// The hot-path contract is: clone a corpus entry into the arena, mutate the
// clone, fix it up, encode it, execute, then Reset. Reset rewinds the bump
// pointers rather than freeing, so after the first few iterations the slabs are
// large enough and steady-state fuzzing allocates nothing at all — which
// ASR-0007 requires and which Go makes easy to lose without measuring.
//
// An Arena is not safe for concurrent use. Each worker owns one; workers are
// separate processes (ADR-0015), so there is nothing to share.
type Arena struct {
	nodeSlabs [][]Node
	nodeSlab  int
	nodeIdx   int

	kidSlabs [][]*Node
	kidSlab  int
	kidIdx   int

	byteSlabs [][]byte
	byteSlab  int
	byteIdx   int

	// Oversized requests get their own buffers, reused in order across resets
	// so that a corpus of similarly shaped inputs stops allocating too.
	bigKids [][]*Node
	bigKid  int
	bigBufs [][]byte
	bigBuf  int

	stats Stats
}

// Stats counts what an Arena has handed out since the last ResetStats.
type Stats struct {
	Nodes       int64
	Kids        int64
	Bytes       int64
	Resets      int64
	Clones      int64
	CopyOnWrite int64
}

// NewArena returns an empty arena.
func NewArena() *Arena { return &Arena{} }

// Stats returns allocation counters, for the health metrics in ASR-0012.
func (a *Arena) Stats() Stats { return a.stats }

// ResetStats zeroes the counters without releasing memory.
func (a *Arena) ResetStats() { a.stats = Stats{} }

// Reset rewinds the arena. Every node, slice, and buffer it handed out becomes
// invalid; nothing is freed.
func (a *Arena) Reset() {
	a.nodeSlab, a.nodeIdx = 0, 0
	a.kidSlab, a.kidIdx = 0, 0
	a.byteSlab, a.byteIdx = 0, 0
	a.bigKid, a.bigBuf = 0, 0
	a.stats.Resets++
}

// New returns a zeroed node of the given kind.
func (a *Arena) New(k Kind) *Node {
	if a.nodeSlab >= len(a.nodeSlabs) {
		a.nodeSlabs = append(a.nodeSlabs, make([]Node, nodeSlabSize))
	}
	n := &a.nodeSlabs[a.nodeSlab][a.nodeIdx]
	*n = Node{Kind: k}
	a.nodeIdx++
	if a.nodeIdx == nodeSlabSize {
		a.nodeSlab++
		a.nodeIdx = 0
	}
	a.stats.Nodes++
	return n
}

// Kids returns a zero-length child slice with capacity for at least n children.
func (a *Arena) Kids(n int) []*Node {
	a.stats.Kids++
	if n > kidSlabSize {
		if a.bigKid < len(a.bigKids) && cap(a.bigKids[a.bigKid]) >= n {
			s := a.bigKids[a.bigKid][:0]
			a.bigKid++
			return s
		}
		s := make([]*Node, 0, n)
		if a.bigKid < len(a.bigKids) {
			a.bigKids[a.bigKid] = s
		} else {
			a.bigKids = append(a.bigKids, s)
		}
		a.bigKid++
		return s
	}
	if a.kidSlab >= len(a.kidSlabs) {
		a.kidSlabs = append(a.kidSlabs, make([]*Node, kidSlabSize))
	}
	if a.kidIdx+n > kidSlabSize {
		a.kidSlab++
		a.kidIdx = 0
		if a.kidSlab >= len(a.kidSlabs) {
			a.kidSlabs = append(a.kidSlabs, make([]*Node, kidSlabSize))
		}
	}
	s := a.kidSlabs[a.kidSlab][a.kidIdx : a.kidIdx : a.kidIdx+n]
	a.kidIdx += n
	return s
}

// CopyBytes returns arena-owned storage holding a copy of src.
//
// Payloads are copied rather than shared so that a mutator can flip a bit in
// place without corrupting the corpus entry the clone came from. That is the
// fastest mutation there is, and it has to be safe.
func (a *Arena) CopyBytes(src []byte) []byte {
	if len(src) == 0 {
		return nil
	}
	dst := a.byteBuf(len(src))
	copy(dst, src)
	a.stats.Bytes += int64(len(src))
	return dst
}

func (a *Arena) byteBuf(n int) []byte {
	if n > byteSlabSize {
		if a.bigBuf < len(a.bigBufs) && cap(a.bigBufs[a.bigBuf]) >= n {
			b := a.bigBufs[a.bigBuf][:n]
			a.bigBuf++
			return b
		}
		b := make([]byte, n)
		if a.bigBuf < len(a.bigBufs) {
			a.bigBufs[a.bigBuf] = b
		} else {
			a.bigBufs = append(a.bigBufs, b)
		}
		a.bigBuf++
		return b
	}
	if a.byteSlab >= len(a.byteSlabs) {
		a.byteSlabs = append(a.byteSlabs, make([]byte, byteSlabSize))
	}
	if a.byteIdx+n > byteSlabSize {
		a.byteSlab++
		a.byteIdx = 0
		if a.byteSlab >= len(a.byteSlabs) {
			a.byteSlabs = append(a.byteSlabs, make([]byte, byteSlabSize))
		}
	}
	b := a.byteSlabs[a.byteSlab][a.byteIdx : a.byteIdx+n : a.byteIdx+n]
	a.byteIdx += n
	return b
}

// Clone deep-copies a tree into the arena. The result shares nothing with the
// original and is fully mutable.
func (a *Arena) Clone(n *Node) *Node {
	if n == nil {
		return nil
	}
	a.stats.Clones++
	return a.clone(n)
}

func (a *Arena) clone(n *Node) *Node {
	c := a.New(n.Kind)
	c.Width, c.Endian, c.Sel, c.Val = n.Width, n.Endian, n.Sel, n.Val
	c.MinLen, c.MaxLen = n.MinLen, n.MaxLen
	c.flags = n.flags &^ flagShared
	c.Name = n.Name
	c.Derive, c.Target = n.Derive, n.Target // derivations and refs are immutable
	c.Raw = a.CopyBytes(n.Raw)
	if len(n.Children) > 0 {
		c.Children = a.Kids(len(n.Children))
		for _, k := range n.Children {
			c.Children = append(c.Children, a.clone(k))
		}
	}
	return c
}

// Share marks a tree as shared, so that any attempt to mutate through the
// copy-on-write helpers copies first. The original stays usable.
func (a *Arena) Share(n *Node) *Node {
	if n != nil {
		n.flags |= flagShared
	}
	return n
}

// Mutable returns a version of n that is safe to modify in place.
//
// If n is shared, it is shallow-copied: the copy owns its own payload and child
// slice, and the children it points at are themselves marked shared, so the
// next level down copies only if it too is touched. Copying a path from the
// root to the node being mutated is what makes cloning a large tree for a
// one-byte change cheap.
func (a *Arena) Mutable(n *Node) *Node {
	if n == nil || !n.Shared() {
		return n
	}
	a.stats.CopyOnWrite++
	c := a.New(n.Kind)
	c.Width, c.Endian, c.Sel, c.Val = n.Width, n.Endian, n.Sel, n.Val
	c.MinLen, c.MaxLen = n.MinLen, n.MaxLen
	c.flags = n.flags &^ flagShared
	c.Name = n.Name
	c.Derive, c.Target = n.Derive, n.Target
	c.Raw = a.CopyBytes(n.Raw)
	if len(n.Children) > 0 {
		c.Children = a.Kids(len(n.Children))
		for _, k := range n.Children {
			k.flags |= flagShared
			c.Children = append(c.Children, k)
		}
	}
	return c
}

// MutableChild makes parent.Children[i] modifiable, replacing it in place if a
// copy was needed. parent must already be mutable.
func (a *Arena) MutableChild(parent *Node, i int) (*Node, error) {
	if parent == nil {
		return nil, fmt.Errorf("ir: MutableChild on a nil parent")
	}
	if parent.Shared() {
		return nil, fmt.Errorf("ir: MutableChild on shared parent %s; make the parent mutable first", parent)
	}
	if i < 0 || i >= len(parent.Children) {
		return nil, fmt.Errorf("ir: MutableChild index %d out of range (%d children)", i, len(parent.Children))
	}
	c := a.Mutable(parent.Children[i])
	parent.Children[i] = c
	return c, nil
}

// MutablePath makes the node at a path modifiable, copying every shared node
// along the way. root is updated in place if the root itself had to be copied.
func (a *Arena) MutablePath(root **Node, steps ...Step) (*Node, error) {
	if root == nil || *root == nil {
		return nil, fmt.Errorf("ir: MutablePath on a nil root")
	}
	*root = a.Mutable(*root)
	cur := *root
	for si, s := range steps {
		i := s.Index
		if !s.ByIndex {
			i = cur.ChildIndex(s.Name)
			if i < 0 {
				return nil, fmt.Errorf("%w: step %d: no child named %q under %s",
					ErrNoSuchNode, si, s.Name, cur)
			}
		}
		next, err := a.MutableChild(cur, i)
		if err != nil {
			return nil, err
		}
		cur = next
	}
	return cur, nil
}

// Alloc returns a named node from the arena. A nil Arena allocates from the
// heap, so a codec can build a tree without one when it is not on the hot path.
func (a *Arena) Alloc(k Kind, name string) *Node {
	if a == nil {
		return &Node{Kind: k, Name: name}
	}
	n := a.New(k)
	n.Name = name
	return n
}

// AllocKids returns a zero-length child slice with capacity n, from the heap
// when the Arena is nil.
func (a *Arena) AllocKids(n int) []*Node {
	if a == nil {
		return make([]*Node, 0, n)
	}
	return a.Kids(n)
}

// Buf returns arena-owned storage of length n. Its contents are unspecified;
// the caller must fill every byte it intends to read.
func (a *Arena) Buf(n int) []byte {
	if n <= 0 {
		return nil
	}
	if a == nil {
		return make([]byte, n)
	}
	a.stats.Bytes += int64(n)
	return a.byteBuf(n)
}

// GrowBytes returns a slice with the same contents as s and room for at least
// need more bytes, taking new storage from the arena rather than the heap.
//
// Mutators that lengthen a payload go through this so that growth stays inside
// the arena and steady-state fuzzing keeps allocating nothing.
func (a *Arena) GrowBytes(s []byte, need int) []byte {
	if need <= 0 || cap(s)-len(s) >= need {
		return s
	}
	want := len(s) + need
	if double := 2 * cap(s); double > want {
		want = double
	}
	dst := a.Buf(want)[:len(s)]
	copy(dst, s)
	return dst
}

// GrowKids returns a child slice with the same contents as s and room for at
// least need more children, taking new storage from the arena.
func (a *Arena) GrowKids(s []*Node, need int) []*Node {
	if need <= 0 || cap(s)-len(s) >= need {
		return s
	}
	want := len(s) + need
	if double := 2 * cap(s); double > want {
		want = double
	}
	dst := a.AllocKids(want)[:len(s)]
	copy(dst, s)
	return dst
}
