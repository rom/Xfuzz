package ir

import (
	"fmt"
	"strconv"
	"strings"
)

// Kind is the type of an IR node.
type Kind uint8

// The node kinds. KindBytes is the degenerate case: an unstructured input is a
// single Bytes node, so byte-level fuzzing is structured fuzzing with a
// one-node tree rather than a separate code path.
const (
	KindInvalid Kind = iota
	KindBytes        // opaque byte run
	KindInt          // integer with width, signedness, endianness
	KindStr          // text with an encoding
	KindStruct       // ordered named fields
	KindRepeat       // homogeneous sequence
	KindChoice       // tagged alternation; exactly one child is selected
	KindOpt          // presence-optional subtree
	KindRef          // reference to another node; contributes no bytes
	KindDerived      // value computed from other nodes
	numKinds
)

var kindNames = [...]string{
	KindInvalid: "invalid",
	KindBytes:   "bytes",
	KindInt:     "int",
	KindStr:     "str",
	KindStruct:  "struct",
	KindRepeat:  "repeat",
	KindChoice:  "choice",
	KindOpt:     "opt",
	KindRef:     "ref",
	KindDerived: "derived",
}

func (k Kind) String() string {
	if int(k) < len(kindNames) && kindNames[k] != "" {
		return kindNames[k]
	}
	return "Kind(" + strconv.Itoa(int(k)) + ")"
}

// IsLeaf reports whether the kind carries a value rather than children.
func (k Kind) IsLeaf() bool {
	return k == KindBytes || k == KindInt || k == KindStr || k == KindDerived || k == KindRef
}

// IsContainer reports whether the kind holds children.
func (k Kind) IsContainer() bool {
	return k == KindStruct || k == KindRepeat || k == KindChoice || k == KindOpt
}

// Endian is the byte order of an integer-valued node.
type Endian uint8

// Byte orders.
const (
	BigEndian Endian = iota
	LittleEndian
)

func (e Endian) String() string {
	if e == LittleEndian {
		return "little"
	}
	return "big"
}

// Node flags, packed to keep Node small enough to pool densely.
const (
	flagShared    uint8 = 1 << iota // copy before mutating (arena copy-on-write)
	flagPresent                     // KindOpt: the subtree is present
	flagSigned                      // KindInt: value is signed
	flagImmutable                   // mutators must leave this node alone
)

// Node is one element of an input tree.
//
// A file is one tree; a protocol message is one tree; a session is a Repeat of
// them; a stateless input is a session of length one. That single
// representation is what lets one engine serve every domain (ADR-0005).
//
// Nodes are pooled by an Arena in the hot path, so this struct is deliberately
// flat: no maps, no interfaces, and optional detail behind pointers that only
// the kinds needing it allocate.
type Node struct {
	Kind   Kind
	Width  uint8  // KindInt, KindDerived: encoded byte width (1, 2, 4, 8)
	Endian Endian // KindInt, KindDerived
	flags  uint8

	Sel int32 // KindChoice: index of the selected alternative
	Val int64 // KindInt, KindDerived: the value

	Name     string
	Raw      []byte  // KindBytes, KindStr: the payload
	Children []*Node // containers

	// MinLen and MaxLen bound the payload length of a Bytes or Str node, or the
	// element count of a Repeat node. A MaxLen of zero means unbounded.
	//
	// These are what stop a mutator producing something no parser would ever
	// see. A PNG chunk type is exactly four bytes; a five-byte one is not a
	// deeper exploration of PNG, it is an input every reader rejects at offset
	// four. Deliberate violation of a format's rules is expressed by relaxing
	// the schema or suppressing derivations, not by operators ignoring the
	// model.
	MinLen, MaxLen int32

	Derive *Derivation // KindDerived
	Target *Ref        // KindRef
}

// Shared reports whether the node is shared between trees and must be copied
// before mutation.
func (n *Node) Shared() bool { return n.flags&flagShared != 0 }

// Present reports whether an optional subtree is present. Non-Opt nodes are
// always present.
func (n *Node) Present() bool { return n.Kind != KindOpt || n.flags&flagPresent != 0 }

// SetPresent marks an optional subtree present or absent.
func (n *Node) SetPresent(v bool) {
	if v {
		n.flags |= flagPresent
	} else {
		n.flags &^= flagPresent
	}
}

// Immutable reports whether mutators must leave the node alone. Magic numbers
// and format signatures are marked this way: mutating them produces an input
// the target discards in its first comparison.
func (n *Node) Immutable() bool { return n.flags&flagImmutable != 0 }

// SetImmutable marks a node as off-limits to mutation.
func (n *Node) SetImmutable(v bool) {
	if v {
		n.flags |= flagImmutable
	} else {
		n.flags &^= flagImmutable
	}
}

// LenBounds returns the node's length or count bounds, with ok false when it is
// unbounded above.
func (n *Node) LenBounds() (minimum, maximum int, ok bool) {
	return int(n.MinLen), int(n.MaxLen), n.MaxLen > 0
}

// FitsLen reports whether a length satisfies the node's bounds.
func (n *Node) FitsLen(l int) bool {
	if l < int(n.MinLen) {
		return false
	}
	return n.MaxLen <= 0 || l <= int(n.MaxLen)
}

// Signed reports whether an integer node is signed.
func (n *Node) Signed() bool { return n.flags&flagSigned != 0 }

// SetSigned marks an integer node as signed.
func (n *Node) SetSigned(v bool) {
	if v {
		n.flags |= flagSigned
	} else {
		n.flags &^= flagSigned
	}
}

// Child returns the first child with the given name, or nil.
func (n *Node) Child(name string) *Node {
	for _, c := range n.Children {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// ChildIndex returns the index of the first child with the given name, or -1.
func (n *Node) ChildIndex(name string) int {
	for i, c := range n.Children {
		if c.Name == name {
			return i
		}
	}
	return -1
}

// Append adds children to a container node.
func (n *Node) Append(kids ...*Node) *Node {
	n.Children = append(n.Children, kids...)
	return n
}

// Selected returns the active child of a Choice node, or nil when the selection
// is out of range.
func (n *Node) Selected() *Node {
	if n.Kind != KindChoice || n.Sel < 0 || int(n.Sel) >= len(n.Children) {
		return nil
	}
	return n.Children[n.Sel]
}

// Walk visits n and its descendants in document (pre-)order. Returning false
// from fn skips the node's children.
func Walk(n *Node, fn func(*Node) bool) {
	if n == nil || !fn(n) {
		return
	}
	for _, c := range n.Children {
		Walk(c, fn)
	}
}

// WalkPost visits n and its descendants bottom-up, children before parents.
func WalkPost(n *Node, fn func(*Node)) {
	if n == nil {
		return
	}
	for _, c := range n.Children {
		WalkPost(c, fn)
	}
	fn(n)
}

// Count returns the number of nodes in the tree rooted at n.
func Count(n *Node) int {
	c := 0
	Walk(n, func(*Node) bool { c++; return true })
	return c
}

// Depth returns the height of the tree rooted at n; a leaf has depth 1.
func Depth(n *Node) int {
	if n == nil {
		return 0
	}
	best := 0
	for _, c := range n.Children {
		if d := Depth(c); d > best {
			best = d
		}
	}
	return best + 1
}

// Equal reports whether two trees have the same structure and values. It
// ignores arena bookkeeping such as the shared flag, so a clone equals its
// original.
func Equal(a, b *Node) bool {
	switch {
	case a == nil || b == nil:
		return a == b
	case a.Kind != b.Kind, a.Name != b.Name, a.Width != b.Width,
		a.Endian != b.Endian, a.Sel != b.Sel, a.Val != b.Val:
		return false
	case a.MinLen != b.MinLen, a.MaxLen != b.MaxLen:
		return false
	case a.Present() != b.Present(), a.Signed() != b.Signed(),
		a.Immutable() != b.Immutable():
		return false
	case !bytesEqual(a.Raw, b.Raw):
		return false
	case len(a.Children) != len(b.Children):
		return false
	}
	if (a.Derive == nil) != (b.Derive == nil) {
		return false
	}
	if a.Derive != nil && !a.Derive.equal(b.Derive) {
		return false
	}
	if (a.Target == nil) != (b.Target == nil) {
		return false
	}
	if a.Target != nil && !a.Target.equal(b.Target) {
		return false
	}
	for i := range a.Children {
		if !Equal(a.Children[i], b.Children[i]) {
			return false
		}
	}
	return true
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Validate reports the first structural problem in a tree, or nil.
func Validate(n *Node) error { return validate(n, "") }

func validate(n *Node, path string) error {
	if n == nil {
		return fmt.Errorf("%s: nil node", pathOr(path))
	}
	here := joinPath(path, n.Name)
	if n.Kind == KindInvalid || n.Kind >= numKinds {
		return fmt.Errorf("%s: invalid kind %d", pathOr(here), n.Kind)
	}
	switch n.Kind {
	case KindInt, KindDerived:
		switch n.Width {
		case 1, 2, 4, 8:
		default:
			return fmt.Errorf("%s: %s width must be 1, 2, 4 or 8, got %d", pathOr(here), n.Kind, n.Width)
		}
		if n.Kind == KindDerived && n.Derive == nil {
			return fmt.Errorf("%s: derived node has no derivation", pathOr(here))
		}
	case KindChoice:
		if len(n.Children) == 0 {
			return fmt.Errorf("%s: choice has no alternatives", pathOr(here))
		}
		if n.Sel < 0 || int(n.Sel) >= len(n.Children) {
			return fmt.Errorf("%s: choice selects %d of %d alternatives", pathOr(here), n.Sel, len(n.Children))
		}
	case KindOpt:
		if len(n.Children) != 1 {
			return fmt.Errorf("%s: optional must have exactly one child, got %d", pathOr(here), len(n.Children))
		}
	case KindRef:
		if n.Target == nil {
			return fmt.Errorf("%s: reference has no target", pathOr(here))
		}
	}
	if n.MaxLen > 0 && n.MinLen > n.MaxLen {
		return fmt.Errorf("%s: MinLen %d exceeds MaxLen %d", pathOr(here), n.MinLen, n.MaxLen)
	}
	switch n.Kind {
	case KindBytes, KindStr:
		if !n.FitsLen(len(n.Raw)) {
			return fmt.Errorf("%s: payload is %d bytes, outside the declared bounds [%d, %d]",
				pathOr(here), len(n.Raw), n.MinLen, n.MaxLen)
		}
	case KindRepeat:
		if !n.FitsLen(len(n.Children)) {
			return fmt.Errorf("%s: has %d elements, outside the declared bounds [%d, %d]",
				pathOr(here), len(n.Children), n.MinLen, n.MaxLen)
		}
	}
	if n.Kind.IsLeaf() && len(n.Children) > 0 {
		return fmt.Errorf("%s: %s is a leaf but has %d children", pathOr(here), n.Kind, len(n.Children))
	}
	for _, c := range n.Children {
		if err := validate(c, here); err != nil {
			return err
		}
	}
	return nil
}

func joinPath(base, name string) string {
	if name == "" {
		return base
	}
	if base == "" {
		return name
	}
	return base + "." + name
}

func pathOr(p string) string {
	if p == "" {
		return "<root>"
	}
	return p
}

// String renders a compact one-line summary, for test failures and debugging.
func (n *Node) String() string {
	if n == nil {
		return "<nil>"
	}
	var b strings.Builder
	b.WriteString(n.Kind.String())
	if n.Name != "" {
		b.WriteString(" ")
		b.WriteString(n.Name)
	}
	switch n.Kind {
	case KindBytes, KindStr:
		fmt.Fprintf(&b, "(%d bytes)", len(n.Raw))
	case KindInt, KindDerived:
		fmt.Fprintf(&b, "(=%d w%d %s)", n.Val, n.Width, n.Endian)
	default:
		if len(n.Children) > 0 {
			fmt.Fprintf(&b, "(%d children)", len(n.Children))
		}
	}
	return b.String()
}
