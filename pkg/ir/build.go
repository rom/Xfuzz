package ir

// Constructors for building trees by hand. Codecs and the grammar DSL produce
// the same shapes; these exist so that schemas, tests, and fixtures read as
// something close to the format they describe.

// Blob returns an opaque byte node. The payload is retained, not copied.
func Blob(name string, b []byte) *Node {
	return &Node{Kind: KindBytes, Name: name, Raw: b}
}

// Text returns a string node.
func Text(name, s string) *Node {
	return &Node{Kind: KindStr, Name: name, Raw: []byte(s)}
}

// Int returns an integer node.
func Int(name string, v int64, width uint8, e Endian) *Node {
	return &Node{Kind: KindInt, Name: name, Val: v, Width: width, Endian: e}
}

// U8, U16BE, U32BE, U16LE, U32LE and U64BE are the common integer widths.
func U8(name string, v int64) *Node    { return Int(name, v, 1, BigEndian) }
func U16BE(name string, v int64) *Node { return Int(name, v, 2, BigEndian) }
func U32BE(name string, v int64) *Node { return Int(name, v, 4, BigEndian) }
func U64BE(name string, v int64) *Node { return Int(name, v, 8, BigEndian) }
func U16LE(name string, v int64) *Node { return Int(name, v, 2, LittleEndian) }
func U32LE(name string, v int64) *Node { return Int(name, v, 4, LittleEndian) }

// Struct returns an ordered group of named fields.
func Struct(name string, kids ...*Node) *Node {
	return &Node{Kind: KindStruct, Name: name, Children: kids}
}

// Repeat returns a homogeneous sequence. A session of protocol messages and a
// file's chunk list are the same shape.
func Repeat(name string, kids ...*Node) *Node {
	return &Node{Kind: KindRepeat, Name: name, Children: kids}
}

// Choice returns a tagged alternation with the given alternative selected.
func Choice(name string, sel int, alts ...*Node) *Node {
	return &Node{Kind: KindChoice, Name: name, Sel: int32(sel), Children: alts}
}

// Opt returns a presence-optional subtree.
func Opt(name string, present bool, child *Node) *Node {
	n := &Node{Kind: KindOpt, Name: name, Children: []*Node{child}}
	n.SetPresent(present)
	return n
}

// RefTo returns a node that names another node without contributing bytes.
func RefTo(name string, target Ref) *Node {
	return &Node{Kind: KindRef, Name: name, Target: &target}
}

// Derived returns a node whose value is computed during fixup.
func Derived(name string, width uint8, e Endian, d Derivation) *Node {
	return &Node{Kind: KindDerived, Name: name, Width: width, Endian: e, Derive: &d}
}

// LenOf returns a field holding the encoded byte length of one target.
func LenOf(name string, width uint8, e Endian, target Ref) *Node {
	return Derived(name, width, e, Derivation{Kind: DeriveLength, From: target})
}

// LenRange returns a field holding the encoded byte length of an inclusive
// range of siblings.
func LenRange(name string, width uint8, e Endian, from, to Ref) *Node {
	return Derived(name, width, e, Derivation{Kind: DeriveLength, From: from, To: to})
}

// CountOf returns a field holding the number of children of the target.
func CountOf(name string, width uint8, e Endian, target Ref) *Node {
	return Derived(name, width, e, Derivation{Kind: DeriveCount, From: target})
}

// OffsetOf returns a field holding the byte offset of the target from the start
// of the encoding.
func OffsetOf(name string, width uint8, e Endian, target Ref) *Node {
	return Derived(name, width, e, Derivation{Kind: DeriveOffset, From: target})
}

// CRC returns a checksum field over an inclusive range of siblings.
func CRC(name, algo string, width uint8, e Endian, from, to Ref) *Node {
	return Derived(name, width, e, Derivation{
		Kind: DeriveChecksum, Algo: algo, From: from, To: to,
	})
}

// WithAddend returns a copy of a derived node whose computed value is shifted
// by a constant, for fields defined as "length including the header".
func WithAddend(n *Node, addend int64) *Node {
	d := *n.Derive
	d.Addend = addend
	c := *n
	c.Derive = &d
	return &c
}

// SelfZeroed returns a copy of a checksum node that covers its own field,
// computed with that field zeroed.
func SelfZeroed(n *Node) *Node {
	d := *n.Derive
	d.SelfZero = true
	c := *n
	c.Derive = &d
	return &c
}
