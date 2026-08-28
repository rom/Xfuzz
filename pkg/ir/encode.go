package ir

// Encoding is generic across every format: the wire form of a tree is the
// concatenation of its leaves in document order. Containers contribute their
// children, a Choice contributes only its selected alternative, an absent Opt
// contributes nothing, and a Ref contributes nothing at all.
//
// That genericity is what keeps format knowledge confined to decoding. A codec
// has to know how to *parse* PNG; it does not have to know how to write one.

// EncodedLen returns the number of bytes the tree rooted at n encodes to,
// without producing them.
func EncodedLen(n *Node) int {
	if n == nil {
		return 0
	}
	switch n.Kind {
	case KindBytes, KindStr:
		return len(n.Raw)
	case KindInt, KindDerived:
		return int(n.Width)
	case KindRef:
		return 0
	case KindChoice:
		return EncodedLen(n.Selected())
	case KindOpt:
		if !n.Present() || len(n.Children) == 0 {
			return 0
		}
		return EncodedLen(n.Children[0])
	}
	total := 0
	for _, c := range n.Children {
		total += EncodedLen(c)
	}
	return total
}

// AppendEncode appends the wire form of n to dst and returns the extended
// slice. Passing a reused buffer keeps encoding allocation-free in steady
// state.
func AppendEncode(dst []byte, n *Node) []byte {
	if n == nil {
		return dst
	}
	switch n.Kind {
	case KindBytes, KindStr:
		return append(dst, n.Raw...)
	case KindInt, KindDerived:
		return appendInt(dst, n.Val, n.Width, n.Endian)
	case KindRef:
		return dst
	case KindChoice:
		return AppendEncode(dst, n.Selected())
	case KindOpt:
		if !n.Present() || len(n.Children) == 0 {
			return dst
		}
		return AppendEncode(dst, n.Children[0])
	}
	for _, c := range n.Children {
		dst = AppendEncode(dst, c)
	}
	return dst
}

// Encode returns the wire form of n. Prefer AppendEncode with a reused buffer
// on the hot path.
func Encode(n *Node) []byte {
	return AppendEncode(make([]byte, 0, EncodedLen(n)), n)
}

// appendInt writes v in the given width and byte order.
func appendInt(dst []byte, v int64, width uint8, e Endian) []byte {
	u := uint64(v)
	if e == LittleEndian {
		for i := 0; i < int(width); i++ {
			dst = append(dst, byte(u>>(8*i)))
		}
		return dst
	}
	for i := int(width) - 1; i >= 0; i-- {
		dst = append(dst, byte(u>>(8*i)))
	}
	return dst
}

// putInt writes v into the first width bytes of dst, which must be long enough.
// It is used to patch a computed value back into an encoding buffer in place.
func putInt(dst []byte, v int64, width uint8, e Endian) {
	u := uint64(v)
	if e == LittleEndian {
		for i := 0; i < int(width); i++ {
			dst[i] = byte(u >> (8 * i))
		}
		return
	}
	for i := 0; i < int(width); i++ {
		dst[i] = byte(u >> (8 * (int(width) - 1 - i)))
	}
}

// ReadInt decodes width bytes as an integer, sign-extending when signed.
func ReadInt(b []byte, width uint8, e Endian, signed bool) int64 {
	var u uint64
	if e == LittleEndian {
		for i := int(width) - 1; i >= 0; i-- {
			u = u<<8 | uint64(b[i])
		}
	} else {
		for i := 0; i < int(width); i++ {
			u = u<<8 | uint64(b[i])
		}
	}
	if !signed || width == 8 {
		return int64(u)
	}
	shift := 64 - 8*uint(width)
	return int64(u<<shift) >> shift
}

// truncate reduces v to what the node's width can hold, matching what the
// encoder will actually write. A derived value that overflows its field is a
// legitimate fuzzing outcome, so this wraps rather than failing.
func truncate(v int64, width uint8) int64 {
	if width >= 8 {
		return v
	}
	mask := int64(1)<<(8*uint(width)) - 1
	return v & mask
}
