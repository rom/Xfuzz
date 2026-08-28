package ir

import (
	"bytes"
	"testing"
)

func TestEncodedLenMatchesEncode(t *testing.T) {
	cases := []struct {
		name string
		node *Node
		want []byte
	}{
		{"bytes", Blob("b", []byte{1, 2, 3}), []byte{1, 2, 3}},
		{"empty bytes", Blob("b", nil), nil},
		{"text", Text("s", "hi"), []byte("hi")},
		{"u8", U8("n", 0xAB), []byte{0xAB}},
		{"u16be", U16BE("n", 0x1234), []byte{0x12, 0x34}},
		{"u16le", U16LE("n", 0x1234), []byte{0x34, 0x12}},
		{"u32be", U32BE("n", 0x01020304), []byte{1, 2, 3, 4}},
		{"u32le", U32LE("n", 0x01020304), []byte{4, 3, 2, 1}},
		{"truncating width", Int("n", 0x1234, 1, BigEndian), []byte{0x34}},
		{"struct", Struct("s", U8("a", 1), U8("b", 2)), []byte{1, 2}},
		{"repeat", Repeat("r", U8("", 1), U8("", 2), U8("", 3)), []byte{1, 2, 3}},
		{"nested", Struct("s", Struct("t", U8("a", 7)), U8("b", 8)), []byte{7, 8}},

		// A Choice contributes only its selected alternative.
		{"choice first", Choice("c", 0, U8("a", 1), U16BE("b", 0x0203)), []byte{1}},
		{"choice second", Choice("c", 1, U8("a", 1), U16BE("b", 0x0203)), []byte{2, 3}},

		// An absent Opt contributes nothing.
		{"opt present", Opt("o", true, U8("a", 9)), []byte{9}},
		{"opt absent", Opt("o", false, U8("a", 9)), nil},

		// A Ref names a node without appearing in the output.
		{"ref", Struct("s", U8("a", 1), RefTo("r", Sibling("a"))), []byte{1}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Encode(tc.node)
			if !bytes.Equal(got, tc.want) {
				t.Errorf("Encode = %x, want %x", got, tc.want)
			}
			if n := EncodedLen(tc.node); n != len(tc.want) {
				t.Errorf("EncodedLen = %d, want %d (the two must never disagree: "+
					"offsets are computed from EncodedLen and read against Encode)", n, len(tc.want))
			}
		})
	}
}

func TestAppendEncodeReusesBuffer(t *testing.T) {
	n := Struct("s", U8("a", 1), Blob("b", []byte{2, 3}))
	buf := make([]byte, 0, 64)

	buf = AppendEncode(buf[:0], n)
	first := string(buf)
	buf = AppendEncode(buf[:0], n)

	if string(buf) != first {
		t.Errorf("second encode = %x, want %x", buf, first)
	}
	if allocs := testingAllocs(func() { buf = AppendEncode(buf[:0], n) }); allocs != 0 {
		t.Errorf("AppendEncode into a sized buffer allocated %v times; the hot path must not allocate", allocs)
	}
}

func TestReadIntRoundTrip(t *testing.T) {
	cases := []struct {
		v      int64
		width  uint8
		e      Endian
		signed bool
	}{
		{0, 1, BigEndian, false},
		{255, 1, BigEndian, false},
		{-1, 1, BigEndian, true},
		{-128, 1, BigEndian, true},
		{0x1234, 2, BigEndian, false},
		{0x1234, 2, LittleEndian, false},
		{-2, 2, LittleEndian, true},
		{0x01020304, 4, BigEndian, false},
		{-70000, 4, LittleEndian, true},
		{0x0102030405060708, 8, BigEndian, false},
		{-1, 8, LittleEndian, true},
	}
	for _, tc := range cases {
		b := appendInt(nil, tc.v, tc.width, tc.e)
		if len(b) != int(tc.width) {
			t.Fatalf("appendInt wrote %d bytes, want %d", len(b), tc.width)
		}
		got := ReadInt(b, tc.width, tc.e, tc.signed)
		want := tc.v
		if !tc.signed {
			want = truncate(tc.v, tc.width)
		}
		if got != want {
			t.Errorf("ReadInt(appendInt(%d, w%d, %s, signed=%v)) = %d, want %d",
				tc.v, tc.width, tc.e, tc.signed, got, want)
		}
	}
}

func TestPutIntMatchesAppendInt(t *testing.T) {
	for _, w := range []uint8{1, 2, 4, 8} {
		for _, e := range []Endian{BigEndian, LittleEndian} {
			want := appendInt(nil, 0x0102030405060708, w, e)
			got := make([]byte, w)
			putInt(got, 0x0102030405060708, w, e)
			if !bytes.Equal(got, want) {
				t.Errorf("putInt(w%d, %s) = %x, want %x (fixup patches the buffer with putInt "+
					"and must produce exactly what the encoder would)", w, e, got, want)
			}
		}
	}
}

func TestValidate(t *testing.T) {
	cases := []struct {
		name    string
		node    *Node
		wantErr bool
	}{
		{"good", Struct("s", U8("a", 1)), false},
		{"bad width", Int("n", 0, 3, BigEndian), true},
		{"choice out of range", &Node{Kind: KindChoice, Sel: 5, Children: []*Node{U8("a", 1)}}, true},
		{"choice empty", &Node{Kind: KindChoice}, true},
		{"opt two children", &Node{Kind: KindOpt, Children: []*Node{U8("a", 1), U8("b", 2)}}, true},
		{"ref without target", &Node{Kind: KindRef}, true},
		{"derived without derivation", &Node{Kind: KindDerived, Width: 4}, true},
		{"leaf with children", &Node{Kind: KindBytes, Children: []*Node{U8("a", 1)}}, true},
		{"invalid kind", &Node{Kind: KindInvalid}, true},
		{"nested error is found", Struct("s", Struct("t", Int("n", 0, 3, BigEndian))), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := Validate(tc.node)
			if (err != nil) != tc.wantErr {
				t.Errorf("Validate = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestTreeHelpers(t *testing.T) {
	tree := Struct("root", Struct("a", U8("x", 1), U8("y", 2)), U8("b", 3))
	if got := Count(tree); got != 5 {
		t.Errorf("Count = %d, want 5", got)
	}
	if got := Depth(tree); got != 3 {
		t.Errorf("Depth = %d, want 3", got)
	}
	if tree.Child("b") == nil || tree.Child("nope") != nil {
		t.Error("Child lookup is wrong")
	}
	if got := tree.ChildIndex("b"); got != 1 {
		t.Errorf("ChildIndex = %d, want 1", got)
	}
	if got := tree.ChildIndex("nope"); got != -1 {
		t.Errorf("ChildIndex of a missing name = %d, want -1", got)
	}

	// Walk can prune.
	visited := 0
	Walk(tree, func(n *Node) bool { visited++; return n.Name != "a" })
	if visited != 3 {
		t.Errorf("pruned walk visited %d nodes, want 3", visited)
	}

	// WalkPost sees children before parents.
	var order []string
	WalkPost(tree, func(n *Node) { order = append(order, n.Name) })
	want := []string{"x", "y", "a", "b", "root"}
	for i := range want {
		if order[i] != want[i] {
			t.Fatalf("WalkPost order = %v, want %v", order, want)
		}
	}
}

func TestEqual(t *testing.T) {
	a := Struct("s", U8("a", 1), Blob("b", []byte{2}))
	if !Equal(a, Struct("s", U8("a", 1), Blob("b", []byte{2}))) {
		t.Error("identical trees must compare equal")
	}
	if Equal(a, Struct("s", U8("a", 2), Blob("b", []byte{2}))) {
		t.Error("differing values must not compare equal")
	}
	if Equal(a, Struct("s", U8("a", 1))) {
		t.Error("differing child counts must not compare equal")
	}
	if Equal(nil, a) || Equal(a, nil) {
		t.Error("nil must not equal a node")
	}
	if !Equal(nil, nil) {
		t.Error("nil equals nil")
	}
}

// testingAllocs is a thin wrapper so allocation assertions read clearly.
func testingAllocs(f func()) float64 {
	return allocsPerRun(50, f)
}
