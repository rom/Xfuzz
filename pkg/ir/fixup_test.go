package ir

import (
	"errors"
	"hash/crc32"
	"testing"
)

// chunk builds the shape that motivates the whole design: a length-prefixed,
// CRC-protected record. Byte-level mutation of this dies in the length check or
// the CRC on nearly every execution; structured mutation plus fixup does not.
func chunk(typ, data string) *Node {
	return Struct("chunk",
		LenOf("length", 4, BigEndian, Sibling("data")),
		Blob("type", []byte(typ)),
		Blob("data", []byte(data)),
		CRC("crc", "crc32", 4, BigEndian, Sibling("type"), Sibling("data")),
	)
}

func TestDeriveLength(t *testing.T) {
	c := chunk("IDAT", "hello")
	if err := Fixup(c, Suppress{}); err != nil {
		t.Fatal(err)
	}
	if got := c.Child("length").Val; got != 5 {
		t.Errorf("length = %d, want 5", got)
	}
}

func TestDeriveLengthOverRange(t *testing.T) {
	n := Struct("s",
		LenRange("len", 2, BigEndian, Sibling("a"), Sibling("c")),
		Blob("a", []byte{1, 2}),
		Blob("b", []byte{3, 4, 5}),
		Blob("c", []byte{6}),
		Blob("d", []byte{7, 7, 7, 7}),
	)
	if err := Fixup(n, Suppress{}); err != nil {
		t.Fatal(err)
	}
	// a..c inclusive is 2+3+1 = 6; d is outside the range.
	if got := n.Child("len").Val; got != 6 {
		t.Errorf("range length = %d, want 6", got)
	}
}

func TestDeriveLengthWithAddend(t *testing.T) {
	n := Struct("s",
		WithAddend(LenOf("len", 2, BigEndian, Sibling("payload")), 4),
		Blob("payload", []byte{1, 2, 3}),
	)
	if err := Fixup(n, Suppress{}); err != nil {
		t.Fatal(err)
	}
	if got := n.Child("len").Val; got != 7 {
		t.Errorf("length including a 4-byte header = %d, want 7", got)
	}
}

func TestDeriveCount(t *testing.T) {
	n := Struct("s",
		CountOf("n", 2, BigEndian, Sibling("items")),
		Repeat("items", U8("", 1), U8("", 2), U8("", 3)),
	)
	if err := Fixup(n, Suppress{}); err != nil {
		t.Fatal(err)
	}
	if got := n.Child("n").Val; got != 3 {
		t.Errorf("count = %d, want 3", got)
	}

	// Removing an element must be reflected on the next fixup — this is exactly
	// what a sequence mutator does.
	items := n.Child("items")
	items.Children = items.Children[:2]
	if err := Fixup(n, Suppress{}); err != nil {
		t.Fatal(err)
	}
	if got := n.Child("n").Val; got != 2 {
		t.Errorf("count after removing an element = %d, want 2", got)
	}
}

func TestDeriveOffset(t *testing.T) {
	n := Struct("s",
		OffsetOf("where", 4, BigEndian, Sibling("target")),
		Blob("filler", []byte{1, 2, 3, 4, 5, 6}),
		Blob("target", []byte{9}),
	)
	if err := Fixup(n, Suppress{}); err != nil {
		t.Fatal(err)
	}
	// The offset field itself occupies bytes 0-3, filler 4-9, target at 10.
	if got := n.Child("where").Val; got != 10 {
		t.Errorf("offset = %d, want 10", got)
	}
}

func TestDeriveChecksumCoversTheRightRange(t *testing.T) {
	c := chunk("IDAT", "hello")
	if err := Fixup(c, Suppress{}); err != nil {
		t.Fatal(err)
	}
	want := int64(crc32.ChecksumIEEE([]byte("IDAThello")))
	if got := c.Child("crc").Val; got != want {
		t.Errorf("crc = %#x, want %#x (the range must span type..data, "+
			"excluding the length field and the crc itself)", got, want)
	}
}

// TestNestedChecksumsOrderByContainment is the ordering property the fixup pass
// exists to guarantee: an outer checksum must see the finished bytes of an inner
// one. Here the outer checksum is declared FIRST in document order, so a pass
// that simply walked the tree would compute it against a stale inner value.
func TestNestedChecksumsOrderByContainment(t *testing.T) {
	tree := Struct("root",
		CRC("ocrc", "crc32", 4, BigEndian, Sibling("inner"), Ref{}),
		Struct("inner",
			Blob("data", []byte("abc")),
			CRC("icrc", "crc32", 4, BigEndian, Sibling("data"), Ref{}),
		),
	)
	if err := Fixup(tree, Suppress{}); err != nil {
		t.Fatal(err)
	}

	wantInner := int64(crc32.ChecksumIEEE([]byte("abc")))
	gotInner := tree.Child("inner").Child("icrc").Val
	if gotInner != wantInner {
		t.Fatalf("inner crc = %#x, want %#x", gotInner, wantInner)
	}

	// The outer checksum covers inner's encoding, which is "abc" followed by the
	// computed inner CRC.
	innerBytes := append([]byte("abc"), byte(wantInner>>24), byte(wantInner>>16), byte(wantInner>>8), byte(wantInner))
	wantOuter := int64(crc32.ChecksumIEEE(innerBytes))
	if got := tree.Child("ocrc").Val; got != wantOuter {
		t.Errorf("outer crc = %#x, want %#x — the outer checksum was computed before "+
			"the inner one was written back", got, wantOuter)
	}
}

func TestSelfInclusiveChecksumRequiresSelfZero(t *testing.T) {
	build := func() *Node {
		return Struct("pkt",
			Blob("data", []byte{1, 2, 3, 4}),
			CRC("ck", "crc32", 4, BigEndian, Parent(), Ref{}),
		)
	}

	// Covering the field that holds the checksum is circular. Without an
	// explicit resolution it must be reported, not silently guessed at.
	err := Fixup(build(), Suppress{})
	if !errors.Is(err, ErrCyclicDerivation) {
		t.Fatalf("self-covering checksum: err = %v, want ErrCyclicDerivation", err)
	}

	// With SelfZero it is computed with the field zeroed, which is how IPv4,
	// ICMP and several container formats define it.
	tree := build()
	tree.Children[1] = SelfZeroed(tree.Children[1])
	if err := Fixup(tree, Suppress{}); err != nil {
		t.Fatal(err)
	}
	want := int64(crc32.ChecksumIEEE([]byte{1, 2, 3, 4, 0, 0, 0, 0}))
	if got := tree.Child("ck").Val; got != want {
		t.Errorf("self-zeroed crc = %#x, want %#x", got, want)
	}
}

func TestMutuallyDependentChecksumsAreReported(t *testing.T) {
	whole := Ref{Absolute: true}
	tree := Struct("root",
		Struct("a",
			Blob("ad", []byte{1}),
			SelfZeroed(CRC("acrc", "crc32", 4, BigEndian, whole, Ref{})),
		),
		Struct("b",
			Blob("bd", []byte{2}),
			SelfZeroed(CRC("bcrc", "crc32", 4, BigEndian, whole, Ref{})),
		),
	)
	err := Fixup(tree, Suppress{})
	if !errors.Is(err, ErrCyclicDerivation) {
		t.Fatalf("two checksums covering each other: err = %v, want ErrCyclicDerivation", err)
	}
}

func TestFixupIsIdempotent(t *testing.T) {
	c := chunk("IDAT", "hello world")
	if err := Fixup(c, Suppress{}); err != nil {
		t.Fatal(err)
	}
	once := Encode(c)
	for i := 0; i < 3; i++ {
		if err := Fixup(c, Suppress{}); err != nil {
			t.Fatal(err)
		}
		if got := Encode(c); string(got) != string(once) {
			t.Fatalf("fixup %d changed the encoding: %x, want %x", i+2, got, once)
		}
	}
}

func TestFixupIsDeterministic(t *testing.T) {
	build := func() *Node {
		return Repeat("chunks", chunk("IHDR", "aaa"), chunk("IDAT", "bbbb"), chunk("IEND", ""))
	}
	a, b := build(), build()
	if err := Fixup(a, Suppress{}); err != nil {
		t.Fatal(err)
	}
	// A reused Fixer must produce identical results to a fresh one; carried
	// scratch state must not leak between calls.
	f := NewFixer()
	if _, err := f.Fix(Repeat("other", chunk("XXXX", "zzz")), Suppress{}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Fix(b, Suppress{}); err != nil {
		t.Fatal(err)
	}
	if !Equal(a, b) {
		t.Error("a reused Fixer produced a different result from a fresh one")
	}
}

func TestSuppressionLeavesValuesAlone(t *testing.T) {
	const bogus = 0x4141

	t.Run("checksum", func(t *testing.T) {
		c := chunk("IDAT", "hello")
		c.Child("crc").Val = bogus
		if err := Fixup(c, Suppress{Checksum: true}); err != nil {
			t.Fatal(err)
		}
		if got := c.Child("crc").Val; got != bogus {
			t.Errorf("suppressed crc = %#x, want the mutated %#x — a fuzzer that always "+
				"writes a correct checksum can never reach checksum-validation code", got, bogus)
		}
		if got := c.Child("length").Val; got != 5 {
			t.Errorf("length = %d, want 5: suppressing checksums must not suppress lengths", got)
		}
	})

	t.Run("length", func(t *testing.T) {
		c := chunk("IDAT", "hello")
		c.Child("length").Val = bogus
		if err := Fixup(c, Suppress{Length: true}); err != nil {
			t.Fatal(err)
		}
		if got := c.Child("length").Val; got != bogus {
			t.Errorf("suppressed length = %d, want the mutated %d", got, bogus)
		}
		// The checksum must still be correct: it covers type..data, not length.
		if got, want := c.Child("crc").Val, int64(crc32.ChecksumIEEE([]byte("IDAThello"))); got != want {
			t.Errorf("crc = %#x, want %#x", got, want)
		}
	})

	t.Run("per node", func(t *testing.T) {
		tree := Repeat("chunks", chunk("A", "aa"), chunk("B", "bbb"))
		first := tree.Children[0].Child("length")
		first.Val = bogus
		sup := Suppress{Node: func(n *Node) bool { return n == first }}
		if err := Fixup(tree, sup); err != nil {
			t.Fatal(err)
		}
		if got := first.Val; got != bogus {
			t.Errorf("node-suppressed length = %d, want %d", got, bogus)
		}
		if got := tree.Children[1].Child("length").Val; got != 3 {
			t.Errorf("other chunk's length = %d, want 3", got)
		}
	})

	t.Run("all", func(t *testing.T) {
		c := chunk("IDAT", "hello")
		c.Child("length").Val = bogus
		c.Child("crc").Val = bogus
		if err := Fixup(c, SuppressAll()); err != nil {
			t.Fatal(err)
		}
		if c.Child("length").Val != bogus || c.Child("crc").Val != bogus {
			t.Error("SuppressAll must leave every derivation untouched")
		}
	})
}

func TestFixupSkipsUnencodedBranches(t *testing.T) {
	// A derivation inside an unselected alternative refers to nodes that are not
	// in the output. It must be skipped, not resolved against a phantom offset.
	tree := Struct("root",
		Choice("c", 0,
			Struct("first", Blob("d", []byte{1, 2})),
			Struct("second",
				LenOf("len", 2, BigEndian, Sibling("d")),
				Blob("d", []byte{9, 9, 9}),
			),
		),
	)
	if err := Fixup(tree, Suppress{}); err != nil {
		t.Fatalf("a derivation in an unselected branch must be skipped, got %v", err)
	}

	// Selecting that branch brings the derivation into play.
	tree.Child("c").Sel = 1
	if err := Fixup(tree, Suppress{}); err != nil {
		t.Fatal(err)
	}
	if got := tree.Child("c").Children[1].Child("len").Val; got != 3 {
		t.Errorf("length in the newly selected branch = %d, want 3", got)
	}
}

func TestFixupErrors(t *testing.T) {
	cases := []struct {
		name string
		node *Node
	}{
		{"unresolvable reference", Struct("s", LenOf("len", 2, BigEndian, Sibling("missing")))},
		{"unknown checksum algorithm", Struct("s",
			Blob("d", []byte{1}),
			CRC("ck", "not-a-real-algorithm", 4, BigEndian, Sibling("d"), Ref{}))},
		{"reversed range", Struct("s",
			Blob("a", []byte{1}),
			Blob("b", []byte{2}),
			LenRange("len", 2, BigEndian, Sibling("b"), Sibling("a")))},
		{"reference above the root", Struct("s",
			LenOf("len", 2, BigEndian, Ref{Up: 3, Steps: []Step{Named("x")}}))},
		{"derived without a derivation", Struct("s", &Node{Kind: KindDerived, Name: "d", Width: 2})},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := Fixup(tc.node, Suppress{}); err == nil {
				t.Error("expected an error, got nil")
			}
		})
	}
}

func TestFixReturnsTheEncoding(t *testing.T) {
	c := chunk("IDAT", "hi")
	f := NewFixer()
	buf, err := f.Fix(c, Suppress{})
	if err != nil {
		t.Fatal(err)
	}
	if want := Encode(c); string(buf) != string(want) {
		t.Errorf("Fix returned %x, want %x", buf, want)
	}
}

func TestChecksumAlgorithms(t *testing.T) {
	data := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
	for _, name := range ChecksumNames() {
		fn, ok := Checksum(name)
		if !ok {
			t.Fatalf("%s: registered but not retrievable", name)
		}
		a, b := fn(data), fn(data)
		if a != b {
			t.Errorf("%s is not deterministic: %d then %d", name, a, b)
		}
	}
	if _, ok := Checksum("nope"); ok {
		t.Error("an unregistered algorithm must not resolve")
	}
}

func TestRegisterChecksumRejectsDuplicates(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("re-registering a checksum name must panic: silently shadowing one " +
				"would corrupt every corpus built with the original")
		}
	}()
	RegisterChecksum("crc32", func([]byte) uint64 { return 0 })
}
