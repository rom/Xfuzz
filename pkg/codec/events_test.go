package codec_test

import (
	"strings"
	"testing"

	"github.com/rom/Xfuzz/pkg/codec"
	"github.com/rom/Xfuzz/pkg/ir"
)

// The codec's whole job is to make a sequence of events a Repeat, so that the
// sequence operators act on events rather than on characters. Everything else
// it must do is not break the contract every codec has.

func decodeEvents(t *testing.T, src string) *ir.Node {
	t.Helper()
	n, err := codec.Events{}.Decode(ir.NewArena(), []byte(src))
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func TestEventsIsARepeatOfLines(t *testing.T) {
	root := decodeEvents(t, "key enter\ntext hello\nclick 3 7\n")
	if root.Kind != ir.KindRepeat {
		t.Fatalf("the root is %s, want a repeat", root.Kind)
	}
	if len(root.Children) != 3 {
		t.Fatalf("three lines became %d children", len(root.Children))
	}
	if got := string(root.Children[0].Raw); got != "key enter\n" {
		t.Errorf("the first event is %q; the newline has to travel with the line "+
			"it terminates, or deleting an event leaves its separator behind", got)
	}
}

// TestEventsRoundTrips is the contract every codec has, and the one that makes
// a corpus entry survive being read and written back.
func TestEventsRoundTrips(t *testing.T) {
	for _, src := range []string{
		"", "\n", "key enter\n", "key enter", "a\nb\nc",
		"key  enter\n", "# a comment\n\nkey q\n",
		"text hello world\r\n", strings.Repeat("key a\n", 200),
		strings.Repeat("key a\n", codec.MaxEventLines+50),
		"\x00\xff not text at all\n",
	} {
		root := decodeEvents(t, src)
		if got := string(ir.AppendEncode(nil, root)); got != src {
			t.Errorf("re-encoding %q produced %q", elide(src), elide(got))
		}
	}
}

// TestEventsBoundsTheTree keeps a text file that landed in the corpus from
// becoming a hundred thousand nodes.
func TestEventsBoundsTheTree(t *testing.T) {
	src := strings.Repeat("key a\n", codec.MaxEventLines*2)
	root := decodeEvents(t, src)
	if len(root.Children) > codec.MaxEventLines+1 {
		t.Errorf("%d children for %d lines", len(root.Children), codec.MaxEventLines*2)
	}
	if got := string(ir.AppendEncode(nil, root)); got != src {
		t.Error("bounding the tree lost bytes")
	}
}

func elide(s string) string {
	if len(s) <= 48 {
		return s
	}
	return s[:48] + "..."
}
