package codec

import (
	"bytes"
	"testing"

	"github.com/rom/Xfuzz/pkg/ir"
)

// A seed file is a conversation: one message per line, and re-encoding it
// reproduces the file exactly.
func TestSessionRoundTripsAndSplitsByLine(t *testing.T) {
	for _, src := range []string{
		"HELLO 1\r\nAUTH LETMEIN\r\nSET k v\r\n",
		"one line with no terminator",
		"trailing\nnewline\n",
		"",
		"\n\n\n",
	} {
		t.Run(src, func(t *testing.T) {
			n, err := Session{}.Decode(ir.NewArena(), []byte(src))
			if err != nil {
				t.Fatal(err)
			}
			if n.Kind != ir.KindRepeat {
				t.Fatalf("a session decoded to %v, not a repeat", n.Kind)
			}
			if got := ir.Encode(n); !bytes.Equal(got, []byte(src)) {
				t.Errorf("re-encoding gave %q, want %q", got, src)
			}
		})
	}
}

func TestSessionMessagesKeepTheirTerminator(t *testing.T) {
	n, err := Session{}.Decode(ir.NewArena(), []byte("A\r\nB\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(n.Children) != 2 {
		t.Fatalf("two lines decoded to %d messages", len(n.Children))
	}
	// The terminator belongs to the message it ends, so a message can be moved,
	// duplicated or deleted without the sequence losing its framing.
	for i, want := range []string{"A\r\n", "B\r\n"} {
		if got := string(ir.Encode(n.Children[i])); got != want {
			t.Errorf("message %d = %q, want %q", i, got, want)
		}
	}
}

// A truncated capture is what it is. Repairing the missing terminator here
// would make the codec disagree with the bytes on disk, and Decode preserves.
func TestSessionDoesNotRepairATruncatedCapture(t *testing.T) {
	src := "HELLO 1\r\nAUTH"
	n, _ := Session{}.Decode(ir.NewArena(), []byte(src))
	if len(n.Children) != 2 {
		t.Fatalf("decoded to %d messages", len(n.Children))
	}
	if got := string(ir.Encode(n.Children[1])); got != "AUTH" {
		t.Errorf("the last message = %q, want it unterminated", got)
	}
}

func TestSessionHonoursItsDelimiter(t *testing.T) {
	c := Session{Delimiter: []byte("\x00")}
	n, err := c.Decode(ir.NewArena(), []byte("a\x00b\x00"))
	if err != nil {
		t.Fatal(err)
	}
	if len(n.Children) != 2 {
		t.Fatalf("a null-delimited session decoded to %d messages", len(n.Children))
	}
	if got := ir.Encode(n); string(got) != "a\x00b\x00" {
		t.Errorf("re-encoding gave %q", got)
	}
}
