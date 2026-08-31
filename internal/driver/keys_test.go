package driver_test

import (
	"testing"

	"github.com/rom/Xfuzz/internal/driver"
	"github.com/rom/Xfuzz/pkg/vt"
)

// A keystroke on a terminal is a short byte sequence, and which sequence depends
// on the key, the modifiers, and modes the program itself sets. Getting this
// wrong is the quietest failure the tier has: the campaign runs, the events are
// delivered, and the program receives characters nobody meant to type. A seed
// that says "key up" and sends a literal "A" is a seed whose finding nobody can
// reproduce by hand.

func TestEncodeKey(t *testing.T) {
	for _, tc := range []struct {
		name string
		want string
	}{
		{"enter", "\r"}, {"tab", "\t"}, {"escape", "\x1b"}, {"space", " "},
		{"backspace", "\x7f"}, {"delete", "\x1b[3~"},
		{"up", "\x1b[A"}, {"down", "\x1b[B"}, {"left", "\x1b[D"}, {"right", "\x1b[C"},
		{"home", "\x1b[H"}, {"end", "\x1b[F"}, {"pgup", "\x1b[5~"}, {"pgdn", "\x1b[6~"},
		{"f1", "\x1bOP"}, {"f5", "\x1b[15~"}, {"f12", "\x1b[24~"},

		// A single character is itself, which is what makes "key q" work.
		{"a", "a"}, {"1", "1"}, {"/", "/"},

		// Control is the ASCII mapping it has always been: clear the top three
		// bits, so ctrl-a is 1 and ctrl-c is 3.
		{"ctrl-a", "\x01"}, {"ctrl-c", "\x03"}, {"ctrl-d", "\x04"}, {"ctrl-l", "\x0c"},
		{"C-x", "\x18"}, {"^k", "\x0b"},
		// The four outside the letters are the ones a program uses for escape
		// and quit, and a table without them makes those keys untestable.
		{"ctrl-[", "\x1b"}, {"ctrl-\\", "\x1c"}, {"ctrl-]", "\x1d"}, {"ctrl-_", "\x1f"},
		{"ctrl-space", "\x00"},

		// Alt is ESC before the key.
		{"alt-x", "\x1bx"}, {"alt-enter", "\x1b\r"}, {"meta-b", "\x1bb"},

		{"ENTER", "\r"}, {"  tab  ", "\t"}, // case and space are the seed author's
	} {
		got, err := driver.EncodeKey(tc.name, false)
		if err != nil {
			t.Errorf("%q: %v", tc.name, err)
			continue
		}
		if string(got) != tc.want {
			t.Errorf("%q encoded as %q, want %q", tc.name, got, tc.want)
		}
	}
}

// TestApplicationCursorKeys is the mode that makes an arrow key ambiguous. A
// program that set DECCKM expects ESC O A; send it ESC [ A and it types a
// literal "A", which is a keystroke the seed never asked for and an event the
// campaign cannot reproduce.
func TestApplicationCursorKeys(t *testing.T) {
	for _, tc := range []struct{ name, normal, app string }{
		{"up", "\x1b[A", "\x1bOA"},
		{"down", "\x1b[B", "\x1bOB"},
		{"right", "\x1b[C", "\x1bOC"},
		{"left", "\x1b[D", "\x1bOD"},
	} {
		got, _ := driver.EncodeKey(tc.name, true)
		if string(got) != tc.app {
			t.Errorf("%q in application mode encoded as %q, want %q", tc.name, got, tc.app)
		}
		got, _ = driver.EncodeKey(tc.name, false)
		if string(got) != tc.normal {
			t.Errorf("%q in normal mode encoded as %q, want %q", tc.name, got, tc.normal)
		}
	}
	// Nothing else changes with the mode.
	if got, _ := driver.EncodeKey("f1", true); string(got) != "\x1bOP" {
		t.Errorf("f1 encoded as %q", got)
	}
	if got, _ := driver.EncodeKey("enter", true); string(got) != "\r" {
		t.Errorf("enter encoded as %q", got)
	}
}

func TestEncodeKeyRejectsWhatItCannotEncode(t *testing.T) {
	for _, name := range []string{"", "  ", "wat", "ctrl-up", "f99"} {
		if got, err := driver.EncodeKey(name, false); err == nil {
			t.Errorf("%q encoded as %q; an unknown key must be reported, not "+
				"silently typed as something else", name, got)
		}
	}
}

// TestEncodeMouseSaysNothingWhenNobodyIsListening. A report delivered to a
// program that never enabled tracking is not a click: it is an escape sequence
// arriving as ordinary keystrokes, which navigates menus and types characters.
func TestEncodeMouseSaysNothingWhenNobodyIsListening(t *testing.T) {
	if got := driver.EncodeMouse(vt.MouseOff, vt.EncodeSGR, 5, 5); got != nil {
		t.Errorf("a click on a program with no mouse tracking encoded as %q", got)
	}
}

func TestEncodeMouse(t *testing.T) {
	// SGR, which is what a modern program enables and the only encoding that can
	// express a coordinate past 223.
	got := driver.EncodeMouse(vt.MouseNormal, vt.EncodeSGR, 9, 3)
	if want := "\x1b[<0;10;4M\x1b[<0;10;4m"; string(got) != want {
		t.Errorf("SGR click encoded as %q, want %q", got, want)
	}
	// The original encoding: offset by 32 so the report is printable, press
	// only under mode 9, which has no releases.
	got = driver.EncodeMouse(vt.MouseX10, vt.EncodeX10, 9, 3)
	if want := "\x1b[M\x20\x2a\x24"; string(got) != want {
		t.Errorf("X10 click encoded as %q, want %q", got, want)
	}
	// Past what the original encoding can say, a real terminal sends nothing
	// rather than wrapping into a coordinate it did not mean.
	if got := driver.EncodeMouse(vt.MouseNormal, vt.EncodeX10, 300, 3); got != nil {
		t.Errorf("a click at column 300 encoded as %q under an encoding that stops at 223", got)
	}
	if got := driver.EncodeMouse(vt.MouseNormal, vt.EncodeSGR, 300, 3); got == nil {
		t.Error("SGR, which has no coordinate limit, refused a click at column 300")
	}
}
