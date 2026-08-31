package driver

import (
	"fmt"
	"strings"

	"github.com/rom/Xfuzz/pkg/vt"
)

// What a keystroke actually is, on a terminal, is a short byte sequence, and
// which sequence depends on the key, on the modifiers, and on modes the program
// itself sets. Getting this table wrong is the quietest possible failure: the
// campaign runs, the events are delivered, and the program receives characters
// nobody meant to type. A seed that says "key up" and sends "A" is a seed whose
// finding nobody can reproduce by hand.

// keys maps a key name to the bytes a terminal sends for it.
//
// The application-cursor-key variants (ESC O A rather than ESC [ A) are not
// here. A program that sets DECCKM expects the O form, and sending the bracket
// form to it types a literal "A" — but sending the O form to a program that did
// not set the mode is equally wrong, and the mode is per-program and per-moment.
// The bracket form is what a program sees from a terminal in its default state
// and what every library handles; encodeKey consults the emulator for the rest.
var keys = map[string]string{
	"enter": "\r", "return": "\r", "cr": "\r",
	"tab": "\t", "escape": "\x1b", "esc": "\x1b",
	"space": " ", "backspace": "\x7f", "bs": "\x7f",
	"delete": "\x1b[3~", "del": "\x1b[3~",
	"insert": "\x1b[2~", "ins": "\x1b[2~",
	"home": "\x1b[H", "end": "\x1b[F",
	"pageup": "\x1b[5~", "pgup": "\x1b[5~",
	"pagedown": "\x1b[6~", "pgdn": "\x1b[6~",
	"up": "\x1b[A", "down": "\x1b[B", "right": "\x1b[C", "left": "\x1b[D",
	"f1": "\x1bOP", "f2": "\x1bOQ", "f3": "\x1bOR", "f4": "\x1bOS",
	"f5": "\x1b[15~", "f6": "\x1b[17~", "f7": "\x1b[18~", "f8": "\x1b[19~",
	"f9": "\x1b[20~", "f10": "\x1b[21~", "f11": "\x1b[23~", "f12": "\x1b[24~",
}

// cursorKeys are the four whose encoding changes with DECCKM.
var cursorKeys = map[string]byte{"up": 'A', "down": 'B', "right": 'C', "left": 'D'}

// EncodeKey returns the bytes a terminal sends for a named key.
//
// appCursor says whether the program has put the terminal in application cursor
// mode, which changes the four arrow keys and nothing else.
func EncodeKey(name string, appCursor bool) ([]byte, error) {
	n := strings.ToLower(strings.TrimSpace(name))
	if n == "" {
		return nil, fmt.Errorf("empty key name")
	}

	// Modifiers first, since ctrl-c is a key and "ctrl" is not.
	if rest, ok := cutPrefixAny(n, "ctrl-", "c-", "^"); ok {
		return encodeCtrl(rest)
	}
	if rest, ok := cutPrefixAny(n, "alt-", "m-", "meta-"); ok {
		inner, err := EncodeKey(rest, appCursor)
		if err != nil {
			return nil, err
		}
		// Alt is ESC before the key, which is what every terminal sends and
		// what every reader has to disambiguate from a real escape by timing.
		return append([]byte{0x1b}, inner...), nil
	}
	if rest, ok := cutPrefixAny(n, "shift-", "s-"); ok {
		// Shift on a printable key is the upper case of it; on a named key it
		// is a modifier parameter this table does not carry.
		if len([]rune(rest)) == 1 {
			return []byte(strings.ToUpper(rest)), nil
		}
		return EncodeKey(rest, appCursor)
	}

	if appCursor {
		if final, ok := cursorKeys[n]; ok {
			return []byte{0x1b, 'O', final}, nil
		}
	}
	if seq, ok := keys[n]; ok {
		return []byte(seq), nil
	}
	// A single character is itself: "key a" types an a.
	if r := []rune(n); len(r) == 1 {
		return []byte(string(r)), nil
	}
	return nil, fmt.Errorf("unknown key %q", name)
}

func cutPrefixAny(s string, prefixes ...string) (string, bool) {
	for _, p := range prefixes {
		if rest, ok := strings.CutPrefix(s, p); ok && rest != "" {
			return rest, true
		}
	}
	return s, false
}

// encodeCtrl returns the control character for a key.
//
// The mapping is the ASCII one it has always been: control clears the top three
// bits, so ctrl-a is 1 and ctrl-c is 3. The four outside the letters —
// ctrl-[, ctrl-\, ctrl-] and ctrl-_ — are the ones a program uses for escape
// and quit, and a table without them makes those keys untestable.
func encodeCtrl(name string) ([]byte, error) {
	r := []rune(name)
	if len(r) != 1 {
		switch name {
		case "space":
			return []byte{0}, nil
		case "backspace":
			return []byte{8}, nil
		}
		return nil, fmt.Errorf("ctrl-%s is not a control character", name)
	}
	c := r[0]
	switch {
	case c >= 'a' && c <= 'z':
		return []byte{byte(c - 'a' + 1)}, nil
	case c >= 'A' && c <= 'Z':
		return []byte{byte(c - 'A' + 1)}, nil
	case c == '@':
		return []byte{0}, nil
	case c == '[':
		return []byte{0x1b}, nil
	case c == '\\':
		return []byte{0x1c}, nil
	case c == ']':
		return []byte{0x1d}, nil
	case c == '^':
		return []byte{0x1e}, nil
	case c == '_' || c == '?':
		return []byte{0x1f}, nil
	}
	return nil, fmt.Errorf("ctrl-%s is not a control character", name)
}

// EncodeMouse returns the report a terminal sends for a button press and release
// at a position, or nil when the program has not asked for mouse reporting.
//
// Nil rather than a best guess. A report delivered to a program that never
// enabled tracking is not a click: it is an escape sequence arriving as ordinary
// keystrokes, which navigates menus and types characters, and makes the same
// click mean something different every time depending on what the program was
// doing when it landed.
func EncodeMouse(mode vt.MouseMode, enc vt.MouseEncoding, x, y int) []byte {
	if mode == vt.MouseOff || x < 0 || y < 0 {
		return nil
	}
	const button = 0 // the left button, which is the only one an event carries

	switch enc {
	case vt.EncodeSGR:
		// The only encoding that can express a coordinate past 223, and the one
		// with a distinct release: 'M' presses, 'm' releases.
		press := fmt.Sprintf("\x1b[<%d;%d;%dM", button, x+1, y+1)
		if mode == vt.MouseX10 {
			return []byte(press)
		}
		return []byte(press + fmt.Sprintf("\x1b[<%d;%d;%dm", button, x+1, y+1))

	case vt.EncodeURXVT:
		press := fmt.Sprintf("\x1b[%d;%d;%dM", button+32, x+1, y+1)
		if mode == vt.MouseX10 {
			return []byte(press)
		}
		return []byte(press + fmt.Sprintf("\x1b[%d;%d;%dM", 3+32, x+1, y+1))

	default:
		// The original encoding offsets everything by 32 so that the report is
		// printable, which caps a coordinate at 223. Beyond that a real terminal
		// sends nothing rather than wrapping, and so does this.
		if x+1 > 223 || y+1 > 223 {
			return nil
		}
		press := []byte{0x1b, '[', 'M', byte(button + 32), byte(x + 1 + 32), byte(y + 1 + 32)}
		if mode == vt.MouseX10 {
			return press
		}
		release := []byte{0x1b, '[', 'M', byte(3 + 32), byte(x + 1 + 32), byte(y + 1 + 32)}
		return append(press, release...)
	}
}
