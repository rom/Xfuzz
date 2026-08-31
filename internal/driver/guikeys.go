package driver

import (
	"fmt"
	"strings"
)

// The same key vocabulary again, in X11's spelling.
//
// Three backends now name keys the same way — a terminal's byte sequences, a
// browser's DOM key values, and an X keysym — because a corpus is a corpus
// (ASR-0013). A sequence recorded against one has to mean the same thing
// replayed against another, or the backends are separate products sharing a
// file format.
var guiKeysyms = map[string]int32{
	"enter": 0xFF0D, "return": 0xFF0D, "cr": 0xFF0D,
	"tab": 0xFF09, "escape": 0xFF1B, "esc": 0xFF1B,
	"space": 0x0020, "backspace": 0xFF08, "bs": 0xFF08,
	"delete": 0xFFFF, "del": 0xFFFF,
	"insert": 0xFF63, "ins": 0xFF63,
	"home": 0xFF50, "end": 0xFF57,
	"pageup": 0xFF55, "pgup": 0xFF55,
	"pagedown": 0xFF56, "pgdn": 0xFF56,
	"up": 0xFF52, "down": 0xFF54, "right": 0xFF53, "left": 0xFF51,
}

// GUIKeysym returns the X keysym for a key name.
//
// Modifiers are refused rather than approximated. AT-SPI's synthesis takes
// either a keysym, which it presses and releases on its own, or a hardware
// keycode, which needs the X keymap this package does not have — so there is no
// way through this interface to hold Control down across another key. Saying so
// is the honest answer: sending the unmodified key instead would deliver a
// keystroke nobody asked for, and a finding from it would not reproduce by
// hand.
func GUIKeysym(name string) (int32, error) {
	n := strings.ToLower(strings.TrimSpace(name))
	if n == "" {
		return 0, fmt.Errorf("empty key name")
	}
	for _, prefix := range []string{"ctrl-", "c-", "^", "alt-", "m-", "meta-", "cmd-", "super-"} {
		if strings.HasPrefix(n, prefix) {
			return 0, fmt.Errorf("a modified key (%s) cannot be synthesised through "+
				"AT-SPI, which takes a keysym and presses it alone", name)
		}
	}
	// Shift on a printable key is its upper case, which the string synthesis
	// handles; on a named key it is a modifier and refused above.
	if rest, ok := cutPrefixAny(n, "shift-", "s-"); ok {
		if r := []rune(rest); len(r) == 1 {
			return int32(strings.ToUpper(rest)[0]), nil
		}
		return 0, fmt.Errorf("shift cannot be held across %s through AT-SPI", rest)
	}

	if sym, ok := guiKeysyms[n]; ok {
		return sym, nil
	}
	if len(n) >= 2 && n[0] == 'f' {
		if num, err := atoiKey(n[1:]); err == nil && num >= 1 && num <= 12 {
			// F1 is 0xFFBE and they run consecutively.
			return int32(0xFFBE + num - 1), nil
		}
	}
	// A single printable character is its own keysym for Latin-1, which is the
	// range every keyboard has and the range a key name is written in.
	if r := []rune(n); len(r) == 1 && r[0] < 0x100 {
		return int32(r[0]), nil
	}
	return 0, fmt.Errorf("unknown key %q", name)
}

func atoiKey(s string) (int, error) {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("not a number")
		}
		n = n*10 + int(c-'0')
	}
	return n, nil
}
