package driver

import (
	"fmt"
	"strings"
	"unicode"

	"github.com/rom/Xfuzz/internal/cdp"
)

// The same key vocabulary as the terminal driver, in the browser's spelling.
//
// The same names deliberately: a corpus is a corpus (ASR-0013), and a sequence
// recorded against a terminal program should mean the same thing when it is
// replayed against a web application. "key enter" has to be Enter in both, or
// the two backends are two products with a shared file format.
//
// What differs is everything underneath. A terminal takes a byte sequence; a
// browser takes a DOM key value, a physical code, a legacy virtual key number
// and a modifier bitmask, and gets the character wrong if any of them disagree.

// webKeys maps a key name to the browser's description of it.
var webKeys = map[string]cdp.Key{
	"enter":     {Key: "Enter", Code: "Enter", VK: 13, Text: "\r"},
	"return":    {Key: "Enter", Code: "Enter", VK: 13, Text: "\r"},
	"cr":        {Key: "Enter", Code: "Enter", VK: 13, Text: "\r"},
	"tab":       {Key: "Tab", Code: "Tab", VK: 9, Text: "\t"},
	"escape":    {Key: "Escape", Code: "Escape", VK: 27},
	"esc":       {Key: "Escape", Code: "Escape", VK: 27},
	"space":     {Key: " ", Code: "Space", VK: 32, Text: " "},
	"backspace": {Key: "Backspace", Code: "Backspace", VK: 8},
	"bs":        {Key: "Backspace", Code: "Backspace", VK: 8},
	"delete":    {Key: "Delete", Code: "Delete", VK: 46},
	"del":       {Key: "Delete", Code: "Delete", VK: 46},
	"insert":    {Key: "Insert", Code: "Insert", VK: 45},
	"ins":       {Key: "Insert", Code: "Insert", VK: 45},
	"home":      {Key: "Home", Code: "Home", VK: 36},
	"end":       {Key: "End", Code: "End", VK: 35},
	"pageup":    {Key: "PageUp", Code: "PageUp", VK: 33},
	"pgup":      {Key: "PageUp", Code: "PageUp", VK: 33},
	"pagedown":  {Key: "PageDown", Code: "PageDown", VK: 34},
	"pgdn":      {Key: "PageDown", Code: "PageDown", VK: 34},
	"up":        {Key: "ArrowUp", Code: "ArrowUp", VK: 38},
	"down":      {Key: "ArrowDown", Code: "ArrowDown", VK: 40},
	"right":     {Key: "ArrowRight", Code: "ArrowRight", VK: 39},
	"left":      {Key: "ArrowLeft", Code: "ArrowLeft", VK: 37},
}

// The protocol's modifier bits.
const (
	modAlt   = 1
	modCtrl  = 2
	modMeta  = 4
	modShift = 8
)

// WebKey turns a key name into the browser's description of a keystroke.
//
// It is the counterpart of EncodeKey, and it answers the same question for a
// different device. An unknown name is an error rather than a guess: the driver
// turns that into a skipped event, because after two mutations most of a corpus
// names keys no keyboard has.
func WebKey(name string) (cdp.Key, error) {
	n := strings.ToLower(strings.TrimSpace(name))
	if n == "" {
		return cdp.Key{}, fmt.Errorf("empty key name")
	}

	// Modifiers first, since ctrl-c is a key and "ctrl" is not.
	if rest, ok := cutPrefixAny(n, "ctrl-", "c-", "^"); ok {
		return withModifier(rest, modCtrl)
	}
	if rest, ok := cutPrefixAny(n, "alt-", "m-", "meta-"); ok {
		return withModifier(rest, modAlt)
	}
	if rest, ok := cutPrefixAny(n, "cmd-", "super-"); ok {
		return withModifier(rest, modMeta)
	}
	if rest, ok := cutPrefixAny(n, "shift-", "s-"); ok {
		k, err := withModifier(rest, modShift)
		if err != nil {
			return k, err
		}
		// Shift on a printable key is its upper case, which is what the page
		// receives; leaving the lower case would type "a" for "shift-a".
		if k.Text != "" {
			k.Text = strings.ToUpper(k.Text)
			k.Key = k.Text
		}
		return k, nil
	}

	if k, ok := webKeys[n]; ok {
		return k, nil
	}
	if fn, ok := functionKey(n); ok {
		return fn, nil
	}
	// A single character is itself: "key a" types an a.
	if r := []rune(n); len(r) == 1 {
		return printableKey(r[0]), nil
	}
	return cdp.Key{}, fmt.Errorf("unknown key %q", name)
}

// withModifier resolves the rest of the name and adds a modifier bit.
//
// A modified printable key keeps its text only for shift: ctrl-a is a command,
// not the letter a, and sending the text with it makes the page insert an "a"
// as well as handling the shortcut.
func withModifier(rest string, bit int) (cdp.Key, error) {
	k, err := WebKey(rest)
	if err != nil {
		return cdp.Key{}, err
	}
	k.Modifiers |= bit
	if bit != modShift {
		k.Text = ""
	}
	return k, nil
}

// functionKey resolves f1 through f12.
func functionKey(n string) (cdp.Key, bool) {
	if len(n) < 2 || n[0] != 'f' {
		return cdp.Key{}, false
	}
	num := 0
	for _, c := range n[1:] {
		if c < '0' || c > '9' {
			return cdp.Key{}, false
		}
		num = num*10 + int(c-'0')
	}
	if num < 1 || num > 12 {
		return cdp.Key{}, false
	}
	name := strings.ToUpper(n)
	return cdp.Key{Key: name, Code: name, VK: 111 + num}, true
}

// printableKey describes an ordinary character.
//
// The physical code matters to page code that reads event.code rather than
// event.key — which is what a game or an editor with a keymap does — and
// getting it wrong there means the keystroke is received as a different key.
func printableKey(r rune) cdp.Key {
	k := cdp.Key{Key: string(r), Text: string(r), VK: int(unicode.ToUpper(r))}
	switch {
	case r >= 'a' && r <= 'z':
		k.Code = "Key" + strings.ToUpper(string(r))
	case r >= 'A' && r <= 'Z':
		k.Code = "Key" + string(r)
		k.Modifiers = modShift
	case r >= '0' && r <= '9':
		k.Code = "Digit" + string(r)
	default:
		// A character with no physical key — anything a keyboard produces with a
		// modifier, and everything outside ASCII. The browser inserts the text
		// regardless; only code-reading page logic sees the difference.
		k.Code = ""
		k.VK = 0
	}
	return k
}
