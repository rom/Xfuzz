package driver

import "testing"

func TestWebKeyUsesTheSameNamesAsTheTerminal(t *testing.T) {
	// A corpus is a corpus. A sequence recorded against a terminal program has
	// to mean the same thing replayed against a web application, or the two
	// backends are two products that happen to share a file format.
	for _, name := range []string{
		"enter", "tab", "escape", "space", "backspace", "delete", "insert",
		"home", "end", "pageup", "pagedown", "up", "down", "left", "right",
		"f1", "f12", "a", "Z", "7",
	} {
		if _, err := EncodeKey(name, false); err != nil {
			t.Fatalf("the terminal backend does not know %q, so this test is wrong", name)
		}
		if _, err := WebKey(name); err != nil {
			t.Errorf("the web backend does not know %q, which the terminal backend does", name)
		}
	}
}

func TestWebKeyDescribesAKeystrokeCompletely(t *testing.T) {
	// A browser gets the character wrong if the DOM key value, the physical
	// code and the legacy virtual key number disagree, and page code reads all
	// three depending on how old it is.
	k, err := WebKey("enter")
	if err != nil {
		t.Fatal(err)
	}
	if k.Key != "Enter" || k.Code != "Enter" || k.VK != 13 {
		t.Fatalf("enter = %+v", k)
	}
	if k.Text != "\r" {
		t.Errorf("enter carries no text, so a form would not submit: %+v", k)
	}

	a, _ := WebKey("a")
	if a.Key != "a" || a.Code != "KeyA" || a.Text != "a" || a.VK != 'A' {
		t.Fatalf("a = %+v", a)
	}
}

func TestAModifiedLetterIsACommandNotText(t *testing.T) {
	// ctrl-a selects; it does not type an "a". Sending the text with it makes
	// the page do both, which is a keystroke nobody could have typed.
	k, err := WebKey("ctrl-a")
	if err != nil {
		t.Fatal(err)
	}
	if k.Modifiers != modCtrl {
		t.Fatalf("ctrl-a has modifiers %d, want %d", k.Modifiers, modCtrl)
	}
	if k.Text != "" {
		t.Errorf("ctrl-a would insert %q as well as being a shortcut", k.Text)
	}
}

func TestShiftUpperCasesAPrintableKey(t *testing.T) {
	k, err := WebKey("shift-a")
	if err != nil {
		t.Fatal(err)
	}
	if k.Text != "A" || k.Key != "A" {
		t.Fatalf("shift-a types %q, want A", k.Text)
	}
	if k.Modifiers&modShift == 0 {
		t.Errorf("shift-a lost its modifier: %+v", k)
	}
}

func TestModifiersStack(t *testing.T) {
	k, err := WebKey("ctrl-alt-delete")
	if err != nil {
		t.Fatal(err)
	}
	if k.Modifiers != modCtrl|modAlt {
		t.Fatalf("ctrl-alt-delete has modifiers %d, want %d", k.Modifiers, modCtrl|modAlt)
	}
	if k.Key != "Delete" {
		t.Fatalf("ctrl-alt-delete resolved to %q", k.Key)
	}
}

func TestFunctionKeysAreBounded(t *testing.T) {
	for _, name := range []string{"f1", "f9", "f12"} {
		if _, err := WebKey(name); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	// f0 and f13 are not keys. Accepting them would send a virtual key code
	// that means something else entirely.
	for _, name := range []string{"f0", "f13", "f99"} {
		if _, err := WebKey(name); err == nil {
			t.Errorf("%s was accepted as a function key", name)
		}
	}
}

func TestAnUnknownKeyIsAnErrorNotAGuess(t *testing.T) {
	// The alternative is typing something nobody meant, which produces findings
	// that cannot be reproduced by hand.
	for _, name := range []string{"", "eykm", "ctrl-", "wingding"} {
		if k, err := WebKey(name); err == nil {
			t.Errorf("WebKey(%q) = %+v, want an error", name, k)
		}
	}
}

func TestANonAsciiCharacterStillTypes(t *testing.T) {
	// A mutator produces text no keyboard has. There is no physical key for it,
	// and the browser inserts the text regardless — which is the right
	// behaviour, since the page under test may well be the thing that breaks.
	k, err := WebKey("é")
	if err != nil {
		t.Fatal(err)
	}
	if k.Text != "é" {
		t.Fatalf("é types %q", k.Text)
	}
	if k.Code != "" {
		t.Errorf("a character with no physical key was given the code %q", k.Code)
	}
}
