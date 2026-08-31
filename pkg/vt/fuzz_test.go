package vt

import (
	"strings"
	"testing"
)

// FuzzTerminal fuzzes the terminal emulator.
//
// Untrusted by construction, and more so than most parsers here: the bytes come
// from a program the fuzzer is actively mutating into misbehaving, so the
// emulator is guaranteed adversarial input rather than merely exposed to it. A
// panic in it is a crash in the fuzzer reported as a crash in the target, which
// is worse than no finding (ADR-0021, SECURITY.md section 3.5).
//
// The property is not that anything is drawn — most inputs draw nothing — but
// that Write returns, Screen renders, and neither indexes outside the grid.
func FuzzTerminal(f *testing.F) {
	f.Add([]byte("hello\r\nworld"))
	f.Add([]byte("\x1b[?1049h\x1b[2J\x1b[H\x1b[1;34mheader\x1b[0m"))
	f.Add([]byte("\x1b[2;5r\x1b[3;1Habc\n\n\n"))
	f.Add([]byte("\x1b[38;2;10;20;30m\x1b[48;5;42mx"))
	f.Add([]byte("\x1b]0;title\x07"))
	f.Add([]byte("\x1b]0;title\x1b\\"))
	f.Add([]byte("日本語\x1b[1;1Hx"))
	f.Add([]byte("\x1b[999;999H\x1b[999L\x1b[999P\x1b[999@"))
	f.Add([]byte("\x1b[;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;m"))
	f.Add([]byte("\x1b[9999999999999999999999m"))
	f.Add([]byte("\xff\xfe\xc0\x80\xed\xa0\x80"))
	f.Add([]byte("\x1b"))
	f.Add([]byte("\x1b["))
	f.Add([]byte("\x1bP\x1b\\"))

	f.Fuzz(func(t *testing.T, in []byte) {
		// Small, because the emulator's cost is linear in the input and a
		// hundred-column screen exercises every wrap, scroll and clamp a
		// thousand-column one would.
		term := New(24, 8)
		if _, err := term.Write(in); err != nil {
			t.Fatalf("Write returned %v; a terminal that refuses input is one a "+
				"target can wedge", err)
		}

		s := term.Screen()
		if len(s.Cells) != s.Cols*s.Rows {
			t.Fatalf("the grid is %d cells for %dx%d", len(s.Cells), s.Cols, s.Rows)
		}
		if s.CursorX < 0 || s.CursorX >= s.Cols || s.CursorY < 0 || s.CursorY >= s.Rows {
			t.Fatalf("the cursor is at %d,%d on a %dx%d screen",
				s.CursorX, s.CursorY, s.Cols, s.Rows)
		}
		// Rendering must not panic and must not invent rows.
		if n := len(strings.Split(s.Text(), "\n")); s.Text() != "" && n > s.Rows {
			t.Fatalf("the screen rendered %d lines on %d rows", n, s.Rows)
		}
		// A resize under any state must leave the grid consistent, which is
		// where an emulator that kept an index rather than a position breaks.
		term.Resize(9, 3)
		s = term.Screen()
		if len(s.Cells) != 9*3 {
			t.Fatalf("after a resize the grid is %d cells", len(s.Cells))
		}
		if s.CursorX >= s.Cols || s.CursorY >= s.Rows {
			t.Fatalf("after a resize the cursor is at %d,%d", s.CursorX, s.CursorY)
		}
	})
}
