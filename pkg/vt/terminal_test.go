package vt_test

import (
	"strings"
	"testing"

	"github.com/rom/Xfuzz/pkg/vt"
)

// The emulator is the TUI driver's only sense organ, so a mistake here is not a
// rendering artefact: it is a campaign that thinks two different screens are the
// same, or the same screen twice is two, and either one ruins the feedback.

func write(t *testing.T, term *vt.Terminal, s string) {
	t.Helper()
	if _, err := term.WriteString(s); err != nil {
		t.Fatal(err)
	}
}

func TestPlainText(t *testing.T) {
	term := vt.New(20, 3)
	write(t, term, "hello\r\nworld")
	if got := term.Text(); got != "hello\nworld" {
		t.Errorf("got %q", got)
	}
}

// TestTrailingBlanksAreNotContent is what makes two renderings of the same
// screen compare equal. A program that pads a row to the terminal width and one
// that does not have drawn the same thing.
func TestTrailingBlanksAreNotContent(t *testing.T) {
	padded, bare := vt.New(20, 4), vt.New(20, 4)
	write(t, padded, "hi"+strings.Repeat(" ", 18))
	write(t, bare, "hi")
	if padded.Text() != bare.Text() {
		t.Errorf("padding changed the screen: %q vs %q", padded.Text(), bare.Text())
	}
}

func TestCursorMovement(t *testing.T) {
	term := vt.New(20, 5)
	write(t, term, "\x1b[3;5Hx")
	s := term.Screen()
	if c := s.At(4, 2); c.Rune != 'x' {
		t.Errorf("CUP put the character at the wrong place; row 2 is %q", s.Row(2))
	}
	// Row and column are one-based in the sequence and zero-based in the grid,
	// and getting that wrong is off-by-one in both directions at once.
	write(t, term, "\x1b[H*")
	if c := term.Screen().At(0, 0); c.Rune != '*' {
		t.Error("CSI H did not home the cursor")
	}
}

func TestCursorMovementClampsToTheScreen(t *testing.T) {
	term := vt.New(10, 3)
	// A program is entitled to ask for row 900. A terminal clamps; a fuzzer that
	// panicked here would be reporting a bug in itself.
	write(t, term, "\x1b[900;900Hx\x1b[1;1H\x1b[999Ay")
	if got := term.Text(); !strings.Contains(got, "y") {
		t.Errorf("screen %q", got)
	}
}

func TestEraseDisplayAndLine(t *testing.T) {
	term := vt.New(10, 3)
	write(t, term, "aaaaa\r\nbbbbb\r\nccccc")
	write(t, term, "\x1b[2;3H\x1b[K") // erase from the cursor to the end of row 2
	if got := term.Screen().Row(1); got != "bb" {
		t.Errorf("EL 0 left %q, want %q", got, "bb")
	}
	write(t, term, "\x1b[2J")
	if got := term.Text(); got != "" {
		t.Errorf("ED 2 left %q", got)
	}
}

func TestScrollingRegion(t *testing.T) {
	term := vt.New(10, 5)
	write(t, term, "1\r\n2\r\n3\r\n4\r\n5")
	// Rows 2-4 scroll; rows 1 and 5 are frozen, which is how every TUI with a
	// header and a status bar is drawn.
	write(t, term, "\x1b[2;4r\x1b[4;1H\n")
	rows := strings.Split(term.Text(), "\n")
	if len(rows) != 5 {
		t.Fatalf("screen is %d rows:\n%s", len(rows), term.Text())
	}
	if rows[0] != "1" {
		t.Errorf("the header scrolled: row 1 is %q", rows[0])
	}
	if rows[4] != "5" {
		t.Errorf("the status bar scrolled: row 5 is %q", rows[4])
	}
	if rows[1] != "3" || rows[2] != "4" {
		t.Errorf("the region did not scroll:\n%s", term.Text())
	}
}

func TestInsertAndDeleteLines(t *testing.T) {
	term := vt.New(10, 4)
	write(t, term, "a\r\nb\r\nc\r\nd")
	write(t, term, "\x1b[2;1H\x1b[L") // insert a line at row 2
	if got := term.Text(); got != "a\n\nb\nc" {
		t.Errorf("IL produced %q", got)
	}
	write(t, term, "\x1b[2;1H\x1b[M") // and take it back out
	if got := term.Text(); got != "a\nb\nc" {
		t.Errorf("DL produced %q", got)
	}
}

func TestInsertAndDeleteCharacters(t *testing.T) {
	term := vt.New(10, 1)
	write(t, term, "abcdef\x1b[1;3H\x1b[2@")
	if got := term.Screen().Row(0); got != "ab  cdef" {
		t.Errorf("ICH produced %q", got)
	}
	write(t, term, "\x1b[1;3H\x1b[2P")
	if got := term.Screen().Row(0); got != "abcdef" {
		t.Errorf("DCH produced %q", got)
	}
}

// TestAutowrap is the difference between a program's output landing on the
// screen and half of it vanishing off the right edge.
func TestAutowrap(t *testing.T) {
	term := vt.New(5, 3)
	write(t, term, "abcdefg")
	if got := term.Text(); got != "abcde\nfg" {
		t.Errorf("wrapped to %q", got)
	}

	term = vt.New(5, 3)
	write(t, term, "\x1b[?7l"+"abcdefg")
	if got := term.Text(); got != "abcdg" {
		t.Errorf("with autowrap off the screen is %q", got)
	}
}

// TestWrapIsDeferred is the property that makes a full-width line not scroll.
// Writing the last column does not move to the next row; writing the column
// after it does. A terminal that wrapped eagerly would scroll a screen every
// time a program filled its bottom row exactly.
func TestWrapIsDeferred(t *testing.T) {
	term := vt.New(5, 2)
	write(t, term, "abcde") // exactly one row
	if got := term.Text(); got != "abcde" {
		t.Fatalf("got %q", got)
	}
	write(t, term, "f")
	if got := term.Text(); got != "abcde\nf" {
		t.Errorf("got %q", got)
	}
}

// TestAlternateScreen is the single most important mode for a TUI: a
// full-screen program switches to it on startup, so an emulator without it
// watches the program draw its entire interface into a buffer nobody reads.
func TestAlternateScreen(t *testing.T) {
	term := vt.New(20, 3)
	write(t, term, "shell prompt $")
	write(t, term, "\x1b[?1049h")
	if !term.Alternate() {
		t.Fatal("1049h did not switch to the alternate buffer")
	}
	if got := term.Text(); got != "" {
		t.Errorf("the alternate buffer started with %q", got)
	}
	write(t, term, "the application")
	if got := term.Text(); got != "the application" {
		t.Errorf("got %q", got)
	}
	write(t, term, "\x1b[?1049l")
	if term.Alternate() {
		t.Fatal("1049l did not switch back")
	}
	if got := term.Text(); got != "shell prompt $" {
		t.Errorf("leaving the alternate buffer lost the primary one: %q", got)
	}
}

func TestSGR(t *testing.T) {
	term := vt.New(20, 1)
	write(t, term, "\x1b[1;31mred\x1b[0mplain")
	s := term.Screen()
	if a := s.At(0, 0).Attr; !a.Has(vt.AttrBold) || a.FG != vt.Indexed(1) {
		t.Errorf("attributes %+v", a)
	}
	if a := s.At(3, 0).Attr; a.Flags != 0 || a.FG.Kind != vt.ColorDefault {
		t.Errorf("SGR 0 did not reset: %+v", a)
	}
}

// TestSGRExtendedColorConsumesTheRightNumberOfParameters is a subtler failure
// than a wrong colour: every parameter after a miscounted one shifts, so a
// sequence that meant bold text sets a background instead, and the screen a
// campaign compares is not the screen the program drew.
func TestSGRExtendedColorConsumesTheRightNumberOfParameters(t *testing.T) {
	for _, tc := range []struct {
		name string
		seq  string
		want vt.Color
		bold bool
	}{
		{"indexed", "\x1b[38;5;42;1mx", vt.Indexed(42), true},
		{"truecolor semicolons", "\x1b[38;2;10;20;30;1mx", vt.RGB(10, 20, 30), true},
		{"truecolor colons", "\x1b[38:2::10:20:30;1mx", vt.RGB(10, 20, 30), true},
		{"indexed colons", "\x1b[38:5:42;1mx", vt.Indexed(42), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			term := vt.New(10, 1)
			write(t, term, tc.seq)
			a := term.Screen().At(0, 0).Attr
			if a.FG != tc.want {
				t.Errorf("colour %+v, want %+v", a.FG, tc.want)
			}
			if a.Has(vt.AttrBold) != tc.bold {
				t.Errorf("bold %v; the parameters after the colour were misread",
					a.Has(vt.AttrBold))
			}
		})
	}
}

func TestUTF8(t *testing.T) {
	term := vt.New(20, 1)
	write(t, term, "héllo")
	if got := term.Screen().Row(0); got != "héllo" {
		t.Errorf("got %q", got)
	}
}

// TestUTF8SplitAcrossWrites is not a corner case: a pseudo-terminal read returns
// whatever bytes have arrived, and a multi-byte rune straddling that boundary is
// the ordinary case for any program that draws box-drawing characters.
func TestUTF8SplitAcrossWrites(t *testing.T) {
	term := vt.New(20, 1)
	s := []byte("│─┼")
	for i := range s {
		write(t, term, string(s[i:i+1]))
	}
	if got := term.Screen().Row(0); got != "│─┼" {
		t.Errorf("got %q, want %q", got, "│─┼")
	}
}

func TestInvalidUTF8DoesNotDesynchroniseTheScreen(t *testing.T) {
	term := vt.New(20, 1)
	write(t, term, "a\xffb\xc3z c")
	if got := term.Screen().Row(0); !strings.HasPrefix(got, "a") ||
		!strings.Contains(got, "b") || !strings.HasSuffix(got, "c") {
		t.Errorf("one bad byte lost the rest of the row: %q", got)
	}
}

func TestWideCharactersOccupyTwoColumns(t *testing.T) {
	term := vt.New(10, 1)
	write(t, term, "日本")
	s := term.Screen()
	if s.At(0, 0).Width != 2 || s.At(1, 0).Width != 0 {
		t.Errorf("widths %d %d", s.At(0, 0).Width, s.At(1, 0).Width)
	}
	if s.At(2, 0).Rune != '本' {
		t.Errorf("the second character landed at column %d", 2)
	}
	if got := s.Row(0); got != "日本" {
		t.Errorf("row %q", got)
	}
}

// TestOverwritingHalfAWideCharacterClearsTheOther keeps the grid a rectangle. A
// continuation cell with nothing in front of it renders as a hole and hashes as
// a state that never existed.
func TestOverwritingHalfAWideCharacterClearsTheOther(t *testing.T) {
	term := vt.New(10, 1)
	write(t, term, "日\x1b[1;1Hx")
	s := term.Screen()
	if s.At(0, 0).Rune != 'x' {
		t.Errorf("cell 0 is %q", s.At(0, 0).Rune)
	}
	if s.At(1, 0).Width == 0 {
		t.Error("the second half of the overwritten wide character survives")
	}
}

func TestCombiningMarksDoNotAdvanceTheCursor(t *testing.T) {
	term := vt.New(10, 1)
	write(t, term, "éx")
	if got := term.Screen().Row(0); got != "ex" {
		t.Errorf("row %q; a combining mark took a column of its own", got)
	}
}

func TestTitle(t *testing.T) {
	for _, seq := range []string{
		"\x1b]0;the title\x07",
		"\x1b]2;the title\x1b\\",
	} {
		term := vt.New(10, 1)
		write(t, term, seq)
		if got := term.Title(); got != "the title" {
			t.Errorf("%q set the title to %q", seq, got)
		}
		if term.Text() != "" {
			t.Errorf("%q drew something: %q", seq, term.Text())
		}
	}
}

func TestBell(t *testing.T) {
	term := vt.New(10, 1)
	write(t, term, "a\x07\x07b")
	if term.Bells() != 2 {
		t.Errorf("counted %d bells", term.Bells())
	}
	if got := term.Screen().Row(0); got != "ab" {
		t.Errorf("BEL drew something: %q", got)
	}
}

func TestSaveAndRestoreCursor(t *testing.T) {
	term := vt.New(10, 3)
	write(t, term, "\x1b[2;3H\x1b7\x1b[1;1Hx\x1b8y")
	s := term.Screen()
	if s.At(0, 0).Rune != 'x' {
		t.Error("the cursor did not move")
	}
	if s.At(2, 1).Rune != 'y' {
		t.Errorf("DECRC did not restore the cursor; row 2 is %q", s.Row(1))
	}
}

func TestReverseIndexScrollsAtTheTop(t *testing.T) {
	term := vt.New(10, 3)
	write(t, term, "a\r\nb\r\nc\x1b[1;1H\x1bM")
	if got := term.Text(); got != "\na\nb" {
		t.Errorf("RI at the top produced %q", got)
	}
}

func TestResizeKeepsWhatFits(t *testing.T) {
	term := vt.New(10, 3)
	write(t, term, "abcdefghij\r\nklm")
	term.Resize(5, 2)
	if c, r := term.Size(); c != 5 || r != 2 {
		t.Fatalf("size %dx%d", c, r)
	}
	if got := term.Text(); got != "abcde\nklm" {
		t.Errorf("after resize %q", got)
	}
}

// TestTerminalSurvivesArbitraryBytes is the property the whole tier depends on.
// The target is being actively mutated into misbehaving, so the emulator reads
// adversarial input by construction, and a panic in it is a crash in the fuzzer
// reported as a crash in the target.
func TestTerminalSurvivesArbitraryBytes(t *testing.T) {
	term := vt.New(80, 24)
	// Every dangerous shape: unterminated sequences, absurd parameters, private
	// markers in the wrong place, nested introducers, a string that never ends.
	for _, s := range []string{
		"\x1b", "\x1b[", "\x1b[999999999999999999999m", "\x1b[;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;m",
		"\x1b[?????25h", "\x1b[1;2;3;4;5;6;7;8;9;10;11;12;13;14;15;16;17;18;19;20;21;22r",
		"\x1b]0;" + strings.Repeat("t", 100000), "\x1b]", "\x1bP" + strings.Repeat("x", 9000),
		"\x1b[-1;-1H", "\x1b[0;0H", "\x1b[2147483647A", "\x1b[2147483647L",
		"\x1b[1;1r\x1b[1;1H\n\n\n\n", "\x1b[24;1r\x1b[100L",
		"\x1b[38;2m", "\x1b[38;5m", "\x1b[48;2;1m", "\x1b[38:2:",
		"\x1b#8", "\x1b(0", "\x1b[!p", "\x1bc",
		"\x1b[?1049h\x1b[?1049h\x1b[?1049l\x1b[?1049l",
		"\xff\xfe\xfd\xc0\x80\xed\xa0\x80\xf4\x90\x80\x80",
		"\x1b[8m\x1b[?7l" + strings.Repeat("W", 500),
	} {
		write(t, term, s)
		_ = term.Screen().Text() // rendering must not panic either
	}
}

// TestScreenIsASnapshot: a campaign holds screens to compare against later ones,
// and a view into a live terminal would change underneath it.
func TestScreenIsASnapshot(t *testing.T) {
	term := vt.New(10, 2)
	write(t, term, "before")
	snap := term.Screen()
	write(t, term, "\x1b[2J\x1b[Hafter")
	if got := snap.Text(); got != "before" {
		t.Errorf("the snapshot changed to %q", got)
	}
}

func TestResetReturnsToStartup(t *testing.T) {
	term := vt.New(10, 3)
	write(t, term, "\x1b[?1049h\x1b[31mstuff\x07\x1b]0;t\x07")
	term.Reset()
	if term.Text() != "" || term.Alternate() || term.Title() != "" || term.Bells() != 0 {
		t.Errorf("after Reset: text %q alt %v title %q bells %d",
			term.Text(), term.Alternate(), term.Title(), term.Bells())
	}
}

// TestRISKeepsTheCounters draws the line between the terminal's state, which a
// target may reset, and the campaign's, which it may not: a program that started
// beeping and then reset itself has still been beeping.
func TestRISKeepsTheCounters(t *testing.T) {
	term := vt.New(10, 3)
	write(t, term, "x\x07\x1bc")
	if term.Text() != "" {
		t.Errorf("RIS left %q", term.Text())
	}
	if term.Bells() != 1 {
		t.Errorf("RIS erased the bell count")
	}
}

func TestRuneWidth(t *testing.T) {
	for _, tc := range []struct {
		r    rune
		want int
	}{
		{'a', 1}, {' ', 1}, {'│', 1}, {'\n', 0}, {0x7f, 0},
		{'日', 2}, {'한', 2}, {'Ａ', 2}, {0x1F600, 2},
		{0x0301, 0}, {0x200B, 0}, {0xFE0F, 0},
	} {
		if got := vt.RuneWidth(tc.r); got != tc.want {
			t.Errorf("RuneWidth(%U) = %d, want %d", tc.r, got, tc.want)
		}
	}
	if got := vt.StringWidth("a日b"); got != 4 {
		t.Errorf("StringWidth = %d, want 4", got)
	}
}

// TestDeterminism is the reproducibility claim (ASR-0008) at the level the
// emulator is responsible for: the same bytes always produce the same screen.
func TestDeterminism(t *testing.T) {
	seq := "\x1b[?1049h\x1b[2J\x1b[1;1H\x1b[1;34mheader\x1b[0m\r\n" +
		"\x1b[2;5rbody\r\n\x1b[10;1Hstatus\x1b[?25l日本語"
	first := ""
	for i := 0; i < 5; i++ {
		term := vt.New(40, 12)
		write(t, term, seq)
		got := term.Screen().Text()
		if i == 0 {
			first = got
			continue
		}
		if got != first {
			t.Fatalf("run %d differed:\n%q\n%q", i, first, got)
		}
	}
}
