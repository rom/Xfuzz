package vt

import "strings"

// ColorKind says how a colour is specified.
type ColorKind uint8

// The three ways a terminal names a colour.
const (
	ColorDefault ColorKind = iota // whatever the terminal's default is
	ColorIndexed                  // one of the 256 palette entries
	ColorRGB                      // 24-bit
)

// Color is a foreground or background colour.
type Color struct {
	Kind    ColorKind
	Index   uint8
	R, G, B uint8
}

// Indexed returns a palette colour.
func Indexed(i uint8) Color { return Color{Kind: ColorIndexed, Index: i} }

// RGB returns a 24-bit colour.
func RGB(r, g, b uint8) Color { return Color{Kind: ColorRGB, R: r, G: g, B: b} }

// AttrFlags are the non-colour attributes.
type AttrFlags uint16

// The attributes SGR can set.
const (
	AttrBold AttrFlags = 1 << iota
	AttrFaint
	AttrItalic
	AttrUnderline
	AttrBlink
	AttrReverse
	AttrInvisible
	AttrStrike
)

// Attr is a cell's appearance.
type Attr struct {
	FG, BG Color
	Flags  AttrFlags
}

// Has reports whether every flag in f is set.
func (a Attr) Has(f AttrFlags) bool { return a.Flags&f == f }

// Cell is one screen position.
//
// Width is 1 for an ordinary character, 2 for the first half of a wide one, and
// 0 for the second half. A cell of width 0 holds no rune of its own: it exists
// so that the grid stays a rectangle, which is what lets a screen be compared to
// another screen position by position.
type Cell struct {
	Rune  rune
	Attr  Attr
	Width uint8
}

// blank is what an erased cell holds. The attribute is deliberately not part of
// it: erasing with a background colour set is a real terminal behaviour, and the
// callers that want it pass their own.
var blank = Cell{Rune: ' ', Width: 1}

// buffer is a screen: a grid, a cursor, and a scrolling region.
type buffer struct {
	cols, rows int
	cells      []Cell

	x, y     int
	attr     Attr
	wrapNext bool // the cursor is past the last column, waiting to wrap

	top, bottom int // the scrolling region, inclusive, in screen rows

	savedX, savedY int
	savedAttr      Attr
	savedValid     bool
}

func newBuffer(cols, rows int) *buffer {
	b := &buffer{cols: cols, rows: rows, bottom: rows - 1}
	b.cells = make([]Cell, cols*rows)
	b.clear(blank)
	return b
}

func (b *buffer) clear(with Cell) {
	for i := range b.cells {
		b.cells[i] = with
	}
}

// at returns a pointer to a cell, or nil when the position is off-screen.
//
// Off-screen writes are not an error: a program is entitled to move the cursor
// somewhere impossible and a terminal simply clamps or ignores it. Returning nil
// rather than panicking is what keeps a mutated escape sequence from taking the
// fuzzer down with the target.
func (b *buffer) at(x, y int) *Cell {
	if x < 0 || y < 0 || x >= b.cols || y >= b.rows {
		return nil
	}
	return &b.cells[y*b.cols+x]
}

func (b *buffer) row(y int) []Cell {
	if y < 0 || y >= b.rows {
		return nil
	}
	return b.cells[y*b.cols : (y+1)*b.cols]
}

// eraseCell is what an erase writes: a blank carrying the current background,
// because a program that sets a background and then clears the screen expects
// the colour to stay.
func (b *buffer) eraseCell() Cell {
	return Cell{Rune: ' ', Width: 1, Attr: Attr{BG: b.attr.BG}}
}

func (b *buffer) fill(from, to int, with Cell) {
	if from < 0 {
		from = 0
	}
	if to > len(b.cells) {
		to = len(b.cells)
	}
	for i := from; i < to; i++ {
		b.cells[i] = with
	}
}

// setCursor moves the cursor, clamping to the screen.
func (b *buffer) setCursor(x, y int) {
	b.x, b.y = clamp(x, 0, b.cols-1), clamp(y, 0, b.rows-1)
	b.wrapNext = false
}

// scrollUp moves the scrolling region up by n lines, discarding the top ones.
func (b *buffer) scrollUp(n int) {
	b.scrollRegionUp(b.top, b.bottom, n)
}

func (b *buffer) scrollRegionUp(top, bottom, n int) {
	if n <= 0 || top > bottom || top < 0 || bottom >= b.rows {
		return
	}
	height := bottom - top + 1
	if n > height {
		n = height
	}
	copy(b.cells[top*b.cols:(bottom+1-n)*b.cols], b.cells[(top+n)*b.cols:(bottom+1)*b.cols])
	b.fill((bottom+1-n)*b.cols, (bottom+1)*b.cols, b.eraseCell())
}

// scrollDown moves the scrolling region down by n lines.
func (b *buffer) scrollDown(n int) {
	b.scrollRegionDown(b.top, b.bottom, n)
}

func (b *buffer) scrollRegionDown(top, bottom, n int) {
	if n <= 0 || top > bottom || top < 0 || bottom >= b.rows {
		return
	}
	height := bottom - top + 1
	if n > height {
		n = height
	}
	// Backwards, because the source and destination overlap.
	copy(b.cells[(top+n)*b.cols:(bottom+1)*b.cols], b.cells[top*b.cols:(bottom+1-n)*b.cols])
	b.fill(top*b.cols, (top+n)*b.cols, b.eraseCell())
}

// lineFeed moves down one row, scrolling at the bottom of the region.
func (b *buffer) lineFeed() {
	switch {
	case b.y == b.bottom:
		b.scrollUp(1)
	case b.y < b.rows-1:
		b.y++
	}
	b.wrapNext = false
}

// reverseIndex moves up one row, scrolling at the top of the region.
func (b *buffer) reverseIndex() {
	switch {
	case b.y == b.top:
		b.scrollDown(1)
	case b.y > 0:
		b.y--
	}
	b.wrapNext = false
}

// put writes a rune at the cursor and advances it.
func (b *buffer) put(r rune, autowrap bool) {
	w := RuneWidth(r)
	if w == 0 {
		// A combining mark belongs to the cell before the cursor, which is the
		// difference between "é" as one screen position and as two.
		b.combine(r)
		return
	}
	if b.wrapNext && autowrap {
		b.x = 0
		b.lineFeed()
	}
	if b.x+w > b.cols {
		if !autowrap {
			// No room and no wrapping: a real terminal overwrites the last
			// column, and a program relying on that draws its border there.
			b.x = b.cols - w
			if b.x < 0 {
				return
			}
		} else {
			b.x = 0
			b.lineFeed()
		}
	}
	// Overwriting either half of a wide character has to clear the other half,
	// or the grid keeps a continuation cell with nothing in front of it.
	b.breakWide(b.x, b.y)
	if w == 2 {
		b.breakWide(b.x+1, b.y)
	}

	if c := b.at(b.x, b.y); c != nil {
		*c = Cell{Rune: r, Attr: b.attr, Width: uint8(w)}
	}
	if w == 2 {
		if c := b.at(b.x+1, b.y); c != nil {
			*c = Cell{Rune: 0, Attr: b.attr, Width: 0}
		}
	}
	b.x += w
	if b.x >= b.cols {
		b.x = b.cols - 1
		b.wrapNext = true
	}
}

// combine appends a zero-width rune to the cell the cursor last wrote.
func (b *buffer) combine(r rune) {
	x := b.x - 1
	if b.wrapNext {
		x = b.x
	}
	for x >= 0 {
		c := b.at(x, b.y)
		if c == nil {
			return
		}
		if c.Width != 0 {
			// A single rune per cell keeps the grid comparable; the base rune is
			// what a screen comparison is about, and dropping the accent loses
			// nothing a fuzzer uses.
			return
		}
		x--
	}
}

// breakWide clears the partner of a wide character overwritten at x,y.
func (b *buffer) breakWide(x, y int) {
	c := b.at(x, y)
	if c == nil {
		return
	}
	switch {
	case c.Width == 2:
		if p := b.at(x+1, y); p != nil && p.Width == 0 {
			*p = b.eraseCell()
		}
	case c.Width == 0:
		if p := b.at(x-1, y); p != nil && p.Width == 2 {
			*p = b.eraseCell()
		}
	}
}

// insertBlanks opens n cells at the cursor, pushing the rest of the line right.
func (b *buffer) insertBlanks(n int) {
	row := b.row(b.y)
	if row == nil || n <= 0 || b.x >= b.cols {
		return
	}
	if n > b.cols-b.x {
		n = b.cols - b.x
	}
	copy(row[b.x+n:], row[b.x:b.cols-n])
	for i := b.x; i < b.x+n; i++ {
		row[i] = b.eraseCell()
	}
}

// deleteChars removes n cells at the cursor, pulling the rest of the line left.
func (b *buffer) deleteChars(n int) {
	row := b.row(b.y)
	if row == nil || n <= 0 || b.x >= b.cols {
		return
	}
	if n > b.cols-b.x {
		n = b.cols - b.x
	}
	copy(row[b.x:], row[b.x+n:])
	for i := b.cols - n; i < b.cols; i++ {
		row[i] = b.eraseCell()
	}
}

// resize changes the grid.
//
// Without reflow: a terminal that rewraps its content on resize is doing
// something a TUI immediately undoes by redrawing, and the intermediate screen
// is not a state anybody wants in a corpus.
func (b *buffer) resize(cols, rows int) {
	if cols == b.cols && rows == b.rows {
		return
	}
	next := make([]Cell, cols*rows)
	for i := range next {
		next[i] = blank
	}
	for y := 0; y < min(rows, b.rows); y++ {
		copy(next[y*cols:(y+1)*cols], b.cells[y*b.cols:y*b.cols+min(cols, b.cols)])
	}
	b.cells, b.cols, b.rows = next, cols, rows
	b.top, b.bottom = 0, rows-1
	b.setCursor(b.x, b.y)
}

// Screen is a snapshot of a terminal's grid.
//
// A value rather than a view: a campaign holds screens to compare against later
// ones, and a view into a live terminal would change underneath it.
type Screen struct {
	Cols, Rows    int
	Cells         []Cell
	CursorX       int
	CursorY       int
	CursorVisible bool
	Title         string
	Alternate     bool
}

// At returns the cell at a position, or a blank when it is off-screen.
func (s *Screen) At(x, y int) Cell {
	if x < 0 || y < 0 || x >= s.Cols || y >= s.Rows {
		return blank
	}
	return s.Cells[y*s.Cols+x]
}

// Row returns one row as text, with trailing blanks removed.
func (s *Screen) Row(y int) string {
	if y < 0 || y >= s.Rows {
		return ""
	}
	var b strings.Builder
	for x := 0; x < s.Cols; x++ {
		c := s.At(x, y)
		if c.Width == 0 {
			continue // the second half of a wide character holds no rune
		}
		if c.Rune == 0 {
			b.WriteByte(' ')
			continue
		}
		b.WriteRune(c.Rune)
	}
	return strings.TrimRight(b.String(), " ")
}

// Text renders the screen as lines.
//
// This is what a person reads in a finding and what the UI-state feedback
// hashes. Trailing blanks go, because a program that pads a row to the width
// and one that does not have drawn the same screen.
func (s *Screen) Text() string {
	rows := make([]string, s.Rows)
	for y := range rows {
		rows[y] = s.Row(y)
	}
	// Trailing empty rows go too: a screen with four lines of content is the
	// same screen whether the terminal is twenty-four rows or fifty.
	for len(rows) > 0 && rows[len(rows)-1] == "" {
		rows = rows[:len(rows)-1]
	}
	return strings.Join(rows, "\n")
}

func (s *Screen) String() string { return s.Text() }

func clamp(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}
