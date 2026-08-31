package vt

import (
	"strings"
	"unicode/utf8"
)

// Limits. Every one of them is a bound on something a target controls, so every
// one of them is a place a fuzzer will push. They are generous enough that no
// real program reaches them and small enough that a program trying to reaches
// them immediately.
const (
	// MaxParams bounds a CSI's parameter list. xterm's own limit is 16; a few
	// sequences legitimately use more, and nothing uses this many.
	MaxParams = 32

	// MaxParam bounds one parameter's value, so a repeat count cannot ask for
	// four billion operations.
	MaxParam = 65535

	// MaxString bounds an OSC or DCS payload. A window title longer than this
	// is not a title.
	MaxString = 4096

	// MaxCols and MaxRows bound a resize, including one the target asks for.
	MaxCols = 1000
	MaxRows = 1000

	// DefaultCols and DefaultRows are the size a terminal starts at.
	DefaultCols = 80
	DefaultRows = 24
)

// parseState is where the parser is in a sequence.
type parseState uint8

const (
	stGround  parseState = iota
	stEscape             // ESC seen
	stCSI                // ESC [ seen
	stOSC                // ESC ] seen
	stString             // ESC P / ESC X / ESC ^ / ESC _ : consumed to ST
	stCharset            // ESC ( ) * + : one more byte to consume
)

// Terminal interprets a byte stream and holds the resulting screen.
//
// Not safe for concurrent use: one goroutine reads the pseudo-terminal and
// writes here, and the driver reads the screen between events.
type Terminal struct {
	cols, rows int

	primary *buffer
	alt     *buffer
	buf     *buffer // whichever of the two is showing

	state  parseState
	params []int
	colon  []bool // whether params[i] was introduced by ':' rather than ';'
	param  int
	hasNum bool
	priv   byte // the private marker of a CSI: '?', '<', '=', '>' or 0
	inter  []byte
	str    strings.Builder
	strCmd byte
	strEsc bool // an ESC arrived inside a string: ST if the next byte is '\\'

	// utf8 accumulates a rune split across writes, which a pseudo-terminal read
	// does constantly.
	u8  [4]byte
	u8n int

	title         string
	cursorVisible bool
	autowrap      bool
	insertMode    bool
	originMode    bool
	mouseMode     MouseMode
	mouseEnc      MouseEncoding
	appCursor     bool

	// bell counts BEL, which is one of the few things a TUI does that is not
	// visible on the screen and is worth noticing: a program that starts
	// beeping has usually hit an error path.
	bell uint64

	// written counts bytes, so a driver can tell "the program is drawing" from
	// "the program has stopped".
	written uint64
}

// New returns a terminal of the given size.
func New(cols, rows int) *Terminal {
	cols, rows = clamp(cols, 1, MaxCols), clamp(rows, 1, MaxRows)
	t := &Terminal{
		cols: cols, rows: rows,
		primary:       newBuffer(cols, rows),
		alt:           newBuffer(cols, rows),
		cursorVisible: true,
		autowrap:      true,
		params:        make([]int, 0, MaxParams),
		colon:         make([]bool, 0, MaxParams),
	}
	t.buf = t.primary
	return t
}

// Size returns the terminal's dimensions.
func (t *Terminal) Size() (cols, rows int) { return t.cols, t.rows }

// Resize changes the terminal's dimensions.
func (t *Terminal) Resize(cols, rows int) {
	cols, rows = clamp(cols, 1, MaxCols), clamp(rows, 1, MaxRows)
	if cols == t.cols && rows == t.rows {
		return
	}
	t.cols, t.rows = cols, rows
	t.primary.resize(cols, rows)
	t.alt.resize(cols, rows)
}

// Bells returns how many times the target rang the bell.
func (t *Terminal) Bells() uint64 { return t.bell }

// Written returns how many bytes the target has produced.
func (t *Terminal) Written() uint64 { return t.written }

// Alternate reports whether the alternate screen buffer is showing, which is
// what a full-screen TUI switches to on startup and away from on exit.
func (t *Terminal) Alternate() bool { return t.buf == t.alt }

// Title returns the last title the target set.
func (t *Terminal) Title() string { return t.title }

// Screen returns a snapshot of the current grid.
func (t *Terminal) Screen() *Screen {
	s := &Screen{
		Cols: t.buf.cols, Rows: t.buf.rows,
		Cells:         make([]Cell, len(t.buf.cells)),
		CursorX:       t.buf.x,
		CursorY:       t.buf.y,
		CursorVisible: t.cursorVisible,
		Title:         t.title,
		Alternate:     t.buf == t.alt,
	}
	copy(s.Cells, t.buf.cells)
	return s
}

// Text is the current screen rendered as lines.
func (t *Terminal) Text() string { return t.Screen().Text() }

// Reset returns the terminal to its startup state, counters included. This is
// what a driver does between sequences.
func (t *Terminal) Reset() {
	t.softReset()
	t.bell, t.written = 0, 0
}

// softReset clears the screen and the modes but leaves the counters alone.
//
// This is RIS and DECSTR. The bell count and the byte count belong to the
// campaign rather than to the terminal, and a target that reset itself would
// otherwise erase the evidence that it had been beeping.
func (t *Terminal) softReset() {
	t.primary = newBuffer(t.cols, t.rows)
	t.alt = newBuffer(t.cols, t.rows)
	t.buf = t.primary
	t.state, t.priv, t.param, t.hasNum, t.u8n = stGround, 0, 0, false, 0
	t.params, t.colon, t.inter = t.params[:0], t.colon[:0], nil
	t.str.Reset()
	t.title, t.cursorVisible, t.autowrap = "", true, true
	t.insertMode, t.originMode = false, false
	t.mouseMode, t.mouseEnc = MouseOff, EncodeX10
	t.appCursor = false
}

// Write implements io.Writer: it feeds bytes to the emulator.
//
// It never returns an error and never returns a short write. A terminal that
// refused input would be a terminal a target could wedge, and the whole point
// of this one is that it survives whatever the target produces.
func (t *Terminal) Write(p []byte) (int, error) {
	t.written += uint64(len(p))
	for _, b := range p {
		t.step(b)
	}
	return len(p), nil
}

// WriteString is Write without the copy.
func (t *Terminal) WriteString(s string) (int, error) {
	t.written += uint64(len(s))
	for i := 0; i < len(s); i++ {
		t.step(s[i])
	}
	return len(s), nil
}

func (t *Terminal) step(b byte) {
	// CAN and SUB abandon whatever sequence is in progress, from any state. So
	// does ESC, which is how a terminal recovers from a truncated sequence
	// rather than swallowing the next one.
	switch b {
	case 0x18, 0x1A: // CAN, SUB
		if t.state != stGround {
			t.reset()
			return
		}
	case 0x1B: // ESC
		if t.state == stOSC || t.state == stString {
			// ESC inside a string is half of ST. Discarding the payload here
			// would lose every OSC a program terminates properly, which is most
			// of them: "\x1b]0;title\x1b\\" is how a title is normally set.
			t.strEsc = true
			return
		}
		t.reset()
		t.state = stEscape
		return
	}

	switch t.state {
	case stGround:
		t.ground(b)
	case stEscape:
		t.escape(b)
	case stCSI:
		t.csi(b)
	case stOSC, stString:
		t.stringByte(b)
	case stCharset:
		t.state = stGround
	}
}

func (t *Terminal) reset() {
	t.state = stGround
	t.params, t.colon, t.inter = t.params[:0], t.colon[:0], nil
	t.param, t.hasNum, t.priv = 0, false, 0
	t.str.Reset()
	t.strEsc = false
	t.u8n = 0
}

// ground handles a byte outside any sequence.
func (t *Terminal) ground(b byte) {
	if b < 0x80 {
		t.u8n = 0
		if b < 0x20 {
			t.control(b)
			return
		}
		if b == 0x7f {
			return // DEL is discarded
		}
		t.emit(rune(b))
		return
	}
	// A continuation byte arriving with nothing to continue, or a lead byte
	// arriving mid-rune, is a broken stream. Emitting the replacement rune and
	// starting over is what a terminal does and what keeps one bad byte from
	// desynchronising the rest of the screen.
	if t.u8n == 0 && b < 0xC2 {
		t.emit(utf8.RuneError)
		return
	}
	if t.u8n > 0 && b&0xC0 != 0x80 {
		t.emit(utf8.RuneError)
		t.u8n = 0
		if b < 0xC2 {
			t.emit(utf8.RuneError)
			return
		}
	}
	t.u8[t.u8n] = b
	t.u8n++
	if utf8.FullRune(t.u8[:t.u8n]) {
		r, _ := utf8.DecodeRune(t.u8[:t.u8n])
		t.u8n = 0
		t.emit(r)
		return
	}
	if t.u8n == len(t.u8) {
		t.u8n = 0
		t.emit(utf8.RuneError)
	}
}

func (t *Terminal) emit(r rune) {
	if t.insertMode && RuneWidth(r) > 0 {
		t.buf.insertBlanks(RuneWidth(r))
	}
	t.buf.put(r, t.autowrap)
}

func (t *Terminal) control(b byte) {
	switch b {
	case 0x07: // BEL
		t.bell++
	case 0x08: // BS
		if t.buf.wrapNext {
			t.buf.wrapNext = false
		} else if t.buf.x > 0 {
			t.buf.x--
		}
	case 0x09: // HT
		t.tab(1)
	case 0x0A, 0x0B, 0x0C: // LF, VT, FF
		t.buf.lineFeed()
	case 0x0D: // CR
		t.buf.x, t.buf.wrapNext = 0, false
	}
}

// tab moves to the next tab stop. Eight columns, which is the default every
// terminal starts with and the only one a TUI relies on.
func (t *Terminal) tab(n int) {
	for ; n > 0; n-- {
		x := (t.buf.x/8 + 1) * 8
		if x >= t.cols {
			x = t.cols - 1
		}
		t.buf.x = x
	}
	t.buf.wrapNext = false
}

func (t *Terminal) escape(b byte) {
	switch b {
	case '[':
		t.state = stCSI
		return
	case ']':
		t.state, t.strCmd = stOSC, b
		return
	case 'P', 'X', '^', '_': // DCS, SOS, PM, APC: consumed whole
		t.state, t.strCmd = stString, b
		return
	case '(', ')', '*', '+': // character set designation
		t.state = stCharset
		return
	}

	t.state = stGround
	switch b {
	case 'D': // IND
		t.buf.lineFeed()
	case 'E': // NEL
		t.buf.x = 0
		t.buf.lineFeed()
	case 'M': // RI
		t.buf.reverseIndex()
	case '7': // DECSC
		t.save()
	case '8': // DECRC
		t.restore()
	case 'c': // RIS
		t.softReset()
	case '=', '>': // keypad modes: no screen effect
	}
}

func (t *Terminal) save() {
	t.buf.savedX, t.buf.savedY = t.buf.x, t.buf.y
	t.buf.savedAttr, t.buf.savedValid = t.buf.attr, true
}

func (t *Terminal) restore() {
	if !t.buf.savedValid {
		t.buf.setCursor(0, 0)
		return
	}
	t.buf.setCursor(t.buf.savedX, t.buf.savedY)
	t.buf.attr = t.buf.savedAttr
}

// stringByte consumes an OSC or DCS payload up to its terminator.
func (t *Terminal) stringByte(b byte) {
	if t.strEsc {
		t.strEsc = false
		if b == '\\' { // ST
			t.endString()
			return
		}
		// ESC followed by anything else abandons the string and begins a new
		// sequence, which is how a terminal recovers from a payload that was
		// never terminated.
		t.reset()
		t.state = stEscape
		t.escape(b)
		return
	}
	switch b {
	case 0x07: // BEL terminates an OSC
		t.endString()
		return
	case 0x9C: // ST, in its single-byte C1 form
		t.endString()
		return
	}
	if t.str.Len() < MaxString {
		t.str.WriteByte(b)
	}
}

func (t *Terminal) endString() {
	payload := t.str.String()
	cmd := t.strCmd
	t.reset()
	if cmd != ']' {
		return // DCS, PM and APC have no screen effect here
	}
	// OSC 0, 1 and 2 set the title. Everything else — colour queries, clipboard,
	// hyperlinks — is recorded as bytes written and otherwise ignored.
	num, rest, ok := strings.Cut(payload, ";")
	if !ok {
		return
	}
	switch num {
	case "0", "1", "2":
		if len(rest) > 256 {
			rest = rest[:256]
		}
		t.title = rest
	}
}

func (t *Terminal) csi(b byte) {
	switch {
	case b >= '0' && b <= '9':
		if t.param <= MaxParam {
			t.param = t.param*10 + int(b-'0')
		}
		if t.param > MaxParam {
			t.param = MaxParam
		}
		t.hasNum = true
		return
	case b == ';' || b == ':':
		t.pushParam(b == ':')
		return
	case b >= '<' && b <= '?':
		// A private marker, valid only before any parameter. One elsewhere is a
		// malformed sequence, and ignoring the byte rather than the sequence is
		// what xterm does.
		if len(t.params) == 0 && !t.hasNum {
			t.priv = b
		}
		return
	case b >= 0x20 && b <= 0x2F:
		if len(t.inter) < 2 {
			t.inter = append(t.inter, b)
		}
		return
	case b < 0x20:
		t.control(b)
		return
	}
	t.pushParam(false)
	final := b
	priv, params := t.priv, t.params
	inter := t.inter
	t.dispatch(priv, inter, params, final)
	t.reset()
}

func (t *Terminal) pushParam(isColon bool) {
	if len(t.params) < MaxParams {
		t.params = append(t.params, t.param)
		t.colon = append(t.colon, isColon)
	}
	t.param, t.hasNum = 0, false
}

// arg returns parameter i, or def when it is absent or zero.
//
// Zero and absent mean the same thing for almost every sequence — "CSI 0 A" and
// "CSI A" both move up one row — which is why this is one function and not two.
func arg(params []int, i, def int) int {
	if i >= len(params) || params[i] == 0 {
		return def
	}
	return params[i]
}

func (t *Terminal) dispatch(priv byte, inter []byte, params []int, final byte) {
	if len(inter) > 0 {
		// DECSTR, a soft reset, is the one sequence with an intermediate that
		// changes the screen. The rest are device-attribute and conformance
		// requests, which a program sends and then reads a reply to; there is
		// nothing to reply on and nothing to draw.
		if final == 'p' && len(inter) == 1 && inter[0] == '!' {
			t.softReset()
		}
		return
	}
	b := t.buf
	switch final {
	case 'A': // CUU
		b.setCursor(b.x, b.y-arg(params, 0, 1))
	case 'B', 'e': // CUD, VPR
		b.setCursor(b.x, b.y+arg(params, 0, 1))
	case 'C', 'a': // CUF, HPR
		b.setCursor(b.x+arg(params, 0, 1), b.y)
	case 'D': // CUB
		b.setCursor(b.x-arg(params, 0, 1), b.y)
	case 'E': // CNL
		b.setCursor(0, b.y+arg(params, 0, 1))
	case 'F': // CPL
		b.setCursor(0, b.y-arg(params, 0, 1))
	case 'G', '`': // CHA, HPA
		b.setCursor(arg(params, 0, 1)-1, b.y)
	case 'H', 'f': // CUP, HVP
		// Row first, then column: the sequence is the other way round from
		// every coordinate pair in this file, and taking them in order puts
		// every cursor move on the transposed screen.
		t.moveTo(arg(params, 1, 1)-1, arg(params, 0, 1)-1)
	case 'I': // CHT
		t.tab(arg(params, 0, 1))
	case 'J': // ED
		t.eraseDisplay(argRaw(params, 0))
	case 'K': // EL
		t.eraseLine(argRaw(params, 0))
	case 'L': // IL
		if b.y >= b.top && b.y <= b.bottom {
			b.scrollRegionDown(b.y, b.bottom, arg(params, 0, 1))
		}
	case 'M': // DL
		if b.y >= b.top && b.y <= b.bottom {
			b.scrollRegionUp(b.y, b.bottom, arg(params, 0, 1))
		}
	case 'P': // DCH
		b.deleteChars(arg(params, 0, 1))
	case 'S': // SU
		b.scrollUp(arg(params, 0, 1))
	case 'T': // SD
		b.scrollDown(arg(params, 0, 1))
	case 'X': // ECH
		t.eraseChars(arg(params, 0, 1))
	case 'Z': // CBT
		t.backTab(arg(params, 0, 1))
	case '@': // ICH
		b.insertBlanks(arg(params, 0, 1))
	case 'd': // VPA
		t.moveTo(b.x, arg(params, 0, 1)-1)
	case 'h':
		t.setMode(priv, params, true)
	case 'l':
		t.setMode(priv, params, false)
	case 'm': // SGR
		t.sgr(params)
	case 'r': // DECSTBM
		t.setRegion(params)
	case 's': // save cursor (ANSI.SYS)
		t.save()
	case 'u': // restore cursor
		t.restore()
	}
}

// argRaw is arg without the zero-means-default rule, for the sequences where 0
// is a distinct selector: ED and EL.
func argRaw(params []int, i int) int {
	if i >= len(params) {
		return 0
	}
	return params[i]
}

// moveTo positions the cursor, honouring origin mode: with DECOM set, row 1 is
// the top of the scrolling region rather than the top of the screen.
func (t *Terminal) moveTo(x, y int) {
	if t.originMode {
		y += t.buf.top
		y = clamp(y, t.buf.top, t.buf.bottom)
	}
	t.buf.setCursor(x, y)
}

func (t *Terminal) eraseDisplay(mode int) {
	b, e := t.buf, t.buf.eraseCell()
	switch mode {
	case 0: // cursor to end
		b.fill(b.y*b.cols+b.x, len(b.cells), e)
	case 1: // start to cursor
		b.fill(0, b.y*b.cols+b.x+1, e)
	case 2, 3: // the whole screen; 3 also clears scrollback, which there is none of
		b.fill(0, len(b.cells), e)
	}
	b.wrapNext = false
}

func (t *Terminal) eraseLine(mode int) {
	b, e := t.buf, t.buf.eraseCell()
	start := b.y * b.cols
	switch mode {
	case 0:
		b.fill(start+b.x, start+b.cols, e)
	case 1:
		b.fill(start, start+b.x+1, e)
	case 2:
		b.fill(start, start+b.cols, e)
	}
	b.wrapNext = false
}

func (t *Terminal) eraseChars(n int) {
	b, e := t.buf, t.buf.eraseCell()
	start := b.y*b.cols + b.x
	end := start + n
	if lineEnd := (b.y + 1) * b.cols; end > lineEnd {
		end = lineEnd
	}
	b.fill(start, end, e)
}

func (t *Terminal) backTab(n int) {
	b := t.buf
	for ; n > 0; n-- {
		x := ((b.x + 7) / 8 * 8) - 8
		if x < 0 {
			x = 0
		}
		b.x = x
	}
	b.wrapNext = false
}

func (t *Terminal) setRegion(params []int) {
	top := arg(params, 0, 1) - 1
	bottom := arg(params, 1, t.rows) - 1
	if bottom >= t.rows {
		bottom = t.rows - 1
	}
	if top < 0 || top >= bottom {
		// A region that is not at least two rows is refused, not clamped: a
		// program setting one has miscalculated, and clamping it would silently
		// change where its output lands.
		return
	}
	t.buf.top, t.buf.bottom = top, bottom
	t.moveTo(0, 0)
}

func (t *Terminal) setMode(priv byte, params []int, on bool) {
	for _, p := range params {
		if priv != '?' {
			if p == 4 { // IRM
				t.insertMode = on
			}
			continue
		}
		switch p {
		case 1: // DECCKM, application cursor keys
			t.appCursor = on
		case 6: // DECOM, origin mode
			t.originMode = on
			t.moveTo(0, 0)
		case 7: // DECAWM, autowrap
			t.autowrap = on
		case 25: // DECTCEM, cursor visibility
			t.cursorVisible = on
		case 9, 1000, 1002, 1003:
			t.setMouse(p, on)
		case 1005, 1006, 1015:
			t.setMouseEncoding(p, on)
		case 47, 1047, 1049:
			t.setAlternate(on, p == 1049)
		case 1048:
			if on {
				t.save()
			} else {
				t.restore()
			}
		}
	}
}

// setAlternate switches between the two screen buffers.
//
// This is the single most important mode for a TUI: a full-screen program
// switches to the alternate buffer on startup, so a driver that did not
// implement it would watch the program draw its entire interface into a buffer
// nobody was looking at.
func (t *Terminal) setAlternate(on, withCursor bool) {
	if on == (t.buf == t.alt) {
		return
	}
	if on {
		if withCursor {
			t.save()
		}
		t.alt = newBuffer(t.cols, t.rows)
		t.alt.attr = t.buf.attr
		t.buf = t.alt
		if withCursor {
			t.buf.setCursor(0, 0)
		}
		return
	}
	t.buf = t.primary
	if withCursor {
		t.restore()
	}
}

func (t *Terminal) sgr(params []int) {
	if len(params) == 0 {
		t.buf.attr = Attr{}
		return
	}
	a := &t.buf.attr
	for i := 0; i < len(params); i++ {
		p := params[i]
		switch {
		case p == 0:
			*a = Attr{}
		case p == 1:
			a.Flags |= AttrBold
		case p == 2:
			a.Flags |= AttrFaint
		case p == 3:
			a.Flags |= AttrItalic
		case p == 4:
			a.Flags |= AttrUnderline
		case p == 5 || p == 6:
			a.Flags |= AttrBlink
		case p == 7:
			a.Flags |= AttrReverse
		case p == 8:
			a.Flags |= AttrInvisible
		case p == 9:
			a.Flags |= AttrStrike
		case p == 21 || p == 22:
			a.Flags &^= AttrBold | AttrFaint
		case p == 23:
			a.Flags &^= AttrItalic
		case p == 24:
			a.Flags &^= AttrUnderline
		case p == 25:
			a.Flags &^= AttrBlink
		case p == 27:
			a.Flags &^= AttrReverse
		case p == 28:
			a.Flags &^= AttrInvisible
		case p == 29:
			a.Flags &^= AttrStrike
		case p >= 30 && p <= 37:
			a.FG = Indexed(uint8(p - 30))
		case p == 38:
			i = t.extendedColor(params, i, &a.FG)
		case p == 39:
			a.FG = Color{}
		case p >= 40 && p <= 47:
			a.BG = Indexed(uint8(p - 40))
		case p == 48:
			i = t.extendedColor(params, i, &a.BG)
		case p == 49:
			a.BG = Color{}
		case p >= 90 && p <= 97:
			a.FG = Indexed(uint8(p - 90 + 8))
		case p >= 100 && p <= 107:
			a.BG = Indexed(uint8(p - 100 + 8))
		}
	}
}

// extendedColor reads a 38/48 colour and returns the index of the last
// parameter it consumed.
//
// The colon form has an extra slot for a colour space that the semicolon form
// does not — "38:2::r:g:b" against "38;2;r;g;b" — so which one this is decides
// how many parameters to skip. Getting that wrong does not merely produce the
// wrong colour: every parameter after it shifts, and a sequence that meant bold
// text means something else entirely.
func (t *Terminal) extendedColor(params []int, i int, dst *Color) int {
	if i+1 >= len(params) {
		return i
	}
	// colon[i] is the separator that ended params[i], so it is the one that
	// introduced params[i+1].
	colonForm := i < len(t.colon) && t.colon[i]
	switch params[i+1] {
	case 5: // indexed
		if i+2 < len(params) {
			*dst = Indexed(uint8(params[i+2]))
			return i + 2
		}
	case 2: // 24-bit
		base := i + 2
		if colonForm && len(params) >= base+4 {
			base++ // skip the colour-space identifier
		}
		if base+2 < len(params) {
			*dst = RGB(uint8(params[base]), uint8(params[base+1]), uint8(params[base+2]))
			return base + 2
		}
	}
	return i + 1
}

// MouseMode says which mouse events a program has asked to be told about.
type MouseMode uint8

// The mouse tracking modes, in the order a program escalates through them.
const (
	MouseOff    MouseMode = iota
	MouseX10              // 9: button presses only, no releases
	MouseNormal           // 1000: presses and releases
	MouseDrag             // 1002: and motion while a button is held
	MouseMotion           // 1003: and motion with no button at all
)

// MouseEncoding is how a mouse report is written on the wire.
type MouseEncoding uint8

// The encodings. The original one cannot express a coordinate past 223, which
// is why the others exist and why a wide terminal needs one of them.
const (
	EncodeX10   MouseEncoding = iota // ESC [ M with three offset-by-32 bytes
	EncodeUTF8                       // 1005
	EncodeSGR                        // 1006: ESC [ < b ; x ; y M
	EncodeURXVT                      // 1015
)

// AppCursor reports whether the program has put the terminal in application
// cursor-key mode.
//
// It changes what the four arrow keys send — ESC O A rather than ESC [ A — and
// nothing else. A driver that ignores it types a literal "A" into any program
// that set the mode, which is most full-screen ones.
func (t *Terminal) AppCursor() bool { return t.appCursor }

// Mouse returns what the program has asked for.
//
// A driver needs this before it sends a click. A mouse report delivered to a
// program that never enabled tracking is not a click: it is the escape sequence
// arriving as ordinary keystrokes, which navigates menus, types characters and
// makes every click in a campaign mean something different depending on what the
// program happened to be doing.
func (t *Terminal) Mouse() (MouseMode, MouseEncoding) { return t.mouseMode, t.mouseEnc }

func (t *Terminal) setMouse(p int, on bool) {
	var m MouseMode
	switch p {
	case 9:
		m = MouseX10
	case 1000:
		m = MouseNormal
	case 1002:
		m = MouseDrag
	case 1003:
		m = MouseMotion
	}
	if on {
		t.mouseMode = m
		return
	}
	// Turning off the mode that is set turns tracking off; turning off one that
	// is not is a program tidying up modes it never enabled, and must not
	// disable the one it is using.
	if t.mouseMode == m {
		t.mouseMode = MouseOff
	}
}

func (t *Terminal) setMouseEncoding(p int, on bool) {
	var e MouseEncoding
	switch p {
	case 1005:
		e = EncodeUTF8
	case 1006:
		e = EncodeSGR
	case 1015:
		e = EncodeURXVT
	}
	if on {
		t.mouseEnc = e
		return
	}
	if t.mouseEnc == e {
		t.mouseEnc = EncodeX10
	}
}
