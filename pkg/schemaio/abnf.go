package schemaio

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/rom/Xfuzz/pkg/schema"
)

// ABNF imports a grammar in the notation of RFC 5234.
//
// The best-fitting of the six, and the one with the most descriptions available:
// every text protocol the IETF has standardised carries its grammar in the RFC
// that defines it, in this notation, and those grammars are the definitive
// statement of what the protocol accepts.
//
// The correspondence is nearly exact. An alternation is a choice, a
// concatenation is a struct, a repetition is a repeat, an option is an opt, a
// rule name is a ref. What does not survive is listed in the report: a
// prose-val is a sentence in English, and a value range wider than the importer
// will enumerate becomes an unconstrained byte.
type ABNF struct{}

// Name implements Importer.
func (ABNF) Name() string { return "abnf" }

// Extensions implements Importer.
func (ABNF) Extensions() []string { return []string{".abnf"} }

// maxRangeAlternatives bounds how wide a value range is enumerated.
//
// A range is a *value* constraint and the schema language has only length
// constraints, so the only exact translation is a choice over the literal
// bytes. That is right for %x30-39 and absurd for %x00-FF, so there is a line,
// and where it falls is stated in the report rather than guessed at silently.
const maxRangeAlternatives = 64

// Import implements Importer.
func (ABNF) Import(src []byte, filename string) (*schema.Schema, *Report, error) {
	p := &abnfParser{
		b:     newBuilder("abnf", filename),
		lines: unfold(string(src)),
	}
	if err := p.parse(); err != nil {
		return nil, nil, err
	}
	if len(p.order) == 0 {
		return nil, nil, fmt.Errorf("abnf: %s declares no rules", filename)
	}
	return p.emit()
}

// abnfRule is one rule, with its alternatives already parsed.
type abnfRule struct {
	name string
	alts []abnfElem
	line int
}

// abnfElem is one element of a rule: the parsed shape of the notation.
type abnfElem struct {
	kind abnfKind

	// seq holds a concatenation, alt an alternation, and inner the body of a
	// repetition or option.
	seq   []abnfElem
	inner *abnfElem

	// repetition bounds, for kindRepeat. Zero max means unbounded.
	min, max int

	// literal content, for kindLiteral, and the case-sensitivity of it.
	lit       string
	sensitive bool

	// value range, for kindRange.
	lo, hi int

	// rule name, for kindRule.
	rule string
}

type abnfKind uint8

const (
	abnfSeq abnfKind = iota
	abnfAlt
	abnfRepeat
	abnfLiteral
	abnfRange
	abnfRule_
	abnfProse
)

type abnfParser struct {
	b     *builder
	lines []abnfLine

	rules map[string]*abnfRule
	order []string
}

type abnfLine struct {
	text string
	num  int
}

// unfold joins continuation lines and strips comments.
//
// ABNF folds a long rule across lines by indenting the continuation, so a line
// that starts with whitespace belongs to the rule above it. Reading the file
// line by line without this splits half the rules in every RFC.
func unfold(src string) []abnfLine {
	var out []abnfLine
	for i, raw := range strings.Split(src, "\n") {
		line := stripComment(strings.TrimRight(raw, "\r"))
		if strings.TrimSpace(line) == "" {
			continue
		}
		if isContinuation(raw) && len(out) > 0 {
			out[len(out)-1].text += " " + strings.TrimSpace(line)
			continue
		}
		out = append(out, abnfLine{text: strings.TrimSpace(line), num: i + 1})
	}
	return out
}

func isContinuation(raw string) bool {
	return len(raw) > 0 && (raw[0] == ' ' || raw[0] == '\t')
}

// stripComment removes a trailing comment, respecting quoted strings.
func stripComment(s string) string {
	inQuote := false
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '"':
			inQuote = !inQuote
		case ';':
			if !inQuote {
				return s[:i]
			}
		case '<':
			// A prose-val may contain a semicolon. Skipping to its close keeps
			// the prose intact so it can be reported rather than mangled.
			if !inQuote {
				if j := strings.IndexByte(s[i:], '>'); j >= 0 {
					i += j
				}
			}
		}
	}
	return s
}

func (p *abnfParser) parse() error {
	p.rules = map[string]*abnfRule{}
	for _, line := range p.lines {
		name, body, incremental, ok := splitRule(line.text)
		if !ok {
			p.b.rep.Add(fmt.Sprintf("%s:%d", p.b.s.File, line.num), "unparsable line",
				"not a rule definition; ABNF requires name = elements")
			continue
		}
		alts, err := parseAlternation(newAbnfLexer(body))
		if err != nil {
			p.b.rep.Add(fmt.Sprintf("%s:%d", p.b.s.File, line.num), "rule "+name, err.Error())
			continue
		}
		if r, ok := p.rules[strings.ToLower(name)]; ok {
			if !incremental {
				// A second plain definition of the same rule is a mistake in
				// the source; taking the later one silently would hide it.
				p.b.rep.Add(fmt.Sprintf("%s:%d", p.b.s.File, line.num), "redefined rule "+name,
					"a second = definition; use =/ to add alternatives")
			}
			r.alts = append(r.alts, alts...)
			continue
		}
		if incremental {
			p.b.rep.Add(fmt.Sprintf("%s:%d", p.b.s.File, line.num), "orphan =/ for "+name,
				"incremental alternation for a rule that was never defined")
			continue
		}
		p.rules[strings.ToLower(name)] = &abnfRule{name: name, alts: alts, line: line.num}
		p.order = append(p.order, strings.ToLower(name))
	}
	return nil
}

// splitRule separates a rule's name from its body.
func splitRule(line string) (name, body string, incremental, ok bool) {
	i := strings.Index(line, "=")
	if i <= 0 {
		return "", "", false, false
	}
	name = strings.TrimSpace(line[:i])
	rest := line[i+1:]
	if strings.HasPrefix(rest, "/") {
		incremental, rest = true, rest[1:]
	}
	if name == "" || !isRuleName(name) {
		return "", "", false, false
	}
	return name, strings.TrimSpace(rest), incremental, true
}

func isRuleName(s string) bool {
	if s == "" {
		return false
	}
	c := s[0]
	if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z') {
		return false
	}
	for i := 1; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

// --- the element grammar ----------------------------------------------------

type abnfLexer struct {
	src string
	pos int
}

func newAbnfLexer(s string) *abnfLexer { return &abnfLexer{src: s} }

func (l *abnfLexer) skipSpace() {
	for l.pos < len(l.src) && (l.src[l.pos] == ' ' || l.src[l.pos] == '\t') {
		l.pos++
	}
}

func (l *abnfLexer) peek() byte {
	l.skipSpace()
	if l.pos >= len(l.src) {
		return 0
	}
	return l.src[l.pos]
}

func (l *abnfLexer) done() bool { return l.peek() == 0 }

func parseAlternation(l *abnfLexer) ([]abnfElem, error) {
	var alts []abnfElem
	for {
		e, err := parseConcatenation(l)
		if err != nil {
			return nil, err
		}
		alts = append(alts, e)
		if l.peek() != '/' {
			return alts, nil
		}
		l.pos++
	}
}

func parseConcatenation(l *abnfLexer) (abnfElem, error) {
	var seq []abnfElem
	for {
		c := l.peek()
		if c == 0 || c == '/' || c == ')' || c == ']' {
			break
		}
		e, err := parseRepetition(l)
		if err != nil {
			return abnfElem{}, err
		}
		seq = append(seq, e)
	}
	switch len(seq) {
	case 0:
		return abnfElem{}, fmt.Errorf("empty alternative")
	case 1:
		return seq[0], nil
	}
	return abnfElem{kind: abnfSeq, seq: seq}, nil
}

func parseRepetition(l *abnfLexer) (abnfElem, error) {
	l.skipSpace()
	minimum, maximum, repeated := parseRepeatPrefix(l)
	e, err := parseElement(l)
	if err != nil {
		return abnfElem{}, err
	}
	if !repeated {
		return e, nil
	}
	return abnfElem{kind: abnfRepeat, inner: &e, min: minimum, max: maximum}, nil
}

// parseRepeatPrefix reads the n*m before an element.
//
// The forms are n, n*m, *m, n* and *, and they mean different things: "3" is
// exactly three, "*" is any number including none, "1*" is at least one. Reading
// "3" as "at least three" or "*" as "exactly none" changes what the grammar
// generates entirely.
func parseRepeatPrefix(l *abnfLexer) (minimum, maximum int, ok bool) {
	start := l.pos
	first, hasFirst := readNumber(l)
	if l.pos < len(l.src) && l.src[l.pos] == '*' {
		l.pos++
		second, hasSecond := readNumber(l)
		minimum = 0
		if hasFirst {
			minimum = first
		}
		maximum = 0
		if hasSecond {
			maximum = second
		}
		return minimum, maximum, true
	}
	if hasFirst {
		// A bare number is an exact count.
		return first, first, true
	}
	l.pos = start
	return 0, 0, false
}

func readNumber(l *abnfLexer) (int, bool) {
	start := l.pos
	for l.pos < len(l.src) && l.src[l.pos] >= '0' && l.src[l.pos] <= '9' {
		l.pos++
	}
	if l.pos == start {
		return 0, false
	}
	n, err := strconv.Atoi(l.src[start:l.pos])
	if err != nil {
		return 0, false
	}
	return n, true
}

func parseElement(l *abnfLexer) (abnfElem, error) {
	switch c := l.peek(); {
	case c == 0:
		return abnfElem{}, fmt.Errorf("expected an element")
	case c == '(':
		l.pos++
		alts, err := parseAlternation(l)
		if err != nil {
			return abnfElem{}, err
		}
		if l.peek() != ')' {
			return abnfElem{}, fmt.Errorf("unclosed (")
		}
		l.pos++
		return groupOf(alts), nil
	case c == '[':
		l.pos++
		alts, err := parseAlternation(l)
		if err != nil {
			return abnfElem{}, err
		}
		if l.peek() != ']' {
			return abnfElem{}, fmt.Errorf("unclosed [")
		}
		l.pos++
		inner := groupOf(alts)
		return abnfElem{kind: abnfRepeat, inner: &inner, min: 0, max: 1}, nil
	case c == '"':
		return parseCharVal(l)
	case c == '%':
		return parseNumVal(l)
	case c == '<':
		j := strings.IndexByte(l.src[l.pos:], '>')
		if j < 0 {
			return abnfElem{}, fmt.Errorf("unclosed <")
		}
		text := l.src[l.pos+1 : l.pos+j]
		l.pos += j + 1
		return abnfElem{kind: abnfProse, lit: text}, nil
	}

	start := l.pos
	for l.pos < len(l.src) {
		c := l.src[l.pos]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' {
			l.pos++
			continue
		}
		break
	}
	if l.pos == start {
		return abnfElem{}, fmt.Errorf("unexpected %q", l.src[l.pos])
	}
	return abnfElem{kind: abnfRule_, rule: l.src[start:l.pos]}, nil
}

func groupOf(alts []abnfElem) abnfElem {
	if len(alts) == 1 {
		return alts[0]
	}
	return abnfElem{kind: abnfAlt, seq: alts}
}

func parseCharVal(l *abnfLexer) (abnfElem, error) {
	// The caller is not always looking at a quote: %s and %i are RFC 7405's
	// case markers and a truncated one leaves the lexer wherever it stopped.
	if l.peek() != '"' {
		return abnfElem{}, fmt.Errorf("expected a quoted string")
	}
	l.pos++ // the opening quote
	j := strings.IndexByte(l.src[l.pos:], '"')
	if j < 0 {
		return abnfElem{}, fmt.Errorf("unterminated string")
	}
	lit := l.src[l.pos : l.pos+j]
	l.pos += j + 1
	// RFC 5234 char-vals are case-insensitive. The literal is used as a
	// starting value, and a case-insensitive one is still a legal instance of
	// itself, so the case is kept and the insensitivity noted where it matters.
	return abnfElem{kind: abnfLiteral, lit: lit}, nil
}

// parseNumVal reads %x41, %x41-5A, %x0D.0A and their decimal and binary forms.
func parseNumVal(l *abnfLexer) (abnfElem, error) {
	l.pos++ // %
	if l.pos >= len(l.src) {
		return abnfElem{}, fmt.Errorf("truncated %%")
	}
	base := 16
	switch l.src[l.pos] {
	case 'x', 'X':
		base = 16
	case 'd', 'D':
		base = 10
	case 'b', 'B':
		base = 2
	case 's', 'S', 'i', 'I':
		// %s"..." and %i"..." are RFC 7405's explicit case markers.
		sensitive := l.src[l.pos] == 's' || l.src[l.pos] == 'S'
		l.pos++
		e, err := parseCharVal(l)
		if err != nil {
			return abnfElem{}, err
		}
		e.sensitive = sensitive
		return e, nil
	default:
		return abnfElem{}, fmt.Errorf("unknown %%%c", l.src[l.pos])
	}
	l.pos++

	first, ok := readInBase(l, base)
	if !ok {
		return abnfElem{}, fmt.Errorf("expected a number after %%")
	}
	if l.pos < len(l.src) && l.src[l.pos] == '-' {
		l.pos++
		hi, ok := readInBase(l, base)
		if !ok {
			return abnfElem{}, fmt.Errorf("expected the end of a range")
		}
		return abnfElem{kind: abnfRange, lo: first, hi: hi}, nil
	}
	// A dotted sequence is a concatenation of single values: %x0D.0A is CRLF.
	lit := []byte{byte(first)}
	for l.pos < len(l.src) && l.src[l.pos] == '.' {
		l.pos++
		v, ok := readInBase(l, base)
		if !ok {
			return abnfElem{}, fmt.Errorf("expected a number after .")
		}
		lit = append(lit, byte(v))
	}
	return abnfElem{kind: abnfLiteral, lit: string(lit), sensitive: true}, nil
}

func readInBase(l *abnfLexer, base int) (int, bool) {
	start := l.pos
	for l.pos < len(l.src) && isBaseDigit(l.src[l.pos], base) {
		l.pos++
	}
	if l.pos == start {
		return 0, false
	}
	v, err := strconv.ParseInt(l.src[start:l.pos], base, 32)
	if err != nil {
		return 0, false
	}
	return int(v), true
}

func isBaseDigit(c byte, base int) bool {
	switch base {
	case 2:
		return c == '0' || c == '1'
	case 10:
		return c >= '0' && c <= '9'
	default:
		return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
	}
}
