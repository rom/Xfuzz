package schemaio

import (
	"fmt"
	"strings"

	"github.com/rom/Xfuzz/pkg/schema"
)

// coreRules is RFC 5234 appendix B.1, in its own notation.
//
// Written as source and parsed by the same parser rather than built by hand: a
// hand-built ALPHA is a second implementation of the same thing, and the two
// drift. Every RFC grammar uses these and almost none of them restate them, so
// an importer without them resolves half its references to nothing.
const coreRules = `
ALPHA  = %x41-5A / %x61-7A
BIT    = "0" / "1"
CHAR   = %x01-7F
CR     = %x0D
CRLF   = CR LF
CTL    = %x00-1F / %x7F
DIGIT  = %x30-39
DQUOTE = %x22
HEXDIG = DIGIT / "A" / "B" / "C" / "D" / "E" / "F"
HTAB   = %x09
LF     = %x0A
LWSP   = *(WSP / CRLF WSP)
OCTET  = %x00-FF
SP     = %x20
VCHAR  = %x21-7E
WSP    = SP / HTAB
`

// loadCore adds the core rules a grammar refers to but does not define.
//
// After the user's rules and only for names still missing, so that a grammar
// redefining DIGIT — which some do, to exclude zero — gets its own and not this
// one. Repeated to a fixpoint because the core rules refer to each other.
func (p *abnfParser) loadCore() {
	core := &abnfParser{b: newBuilder("abnf", ""), lines: unfold(coreRules)}
	if err := core.parse(); err != nil {
		return
	}
	for {
		missing := p.undefined()
		added := false
		for _, name := range missing {
			r, ok := core.rules[name]
			if !ok {
				continue
			}
			p.rules[name] = r
			added = true
		}
		if !added {
			return
		}
	}
}

// undefined lists the rule names referenced but not defined, sorted.
func (p *abnfParser) undefined() []string {
	missing := map[string]bool{}
	var walk func(e abnfElem)
	walk = func(e abnfElem) {
		switch e.kind {
		case abnfRule_:
			if _, ok := p.rules[strings.ToLower(e.rule)]; !ok {
				missing[strings.ToLower(e.rule)] = true
			}
		case abnfSeq, abnfAlt:
			for _, k := range e.seq {
				walk(k)
			}
		case abnfRepeat:
			if e.inner != nil {
				walk(*e.inner)
			}
		}
	}
	for _, r := range p.rules {
		for _, a := range r.alts {
			walk(a)
		}
	}
	return sortedKeys(missing)
}

func (p *abnfParser) emit() (*schema.Schema, *Report, error) {
	p.loadCore()

	// Every rule gets its identifier before any body is built, so that a
	// reference to a rule defined later in the file resolves to the same name
	// the definition will use.
	names := make([]string, 0, len(p.rules))
	for _, key := range p.order {
		names = append(names, key)
	}
	for _, key := range sortedKeys(p.rules) {
		if _, ok := p.rules[key]; ok && !contains(names, key) {
			names = append(names, key)
		}
	}
	for _, key := range names {
		p.b.nameFor(p.rules[key].name)
	}

	for _, key := range names {
		r := p.rules[key]
		t := p.typeForAlts(r.alts, r.name)
		p.b.s.Types[p.b.nameFor(r.name)] = wrap(t)
	}
	return p.b.finish(p.b.nameFor(p.rules[p.order[0]].name))
}

// flattenAlts splices an alternation nested directly inside another.
//
// "a / (b / c)" is three alternatives, not two, and the difference shows up in
// the scheduler: a choice with two children picks the group half the time and
// then b or c a quarter each, which is not what the grammar says.
func flattenAlts(alts []abnfElem) []abnfElem {
	flat := false
	for _, a := range alts {
		if a.kind == abnfAlt {
			flat = true
			break
		}
	}
	if !flat {
		return alts
	}
	out := make([]abnfElem, 0, len(alts))
	for _, a := range alts {
		if a.kind == abnfAlt {
			out = append(out, flattenAlts(a.seq)...)
			continue
		}
		out = append(out, a)
	}
	return out
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

// typeForAlts builds the type for a rule's alternatives.
func (p *abnfParser) typeForAlts(alts []abnfElem, hint string) *schema.Type {
	alts = flattenAlts(alts)
	if len(alts) == 1 {
		return p.typeFor(alts[0], hint)
	}
	fields := make([]schema.Field, 0, len(alts))
	for i, a := range alts {
		fields = append(fields, field(fmt.Sprintf("alt%d", i+1), p.typeFor(a, fmt.Sprintf("%s_alt%d", hint, i+1))))
	}
	return choiceOf(uniqueFields(fields)...)
}

// typeFor builds the type for one element, declaring helper types where the
// schema language needs a name for something the notation left anonymous.
func (p *abnfParser) typeFor(e abnfElem, hint string) *schema.Type {
	switch e.kind {
	case abnfLiteral:
		return magic(e.lit)

	case abnfRange:
		return p.rangeType(e, hint)

	case abnfRule_:
		key := strings.ToLower(e.rule)
		if _, ok := p.rules[key]; !ok {
			p.b.rep.Add(hint, "undefined rule "+e.rule,
				"referenced but never defined and not a core rule; generated as free bytes")
			return bytesOf(0, 16)
		}
		return refTo(p.b.nameFor(p.rules[key].name))

	case abnfSeq:
		fields := make([]schema.Field, 0, len(e.seq))
		for i, k := range e.seq {
			fields = append(fields, field(elemName(k, i), p.typeFor(k, fmt.Sprintf("%s_%d", hint, i+1))))
		}
		return structOf(uniqueFields(fields)...)

	case abnfAlt:
		return p.typeForAlts(e.seq, hint)

	case abnfRepeat:
		elem := p.declareElem(*e.inner, hint+"_elem")
		if e.min == 0 && e.max == 1 {
			return optOf(elem)
		}
		maximum := e.max
		if maximum == 0 && e.min > 0 {
			// The grammar language needs both bounds where either is written.
			maximum = UnboundedRepeatMax
			p.b.rep.Add(hint, "unbounded repetition",
				fmt.Sprintf("a lower bound with no upper bound is capped at %d elements; "+
					"the grammar language requires both", UnboundedRepeatMax))
		}
		return repeatOf(elem, e.min, maximum)

	case abnfProse:
		p.b.rep.Add(hint, "prose-val",
			"<"+trimTo(e.lit, 60)+"> is a sentence in English; nothing can generate it")
		return bytesOf(0, 16)
	}
	return bytesOf(0, 8)
}

// declareElem gives an anonymous element a name, because repeat and opt refer to
// their element by one.
func (p *abnfParser) declareElem(e abnfElem, hint string) string {
	if e.kind == abnfRule_ {
		if r, ok := p.rules[strings.ToLower(e.rule)]; ok {
			return p.b.nameFor(r.name)
		}
	}
	name := p.b.nameFor(hint)
	p.b.s.Types[name] = wrap(p.typeFor(e, hint))
	return name
}

// rangeType turns a value range into the only thing the schema language can say
// exactly: a choice over the bytes in it.
//
// Up to a limit, because %x00-FF as two hundred and fifty-six alternatives is a
// choice no scheduler benefits from and no reader can follow. Past it the field
// becomes one free byte and the report says which constraint was dropped, so a
// person can decide whether it mattered.
func (p *abnfParser) rangeType(e abnfElem, hint string) *schema.Type {
	lo, hi := e.lo, e.hi
	if lo > hi {
		lo, hi = hi, lo
	}
	n := hi - lo + 1
	if n <= 0 {
		return bytesOf(1, 1)
	}
	if n > maxRangeAlternatives {
		p.b.rep.Add(hint, fmt.Sprintf("value range %%x%02X-%02X", lo, hi),
			fmt.Sprintf("%d alternatives is past the %d the importer will enumerate; "+
				"generated as one unconstrained byte", n, maxRangeAlternatives))
		return bytesOf(1, 1)
	}
	fields := make([]schema.Field, 0, n)
	for c := lo; c <= hi; c++ {
		fields = append(fields, field(fmt.Sprintf("v%02x", c), magic(string([]byte{byte(c)}))))
	}
	return choiceOf(fields...)
}

// elemName gives a struct field a name a person can read.
func elemName(e abnfElem, i int) string {
	switch e.kind {
	case abnfRule_:
		return ident(e.rule)
	case abnfLiteral:
		if n := ident(e.lit); n != "x" && len(n) <= 16 {
			return n
		}
	}
	return fmt.Sprintf("f%d", i+1)
}

func trimTo(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
