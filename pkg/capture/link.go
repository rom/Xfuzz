package capture

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Data dependencies: what separates useful API fuzzing from a 400 generator.
//
// A captured session is login, create, use, delete. Replay it unchanged and it
// works, because the identifiers in it are the ones the server issued that time.
// Replay it against a server that has restarted, or mutate the create so the
// server issues a different identifier, and every request after it addresses an
// object that does not exist — and the campaign spends its whole budget
// collecting 404s from a sequence that never gets past its second step.
//
// ADR-0014's answer is to observe the dependency rather than guess it: a value
// that appears in one response and again in a later request is, with high
// probability, a value the client took from the first and put in the second. The
// inference is a correlation and therefore fallible, which is why every link
// records what it was derived from and can be overridden.
//
// The alternative is to *guess* chaining from a specification, which is what
// ADR-0014 rejected: a specification says an endpoint returns an identifier and
// says nothing about which later request needs it.

// Part names where in a request or response a value sits.
type Part uint8

// The parts a value can occupy.
const (
	PartPath Part = iota
	PartQuery
	PartHeader
	PartBody
)

var partNames = [...]string{
	PartPath: "path", PartQuery: "query", PartHeader: "header", PartBody: "body",
}

func (p Part) String() string {
	if int(p) < len(partNames) {
		return partNames[p]
	}
	return "unknown"
}

// Location names one value inside a capture.
type Location struct {
	// Exchange is the index in the capture.
	Exchange int

	// Part is which half of the message, and Name identifies the field within
	// it: a header name, a query parameter, or a JSON pointer into the body. For
	// a path, Name is the index of the segment.
	Part Part
	Name string
}

func (l Location) String() string {
	return fmt.Sprintf("#%d %s %s", l.Exchange, l.Part, l.Name)
}

// Link is an inferred data dependency: a value the server produced and the
// client sent back.
type Link struct {
	// From is where the value appeared in a response, To where it reappeared in
	// a later request.
	From, To Location

	// Value is what was seen, kept so an operator reviewing the inference can
	// see what it was based on.
	Value string
}

func (l Link) String() string {
	return fmt.Sprintf("%s -> %s (%q)", l.From, l.To, elide(l.Value, 32))
}

// Links is a capture's inferred dependencies, in the order they were found.
type Links []Link

// For returns the links whose value has to be substituted into a given request.
func (ls Links) For(exchange int) []Link {
	var out []Link
	for _, l := range ls {
		if l.To.Exchange == exchange {
			out = append(out, l)
		}
	}
	return out
}

// minLinkValue is how short a value may be and still be worth correlating.
//
// The number is doing real work. A correlation over short values finds "1" in a
// response and "1" in the next twelve requests and infers twelve dependencies
// that do not exist — and a wrong link is worse than a missing one, because the
// campaign then rewrites a field the server was perfectly happy with. Eight
// characters is past every boolean, every status word, every small integer, and
// short of every identifier format anyone uses: a UUID is thirty-six, a
// database key is usually eight or more, a token is longer still.
const minLinkValue = 8

// maxLinkValue bounds what is worth treating as an identifier rather than as
// content. A whole JSON document appearing in a later request is an echo, not a
// dependency.
const maxLinkValue = 512

// origin is where a produced value came from.
type origin struct {
	loc Location
	at  int
}

// Infer finds the values a response produced and a later request sent back.
//
// Later, strictly: a value in a request that precedes the response containing it
// is a coincidence — usually a client-generated identifier the server echoed —
// and treating it as a dependency would have the campaign rewriting a value it
// itself chose.
func Infer(c *Capture) Links {
	// Every distinctive value each response produced, and where it was.
	produced := map[string]origin{}

	// The produced values in the order they were first seen, so matching is
	// deterministic and the longest match can be preferred.
	var order []string

	var links Links
	for i := range c.Exchanges {
		// First, look for values this request repeats from an earlier response.
		for _, v := range requestValues(c, i) {
			if from, value, ok := match(produced, order, v.value, i); ok {
				links = append(links, Link{From: from, To: v.loc, Value: value})
			}
		}

		// Then record what this response produced, so a later request can match
		// it. Recorded after, so a request cannot link to its own response.
		for _, v := range responseValues(c, i) {
			// The first response to produce a value is the one credited with
			// it: a token that appears in every subsequent response came from
			// the login, and linking to the most recent occurrence would chain
			// each request to the one before it in a meaningless ladder.
			if _, seen := produced[v.value]; !seen && len(order) < maxTrackedValues {
				produced[v.value] = origin{loc: v.loc, at: i}
				order = append(order, v.value)
			}
		}
	}
	sort.SliceStable(links, func(a, b int) bool {
		if links[a].To.Exchange != links[b].To.Exchange {
			return links[a].To.Exchange < links[b].To.Exchange
		}
		return links[a].To.Name < links[b].To.Name
	})
	return links
}

// maxTrackedValues bounds how many produced values are correlated against, so a
// capture of a thousand exchanges cannot turn matching into a quadratic walk
// over every string either side ever contained.
const maxTrackedValues = 4096

// match finds the produced value a request value carries.
//
// Containment, not equality, because a value almost never arrives on its own.
// A token is sent as "Bearer <token>", a session as "sid=<value>; theme=dark", an
// identifier inside a templated path. Requiring an exact match finds the bare
// cases and misses every real one — measured on a login-create-use session, it
// found the created identifier and neither of the two places the access token
// was used.
//
// The longest match wins. A short produced value that happens to sit inside a
// longer one would otherwise claim the field, and substituting it would rewrite
// part of a value rather than the value.
func match(produced map[string]origin, order []string, requestValue string, before int) (Location, string, bool) {
	var best string
	var bestOrigin origin
	for _, v := range order {
		o := produced[v]
		if o.at >= before {
			continue
		}
		if !strings.Contains(requestValue, v) {
			continue
		}
		if len(v) > len(best) {
			best, bestOrigin = v, o
		}
	}
	if best == "" {
		return Location{}, "", false
	}
	return bestOrigin.loc, best, true
}

// valueAt is one distinctive value and where it was found.
type valueAt struct {
	value string
	loc   Location
}

// requestValues enumerates the places in a request a dependency could land.
func requestValues(c *Capture, i int) []valueAt {
	r := &c.Exchanges[i].Request
	var out []valueAt
	add := func(part Part, name, v string) {
		if distinctive(v) {
			out = append(out, valueAt{value: v, loc: Location{Exchange: i, Part: part, Name: name}})
		}
	}

	for n, seg := range strings.Split(strings.TrimPrefix(r.Path(), "/"), "/") {
		add(PartPath, strconv.Itoa(n), seg)
	}
	for _, q := range r.Query() {
		add(PartQuery, q.Name, q.Value)
	}
	for _, h := range r.Headers {
		add(PartHeader, h.Name, h.Value)
	}
	for _, jv := range jsonValues(r.Body) {
		add(PartBody, jv.pointer, jv.value)
	}
	return out
}

// responseValues enumerates the places in a response a value could come from.
func responseValues(c *Capture, i int) []valueAt {
	r := &c.Exchanges[i].Response
	var out []valueAt
	add := func(part Part, name, v string) {
		if distinctive(v) {
			out = append(out, valueAt{value: v, loc: Location{Exchange: i, Part: part, Name: name}})
		}
	}

	for _, h := range r.Headers {
		// Set-Cookie carries several values in one field, and the one that
		// matters is the cookie's own value.
		if strings.EqualFold(h.Name, "Set-Cookie") {
			name, value, _ := strings.Cut(firstField(h.Value), "=")
			add(PartHeader, "Set-Cookie:"+name, value)
			continue
		}
		add(PartHeader, h.Name, h.Value)
	}
	for _, jv := range jsonValues(r.Body) {
		add(PartBody, jv.pointer, jv.value)
	}
	return out
}

// distinctive reports whether a value is worth correlating on.
func distinctive(v string) bool {
	if len(v) < minLinkValue || len(v) > maxLinkValue {
		return false
	}
	// A value that is entirely one repeated character, or entirely spaces, is
	// padding rather than an identifier.
	if strings.TrimSpace(v) == "" {
		return false
	}
	// Common header values that appear in every message and mean nothing as a
	// dependency. Without this every request "depends" on the content type.
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "application/json", "application/json; charset=utf-8", "text/plain",
		"text/html", "no-cache", "keep-alive", "gzip, deflate", "gzip, deflate, br",
		"chunked", "identity", "*/*", "close":
		return false
	}
	return true
}

// jsonPair is a value found in a JSON document and the pointer to it.
type jsonPair struct {
	pointer string
	value   string
}

// jsonValues walks a JSON document and returns every scalar with its pointer.
//
// Pointers in RFC 6901 form, so a link an operator reads names something they
// can look up. Non-JSON bodies produce nothing: correlating over arbitrary bytes
// finds substrings rather than fields, and a substring match is exactly the kind
// of false dependency that makes an inference untrustworthy.
func jsonValues(body []byte) []jsonPair {
	if len(body) == 0 || len(body) > MaxJSONBody {
		return nil
	}
	var doc any
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil
	}
	var out []jsonPair
	var walk func(prefix string, v any)
	walk = func(prefix string, v any) {
		if len(out) >= MaxJSONValues {
			return
		}
		switch t := v.(type) {
		case map[string]any:
			keys := make([]string, 0, len(t))
			for k := range t {
				keys = append(keys, k)
			}
			// Sorted, because Go randomises map iteration and a link table that
			// differed between two reads of the same capture would make the
			// campaign it seeds irreproducible (ASR-0008).
			sort.Strings(keys)
			for _, k := range keys {
				walk(prefix+"/"+escapePointer(k), t[k])
			}
		case []any:
			for i, e := range t {
				walk(prefix+"/"+strconv.Itoa(i), e)
			}
		case string:
			out = append(out, jsonPair{pointer: prefix, value: t})
		case float64:
			out = append(out, jsonPair{pointer: prefix, value: formatNumber(t)})
		}
	}
	walk("", doc)
	return out
}

// Bounds on what one body contributes, since a capture is a file from elsewhere.
const (
	MaxJSONBody   = 4 << 20
	MaxJSONValues = 4096
)

func escapePointer(s string) string {
	s = strings.ReplaceAll(s, "~", "~0")
	return strings.ReplaceAll(s, "/", "~1")
}

// formatNumber renders a JSON number the way it most likely appeared.
//
// JSON has one number type and Go decodes it as a float, so an identifier of
// 12345678 comes back as 1.2345678e+07 unless it is rendered as an integer. A
// correlation on the exponent form would match nothing.
func formatNumber(f float64) string {
	if f == float64(int64(f)) {
		return strconv.FormatInt(int64(f), 10)
	}
	return strconv.FormatFloat(f, 'g', -1, 64)
}

func firstField(s string) string {
	f, _, _ := strings.Cut(s, ";")
	return strings.TrimSpace(f)
}

func elide(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
