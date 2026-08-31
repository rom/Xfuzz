package capture

import (
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"
)

// Header is one header field. A slice rather than a map, because order and
// duplication are part of what was captured: a request with two Cookie headers
// is not the same request as one with them merged, and a fuzzer that silently
// normalises loses the ability to reproduce what it saw.
type Header struct {
	Name  string
	Value string
}

// Request is one captured HTTP request.
type Request struct {
	Method  string
	URL     string
	Proto   string
	Headers []Header
	Body    []byte
}

// Response is what the server said.
type Response struct {
	Status  int
	Proto   string
	Headers []Header
	Body    []byte

	// Elapsed is how long the request took, when the capture recorded it. It is
	// what a latency oracle compares against, and zero when unknown — which is
	// different from fast, and is why it is not defaulted.
	Elapsed time.Duration
}

// Exchange is a request and the response it received.
type Exchange struct {
	Request  Request
	Response Response

	// At is when the request was sent, which is what orders a capture. Captures
	// from a proxy and from a packet trace both record it; a HAR file may not,
	// and then the file's own order stands.
	At time.Time

	// Source names where this exchange came from, for reporting: the HAR file,
	// the pcap, the proxy.
	Source string
}

// Capture is an ordered sequence of exchanges.
//
// Ordered, and kept that way, because a capture is a *session* rather than a bag
// of requests. The login that produced the token, the create that produced the
// identifier, and the use that needed both are only meaningful in sequence, and
// that sequence is the thing a specification cannot supply (ADR-0014).
type Capture struct {
	Exchanges []Exchange

	// Notes are things the reader could not represent, kept rather than
	// discarded. A capture that silently dropped every request it did not
	// understand would look like a small capture rather than an incomplete one.
	Notes []string
}

// Len returns how many exchanges the capture holds.
func (c *Capture) Len() int { return len(c.Exchanges) }

// Sort orders the capture by time, leaving exchanges with no timestamp in the
// order they were read.
//
// Stable, and only among the timestamped ones: a HAR file need not record
// times, and reordering untimed entries by a zero timestamp would put them all
// at the front and destroy the file's own ordering, which is the only ordering
// information such a file has.
func (c *Capture) Sort() {
	if !c.timestamped() {
		return
	}
	sort.SliceStable(c.Exchanges, func(i, j int) bool {
		a, b := c.Exchanges[i].At, c.Exchanges[j].At
		if a.IsZero() || b.IsZero() {
			return false
		}
		return a.Before(b)
	})
}

func (c *Capture) timestamped() bool {
	for _, e := range c.Exchanges {
		if e.At.IsZero() {
			return false
		}
	}
	return len(c.Exchanges) > 0
}

// Hosts returns the distinct hosts the capture reached, sorted.
//
// It is what a campaign's scope is checked against: a capture recorded against
// one API routinely contains requests to a content delivery network, an
// analytics endpoint and an identity provider, and fuzzing those is both useless
// and, under ADR-0012, something an operator has to have authorised on purpose.
func (c *Capture) Hosts() []string {
	seen := map[string]bool{}
	for _, e := range c.Exchanges {
		if h := e.Request.Host(); h != "" {
			seen[h] = true
		}
	}
	out := make([]string, 0, len(seen))
	for h := range seen {
		out = append(out, h)
	}
	sort.Strings(out)
	return out
}

// Filter returns the exchanges whose host matches one of the given hosts.
func (c *Capture) Filter(hosts ...string) *Capture {
	if len(hosts) == 0 {
		return c
	}
	want := map[string]bool{}
	for _, h := range hosts {
		want[strings.ToLower(h)] = true
	}
	out := &Capture{Notes: c.Notes}
	for _, e := range c.Exchanges {
		if want[strings.ToLower(e.Request.Host())] {
			out.Exchanges = append(out.Exchanges, e)
		}
	}
	return out
}

// Host returns the request's host, from the URL or the Host header.
func (r *Request) Host() string {
	if u, err := url.Parse(r.URL); err == nil && u.Host != "" {
		return u.Hostname()
	}
	if h := r.Get("Host"); h != "" {
		host, _, _ := strings.Cut(h, ":")
		return host
	}
	return ""
}

// Get returns the first value of a header, case-insensitively.
func (r *Request) Get(name string) string {
	for _, h := range r.Headers {
		if strings.EqualFold(h.Name, name) {
			return h.Value
		}
	}
	return ""
}

// Get returns the first value of a response header, case-insensitively.
func (r *Response) Get(name string) string {
	for _, h := range r.Headers {
		if strings.EqualFold(h.Name, name) {
			return h.Value
		}
	}
	return ""
}

// Set replaces a header's value, or adds it.
func (r *Request) Set(name, value string) {
	for i := range r.Headers {
		if strings.EqualFold(r.Headers[i].Name, name) {
			r.Headers[i].Value = value
			return
		}
	}
	r.Headers = append(r.Headers, Header{Name: name, Value: value})
}

// ContentType returns the media type of a request body, without parameters.
func (r *Request) ContentType() string { return mediaType(r.Get("Content-Type")) }

// ContentType returns the media type of a response body, without parameters.
func (r *Response) ContentType() string { return mediaType(r.Get("Content-Type")) }

func mediaType(v string) string {
	t, _, _ := strings.Cut(v, ";")
	return strings.ToLower(strings.TrimSpace(t))
}

// Path returns the request's path, or "/" when it has none.
func (r *Request) Path() string {
	if u, err := url.Parse(r.URL); err == nil {
		if u.Path == "" {
			return "/"
		}
		return u.Path
	}
	return "/"
}

// Query returns the request's query parameters in the order they appear.
//
// In order, and without collapsing duplicates, for the same reason headers are a
// slice: `?a=1&a=2` is a request some servers read differently from `?a=2&a=1`,
// and normalising it away removes a distinction the target may care about.
func (r *Request) Query() []Header {
	u, err := url.Parse(r.URL)
	if err != nil || u.RawQuery == "" {
		return nil
	}
	var out []Header
	for _, pair := range strings.Split(u.RawQuery, "&") {
		if pair == "" {
			continue
		}
		k, v, _ := strings.Cut(pair, "=")
		key, kerr := url.QueryUnescape(k)
		if kerr != nil {
			key = k
		}
		val, verr := url.QueryUnescape(v)
		if verr != nil {
			val = v
		}
		out = append(out, Header{Name: key, Value: val})
	}
	return out
}

func (e Exchange) String() string {
	return fmt.Sprintf("%s %s -> %d (%d bytes)",
		e.Request.Method, e.Request.URL, e.Response.Status, len(e.Response.Body))
}
