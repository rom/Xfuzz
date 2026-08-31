package capture

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"
)

// Turning a capture back into the bytes that went on the wire.
//
// This is what a campaign's seed file is: the requests, in order, exactly as a
// client sent them. Not a rendering of them — the HTTP codec parses this back
// into a tree and re-encodes it byte for byte, so anything invented here is
// something the campaign will fuzz and the server never saw.

// Session returns the capture's requests as HTTP/1.1 wire bytes.
//
// Content-Length is recomputed from the body rather than copied. A HAR records
// the decoded body and the header the browser sent, and those disagree whenever
// the body was compressed; a pcap records both faithfully and a truncated
// capture makes them disagree too. Sending the recorded length with a different
// body produces a request that hangs or is rejected at the framing layer, which
// is a bug in the seed rather than a finding.
func (c *Capture) Session() []byte {
	var b bytes.Buffer
	for i := range c.Exchanges {
		writeRequest(&b, &c.Exchanges[i].Request)
	}
	return b.Bytes()
}

// SessionOf returns one request's wire bytes.
func SessionOf(r *Request) []byte {
	var b bytes.Buffer
	writeRequest(&b, r)
	return b.Bytes()
}

func writeRequest(b *bytes.Buffer, r *Request) {
	method := r.Method
	if method == "" {
		method = "GET"
	}
	proto := r.Proto
	// HTTP/2 and HTTP/3 have no textual framing. A capture of one is replayed
	// over HTTP/1.1, which is what the wire form here can express and what every
	// server that speaks the later versions also accepts.
	if proto == "" || !strings.HasPrefix(proto, "HTTP/1") {
		proto = "HTTP/1.1"
	}

	fmt.Fprintf(b, "%s %s %s\r\n", method, requestTarget(r), proto)

	wroteHost, wroteLength := false, false
	for _, h := range r.Headers {
		switch {
		case strings.EqualFold(h.Name, "Content-Length"):
			continue // recomputed below
		case strings.EqualFold(h.Name, "Transfer-Encoding"):
			// The body here is already decoded, so re-declaring the encoding
			// would describe a framing that is not present.
			continue
		case strings.EqualFold(h.Name, "Host"):
			wroteHost = true
		}
		fmt.Fprintf(b, "%s: %s\r\n", h.Name, h.Value)
	}
	if !wroteHost {
		if host := r.Host(); host != "" {
			fmt.Fprintf(b, "Host: %s\r\n", host)
		}
	}
	if len(r.Body) > 0 || methodExpectsBody(method) {
		fmt.Fprintf(b, "Content-Length: %d\r\n", len(r.Body))
		wroteLength = true
	}
	_ = wroteLength

	b.WriteString("\r\n")
	b.Write(r.Body)
}

// requestTarget is the path and query a request line carries.
//
// The origin form, not the absolute URL: the authority belongs in the Host
// header, and a server given an absolute URL in the request line of an ordinary
// request is being spoken to as though it were a proxy.
func requestTarget(r *Request) string {
	path := r.Path()
	if u := r.Query(); len(u) > 0 {
		if i := strings.IndexByte(r.URL, '?'); i >= 0 {
			return path + r.URL[i:]
		}
	}
	return path
}

// methodExpectsBody reports whether a method is normally sent with one, so that
// a POST with an empty body still declares a length of zero — which is what
// distinguishes "no body" from "a body that has not arrived yet" to a server
// waiting on the connection.
func methodExpectsBody(method string) bool {
	switch strings.ToUpper(method) {
	case "POST", "PUT", "PATCH":
		return true
	}
	return false
}

// Content-Length after the fact.
//
// Two different things change a body's length after a session's bytes were
// written: a mutation, which is the whole point of the campaign, and secret
// substitution, where a placeholder and the value it stands for are rarely the
// same size. Either leaves a request whose declared length disagrees with its
// body, and a server given one of those either hangs waiting for bytes that will
// not come or reads the next request as this one's payload.
//
// Repairing that on a flat stream of concatenated requests is not possible, and
// the attempt is instructive: finding where one request ends *requires* its
// declared length, so a stream whose lengths are already wrong cannot be split,
// and the repair reads part of the next request as this one's body. It has to
// split first and change second — which is what applySession does, and why
// there is no function here that takes a stream whose lengths have already been
// invalidated.

// splitRequest finds one request's header block and body.
func splitRequest(src []byte) (head, body []byte, consumed int, ok bool) {
	end := bytes.Index(src, []byte("\r\n\r\n"))
	sepLen := 4
	if end < 0 {
		end = bytes.Index(src, []byte("\n\n"))
		sepLen = 2
	}
	if end < 0 {
		return nil, nil, 0, false
	}
	head = src[:end+sepLen]

	n := declaredLength(head)
	if n < 0 {
		return head, nil, end + sepLen, true
	}
	start := end + sepLen
	stop := start + n
	if stop > len(src) {
		stop = len(src)
	}
	return head, src[start:stop], stop, true
}

// declaredLength reads the Content-Length a header block declares, or -1.
func declaredLength(head []byte) int {
	for _, line := range bytes.Split(head, []byte("\n")) {
		name, value, found := bytes.Cut(line, []byte(":"))
		if !found {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(string(name)), "content-length") {
			continue
		}
		n, err := strconv.Atoi(strings.TrimSpace(string(value)))
		if err != nil || n < 0 {
			return -1
		}
		return n
	}
	return -1
}

// rewriteLength replaces the Content-Length value in a header block.
func rewriteLength(head []byte, n int) []byte {
	lines := bytes.Split(head, []byte("\n"))
	for i, line := range lines {
		name, _, found := bytes.Cut(line, []byte(":"))
		if !found || !strings.EqualFold(strings.TrimSpace(string(name)), "content-length") {
			continue
		}
		eol := ""
		if bytes.HasSuffix(line, []byte("\r")) {
			eol = "\r"
		}
		lines[i] = []byte(string(name) + ": " + strconv.Itoa(n) + eol)
	}
	return bytes.Join(lines, []byte("\n"))
}

// ReadSession reads a flat file of HTTP requests back into a capture.
//
// The inverse of Session, and the format a person produces by pasting requests
// into a file. There are no responses in it, which is not a gap: the API tier
// sends the requests and reads the responses live, and what a recording adds
// over this is the responses that dependency inference needs. A session file is
// the honest shape for "these are the requests, work the rest out".
func ReadSession(src []byte) (*Capture, error) {
	c := &Capture{}
	for len(src) > 0 {
		head, body, consumed, ok := splitRequest(src)
		if !ok {
			if len(c.Exchanges) == 0 {
				return nil, fmt.Errorf("no complete request in %d bytes", len(src))
			}
			// A trailing fragment is what a truncated capture ends with, and
			// the requests before it are still worth having.
			c.Notes = append(c.Notes,
				fmt.Sprintf("%d trailing bytes were not a complete request", len(src)))
			break
		}
		req, err := parseRequestHead(head)
		if err != nil {
			return nil, err
		}
		req.Body = append([]byte(nil), body...)
		c.Exchanges = append(c.Exchanges, Exchange{Request: *req})
		src = src[consumed:]
	}
	if len(c.Exchanges) == 0 {
		return nil, fmt.Errorf("no requests")
	}
	return c, nil
}

// parseRequestHead reads a request line and its headers.
func parseRequestHead(head []byte) (*Request, error) {
	lines := strings.Split(strings.ReplaceAll(string(head), "\r\n", "\n"), "\n")
	if len(lines) == 0 || lines[0] == "" {
		return nil, fmt.Errorf("empty request")
	}
	parts := strings.Fields(lines[0])
	if len(parts) < 2 {
		return nil, fmt.Errorf("%q is not a request line", lines[0])
	}
	r := &Request{Method: parts[0]}
	target := parts[1]

	for _, line := range lines[1:] {
		if strings.TrimSpace(line) == "" {
			continue
		}
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		r.Headers = append(r.Headers, Header{
			Name: strings.TrimSpace(name), Value: strings.TrimSpace(value),
		})
	}

	// A URL, because everything downstream — the host, the path segments, the
	// query parameters that dependency inference reads — is addressed through
	// one. The scheme is a guess and it does not matter: nothing dials it, and
	// the campaign's own address is where the request actually goes.
	scheme := "http"
	if strings.EqualFold(r.Get("X-Forwarded-Proto"), "https") {
		scheme = "https"
	}
	host := r.Get("Host")
	if host == "" {
		host = "localhost"
	}
	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		r.URL = target
	} else {
		r.URL = scheme + "://" + host + target
	}
	return r, nil
}
