package codec

import (
	"bytes"
	"strconv"
	"strings"

	"github.com/rom/Xfuzz/pkg/ir"
)

func init() { Register(HTTP{}) }

// HTTP lifts a sequence of HTTP/1.1 requests into the IR.
//
// A captured API session is a conversation, and its seed file is the requests
// exactly as they went on the wire, one after another. This is what turns that
// file into a tree: a Repeat of requests, each a struct of method, target,
// version, headers and body — so mutation can change a path segment, a header
// value, or one field of a JSON body, rather than a byte in the middle of the
// word "Authorization".
//
// Every separator is a node. That looks verbose beside a parser that splits on
// spaces and colons and rebuilds them on the way out, and it is what makes the
// codec's contract hold: re-encoding reproduces the input byte for byte,
// including the request that used a bare newline, the header written without a
// space after its colon, and the trailing whitespace nobody meant to leave. A
// codec that normalised those would quietly rewrite the operator's capture, and
// the campaign would be fuzzing something the server never sent.
//
// Malformed input is preserved rather than rejected, as ASR-0014 requires: a
// line this cannot read becomes an opaque node and the parse continues. Real
// captures are full of truncated and subtly wrong requests, and those are
// frequently the most valuable seeds.
type HTTP struct{}

// Name implements Codec.
func (HTTP) Name() string { return "http" }

// Extensions implements Codec.
func (HTTP) Extensions() []string { return []string{"http", "req"} }

// Node names the tree uses. They are the handles a campaign file and a mutator
// weight refer to, so they are named constants rather than literals.
const (
	HTTPRequest = "request"
	HTTPMethod  = "method"
	HTTPTarget  = "target"
	HTTPVersion = "version"
	HTTPHeaders = "headers"
	HTTPHeader  = "header"
	HTTPName    = "name"
	HTTPValue   = "value"
	HTTPBody    = "body"

	// Separator nodes. Named with a leading @ like the opaque node, so that a
	// mutator restricted to named fields does not spend its budget rewriting
	// the colons.
	httpSep = "@sep"
	httpEOL = "@eol"
)

// maxHTTPRequests bounds how many requests one seed may hold. A capture is a
// file from somewhere else, and a session of ten thousand requests is not a seed
// a campaign can usefully mutate.
const maxHTTPRequests = 1024

// Decode implements Codec.
func (h HTTP) Decode(a *ir.Arena, src []byte) (*ir.Node, error) {
	root := a.Alloc(ir.KindRepeat, "session")
	rest := src
	for len(rest) > 0 && len(root.Children) < maxHTTPRequests {
		req, consumed := h.request(a, rest)
		if consumed <= 0 {
			// Nothing recognisable is left. Kept whole rather than dropped: a
			// truncated final request is what a cut-short capture looks like,
			// and re-encoding has to reproduce it.
			n := a.Alloc(ir.KindBytes, OpaqueName)
			n.Raw = rest
			root.Children = append(root.Children, n)
			break
		}
		root.Children = append(root.Children, req)
		rest = rest[consumed:]
	}
	if len(rest) > 0 && len(root.Children) >= maxHTTPRequests {
		n := a.Alloc(ir.KindBytes, OpaqueName)
		n.Raw = rest
		root.Children = append(root.Children, n)
	}
	return root, nil
}

// request parses one request and returns how many bytes it consumed.
func (h HTTP) request(a *ir.Arena, src []byte) (*ir.Node, int) {
	line, lineEnd, ok := readLine(src)
	if !ok || len(line) == 0 {
		return nil, 0
	}
	req := a.Alloc(ir.KindStruct, HTTPRequest)

	// The request line: method, target, version, separated by single spaces. A
	// line that is not that shape is kept opaque, because guessing at it would
	// produce a tree that re-encodes to something else.
	sp1 := bytes.IndexByte(line, ' ')
	sp2 := bytes.LastIndexByte(line, ' ')
	if sp1 <= 0 || sp2 <= sp1 || sp2 == len(line)-1 {
		return nil, 0
	}
	req.Children = append(req.Children,
		str(a, HTTPMethod, line[:sp1]),
		raw(a, httpSep, line[sp1:sp1+1]),
		str(a, HTTPTarget, line[sp1+1:sp2]),
		raw(a, httpSep, line[sp2:sp2+1]),
		str(a, HTTPVersion, line[sp2+1:]),
		raw(a, httpEOL, src[len(line):lineEnd]),
	)

	// Headers, to the blank line.
	headers := a.Alloc(ir.KindRepeat, HTTPHeaders)
	pos := lineEnd
	contentLength := -1
	chunked := false
	for pos < len(src) {
		hline, hend, hok := readLine(src[pos:])
		if !hok {
			break
		}
		if len(hline) == 0 {
			// The blank line that ends the header block.
			req.Children = append(req.Children, headers, raw(a, httpEOL, src[pos:pos+hend]))
			pos += hend
			goto body
		}
		colon := bytes.IndexByte(hline, ':')
		if colon <= 0 {
			// A continuation line, or something malformed. Preserved whole.
			hdr := a.Alloc(ir.KindStruct, HTTPHeader)
			hdr.Children = append(hdr.Children,
				raw(a, OpaqueName, hline),
				raw(a, httpEOL, src[pos+len(hline):pos+hend]))
			headers.Children = append(headers.Children, hdr)
			pos += hend
			continue
		}

		name := hline[:colon]
		// The separator is the colon plus whatever whitespace followed it, kept
		// exactly: some clients write no space, some write two.
		vstart := colon + 1
		for vstart < len(hline) && (hline[vstart] == ' ' || hline[vstart] == '\t') {
			vstart++
		}
		value := hline[vstart:]

		switch {
		case matchHeader(name, "content-length"):
			if n, err := strconv.Atoi(strings.TrimSpace(string(value))); err == nil && n >= 0 {
				contentLength = n
			}
		case matchHeader(name, "transfer-encoding"):
			if bytes.Contains(bytes.ToLower(value), []byte("chunked")) {
				chunked = true
			}
		}

		hdr := a.Alloc(ir.KindStruct, HTTPHeader)
		hdr.Children = append(hdr.Children,
			str(a, HTTPName, name),
			raw(a, httpSep, hline[colon:vstart]),
			str(a, HTTPValue, value),
			raw(a, httpEOL, src[pos+len(hline):pos+hend]),
		)
		headers.Children = append(headers.Children, hdr)
		pos += hend
	}
	// The headers ran to the end of the input without a blank line: a truncated
	// capture. Everything read is kept and the request ends here.
	req.Children = append(req.Children, headers)
	return req, pos

body:
	switch {
	case contentLength > 0:
		end := pos + contentLength
		if end > len(src) {
			end = len(src)
		}
		req.Children = append(req.Children, raw(a, HTTPBody, src[pos:end]))
		return req, end
	case chunked:
		n := chunkedLen(src[pos:])
		req.Children = append(req.Children, raw(a, HTTPBody, src[pos:pos+n]))
		return req, pos + n
	default:
		return req, pos
	}
}

// readLine returns the line's content without its terminator, and how many bytes
// the line and terminator occupy together.
//
// Both CRLF and a bare LF, because a real capture contains both and a codec that
// only understood one would re-encode the other into something the server never
// received.
func readLine(src []byte) (line []byte, end int, ok bool) {
	i := bytes.IndexByte(src, '\n')
	if i < 0 {
		return nil, 0, false
	}
	end = i + 1
	line = src[:i]
	if i > 0 && src[i-1] == '\r' {
		line = src[:i-1]
	}
	return line, end, true
}

// chunkedLen measures a chunked body, terminator included.
//
// The body is preserved as bytes rather than lifted into per-chunk nodes.
// Chunking is a transfer detail rather than a property of the message, and
// mutating chunk lengths independently of chunk contents produces requests every
// server rejects at the framing layer — which is a fuzzing target in its own
// right, and not the one an API campaign is aimed at.
func chunkedLen(src []byte) int {
	pos := 0
	for pos < len(src) {
		line, end, ok := readLine(src[pos:])
		if !ok {
			return len(src)
		}
		sizeStr, _, _ := bytes.Cut(line, []byte(";"))
		size, err := strconv.ParseInt(string(bytes.TrimSpace(sizeStr)), 16, 32)
		if err != nil || size < 0 {
			return len(src)
		}
		pos += end
		if size == 0 {
			// The trailer, up to the blank line.
			for pos < len(src) {
				tl, tend, tok := readLine(src[pos:])
				if !tok {
					return len(src)
				}
				pos += tend
				if len(tl) == 0 {
					return pos
				}
			}
			return pos
		}
		pos += int(size)
		if pos > len(src) {
			return len(src)
		}
		// The CRLF after the chunk data.
		if _, end, ok := readLine(src[pos:]); ok {
			pos += end
		}
	}
	return pos
}

func matchHeader(name []byte, want string) bool {
	return strings.EqualFold(strings.TrimSpace(string(name)), want)
}

func str(a *ir.Arena, name string, b []byte) *ir.Node {
	n := a.Alloc(ir.KindStr, name)
	n.Raw = b
	return n
}

func raw(a *ir.Arena, name string, b []byte) *ir.Node {
	n := a.Alloc(ir.KindBytes, name)
	n.Raw = b
	return n
}
