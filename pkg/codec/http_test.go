package codec_test

import (
	"strings"
	"testing"

	"github.com/rom/Xfuzz/pkg/codec"
	"github.com/rom/Xfuzz/pkg/ir"
)

// The codec's contract is that re-encoding reproduces the input byte for byte,
// and for HTTP that contract is doing real work: a capture is full of requests
// that are not written the way a library would write them. A bare newline where
// the specification says CRLF, no space after a colon, two spaces, a header with
// no colon at all, a body cut off mid-way. Normalising any of those would
// rewrite the operator's capture and the campaign would be fuzzing something the
// server never sent.

// roundTrip decodes and re-encodes, and reports what came back.
func roundTrip(t *testing.T, src string) (*ir.Node, string) {
	t.Helper()
	a := ir.NewArena()
	root, err := codec.HTTP{}.Decode(a, []byte(src))
	if err != nil {
		t.Fatalf("decoding: %v", err)
	}
	return root, string(ir.AppendEncode(nil, root))
}

func TestHTTPRoundTripsWhatItWasGiven(t *testing.T) {
	cases := []struct{ name, src string }{
		{
			"a plain request",
			"GET /items/42 HTTP/1.1\r\nHost: api.example.com\r\n\r\n",
		},
		{
			"a body with a content length",
			"POST /items HTTP/1.1\r\nHost: h\r\nContent-Length: 12\r\n\r\n{\"name\":\"x\"}",
		},
		{
			"two requests in sequence",
			"GET /a HTTP/1.1\r\nHost: h\r\n\r\n" +
				"POST /b HTTP/1.1\r\nHost: h\r\nContent-Length: 3\r\n\r\nabc",
		},
		{
			"bare newlines instead of CRLF",
			"GET /a HTTP/1.1\nHost: h\n\n",
		},
		{
			"no space after the colon",
			"GET /a HTTP/1.1\r\nHost:h\r\nX-Odd:  two spaces\r\n\r\n",
		},
		{
			"a header with no colon",
			"GET /a HTTP/1.1\r\nHost: h\r\nnonsense\r\n\r\n",
		},
		{
			"a truncated request",
			"POST /a HTTP/1.1\r\nHost: h\r\nContent-Length: 100\r\n\r\nonly ten b",
		},
		{
			"headers that run off the end",
			"GET /a HTTP/1.1\r\nHost: h\r\nX-Cut",
		},
		{
			"a chunked body",
			"POST /a HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n" +
				"5\r\nhello\r\n0\r\n\r\n",
		},
		{
			"something that is not HTTP at all",
			"this is not a request\r\nand neither is this\r\n",
		},
		{
			"an empty input",
			"",
		},
		{
			"a query string with reserved characters",
			"GET /search?q=a%20b&r=1&r=2 HTTP/1.1\r\nHost: h\r\n\r\n",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, got := roundTrip(t, c.src)
			if got != c.src {
				t.Errorf("re-encoding changed the input.\n got: %q\nwant: %q", got, c.src)
			}
		})
	}
}

func TestHTTPGivesTheRequestItsParts(t *testing.T) {
	root, _ := roundTrip(t, "POST /items?a=1 HTTP/1.1\r\nHost: h\r\n"+
		"Content-Type: application/json\r\nContent-Length: 12\r\n\r\n{\"name\":\"x\"}")

	if len(root.Children) != 1 {
		t.Fatalf("decoded %d requests, want 1", len(root.Children))
	}
	req := root.Children[0]
	if req.Name != codec.HTTPRequest {
		t.Fatalf("the child is %q", req.Name)
	}

	find := func(n *ir.Node, name string) *ir.Node {
		for _, c := range n.Children {
			if c.Name == name {
				return c
			}
		}
		return nil
	}

	for _, want := range []struct{ field, value string }{
		{codec.HTTPMethod, "POST"},
		{codec.HTTPTarget, "/items?a=1"},
		{codec.HTTPVersion, "HTTP/1.1"},
		{codec.HTTPBody, `{"name":"x"}`},
	} {
		n := find(req, want.field)
		if n == nil {
			t.Errorf("no %s node; a mutator cannot aim at a field that is not there", want.field)
			continue
		}
		if string(n.Raw) != want.value {
			t.Errorf("%s = %q, want %q", want.field, n.Raw, want.value)
		}
	}

	headers := find(req, codec.HTTPHeaders)
	if headers == nil || len(headers.Children) != 3 {
		t.Fatalf("headers node holds %v", headers)
	}
	first := headers.Children[0]
	if n := find(first, codec.HTTPName); n == nil || string(n.Raw) != "Host" {
		t.Errorf("first header name %v", n)
	}
	if n := find(first, codec.HTTPValue); n == nil || string(n.Raw) != "h" {
		t.Errorf("first header value %v", n)
	}
}

// TestHTTPMutatingAFieldChangesOnlyThatField is what the structure is for. A
// byte-level mutator changing one character of "Authorization" produces a
// request the server rejects at the header parser; a structural one changing the
// *value* produces a request it tries to authenticate.
func TestHTTPMutatingAFieldChangesOnlyThatField(t *testing.T) {
	src := "GET /items/42 HTTP/1.1\r\nHost: h\r\nAuthorization: Bearer abc\r\n\r\n"
	root, _ := roundTrip(t, src)

	// Change the target, as a mutator would.
	for _, c := range root.Children[0].Children {
		if c.Name == codec.HTTPTarget {
			c.Raw = []byte("/items/99999")
		}
	}
	got := string(ir.AppendEncode(nil, root))
	want := "GET /items/99999 HTTP/1.1\r\nHost: h\r\nAuthorization: Bearer abc\r\n\r\n"
	if got != want {
		t.Errorf("changing the target produced:\n %q\nwant:\n %q", got, want)
	}
}

// TestHTTPBoundsWhatOneSeedCanHold keeps a capture from somewhere else from
// costing an unbounded amount, and keeps the round-trip property while doing it.
func TestHTTPBoundsWhatOneSeedCanHold(t *testing.T) {
	one := "GET /a HTTP/1.1\r\nHost: h\r\n\r\n"
	src := strings.Repeat(one, 2000)
	root, got := roundTrip(t, src)
	if got != src {
		t.Error("re-encoding a capture past the request limit lost bytes")
	}
	if len(root.Children) > 1100 {
		t.Errorf("decoded %d children from 2000 requests; the limit is not being applied",
			len(root.Children))
	}
}
