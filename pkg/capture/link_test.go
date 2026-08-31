package capture_test

import (
	"strings"
	"testing"

	"github.com/rom/Xfuzz/pkg/capture"
)

// The session every API capture is: log in, create something, use it, delete it.
// Every step after the first depends on a value the server produced, and the
// point of inference is to find those without being told.
func loginCreateUse() *capture.Capture {
	json := func(s string) []capture.Header {
		return []capture.Header{{Name: "Content-Type", Value: "application/json"}}
	}
	return &capture.Capture{Exchanges: []capture.Exchange{
		{
			Request: capture.Request{
				Method: "POST", URL: "https://api.example.com/login",
				Headers: json(""), Body: []byte(`{"user":"alice","password":"hunter2xyz"}`),
			},
			Response: capture.Response{
				Status: 200, Headers: json(""),
				Body: []byte(`{"access_token":"eyJhbGciOiJIUzI1NiJ9.tokenvalue","expires_in":3600}`),
			},
		},
		{
			Request: capture.Request{
				Method: "POST", URL: "https://api.example.com/items",
				Headers: append(json(""), capture.Header{
					Name: "Authorization", Value: "Bearer eyJhbGciOiJIUzI1NiJ9.tokenvalue"}),
				Body: []byte(`{"name":"widget"}`),
			},
			Response: capture.Response{
				Status: 201, Headers: json(""),
				Body: []byte(`{"id":"018f2c3d-4e5a-7b8c-9d0e-1f2a3b4c5d6e","name":"widget"}`),
			},
		},
		{
			Request: capture.Request{
				Method: "GET",
				URL:    "https://api.example.com/items/018f2c3d-4e5a-7b8c-9d0e-1f2a3b4c5d6e",
				Headers: []capture.Header{{
					Name: "Authorization", Value: "Bearer eyJhbGciOiJIUzI1NiJ9.tokenvalue"}},
			},
			Response: capture.Response{Status: 200, Headers: json(""), Body: []byte(`{"name":"widget"}`)},
		},
	}}
}

func TestInferFindsTheIdentifierAndTheToken(t *testing.T) {
	links := capture.Infer(loginCreateUse())
	if len(links) == 0 {
		t.Fatal("no dependencies inferred from a login-create-use session")
	}
	t.Logf("inferred:\n%s", joinLinks(links))

	// The token the login produced, sent back on both later requests.
	var tokenLinks, idLinks int
	for _, l := range links {
		switch {
		case strings.Contains(l.Value, "tokenvalue"):
			tokenLinks++
			if l.From.Exchange != 0 {
				t.Errorf("the token is credited to exchange %d, not the login", l.From.Exchange)
			}
		case strings.HasPrefix(l.Value, "018f2c3d"):
			idLinks++
			if l.From.Exchange != 1 {
				t.Errorf("the identifier is credited to exchange %d, not the create", l.From.Exchange)
			}
			if l.To.Exchange != 2 || l.To.Part != capture.PartPath {
				t.Errorf("the identifier is used at %s, want a path segment of exchange 2", l.To)
			}
		}
	}
	if tokenLinks < 2 {
		t.Errorf("the token was linked into %d later requests, want both", tokenLinks)
	}
	if idLinks != 1 {
		t.Errorf("the created identifier produced %d links, want 1", idLinks)
	}
}

// TestInferOnlyLooksForward is the rule that keeps a client-generated value from
// being mistaken for a server-generated one. A request cannot depend on a
// response that had not happened yet.
func TestInferOnlyLooksForward(t *testing.T) {
	c := &capture.Capture{Exchanges: []capture.Exchange{
		{
			Request:  capture.Request{Method: "POST", URL: "https://h/a", Body: []byte(`{"idem":"client-generated-key-1"}`)},
			Response: capture.Response{Status: 200, Body: []byte(`{"echo":"client-generated-key-1"}`)},
		},
	}}
	for _, l := range capture.Infer(c) {
		if l.From.Exchange >= l.To.Exchange {
			t.Errorf("inferred %s: a request cannot take a value from its own response", l)
		}
	}
}

// TestInferIgnoresValuesTooShortToMeanAnything is the guard against the failure
// that makes correlation untrustworthy. "1" appears in a response and in every
// request after it, and a link table full of those would have the campaign
// rewriting fields the server was perfectly happy with.
func TestInferIgnoresValuesTooShortToMeanAnything(t *testing.T) {
	c := &capture.Capture{Exchanges: []capture.Exchange{
		{
			Request:  capture.Request{Method: "GET", URL: "https://h/a"},
			Response: capture.Response{Status: 200, Body: []byte(`{"page":1,"ok":true,"n":42}`)},
		},
		{
			Request:  capture.Request{Method: "GET", URL: "https://h/b?page=1&n=42"},
			Response: capture.Response{Status: 200},
		},
	}}
	if links := capture.Infer(c); len(links) != 0 {
		t.Errorf("inferred %d dependencies from short values:\n%s", len(links), joinLinks(links))
	}
}

// TestInferIgnoresTheHeadersEveryMessageCarries keeps a content type from
// looking like a dependency, which it is in the literal sense and not in any
// useful one.
func TestInferIgnoresTheHeadersEveryMessageCarries(t *testing.T) {
	ct := []capture.Header{{Name: "Content-Type", Value: "application/json"}}
	c := &capture.Capture{Exchanges: []capture.Exchange{
		{Request: capture.Request{Method: "GET", URL: "https://h/a", Headers: ct},
			Response: capture.Response{Status: 200, Headers: ct}},
		{Request: capture.Request{Method: "GET", URL: "https://h/b", Headers: ct},
			Response: capture.Response{Status: 200, Headers: ct}},
	}}
	for _, l := range capture.Infer(c) {
		if strings.Contains(l.Value, "application/json") {
			t.Errorf("inferred %s", l)
		}
	}
}

// TestInferIsDeterministic guards a property the whole campaign rests on: Go
// randomises map iteration, and JSON decodes into a map.
func TestInferIsDeterministic(t *testing.T) {
	first := joinLinks(capture.Infer(loginCreateUse()))
	for i := 0; i < 8; i++ {
		if got := joinLinks(capture.Infer(loginCreateUse())); got != first {
			t.Fatalf("inference run %d differed:\n%s\n---\n%s", i+1, first, got)
		}
	}
}

func TestLinksForOneRequest(t *testing.T) {
	links := capture.Infer(loginCreateUse())
	if n := len(links.For(0)); n != 0 {
		t.Errorf("the first request has %d dependencies; nothing precedes it", n)
	}
	if n := len(links.For(2)); n == 0 {
		t.Error("the third request has no dependencies; it uses both the token and the id")
	}
}

func joinLinks(ls capture.Links) string {
	var b strings.Builder
	for _, l := range ls {
		b.WriteString(l.String())
		b.WriteByte('\n')
	}
	return b.String()
}
