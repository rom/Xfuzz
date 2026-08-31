package capture_test

import (
	"strings"
	"testing"

	"github.com/rom/Xfuzz/pkg/capture"
)

// Two things have to hold, and they are different things. The credentials have
// to be found, or the campaign fuzzes them and collects 401s. And the redacted
// capture must not contain them anywhere — not in the request that sent them,
// and not in the response that issued them, because a login's response carries
// the token the next request uses and redacting only one half leaves the secret
// sitting beside the placeholder that hides it.

func TestFindCredentials(t *testing.T) {
	c := loginCreateUse()
	creds := capture.FindCredentials(c)
	if len(creds) == 0 {
		t.Fatal("no credentials found in a session that logs in with a password and " +
			"then sends a bearer token twice")
	}

	kinds := map[capture.CredentialKind]int{}
	for _, cr := range creds {
		kinds[cr.Kind]++
		t.Logf("%s at %s", cr.Kind, cr.Location)
	}
	if kinds[capture.CredAuthorization] != 2 {
		t.Errorf("found %d Authorization headers, want the 2 that are there",
			kinds[capture.CredAuthorization])
	}
	if kinds[capture.CredTokenField] == 0 {
		t.Error("the password in the login body was not recognised")
	}
}

func TestRedactRemovesSecretsFromBothHalves(t *testing.T) {
	c := loginCreateUse()
	red, secrets := capture.Redact(c)

	if secrets.Len() == 0 {
		t.Fatal("nothing was redacted")
	}

	// The whole redacted capture, request and response alike, must not contain
	// any secret.
	whole := renderAll(red)
	for _, ph := range secrets.Placeholders() {
		value, _ := secrets.Value(ph)
		if strings.Contains(whole, value) {
			t.Errorf("the secret %q survives in the redacted capture", elideFor(value))
		}
	}
	// And the login's response, which issued the token, must be redacted too.
	if strings.Contains(string(red.Exchanges[0].Response.Body), "tokenvalue") {
		t.Error("the response that issued the token still contains it")
	}

	// The original is untouched: it is what the executor authenticates with.
	if !strings.Contains(string(c.Exchanges[0].Response.Body), "tokenvalue") {
		t.Error("Redact modified the capture it was given rather than copying it")
	}
}

// TestTheSameSecretGetsTheSamePlaceholder is what keeps a redacted capture
// readable. The token sent on forty requests is one token, and a counter would
// make each occurrence look like a different one — a campaign reading the
// redacted seed would conclude every request authenticated differently.
func TestTheSameSecretGetsTheSamePlaceholder(t *testing.T) {
	red, _ := capture.Redact(loginCreateUse())
	first := headerValue(red, 1, "Authorization")
	second := headerValue(red, 2, "Authorization")
	if first == "" || first != second {
		t.Errorf("the same token was redacted to %q and %q", first, second)
	}
}

// TestApplyPutsTheSecretsBack is the other half: a redacted request has to
// become a working one immediately before it is sent.
func TestApplyPutsTheSecretsBack(t *testing.T) {
	c := loginCreateUse()
	red, secrets := capture.Redact(c)

	original := string(c.Session())
	// Through ApplySession, which splits before it substitutes: a placeholder
	// and the value it stands for are rarely the same size, and a request whose
	// declared length disagrees with its body is one no server reads correctly.
	restored := string(secrets.ApplySession(red.Session()))
	if restored != original {
		t.Errorf("restoring the redacted session did not reproduce the original.\n"+
			"got:  %q\nwant: %q", elideFor(restored), elideFor(original))
	}
}

// TestApplyLeavesAnInventedPlaceholderAlone matters because a mutator will
// eventually produce one. A placeholder that stands for nothing must not resolve
// to some other secret.
func TestApplyLeavesAnInventedPlaceholderAlone(t *testing.T) {
	_, secrets := capture.Redact(loginCreateUse())
	in := "Authorization: Bearer xfuzz-secret-000000000000\r\n"
	if got := string(secrets.Apply([]byte(in))); got != in {
		t.Errorf("an invented placeholder resolved to %q", got)
	}
}

func TestRedactOfACaptureWithNoSecretsChangesNothing(t *testing.T) {
	c := &capture.Capture{Exchanges: []capture.Exchange{{
		Request:  capture.Request{Method: "GET", URL: "https://h/health"},
		Response: capture.Response{Status: 200, Body: []byte(`{"ok":true}`)},
	}}}
	red, secrets := capture.Redact(c)
	if secrets.Len() != 0 {
		t.Errorf("%d secrets found in a capture that has none", secrets.Len())
	}
	if string(red.Session()) != string(c.Session()) {
		t.Error("redacting a capture with no secrets changed it")
	}
}

// TestSessionIsWhatTheCodecReads closes the loop: what Redact produces is what a
// seed file holds, and the codec has to be able to read it back.
func TestSessionRecomputesContentLength(t *testing.T) {
	c := &capture.Capture{Exchanges: []capture.Exchange{{
		Request: capture.Request{
			Method: "POST", URL: "https://h/items",
			// A length that disagrees with the body, which is what a HAR
			// recording a compressed body produces.
			Headers: []capture.Header{{Name: "Content-Length", Value: "999"}},
			Body:    []byte("hello"),
		},
	}}}
	got := string(c.Session())
	if !strings.Contains(got, "Content-Length: 5\r\n") {
		t.Errorf("the session declares the recorded length rather than the real one:\n%q", got)
	}
	if strings.Contains(got, "999") {
		t.Errorf("the recorded length survived:\n%q", got)
	}
}

func renderAll(c *capture.Capture) string {
	var b strings.Builder
	for _, e := range c.Exchanges {
		b.Write(capture.SessionOf(&e.Request))
		for _, h := range e.Response.Headers {
			b.WriteString(h.Name + ": " + h.Value + "\n")
		}
		b.Write(e.Response.Body)
	}
	return b.String()
}

func headerValue(c *capture.Capture, i int, name string) string {
	return c.Exchanges[i].Request.Get(name)
}

func elideFor(s string) string {
	if len(s) <= 64 {
		return s
	}
	return s[:64] + "..."
}
