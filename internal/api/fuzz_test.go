package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rom/Xfuzz/internal/daemon"
	"github.com/rom/Xfuzz/internal/testenv"
)

// FuzzRequest fuzzes the API's request handling.
//
// Untrusted because the API is the network surface: the console speaks it, the
// CLI speaks it, and on a TCP listener anything that can reach the port speaks
// it. ADR-0024 chose hand-written JSON handling over generated stubs, which
// puts the parsing where a defect is possible and therefore where it has to be
// fuzzed.
//
// The path, the method and the body together, because they are decided in that
// order and the interesting failures are in the joins: a path that routes
// somewhere unexpected, a body parsed under the wrong shape, an identifier that
// escapes the segment it was taken from.
func FuzzRequest(f *testing.F) {
	f.Add("GET", "/v1/info", "")
	f.Add("GET", "/v1/campaigns", "")
	f.Add("POST", "/v1/campaigns/validate", `{"document":"name: c\n"}`)
	f.Add("POST", "/v1/campaigns/load", `{"name":"c"}`)
	f.Add("POST", "/v1/campaigns/edit", `{"document":"name: c\n","set":{"a":"b"}}`)
	f.Add("GET", "/v1/campaigns/../../etc/passwd", "")
	f.Add("GET", "/v1/campaigns/%2e%2e%2f/findings", "")
	f.Add("POST", "/v1/campaigns/c/findings/999999999999999999999/triage", `{"as":"confirmed"}`)
	f.Add("POST", "/v1/grammar/sample", `{"grammar":"format m { a: u8 }","count":-1}`)
	f.Add("GET", "/v1/", "")
	f.Add("PATCH", "/v1//////", "{")

	// One daemon for every case. Building one per execution would make the
	// fuzzer measure SQLite's startup rather than the handlers.
	dir := testenv.ReachableDir(fuzzTB{f})
	d, err := daemon.New(daemon.Options{DataDir: dir})
	if err != nil {
		f.Fatal(err)
	}
	f.Cleanup(func() { d.Close(context.Background()) })

	srv := NewServer(d)

	f.Fuzz(func(t *testing.T, method, path, body string) {
		if len(path) > 4096 || len(body) > 1<<16 {
			return
		}
		// http.NewRequest refuses a method with illegal characters, which is
		// the net/http package's business rather than this one's.
		if method == "" || strings.ContainsAny(method, " \t\r\n\x00") {
			return
		}
		if !strings.HasPrefix(path, "/") {
			return
		}

		req, err := http.NewRequest(method, "http://unix"+path, strings.NewReader(body))
		if err != nil {
			return
		}
		req.Header.Set("Content-Type", "application/json")

		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)

		// Every answer must be an answer. A handler that writes nothing leaves
		// a client waiting on a response that never comes, which reads as a
		// hung daemon rather than a rejected request.
		if rec.Code < 100 || rec.Code > 599 {
			t.Fatalf("%s %s produced status %d", method, path, rec.Code)
		}
		// An API path must never answer with the console's page. The two share
		// a listener, and a routing mistake that let /v1/... fall through to
		// the SPA would turn a broken request into an HTML page a JSON client
		// cannot read (which is the bug the shared IsAPIPath exists to stop).
		//
		// A redirect is not the console answering: it is this handler saying
		// the path is not the one it will act on, and http.Redirect writes an
		// HTML body for a GET by convention.
		if rec.Code/100 != 3 && (strings.HasPrefix(req.URL.Path, "/v1/") || req.URL.Path == "/v1") {
			if ct := rec.Header().Get("Content-Type"); strings.Contains(ct, "text/html") {
				t.Fatalf("%s %s (path %q) was answered by the console with %s",
					method, path, req.URL.Path, ct)
			}
		}
	})
}

// fuzzTB adapts *testing.F to the testing.TB the fixture helper wants.
type fuzzTB struct{ *testing.F }
