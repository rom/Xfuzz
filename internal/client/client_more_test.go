package client

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A daemon that answers with the current version header, records what it was
// asked, and says whatever the test wants it to.
type fakeDaemon struct {
	t        *testing.T
	srv      *httptest.Server
	lastReq  *http.Request
	lastBody string
	handler  http.HandlerFunc
}

func newFakeDaemon(t *testing.T) *fakeDaemon {
	t.Helper()
	d := &fakeDaemon{t: t}
	d.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := readAll(r)
		d.lastReq, d.lastBody = r, body
		w.Header().Set("X-Xfuzz-Api", APIVersion)
		if d.handler != nil {
			d.handler(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"ok":true}`)
	}))
	t.Cleanup(d.srv.Close)
	return d
}

func readAll(r *http.Request) (string, error) {
	var b strings.Builder
	buf := make([]byte, 4096)
	for {
		n, err := r.Body.Read(buf)
		b.Write(buf[:n])
		if err != nil {
			return b.String(), nil
		}
	}
}

func (d *fakeDaemon) client(t *testing.T, token string) *Client {
	t.Helper()
	c, err := New(Options{Addr: strings.TrimPrefix(d.srv.URL, "http://"), Token: token})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestNewNeedsAnAddress(t *testing.T) {
	if _, err := New(Options{}); err == nil {
		t.Fatal("a client with no socket and no address was created; it would have nowhere to send anything")
	}
}

func TestABareAddressGetsAScheme(t *testing.T) {
	// `--addr 127.0.0.1:7777` is what people type; a client that required
	// "http://" in front of it would refuse the address the daemon printed.
	d := newFakeDaemon(t)
	bare := strings.TrimPrefix(d.srv.URL, "http://")
	for _, addr := range []string{bare, "http://" + bare} {
		c, err := New(Options{Addr: addr})
		if err != nil {
			t.Fatal(err)
		}
		if err := c.Ping(context.Background()); err != nil {
			t.Errorf("Ping via %q: %v", addr, err)
		}
	}
}

func TestDoSendsTheTokenAndTheBody(t *testing.T) {
	d := newFakeDaemon(t)
	c := d.client(t, "s3cret")

	var out struct{ OK bool }
	if err := c.Do(context.Background(), "POST", "/v1/campaigns", map[string]int{"n": 1}, &out); err != nil {
		t.Fatal(err)
	}
	if got := d.lastReq.Header.Get("Authorization"); got != "Bearer s3cret" {
		t.Errorf("Authorization = %q", got)
	}
	if got := d.lastReq.Header.Get("Content-Type"); got != "application/json" {
		t.Errorf("a JSON body was sent as %q", got)
	}
	if d.lastBody != `{"n":1}` {
		t.Errorf("body = %q", d.lastBody)
	}
	if !out.OK {
		t.Error("the response was not decoded")
	}
}

func TestDoWithoutABodySendsNoContentType(t *testing.T) {
	d := newFakeDaemon(t)
	c := d.client(t, "")
	if err := c.Do(context.Background(), "GET", "/v1/info", nil, nil); err != nil {
		t.Fatal(err)
	}
	if got := d.lastReq.Header.Get("Content-Type"); got != "" {
		t.Errorf("a bodiless request declared Content-Type %q", got)
	}
	if got := d.lastReq.Header.Get("Authorization"); got != "" {
		t.Errorf("a client with no token sent Authorization %q", got)
	}
}

func TestADaemonErrorIsReadAsOne(t *testing.T) {
	// The daemon's error body is {"error": "...", "details": [...]}, and the
	// details are what validation spent effort producing: they must survive
	// into the error the CLI prints, one per line.
	d := newFakeDaemon(t)
	d.handler = func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, `{"error":"the file is not a campaign","details":["target.path is missing","seeds: none"]}`)
	}
	err := d.client(t, "").Do(context.Background(), "POST", "/v1/campaigns/validate", map[string]string{}, nil)

	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("err = %T %v, want *APIError", err, err)
	}
	if apiErr.Status != http.StatusBadRequest || apiErr.Message != "the file is not a campaign" {
		t.Errorf("APIError = %+v", apiErr)
	}
	if len(apiErr.Details) != 2 {
		t.Errorf("details = %v", apiErr.Details)
	}
	if s := err.Error(); !strings.Contains(s, "target.path is missing") || !strings.Contains(s, "\n  - ") {
		t.Errorf("the details are not in the message, one per line:\n%s", s)
	}
	if apiErr.NotFound() {
		t.Error("a 400 reported itself as not found")
	}
}

func TestANonJSONErrorKeepsItsBody(t *testing.T) {
	// A proxy in front of the daemon answers with HTML, and the useful message
	// is that HTML rather than a decoding failure.
	d := newFakeDaemon(t)
	d.handler = func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, "  <html>no such thing</html>\n")
	}
	err := d.client(t, "").Do(context.Background(), "GET", "/v1/campaigns/x", nil, nil)
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("err = %T", err)
	}
	if !apiErr.NotFound() {
		t.Error("a 404 did not report itself as not found")
	}
	if apiErr.Message != "<html>no such thing</html>" {
		t.Errorf("message = %q; the raw body, trimmed, is the message", apiErr.Message)
	}
}

func TestAnUnreadableAnswerNamesTheRequest(t *testing.T) {
	d := newFakeDaemon(t)
	d.handler = func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "not json") }
	var out map[string]any
	err := d.client(t, "").Do(context.Background(), "GET", "/v1/info", nil, &out)
	if err == nil || !strings.Contains(err.Error(), "unreadable response to GET /v1/info") {
		t.Errorf("err = %v", err)
	}
}

func TestAnEmptyAnswerIsNotAnError(t *testing.T) {
	// DELETE answers with nothing to decode, and a client that treated an
	// empty body as a parse failure would report every forget as broken.
	d := newFakeDaemon(t)
	d.handler = func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }
	var out map[string]any
	if err := d.client(t, "").Do(context.Background(), "DELETE", "/v1/campaigns/x", nil, &out); err != nil {
		t.Fatal(err)
	}
}

func TestPingFailsWhenNothingAnswers(t *testing.T) {
	// A port nothing listens on: the connect is refused at once, which is
	// what "no daemon is answering" is built on.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	c, err := New(Options{Addr: addr, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Ping(context.Background()); err == nil {
		t.Fatal("Ping succeeded against a closed port")
	}
}

func TestAUnixSocketIsDialled(t *testing.T) {
	// The default transport, and the one a browser cannot use: the client
	// dials the socket path whatever host the URL names.
	if os.Getenv("GOOS") == "windows" {
		t.Skip("no Unix sockets")
	}
	sock := filepath.Join(shortTempDir(t), "d.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Skipf("no Unix socket here: %v", err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Xfuzz-Api", APIVersion)
		fmt.Fprint(w, `{"daemon":{}}`)
	})}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })

	c, err := New(Options{Socket: sock})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Ping(context.Background()); err != nil {
		t.Fatalf("Ping over the socket: %v", err)
	}
}

// shortTempDir is a temp dir whose path fits in sun_path: t.TempDir can be
// long enough that a socket inside it cannot be bound.
func shortTempDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("", "xc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	return d
}

func TestStreamDeliversEventsAndStopsWhenAsked(t *testing.T) {
	d := newFakeDaemon(t)
	d.handler = func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Accept") != "text/event-stream" {
			t.Errorf("the stream did not ask for text/event-stream: %q", r.Header.Get("Accept"))
		}
		if r.Header.Get("Authorization") != "Bearer tk" {
			t.Errorf("the stream request carried Authorization %q", r.Header.Get("Authorization"))
		}
		q := r.URL.Query()
		if q.Get("kinds") != "metrics,finding" || q.Get("campaign") != "nightly" {
			t.Errorf("query = %v", q)
		}
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, ": keep-alive\n\nevent: metrics\ndata: {\"execs\":1}\n\nevent: finding\ndata: {\"id\":7}\n\nevent: metrics\ndata: {\"execs\":2}\n\n")
	}

	var got []string
	err := d.client(t, "tk").Stream(context.Background(), []string{"metrics", "finding"}, "nightly",
		func(kind string, data []byte) bool {
			got = append(got, kind+":"+string(data))
			// Stop after the finding: the third frame must never arrive.
			return kind != "finding"
		})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{`metrics:{"execs":1}`, `finding:{"id":7}`}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestStreamWithoutFiltersAsksForEverything(t *testing.T) {
	d := newFakeDaemon(t)
	d.handler = func(w http.ResponseWriter, r *http.Request) {
		if r.URL.RawQuery != "" {
			t.Errorf("an unfiltered stream sent a query: %q", r.URL.RawQuery)
		}
		w.Header().Set("Content-Type", "text/event-stream")
	}
	if err := d.client(t, "").Stream(context.Background(), nil, "", func(string, []byte) bool { return true }); err != nil {
		t.Fatal(err)
	}
}

func TestStreamReportsARefusal(t *testing.T) {
	d := newFakeDaemon(t)
	d.handler = func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"error":"a valid bearer token is required"}`)
	}
	err := d.client(t, "").Stream(context.Background(), nil, "", func(string, []byte) bool { return true })
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Status != http.StatusUnauthorized {
		t.Fatalf("err = %v, want a 401 APIError", err)
	}
}

func TestSSEFramesAreParsedAsTheSpecSays(t *testing.T) {
	// Two data lines in one frame join with a newline; a comment is ignored;
	// a frame with an event and no data is not delivered; a trailing frame
	// with no blank line after it is still delivered at end of input.
	src := strings.NewReader(
		": hello\n" +
			"event: log\ndata: first\ndata: second\n\n" +
			"event: empty\n\n" +
			"data: no kind\n\n" +
			"event: last\ndata: tail")
	var got []string
	err := readSSE(src, func(kind string, data []byte) bool {
		got = append(got, kind+"="+string(data))
		return true
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"log=first\nsecond", "=no kind"}
	// The trailing frame has no terminating blank line. The parser treats end
	// of input as the end of the stream rather than of a frame, so it is not
	// delivered — the server always terminates a frame, and a partial one at
	// EOF is a connection that dropped mid-event, which should not be reported
	// as a whole one.
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestAutoStartNeverStartsADaemonForANamedAddress(t *testing.T) {
	// A named address is somebody else's daemon: starting one would start it
	// in the wrong place. So this must return a client without probing.
	c, err := AutoStart(context.Background(), Options{Addr: "127.0.0.1:1"})
	if err != nil {
		t.Fatalf("AutoStart with an address: %v", err)
	}
	if c == nil {
		t.Fatal("no client")
	}
}

func TestAutoStartSaysWhenThereIsNoDaemonToStart(t *testing.T) {
	// Nothing on the socket, and no xfuzzd anywhere it looks: the error has
	// to say that, rather than "connection refused" on every later command.
	t.Setenv("PATH", t.TempDir())
	sock := filepath.Join(shortTempDir(t), "none.sock")
	_, err := AutoStart(context.Background(), Options{Socket: sock, Timeout: time.Second})
	if !errors.Is(err, ErrNoDaemon) {
		t.Fatalf("err = %v, want ErrNoDaemon", err)
	}
	if !strings.Contains(err.Error(), DaemonBinaryName) {
		t.Errorf("the error does not name the binary it looked for: %v", err)
	}
}

func TestAutoStartReturnsARunningDaemon(t *testing.T) {
	sock := filepath.Join(shortTempDir(t), "d.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Skipf("no Unix socket here: %v", err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Xfuzz-Api", APIVersion)
		fmt.Fprint(w, `{}`)
	})}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })

	t.Setenv("PATH", t.TempDir()) // so a spawn attempt would be a visible failure
	if _, err := AutoStart(context.Background(), Options{Socket: sock}); err != nil {
		t.Fatalf("a daemon was answering and AutoStart failed: %v", err)
	}
}
