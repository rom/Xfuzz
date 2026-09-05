package api

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/rom/Xfuzz/internal/client"
	"github.com/rom/Xfuzz/internal/daemon"
	"github.com/rom/Xfuzz/internal/testenv"
)

// harness is a daemon behind an httptest server, with no worker processes: the
// API's job is to expose state, and the state can be made by hand.
type harness struct {
	t      *testing.T
	daemon *daemon.Daemon
	server *Server
	http   *httptest.Server
	dir    string
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	dir := testenv.ReachableDir(t)
	d, err := daemon.New(daemon.Options{DataDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close(context.Background()) })

	s := NewServer(d)
	ts := httptest.NewServer(s)
	t.Cleanup(ts.Close)

	return &harness{t: t, daemon: d, server: s, http: ts, dir: dir}
}

// document returns a valid campaign file whose target exists.
func (h *harness) document(name string) string {
	h.t.Helper()
	target := testenv.StubTarget(h.t, h.dir)
	return fmt.Sprintf(`
name: %s
target:
  path: %s
seeds:
  inline: ["alpha"]
workers:
  count: 1
stop:
  execs: 1000
`, name, target)
}

func (h *harness) do(method, path string, body any) (*http.Response, []byte) {
	h.t.Helper()
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			h.t.Fatal(err)
		}
		rdr = strings.NewReader(string(b))
	}
	req, err := http.NewRequest(method, h.http.URL+path, rdr)
	if err != nil {
		h.t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if h.server.Token != "" {
		req.Header.Set("Authorization", "Bearer "+h.server.Token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp, out
}

func (h *harness) json(method, path string, body any, into any) *http.Response {
	h.t.Helper()
	resp, raw := h.do(method, path, body)
	if into != nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, into); err != nil {
			h.t.Fatalf("%s %s returned unreadable JSON: %v\n%s", method, path, err, raw)
		}
	}
	return resp
}

func TestValidateAcceptsAGoodCampaign(t *testing.T) {
	h := newHarness(t)
	var got ValidateResponse
	resp := h.json("POST", "/v1/campaigns/validate",
		CampaignRequest{Document: h.document("ok")}, &got)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if !got.Valid || got.Name != "ok" {
		t.Fatalf("response = %+v", got)
	}
	if len(got.Warnings) != 0 {
		t.Errorf("unexpected warnings: %v", got.Warnings)
	}
}

func TestValidateReportsEveryProblem(t *testing.T) {
	// Flattening a validation list into one string would undo the work
	// validation did to produce it.
	h := newHarness(t)
	var got Error
	resp := h.json("POST", "/v1/campaigns/validate", CampaignRequest{Document: `
target:
  path: /nonexistent
  executor: teleport
feedback:
  coverage: guessing
`}, &got)

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if len(got.Details) < 4 {
		t.Fatalf("reported %d details, want one per problem: %+v", len(got.Details), got)
	}
	joined := strings.Join(got.Details, "\n")
	for _, want := range []string{"name", "target.path", "target.executor", "feedback.coverage"} {
		if !strings.Contains(joined, want) {
			t.Errorf("no detail mentions %s:\n%s", want, joined)
		}
	}
}

func TestValidateWarnsAboutAnEndlessCampaign(t *testing.T) {
	// Legitimate for interactive use, and a CI user needs to know before their
	// pipeline hangs.
	h := newHarness(t)
	doc := strings.ReplaceAll(h.document("endless"), "stop:\n  execs: 1000\n", "")
	var got ValidateResponse
	h.json("POST", "/v1/campaigns/validate", CampaignRequest{Document: doc}, &got)

	if !got.Valid {
		t.Fatal("a campaign with no termination condition was rejected")
	}
	if len(got.Warnings) == 0 || !strings.Contains(got.Warnings[0], "interrupted") {
		t.Fatalf("warnings = %v", got.Warnings)
	}
}

func TestExplainRendersTheResolvedConfiguration(t *testing.T) {
	h := newHarness(t)
	var got ExplainResponse
	resp := h.json("POST", "/v1/campaigns/explain",
		CampaignRequest{Document: h.document("explained")}, &got)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if !strings.Contains(got.Text, "feedback.map_size") || !strings.Contains(got.Text, "(default)") {
		t.Fatalf("the rendering does not show defaults:\n%s", got.Text)
	}
	// And the YAML runs the same campaign, which is how a run is pinned to an
	// artefact after the fact.
	var again ValidateResponse
	h.json("POST", "/v1/campaigns/validate", CampaignRequest{Document: got.YAML}, &again)
	if !again.Valid {
		t.Fatalf("the rendered configuration does not validate:\n%s", got.YAML)
	}
}

func TestCampaignLifecycleOverTheAPI(t *testing.T) {
	h := newHarness(t)

	var created daemon.Status
	resp := h.json("POST", "/v1/campaigns", CampaignRequest{Document: h.document("life")}, &created)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create status = %d", resp.StatusCode)
	}
	if created.Name != "life" || created.State != daemon.StateCreated {
		t.Fatalf("created = %+v", created)
	}
	if created.Seed == 0 {
		t.Error("the campaign was created without recording a seed; it could never be replayed")
	}

	var listed struct {
		Campaigns []daemon.Status `json:"campaigns"`
	}
	h.json("GET", "/v1/campaigns", nil, &listed)
	if len(listed.Campaigns) != 1 {
		t.Fatalf("the list holds %d campaigns", len(listed.Campaigns))
	}

	var got daemon.Status
	if resp := h.json("GET", "/v1/campaigns/life", nil, &got); resp.StatusCode != 200 {
		t.Fatalf("get status = %d", resp.StatusCode)
	}
	if got.Isolation == "" {
		t.Error("the status does not report the isolation in force")
	}

	// A campaign that was never started cannot be paused, and the API says so
	// with a status a client can act on rather than a 500.
	if resp, _ := h.do("POST", "/v1/campaigns/life/pause", nil); resp.StatusCode != http.StatusConflict {
		t.Errorf("pausing an unstarted campaign returned %d, want 409", resp.StatusCode)
	}

	if resp, _ := h.do("DELETE", "/v1/campaigns/life", nil); resp.StatusCode != 200 {
		t.Errorf("forget returned %d", resp.StatusCode)
	}
	if resp, _ := h.do("GET", "/v1/campaigns/life", nil); resp.StatusCode != http.StatusNotFound {
		t.Errorf("a forgotten campaign returned %d, want 404", resp.StatusCode)
	}
}

func TestUnknownCampaignIsNotFound(t *testing.T) {
	h := newHarness(t)
	for _, path := range []string{
		"/v1/campaigns/absent", "/v1/campaigns/absent/metrics",
		"/v1/campaigns/absent/findings", "/v1/campaigns/absent/corpus",
		"/v1/campaigns/absent/workers", "/v1/campaigns/absent/safety",
	} {
		resp, body := h.do("GET", path, nil)
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("%s returned %d, want 404: %s", path, resp.StatusCode, body)
		}
	}
}

func TestCorpusAndFindingsAreReadable(t *testing.T) {
	h := newHarness(t)
	var created daemon.Status
	h.json("POST", "/v1/campaigns", CampaignRequest{Document: h.document("data")}, &created)

	c, err := h.daemon.Campaign("data")
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer c.Stop(context.Background(), "test over")

	// The inline seed was imported by the daemon at start.
	var corpus struct {
		Entries []corpusEntryView `json:"entries"`
		Count   int               `json:"count"`
	}
	waitForJSON(t, func() bool {
		h.json("GET", "/v1/campaigns/data/corpus", nil, &corpus)
		return corpus.Count >= 1
	}, "the seed never appeared in the corpus")

	// A listing carries no payloads: ten thousand entries with payloads is a
	// response nobody wanted.
	for _, e := range corpus.Entries {
		if len(e.Payload) != 0 {
			t.Fatal("a corpus listing carries payloads")
		}
	}

	// Asking for one does carry it.
	var one corpusEntryView
	resp := h.json("GET", "/v1/campaigns/data/corpus/"+corpus.Entries[0].Digest, nil, &one)
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if string(one.Payload) != "alpha" {
		t.Fatalf("payload = %q", one.Payload)
	}

	var findings struct {
		Findings []findingView `json:"findings"`
		Count    int           `json:"count"`
	}
	if resp := h.json("GET", "/v1/campaigns/data/findings", nil, &findings); resp.StatusCode != 200 {
		t.Fatalf("findings status = %d", resp.StatusCode)
	}
	if findings.Count != 0 {
		t.Errorf("a fresh campaign has %d findings", findings.Count)
	}
}

func TestSafetyReportsTheLevelAndWhyItIsNotHigher(t *testing.T) {
	h := newHarness(t)
	h.json("POST", "/v1/campaigns", CampaignRequest{Document: h.document("safe")}, nil)

	var got struct {
		Isolation   string            `json:"isolation"`
		Explanation string            `json:"explanation"`
		Reasons     []string          `json:"reasons"`
		Scope       string            `json:"scope"`
		Allow       []string          `json:"allow"`
		Loopback    *bool             `json:"loopback"`
		Connections map[string]uint64 `json:"connections"`
	}
	resp := h.json("GET", "/v1/campaigns/safe/safety", nil, &got)
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if got.Isolation == "" {
		t.Fatal("no isolation level reported")
	}
	// A campaign refused for insufficient isolation has to be told what is
	// missing; the remedy is usually one line of host configuration.
	if !strings.Contains(got.Explanation, got.Isolation) {
		t.Errorf("the explanation does not mention the level:\n%s", got.Explanation)
	}
	if got.Scope == "" {
		t.Error("no scope reported")
	}
	// The list and the paragraph are the same facts in two shapes, for a page
	// and a terminal. The console read a list the route never sent, and showed
	// "nothing is missing on this host" whatever the host — so the list is
	// checked against the paragraph, item by item.
	if got.Reasons == nil {
		t.Error("no reasons list; the console renders one")
	}
	for _, reason := range got.Reasons {
		if !strings.Contains(got.Explanation, reason) {
			t.Errorf("a reason is not in the explanation: %q", reason)
		}
	}
	if got.Allow == nil {
		t.Error("no allow list; the console renders one")
	}
	if got.Loopback == nil {
		t.Error("loopback is not reported; a scope that omits it reads as one that forbids it")
	}
}

func TestValidateWarnsAboutACapThisHostWillNotEnforce(t *testing.T) {
	// A file-size cap is a Unix rlimit. Windows has a job object, which caps
	// memory, process count and CPU time and nothing else, and before this
	// the cap was accepted from the file and dropped — in a tool whose
	// isolation report exists to say what is enforced. The warning names the
	// field, so the person reading it knows which line of their file it is.
	h := newHarness(t)
	doc := h.document("capped") + "safety:\n  file_size_limit: 1MB\n"

	var got ValidateResponse
	if resp := h.json("POST", "/v1/campaigns/validate", CampaignRequest{Document: doc}, &got); resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	var mentioned bool
	for _, w := range got.Warnings {
		if strings.Contains(w, "file_size_limit") {
			mentioned = true
		}
	}
	if runtime.GOOS == "windows" && !mentioned {
		t.Errorf("a file-size cap on Windows drew no warning: %q", got.Warnings)
	}
	if runtime.GOOS != "windows" && mentioned {
		t.Errorf("a file-size cap is enforced here and was warned about anyway: %q", got.Warnings)
	}
}

func TestEventStreamDeliversAndReportsItsLosses(t *testing.T) {
	h := newHarness(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, _ := http.NewRequestWithContext(ctx, "GET", h.http.URL+"/v1/events?kinds=log", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/event-stream") {
		t.Fatalf("content type = %q", ct)
	}

	go func() {
		time.Sleep(50 * time.Millisecond)
		for i := 0; i < 5; i++ {
			h.daemon.Bus().Publish(daemon.Event{
				Kind: daemon.EventLog, Campaign: "c",
				Data: map[string]any{"text": fmt.Sprintf("line %d", i)},
			})
		}
	}()

	sc := bufio.NewScanner(resp.Body)
	events := 0
	deadline := time.Now().Add(5 * time.Second)
	for sc.Scan() && time.Now().Before(deadline) {
		line := sc.Text()
		if strings.HasPrefix(line, "event: log") {
			events++
			if events == 5 {
				break
			}
		}
	}
	if events != 5 {
		t.Fatalf("received %d events, want 5", events)
	}
}

func TestEventStreamFiltersByKind(t *testing.T) {
	h := newHarness(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, _ := http.NewRequestWithContext(ctx, "GET", h.http.URL+"/v1/events?kinds=finding", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	go func() {
		time.Sleep(50 * time.Millisecond)
		h.daemon.Bus().Publish(daemon.Event{Kind: daemon.EventLog, Data: "ignored"})
		h.daemon.Bus().Publish(daemon.Event{Kind: daemon.EventFinding, Data: "wanted"})
	}()

	sc := bufio.NewScanner(resp.Body)
	deadline := time.Now().Add(3 * time.Second)
	for sc.Scan() && time.Now().Before(deadline) {
		line := sc.Text()
		if strings.HasPrefix(line, "event: log") {
			t.Fatal("a filtered-out kind was delivered")
		}
		if strings.HasPrefix(line, "event: finding") {
			return
		}
	}
	t.Fatal("the requested kind was never delivered")
}

func TestTokenIsRequiredWhenConfigured(t *testing.T) {
	h := newHarness(t)
	h.server.Token = "s3cret"

	req, _ := http.NewRequest("GET", h.http.URL+"/v1/info", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("an unauthenticated request returned %d", resp.StatusCode)
	}

	req.Header.Set("Authorization", "Bearer wrong")
	resp, _ = http.DefaultClient.Do(req)
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("a wrong token returned %d", resp.StatusCode)
	}

	if resp := h.json("GET", "/v1/info", nil, nil); resp.StatusCode != 200 {
		t.Fatalf("the correct token returned %d", resp.StatusCode)
	}
}

func TestTheConsoleIsServedWithoutATokenAndTheAPIIsNot(t *testing.T) {
	// A browser arrives with no token, and the console is how it asks for
	// one: a login page that needs a login is not one. The bundle is the same
	// public code in every build, so nothing is given away; every route under
	// /v1 still needs the token. Before this, `/` itself answered 401 on a TCP
	// listener and the console could not be reached from a browser at all.
	h := newHarness(t)
	h.server.Token = "s3cret"

	for _, path := range []string{"/", "/index.html", "/campaigns/nightly"} {
		req, _ := http.NewRequest("GET", h.http.URL+path, nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusUnauthorized {
			t.Errorf("GET %s without a token returned 401; the console has to load before it can ask for one", path)
		}
	}
	for _, path := range []string{"/v1/info", "/v1/campaigns", "/v1/events"} {
		req, _ := http.NewRequest("GET", h.http.URL+path, nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("GET %s without a token returned %d, want 401", path, resp.StatusCode)
		}
	}
}

func TestACookieCarriesTheToken(t *testing.T) {
	// EventSource takes a URL and nothing else, so the console cannot send
	// the header the CLI sends; the token travels as a cookie instead,
	// percent-encoded because a cookie value may not hold everything a token
	// may. The cookie is the token: it opens a mutating route as readily as
	// a read, and a wrong one opens nothing.
	h := newHarness(t)
	h.server.Token = "s3c ret/%" // three characters a cookie value may not carry raw

	status := func(method, path, cookie string, body string) int {
		t.Helper()
		var rdr io.Reader
		if body != "" {
			rdr = strings.NewReader(body)
		}
		req, _ := http.NewRequest(method, h.http.URL+path, rdr)
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		if cookie != "" {
			req.AddCookie(&http.Cookie{Name: TokenCookie, Value: cookie})
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	// What the console writes: encodeURIComponent, which PathEscape matches.
	good := url.PathEscape(h.server.Token)

	if code := status("GET", "/v1/info", good, ""); code != http.StatusOK {
		t.Errorf("the token as a cookie returned %d", code)
	}
	if code := status("GET", "/v1/info", url.PathEscape("wrong"), ""); code != http.StatusUnauthorized {
		t.Errorf("a wrong token as a cookie returned %d", code)
	}
	if code := status("GET", "/v1/info", h.server.Token, ""); code == http.StatusOK {
		t.Errorf("the raw token, not percent-encoded, was accepted; the encoding is the contract")
	}
	if code := status("POST", "/v1/campaigns/validate", good, `{"document":"","name":"x"}`); code == http.StatusUnauthorized {
		t.Errorf("a mutating route refused the cookie; it is the token, not a lesser one")
	}
}

func TestTCPWithoutATokenIsRefused(t *testing.T) {
	// A campaign file names a binary to execute, so an unauthenticated daemon
	// on a network address is a remote code execution service.
	h := newHarness(t)
	err := Serve(context.Background(), h.server, Listener{Addr: "127.0.0.1:0"})
	if err == nil || !strings.Contains(err.Error(), "token") {
		t.Fatalf("err = %v, want a refusal", err)
	}
}

func TestUnixSocketIsOwnerOnly(t *testing.T) {
	h := newHarness(t)
	sock := DefaultSocket(h.dir)

	ctx, cancel := context.WithCancel(context.Background())
	go Serve(ctx, h.server, Listener{Socket: sock})
	defer cancel()

	waitForJSON(t, func() bool {
		_, err := os.Stat(sock)
		return err == nil
	}, "the socket never appeared")

	fi, err := os.Stat(sock)
	if err != nil {
		t.Fatal(err)
	}
	// Filesystem permissions are the access control on the default transport,
	// so they are set explicitly rather than left to whatever umask is in force.
	//
	// Where a file's mode is not what decides who may open it, this measures
	// nothing: os.Chmod on Windows sets the read-only attribute and nothing
	// else, so the mode comes back 0666 for a socket that may or may not be
	// reachable by another user — the answer there is the directory's inherited
	// permissions, which this cannot read. Skipped rather than asserted loosely,
	// and the gap is recorded in ADR-0033 rather than left in a passing test.
	if runtime.GOOS == "windows" {
		t.Skipf("a file's mode is not the access control here; the socket reports %v "+
			"and what protects it is the directory's permissions", fi.Mode().Perm())
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("socket mode = %v, want 0600", perm)
	}

	client := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (netConn, error) {
			return dialUnix(ctx, sock)
		},
	}}
	resp, err := client.Get("http://unix/v1/info")
	if err != nil {
		t.Fatalf("the socket does not serve: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
}

func TestOpenAPIDescribesEveryRoute(t *testing.T) {
	h := newHarness(t)
	b, err := h.server.OpenAPI()
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Paths map[string]map[string]struct {
			OperationID string `json:"operationId"`
		} `json:"paths"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}

	described := map[string]bool{}
	for _, ops := range doc.Paths {
		for _, op := range ops {
			described[op.OperationID] = true
		}
	}
	for _, r := range h.server.Routes() {
		if !described[r.Name] {
			t.Errorf("the OpenAPI document omits %s (%s %s)", r.Name, r.Method, r.Path)
		}
	}

	// And it is served, so a client can fetch it from the daemon it is talking
	// to rather than from a document that may describe a different version.
	resp, body := h.do("GET", "/v1/openapi.json", nil)
	if resp.StatusCode != 200 || len(body) == 0 {
		t.Fatalf("GET /v1/openapi.json returned %d", resp.StatusCode)
	}
}

func TestEveryRouteIsUniqueAndNamed(t *testing.T) {
	h := newHarness(t)
	names := map[string]bool{}
	endpoints := map[string]bool{}
	for _, r := range h.server.Routes() {
		if r.Name == "" || r.Summary == "" {
			t.Errorf("%s %s has no name or summary", r.Method, r.Path)
		}
		if names[r.Name] {
			t.Errorf("two routes are named %s", r.Name)
		}
		names[r.Name] = true

		ep := r.Method + " " + r.Path
		if endpoints[ep] {
			t.Errorf("two routes serve %s", ep)
		}
		endpoints[ep] = true

		// Mutating routes are the ones a token protects; a GET that changes
		// state would be invisible to that rule and to every cache.
		if r.Mutating && r.Method == "GET" {
			t.Errorf("%s mutates state on a GET", r.Name)
		}
	}
}

func TestSchemaIsServed(t *testing.T) {
	h := newHarness(t)
	resp, body := h.do("GET", "/v1/schema", nil)
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if !strings.Contains(string(body), "xfuzz.dev/schema/campaign") {
		t.Fatalf("the served schema is not the campaign schema:\n%s", body[:min(200, len(body))])
	}
}

func TestUnknownRequestFieldsAreRejected(t *testing.T) {
	// A typo in a request field silently doing nothing is the same failure as a
	// typo in a campaign file, and gets the same answer.
	h := newHarness(t)
	resp, _ := h.do("POST", "/v1/campaigns/validate", map[string]any{
		"document": "name: x", "profile": "ci",
	})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("an unknown request field returned %d", resp.StatusCode)
	}
}

func waitForJSON(t *testing.T, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal(msg)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func TestASecondDaemonCannotTakeTheSameSocket(t *testing.T) {
	// A connect probe cannot tell "a daemon is starting" from "a daemon
	// crashed and left its socket", and gives two daemons starting at once no
	// way to notice each other. A lock answers both.
	h := newHarness(t)
	sock := DefaultSocket(h.dir)

	ctx, cancel := context.WithCancel(context.Background())
	go Serve(ctx, h.server, Listener{Socket: sock})
	defer cancel()
	waitForJSON(t, func() bool { _, err := os.Stat(sock); return err == nil }, "the socket never appeared")

	second := newHarness(t)
	err := Serve(context.Background(), second.server, Listener{Socket: sock})
	if err == nil {
		t.Fatal("a second daemon took a socket another one was serving")
	}
	if !strings.Contains(err.Error(), "already running") {
		t.Fatalf("err = %v", err)
	}
}

func TestAStaleSocketIsReclaimed(t *testing.T) {
	// A daemon killed rather than stopped leaves its socket behind, and that is
	// the commonest reason a restart fails.
	h := newHarness(t)
	sock := DefaultSocket(h.dir)
	if err := os.WriteFile(sock, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errc := make(chan error, 1)
	go func() { errc <- Serve(ctx, h.server, Listener{Socket: sock}) }()

	waitForJSON(t, func() bool {
		fi, err := os.Stat(sock)
		return err == nil && fi.Mode()&os.ModeSocket != 0
	}, "the stale socket was never replaced with a live one")

	select {
	case err := <-errc:
		t.Fatalf("Serve returned early: %v", err)
	default:
	}
}

// The client declares the API version it understands rather than importing it,
// because internal/api pulls in the daemon and a client binary has no business
// carrying one. That leaves two constants which must agree, so they are held
// equal here: drift becomes a failing test rather than a mismatch discovered
// by a user whose CLI silently misreads a daemon.
func TestTheClientAgreesOnTheAPIVersion(t *testing.T) {
	if client.APIVersion != APIVersion {
		t.Errorf("the client understands API version %q and the server speaks %q; "+
			"one of them was changed without the other",
			client.APIVersion, APIVersion)
	}
}

func TestAPathThatDoesNotSurviveCleaningIsRedirectedRatherThanReroutedToTheConsole(t *testing.T) {
	// The console and the API share a listener, and which of them answers is
	// decided by the path. Deciding it on the *cleaned* path meant that
	// "/v1/campaigns/../../etc/passwd" cleaned to "/etc/passwd" and fell
	// through to the console: a client that asked the API a question got an
	// HTML page. Found by this package's self-fuzzing target on its first run.
	h := newHarness(t)

	for _, path := range []string{
		"/v1/campaigns/../../etc/passwd",
		"/v1/campaigns/%2e%2e%2f/findings",
		"/v1/",
		"/v1/campaigns//",
	} {
		req, err := http.NewRequest("GET", h.http.URL+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		// The client must not follow the redirect, or the assertion would be
		// about wherever it landed rather than about this decision.
		client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		resp.Body.Close()

		if resp.StatusCode/100 != 3 {
			t.Errorf("%s answered %d, want a redirect: the path does not survive cleaning",
				path, resp.StatusCode)
		}
		if ct := resp.Header.Get("Location"); ct == "" {
			t.Errorf("%s redirected without saying where to", path)
		}
	}

	// And a path that is already clean is not redirected, so the rule costs
	// nothing on every ordinary request.
	resp, body := h.do("GET", "/v1/info", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/v1/info answered %d: %s", resp.StatusCode, body)
	}
}

func TestASeedSurvivesJSONInEveryFormAClientMightSendIt(t *testing.T) {
	// The value that started this: 14879488505964903031 is what a campaign's
	// seed looks like, and as a JSON number it arrives as 14879488505964902000.
	// A workbench sample generated from that answers a question about a
	// different campaign, silently and plausibly.
	const big = 14879488505964903031

	for _, c := range []struct {
		name string
		body string
		want Seed64
	}{
		{"a quoted 64-bit seed", `"14879488505964903031"`, big},
		{"a small number, as the console has always sent", `42`, 42},
		{"a quoted small number", `"42"`, 42},
		{"absent", `null`, 0},
		{"empty", `""`, 0},
	} {
		t.Run(c.name, func(t *testing.T) {
			var got Seed64
			if err := json.Unmarshal([]byte(c.body), &got); err != nil {
				t.Fatalf("decoding %s: %v", c.body, err)
			}
			if got != c.want {
				t.Errorf("decoded %s as %d, want %d", c.body, got, c.want)
			}
		})
	}

	// Round trip: what comes back out is always a string, so a client that
	// re-sends what it was given loses nothing.
	out, err := json.Marshal(Seed64(big))
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != `"14879488505964903031"` {
		t.Errorf("encoded as %s, want a quoted string", out)
	}
	var back Seed64
	if err := json.Unmarshal(out, &back); err != nil || back != big {
		t.Errorf("round trip gave %d (%v), want %d", back, err, uint64(big))
	}

	// And a number that is not a seed is refused rather than becoming one.
	for _, bad := range []string{`"twelve"`, `1.5`, `-1`} {
		var got Seed64
		if err := json.Unmarshal([]byte(bad), &got); err == nil {
			t.Errorf("%s was accepted as the seed %d", bad, got)
		}
	}
}

func TestASeedInTheRequestBodySaysWhereItBelongs(t *testing.T) {
	// The field existed and nothing read it, so pinning a seed through the API
	// produced a random campaign and no error. Removing it makes the decoder
	// refuse the request, which is right — but a client told only "unknown
	// field" knows its request is wrong and not what to do instead.
	h := newHarness(t)

	var resp Error
	got := h.json(http.MethodPost, "/v1/campaigns", map[string]any{
		"document": h.document("pinned"),
		"name":     "pinned",
		"seed":     42,
	}, &resp)

	if got.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; a seed nobody reads must not look accepted",
			got.StatusCode)
	}
	if !strings.Contains(resp.Error, "seed:") {
		t.Errorf("the error does not say where the seed belongs: %q", resp.Error)
	}
}
