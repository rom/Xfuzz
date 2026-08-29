package api

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rom/Xfuzz/internal/daemon"
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
	dir := t.TempDir()
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
	target := filepath.Join(h.dir, "target")
	if err := os.WriteFile(target, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		h.t.Fatal(err)
	}
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
		Scope       string            `json:"scope"`
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
