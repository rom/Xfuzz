package api

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/rom/Xfuzz/internal/daemon"
	"github.com/rom/Xfuzz/internal/store"
	"github.com/rom/Xfuzz/pkg/corpus"
	"github.com/rom/Xfuzz/pkg/feedback"
)

// finding files one by hand, the way the store tests do, so the finding
// routes can be exercised without a crash having happened.
func (h *harness) finding(t *testing.T, name string, payload []byte) int64 {
	t.Helper()
	c, err := h.daemon.Campaign(name)
	if err != nil {
		t.Fatal(err)
	}
	f := &store.Finding{
		CampaignID:   c.ID(),
		Digest:       corpus.DigestOf(payload),
		OriginalSize: len(payload),
		Finding: feedback.Finding{Kind: "crash", Signal: 11, Summary: "SIGSEGV",
			Detail: "stack", Frames: []string{"parse+0x10"}},
	}
	// Filed under the campaign's own strategy, which is what the bucket
	// listing reads by default.
	f.SetBucket(c.Config.Triage.Strategy, "parse+0x10")
	if err := c.Store().SaveFinding(context.Background(), f, payload); err != nil {
		t.Fatal(err)
	}
	return f.ID
}

func TestAFindingIsReadableAndItsBucketCounted(t *testing.T) {
	h := newHarness(t)
	h.json("POST", "/v1/campaigns", CampaignRequest{Document: h.document("found")}, nil)
	id := h.finding(t, "found", []byte("crash input"))
	h.finding(t, "found", []byte("crash input two")) // same bucket, second finding

	var got findingView
	if resp := h.json("GET", "/v1/campaigns/found/findings/"+itoa(id), nil, &got); resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if got.ID != id || got.Kind != "crash" || string(got.Reproducer) != "crash input" || got.Bucket == 0 {
		t.Errorf("finding = %+v", got)
	}
	if got.OriginalSize != len("crash input") {
		t.Errorf("original size = %d", got.OriginalSize)
	}

	var buckets struct {
		Buckets []bucketView `json:"buckets"`
		Count   int          `json:"count"`
	}
	if resp := h.json("GET", "/v1/campaigns/found/buckets", nil, &buckets); resp.StatusCode != 200 {
		t.Fatalf("buckets status = %d", resp.StatusCode)
	}
	if buckets.Count != 1 || len(buckets.Buckets) != 1 || buckets.Buckets[0].Count != 2 {
		t.Errorf("buckets = %+v", buckets)
	}
	if buckets.Buckets[0].Signature != "parse+0x10" {
		t.Errorf("bucket = %+v", buckets.Buckets[0])
	}
	// Buckets are per strategy: a strategy nothing was filed under is empty
	// rather than recomputed here.
	h.json("GET", "/v1/campaigns/found/buckets?strategy=coverage", nil, &buckets)
	if buckets.Count != 0 {
		t.Errorf("by a strategy nothing used: %+v", buckets)
	}

	// Filtering by triage state, and a state nothing is in.
	var list struct{ Count int }
	h.json("GET", "/v1/campaigns/found/findings?state="+store.TriageNew, nil, &list)
	if list.Count != 2 {
		t.Errorf("new findings = %d", list.Count)
	}
	h.json("GET", "/v1/campaigns/found/findings?state=verified", nil, &list)
	if list.Count != 0 {
		t.Errorf("verified findings = %d", list.Count)
	}

	if resp, _ := h.do("GET", "/v1/campaigns/found/findings/999", nil); resp.StatusCode != http.StatusNotFound {
		t.Errorf("an absent finding returned %d", resp.StatusCode)
	}
	if resp, _ := h.do("GET", "/v1/campaigns/found/findings/x", nil); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("a non-numeric id returned %d", resp.StatusCode)
	}
}

func TestReplayAndMinimizeRunTheReproducer(t *testing.T) {
	// A created campaign can already replay: triage is built with the
	// campaign, and the reproducer runs through its sandbox. The stub target
	// prints a marker on every run, so what is asserted is the report's
	// shape and that the request's own numbers are honoured.
	h := newHarness(t)
	h.json("POST", "/v1/campaigns", CampaignRequest{Document: h.document("tri")}, nil)
	id := h.finding(t, "tri", []byte("crash input"))

	var rep daemon.ReplayReport
	if resp := h.json("POST", "/v1/campaigns/tri/findings/"+itoa(id)+"/replay", nil, &rep); resp.StatusCode != 200 {
		t.Fatalf("replay = %d", resp.StatusCode)
	}
	if rep.Trials <= 0 || rep.Reproduced < 0 || rep.Reproduced > rep.Trials || rep.State == "" {
		t.Errorf("replay = %+v", rep)
	}
	if resp := h.json("POST", "/v1/campaigns/tri/findings/"+itoa(id)+"/replay", TriageRequest{Trials: 2}, &rep); resp.StatusCode != 200 || rep.Trials != 2 {
		t.Errorf("replay with trials=2: %d %+v", resp.StatusCode, rep)
	}

	if rep.Reproduced != 0 {
		t.Errorf("the stub target reproduced a crash it cannot have: %+v", rep)
	}
	// An input that does not fail has nothing for a minimiser to preserve,
	// and the refusal is an error a client can read rather than a smaller
	// input for no bug.
	resp, body := h.do("POST", "/v1/campaigns/tri/findings/"+itoa(id)+"/minimize", TriageRequest{Budget: 20})
	if resp.StatusCode < 400 || resp.StatusCode >= 500 || !strings.Contains(string(body), "does not fail") {
		t.Errorf("minimize of a non-failing input: %d %s", resp.StatusCode, body)
	}
	// The finding now carries what replay found.
	var f findingView
	h.json("GET", "/v1/campaigns/tri/findings/"+itoa(id), nil, &f)
	if f.ReproTrials != 2 || f.ReproRate != 0 {
		t.Errorf("after replay the finding reads %+v", f)
	}
	for _, route := range []string{"replay", "minimize"} {
		if resp, _ := h.do("POST", "/v1/campaigns/tri/findings/nope/"+route, nil); resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%s with a bad id returned %d", route, resp.StatusCode)
		}
		if resp, _ := h.do("POST", "/v1/campaigns/tri/findings/999/"+route, nil); resp.StatusCode != http.StatusNotFound {
			t.Errorf("%s of an absent finding returned %d", route, resp.StatusCode)
		}
	}
}

func TestDecodeOptionalTakesNothingOrJSON(t *testing.T) {
	var v TriageRequest
	req, _ := http.NewRequest("POST", "/", nil)
	if err := decodeOptional(req, &v); err != nil {
		t.Errorf("no body: %v", err)
	}
	req, _ = http.NewRequest("POST", "/", strings.NewReader(`{"trials":3}`))
	if err := decodeOptional(req, &v); err != nil || v.Trials != 3 {
		t.Errorf("a body: %v %+v", err, v)
	}
	req, _ = http.NewRequest("POST", "/", strings.NewReader(`{`))
	if err := decodeOptional(req, &v); err == nil {
		t.Error("malformed JSON was accepted")
	}
}

func TestCorpusImportAndExportOverTheAPI(t *testing.T) {
	h := newHarness(t)
	h.json("POST", "/v1/campaigns", CampaignRequest{Document: h.document("io")}, nil)

	in := filepath.Join(h.dir, "in")
	os.MkdirAll(in, 0o755)
	os.WriteFile(filepath.Join(in, "a"), []byte("alpha"), 0o644)
	os.WriteFile(filepath.Join(in, "b"), []byte("beta"), 0o644)

	var imp struct {
		Imported  int
		Duplicate int
		Format    string
	}
	if resp := h.json("POST", "/v1/campaigns/io/corpus/import", ImportRequest{Dir: in, Format: "raw"}, &imp); resp.StatusCode != 200 {
		t.Fatalf("import status = %d", resp.StatusCode)
	}
	if imp.Imported != 2 || imp.Format != "raw" {
		t.Errorf("import = %+v", imp)
	}
	if resp, _ := h.do("POST", "/v1/campaigns/io/corpus/import", ImportRequest{Dir: in, Format: "nonsense"}); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("an unknown format returned %d", resp.StatusCode)
	}
	if resp, _ := h.do("POST", "/v1/campaigns/io/corpus/import", ImportRequest{Dir: filepath.Join(h.dir, "absent")}); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("an absent directory returned %d", resp.StatusCode)
	}
	if resp, _ := h.do("POST", "/v1/campaigns/io/corpus/import", "not json"); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("a malformed body returned %d", resp.StatusCode)
	}

	out := filepath.Join(h.dir, "out")
	var exp struct{ Written int }
	if resp := h.json("POST", "/v1/campaigns/io/corpus/export", ExportRequest{Dir: out, Format: "libfuzzer"}, &exp); resp.StatusCode != 200 {
		t.Fatalf("export status = %d", resp.StatusCode)
	}
	if exp.Written != 2 {
		t.Errorf("export = %+v", exp)
	}
	if resp, _ := h.do("POST", "/v1/campaigns/io/corpus/export", ExportRequest{Dir: out, Format: "libfuzzer"}); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("an export into a full directory returned %d, want a refusal", resp.StatusCode)
	}
	if resp := h.json("POST", "/v1/campaigns/io/corpus/export", ExportRequest{Dir: out, Format: "raw", Overwrite: true, FavouredOnly: true}, &exp); resp.StatusCode != 200 {
		t.Errorf("an overwriting export returned %d", resp.StatusCode)
	}
	if resp, _ := h.do("GET", "/v1/campaigns/io/corpus/zz", nil); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("a malformed digest returned %d", resp.StatusCode)
	}
	if resp, _ := h.do("GET", "/v1/campaigns/io/corpus/"+strings.Repeat("0", 64), nil); resp.StatusCode != http.StatusNotFound {
		t.Errorf("an absent digest returned %d", resp.StatusCode)
	}
}

func TestMetricsRoutesAnswerForACreatedCampaign(t *testing.T) {
	h := newHarness(t)
	h.json("POST", "/v1/campaigns", CampaignRequest{Document: h.document("m")}, nil)

	var snap map[string]any
	if resp := h.json("GET", "/v1/campaigns/m/metrics", nil, &snap); resp.StatusCode != 200 {
		t.Fatalf("metrics = %d", resp.StatusCode)
	}
	if _, ok := snap["execs"]; !ok {
		t.Errorf("no execs in %v", snap)
	}
	var hist struct{ Points []any }
	if resp := h.json("GET", "/v1/campaigns/m/metrics/history", nil, &hist); resp.StatusCode != 200 {
		t.Errorf("history = %d", resp.StatusCode)
	}
	var health struct{ Diagnostics []any }
	if resp := h.json("GET", "/v1/campaigns/m/health", nil, &health); resp.StatusCode != 200 {
		t.Errorf("health = %d", resp.StatusCode)
	}
	var states struct {
		Fn     string
		States []any
	}
	if resp := h.json("GET", "/v1/campaigns/m/states", nil, &states); resp.StatusCode != 200 {
		t.Errorf("states = %d", resp.StatusCode)
	}
	if len(states.States) != 0 {
		t.Errorf("a file campaign has states: %+v", states)
	}
}

func TestStartStopResumeOverTheAPI(t *testing.T) {
	h := newHarness(t)
	h.json("POST", "/v1/campaigns", CampaignRequest{Document: h.document("life2")}, nil)

	var st daemon.Status
	if resp := h.json("POST", "/v1/campaigns/life2/start", nil, &st); resp.StatusCode != 200 {
		t.Fatalf("start = %d", resp.StatusCode)
	}
	if st.State != daemon.StateRunning {
		t.Errorf("after start the state is %s", st.State)
	}
	// Resume is for a paused campaign; a running one is refused with a status
	// a client can act on.
	if resp, _ := h.do("POST", "/v1/campaigns/life2/resume", nil); resp.StatusCode != http.StatusConflict {
		t.Errorf("resuming a running campaign returned %d", resp.StatusCode)
	}
	if resp, _ := h.do("POST", "/v1/campaigns/life2/start", nil); resp.StatusCode != http.StatusConflict {
		t.Errorf("starting twice returned %d", resp.StatusCode)
	}
	resp := h.json("POST", "/v1/campaigns/life2/stop?reason=test%20over", nil, &st)
	if resp.StatusCode != 200 {
		t.Fatalf("stop = %d", resp.StatusCode)
	}
	if st.State == daemon.StateRunning {
		t.Errorf("after stop the state is still running")
	}
	if st.Reason != "test over" {
		t.Errorf("the reason was not recorded: %q", st.Reason)
	}
	// And a stopped campaign cannot be forgotten while... it can: it is not
	// running. The store stays, which load proves.
	if resp, _ := h.do("DELETE", "/v1/campaigns/life2", nil); resp.StatusCode != 200 {
		t.Errorf("forget after stop returned %d", resp.StatusCode)
	}
	if resp := h.json("POST", "/v1/campaigns/load", map[string]string{"name": "life2"}, &st); resp.StatusCode != 200 {
		t.Errorf("load after forget returned %d", resp.StatusCode)
	}
	if resp, _ := h.do("POST", "/v1/campaigns/load", map[string]string{"name": "never"}); resp.StatusCode != http.StatusNotFound {
		t.Errorf("loading a campaign with no store returned %d", resp.StatusCode)
	}
}

func TestCapabilitiesDescribeThisHost(t *testing.T) {
	// The doctor's report, which probes rather than assumes: every row is a
	// measurement on the host answering. What can be asserted is its shape
	// and that the rows a first campaign depends on are present.
	h := newHarness(t)
	var rep CapabilitiesResponse
	if resp := h.json("GET", "/v1/capabilities", nil, &rep); resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if rep.Platform == "" || rep.Isolation == "" || rep.Explanation == "" {
		t.Errorf("report = %+v", rep)
	}
	names := map[string]Capability{}
	for _, c := range rep.Capabilities {
		names[c.Name] = c
	}
	for _, want := range []string{"shared-memory", "process-groups", "rlimits", "pseudo-terminal", "browser",
		"desktop-accessibility", "xfuzz-worker", "clang", "gocov", "ptrace-bb", "qemu", "frida",
		"data-directory", "execution", "web-console"} {
		if _, ok := names[want]; !ok {
			t.Errorf("no %q row in %v", want, keys(names))
		}
	}
	// Every row explains itself: a bare yes or no is not a diagnosis.
	for _, c := range rep.Capabilities {
		if c.Detail == "" {
			t.Errorf("%s has no detail", c.Name)
		}
	}
	// The execution probe runs this daemon's own binary with --version, which
	// under `go test` is the test binary and does not take that flag; so the
	// row's presence and its explanation are what can be checked here.
	if names["execution"].Detail == "" {
		t.Error("the execution probe explained nothing")
	}
	if got := names["web-console"].Available; got != ConsoleBuilt() {
		t.Errorf("web-console = %v, ConsoleBuilt() = %v", got, ConsoleBuilt())
	}
}

func keys(m map[string]Capability) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestAuditIsChainedAndReadable(t *testing.T) {
	h := newHarness(t)
	var empty struct {
		Entries  []any `json:"entries"`
		Verified int   `json:"verified"`
	}
	if resp := h.json("GET", "/v1/audit", nil, &empty); resp.StatusCode != 200 {
		t.Fatalf("with no campaign: %d", resp.StatusCode)
	}

	h.json("POST", "/v1/campaigns", CampaignRequest{Document: h.document("audited")}, nil)
	var got struct {
		Entries  []map[string]any `json:"entries"`
		Verified int              `json:"verified"`
		Intact   bool             `json:"intact"`
	}
	if resp := h.json("GET", "/v1/audit", nil, &got); resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if !got.Intact {
		t.Error("a fresh audit log reports tampering")
	}
	if len(got.Entries) == 0 || got.Verified != len(got.Entries) {
		t.Errorf("entries = %d, verified = %d", len(got.Entries), got.Verified)
	}
}

func TestSchemaAndOpenAPIAreServedAsTheirTypes(t *testing.T) {
	h := newHarness(t)
	resp, raw := h.do("GET", "/v1/openapi.json", nil)
	if resp.StatusCode != 200 || !strings.Contains(resp.Header.Get("Content-Type"), "application/json") {
		t.Errorf("openapi: %d %s", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	var doc struct {
		Paths map[string]any `json:"paths"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil || len(doc.Paths) == 0 {
		t.Errorf("the OpenAPI document has no paths: %v", err)
	}
	resp, raw = h.do("GET", "/v1/schema", nil)
	if resp.StatusCode != 200 || !strings.Contains(resp.Header.Get("Content-Type"), "schema+json") {
		t.Errorf("schema: %d %s", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	if !strings.Contains(string(raw), `"properties"`) {
		t.Error("the schema has no properties")
	}
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }
