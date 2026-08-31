//go:build integration

// The two tiers a campaign file selects by naming a block rather than a mode:
// an api block replays HTTP against a service, and a driver block drives a
// terminal program. Both run the whole worker — the corpus, the mutators, the
// feedback stack, the triage — which is the claim ADR-0013 and ADR-0014 both
// rest on.

package worker

import (
	"context"
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
	"github.com/rom/Xfuzz/internal/safety"
	"github.com/rom/Xfuzz/internal/testenv"
	"github.com/rom/Xfuzz/pkg/campaign"
)

// runWorker starts a worker on a campaign and returns what it reported.
func runWorker(t *testing.T, cfg *campaign.Resolved, until func(*observer) bool,
	why string, bound time.Duration) *observer {

	t.Helper()
	p := newPipes(t)
	obs := &observer{}
	go obs.watch(p)

	w := New(Options{
		Config: cfg, ID: 0, Seed: 0x5EED,
		Control: p.toWorker, Status: p.status,
		ReportInterval: 100 * time.Millisecond,
	})
	t.Cleanup(func() { w.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), bound+30*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- w.Run(ctx) }()

	waitFor(t, obs, 30*time.Second, func(o *observer) bool { return o.ready != nil },
		"the worker never announced itself")
	waitFor(t, obs, bound, until, why)

	_ = daemon.NewEncoder(p.control).Encode(&daemon.Message{Type: daemon.CmdStop})
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		obs.mu.Lock()
		t.Errorf("the worker did not stop when asked (execs %d, stopped %q, logs %v)",
			obs.execs, obs.stopped, obs.logs)
		obs.mu.Unlock()
	}
	return obs
}

func writeFile(t *testing.T, dir, name, body string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestWorkerReplaysACaptureAndJudgesTheResponses is the v0.4 path end to end: a
// recorded session becomes a seed, the requests are replayed against a live
// service, and a response oracle rather than a crash is what produces the
// finding — because a service almost never crashes.
func TestWorkerReplaysACaptureAndJudgesTheResponses(t *testing.T) {
	var seen int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		seen++
		// The planted bug: a body the handler cannot cope with produces a 500,
		// which is the shape of nearly every real API finding.
		if strings.Contains(string(body), "\x00") || len(body) > 64 {
			w.WriteHeader(http.StatusInternalServerError)
			io.WriteString(w, `{"error":"boom"}`)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"ok":true,"seen":%d}`, seen)
	}))
	defer srv.Close()

	dir := t.TempDir()
	session := "POST /items HTTP/1.1\r\nHost: h\r\nContent-Type: application/json\r\n" +
		"Content-Length: 17\r\n\r\n{\"name\":\"widget\"}" +
		"GET /items/1 HTTP/1.1\r\nHost: h\r\n\r\n"
	capturePath := writeFile(t, dir, "session.http", session)

	body := "name: apitest\n" +
		"api:\n" +
		"  address: tcp:" + strings.TrimPrefix(srv.URL, "http://") + "\n" +
		"  capture: " + capturePath + "\n" +
		"  oracles: [status]\n" +
		// A local service answers in microseconds; five seconds is the default
		// for a service across a network, and here it is only how long a
		// malformed request stalls before the tier gives up on it.
		"  per_request: 150ms\n  timeout: 2s\n" +
		"feedback:\n  coverage: none\n  novelty: true\n" +
		"stop:\n  execs: 4000\n"
	cfgPath := writeFile(t, dir, "c.yaml", body)
	cfg, err := campaign.Load(cfgPath)
	if err != nil {
		t.Fatalf("loading the campaign: %v\n%s", err, body)
	}

	obs := runWorker(t, cfg, func(o *observer) bool { return o.findings > 0 },
		"no 5xx was reported against a service that answers 500 to a mutated body",
		90*time.Second)

	obs.mu.Lock()
	defer obs.mu.Unlock()
	t.Logf("ready: %s", obs.ready.Executor)
	if !strings.Contains(obs.ready.Executor, "api") {
		t.Errorf("the worker built the %q tier", obs.ready.Executor)
	}
	if !strings.Contains(obs.ready.Executor, "request") {
		t.Errorf("the ready message does not say what the capture held: %s", obs.ready.Executor)
	}
	if obs.ready.Seeds == 0 {
		t.Error("the capture did not become a seed")
	}
	if obs.kinds["server-error"] == 0 {
		t.Errorf("the findings are %v; the status oracle reported none", obs.kinds)
	}
}

// TestWorkerDrivesATerminalProgram is the v0.5 path end to end: a sequence of
// keystrokes is the input, a screen is the state, and the finding comes from an
// oracle reading the screen.
func TestWorkerDrivesATerminalProgram(t *testing.T) {
	if !safety.PTYSupported() {
		t.Skip("no pseudo-terminal support on this host")
	}
	dir := testenv.ReachableDir(t)
	target := testenv.BuildAt(t, filepath.Join(dir, "tui_menu"), "./testdata/targets/go/tui_menu")

	body := "name: tuitest\n" +
		"target:\n  path: " + target + "\n" +
		"driver:\n" +
		"  kind: tui\n  cols: 40\n  rows: 12\n  settle: 20ms\n  max_events: 12\n" +
		"  oracles: [diagnostic, unresponsive]\n" +
		"seeds:\n  inline: [\"key 1\\nkey down\\nkey down\\nkey d\\n\", \"key 2\\nkey x\\nkey escape\\n\"]\n" +
		"feedback:\n  coverage: none\n  novelty: true\n" +
		"stop:\n  execs: 400\n"
	cfgPath := writeFile(t, t.TempDir(), "c.yaml", body)
	cfg, err := campaign.Load(cfgPath)
	if err != nil {
		t.Fatalf("loading the campaign: %v\n%s", err, body)
	}

	obs := runWorker(t, cfg, func(o *observer) bool { return o.findings > 0 },
		"no finding from a terminal program with a planted crash and a planted "+
			"unrecoverable screen", 180*time.Second)

	obs.mu.Lock()
	defer obs.mu.Unlock()
	t.Logf("ready: %s findings: %v", obs.ready.Executor, obs.kinds)
	if !strings.Contains(obs.ready.Executor, "tui") {
		t.Errorf("the worker built the %q tier", obs.ready.Executor)
	}
	if obs.execs == 0 {
		t.Error("the worker reported no executions")
	}
	// Whichever oracle spoke first, it must be one of the interface ones or a
	// crash: what must not happen is a campaign that runs sequences and reports
	// nothing, which is what an interface campaign without oracles does.
	var ui int
	for kind, n := range obs.kinds {
		if strings.HasPrefix(kind, "ui-") || kind == "crash" {
			ui += n
		}
	}
	if ui == 0 {
		t.Errorf("the findings are %v; none came from the interface", obs.kinds)
	}
}

// TestWorkerDrivesAWebApplication is the v0.8 path end to end: a browser is the
// harness, a page is the target, a sequence of keystrokes and clicks is the
// input, and the finding is an exception nothing else would have noticed —
// the process does not exit, no signal is raised, and the HTTP status is 200.
//
// The whole machine, deliberately. What ADR-0013 claims about the driver tier
// is that a second interface domain costs one backend and nothing else: the
// same corpus, the same mutation operators over an IR Repeat, the same state
// model, the same triage. This test fails if any of that turned out to need a
// special case.
func TestWorkerDrivesAWebApplication(t *testing.T) {
	browser := testenv.Browser(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		io.WriteString(w, webBugPage)
	}))
	defer srv.Close()

	host := strings.TrimPrefix(srv.URL, "http://")
	body := "name: webtest\n" +
		"target:\n  path: " + browser + "\n" +
		"driver:\n" +
		"  kind: web\n  url: " + srv.URL + "\n" +
		"  settle: 40ms\n  max_events: 10\n  width: 400\n  height: 300\n" +
		"  start_timeout: 15s\n" +
		// The browser's own sandbox is off because the suite runs as root in a
		// container, where Chromium refuses to start with it. A campaign on an
		// ordinary machine leaves it on, which is the default.
		"  browser_sandbox: false\n" +
		"  oracles: [exception]\n" +
		"seeds:\n  inline: [\"click 100,20\\ntext xyzz\\nkey y\\n\", \"click 50,70\\nkey tab\\n\"]\n" +
		"feedback:\n  coverage: none\n  novelty: true\n" +
		"safety:\n  network: true\n" +
		"  scope:\n    allow: [\"" + host + "\"]\n" +
		"  authorization:\n" +
		"    operator: \"suite@example.test\"\n" +
		"    reference: \"XFUZZ-TESTS\"\n" +
		"    attestation: \"authorised to test the declared scope\"\n" +
		"stop:\n  execs: 60\n"

	cfgPath := writeFile(t, t.TempDir(), "c.yaml", body)
	cfg, err := campaign.Load(cfgPath)
	if err != nil {
		t.Fatalf("loading the campaign: %v\n%s", err, body)
	}

	obs := runWorker(t, cfg, func(o *observer) bool { return o.findings > 0 },
		"no finding from a page whose handler throws on one particular input",
		240*time.Second)

	obs.mu.Lock()
	defer obs.mu.Unlock()
	t.Logf("ready: %s seeds: %d findings: %v execs: %d logs: %v",
		obs.ready.Executor, obs.ready.Seeds, obs.kinds, obs.execs, obs.logs)
	if !strings.Contains(obs.ready.Executor, "web") {
		t.Errorf("the worker built the %q tier", obs.ready.Executor)
	}
	if obs.execs == 0 {
		t.Error("the worker reported no executions")
	}
	if obs.kinds["ui-exception"] == 0 {
		t.Errorf("the findings are %v; the exception oracle reported none, so the "+
			"uncaught error never reached a finding", obs.kinds)
	}
}

// webBugPage is a page that fails the way web applications fail: an exception
// inside an event handler, reachable only by typing one particular string.
const webBugPage = `<!doctype html>
<html><head><title>xfuzz web target</title>
<style>
 body { margin: 0; font: 16px sans-serif; }
 #q   { position: absolute; left: 0;    top: 0;    width: 200px; height: 40px; }
 #go  { position: absolute; left: 0;    top: 50px; width: 100px; height: 40px; }
 #box { position: absolute; left: 0;    top: 100px; }
</style></head>
<body>
<input id="q" type="text">
<button id="go">go</button>
<div id="box" hidden><p>opened</p></div>
<script>
var q = document.getElementById('q');
q.addEventListener('keyup', function () {
  if (q.value === 'xyzzy') { null.explode(); }
});
document.getElementById('go').addEventListener('click', function () {
  document.getElementById('box').hidden = false;
});
</script>
</body></html>`
