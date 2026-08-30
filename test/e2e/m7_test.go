//go:build integration

// M7's exit criteria: the console.
//
// The console is a pure API client with no privileged path of its own
// (ADR-0011), so "can this be done from the console" is exactly "is this a
// route, and does it work over the daemon's own listener". These drive that
// listener the way the console's fetch() does — over the Unix socket, as JSON —
// rather than through the CLI, so what they prove is the console's reach and
// not the CLI's.
//
// What they cannot prove is that it renders, which was checked by driving a
// browser against a live campaign and reading the result.

package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// console is an HTTP client over the daemon's socket: the console's own path.
type console struct {
	t    *testing.T
	http *http.Client
}

func newConsole(t *testing.T, dataDir string) *console {
	t.Helper()
	socket := filepath.Join(dataDir, "xfuzzd.sock")
	return &console{
		t: t,
		http: &http.Client{
			Timeout: 60 * time.Second,
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					return (&net.Dialer{}).DialContext(ctx, "unix", socket)
				},
			},
		},
	}
}

func (c *console) do(method, path string, body any, out any) error {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, "http://unix"+path, rdr)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)

	if resp.StatusCode >= 400 {
		return fmt.Errorf("%s %s: %d: %s", method, path, resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	if out != nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, out); err != nil {
			return fmt.Errorf("%s %s: unreadable response: %w\n%s", method, path, err, raw)
		}
	}
	return nil
}

func (c *console) must(method, path string, body any, out any) {
	c.t.Helper()
	if err := c.do(method, path, body, out); err != nil {
		c.t.Fatal(err)
	}
}

// M7's first criterion: a campaign is configurable, launchable, monitorable and
// triageable entirely from the console.
func TestACampaignIsRunEntirelyFromTheConsole(t *testing.T) {
	e := newEnvFor(t, "simple_parser")
	// A daemon has to exist before there is a socket to talk to, and starting
	// one is the CLI's job on a machine where nothing is running yet.
	e.mustRun(60*time.Second, "info")
	c := newConsole(t, e.dataDir)

	// Configurable. The console edits the campaign file rather than a form over
	// it, so the document it holds is the document that runs.
	doc := fmt.Sprintf(`# Written in the console.
name: console-run

target:
  # A comment the console must not eat.
  path: %s
  input: stdin

seeds:
  inline: ["a", "bb", "ccc"]

feedback:
  coverage: sancov

workers:
  count: 1

stop:
  after: 20s
`, e.target)

	var edited struct {
		Document string `json:"document"`
		Valid    bool   `json:"valid"`
		Error    string `json:"error"`
	}
	c.must("POST", "/v1/campaigns/edit", map[string]any{
		"document": doc, "name": "console-run",
		"set": map[string]any{"workers.count": 2},
	}, &edited)

	if !edited.Valid {
		t.Fatalf("the edited campaign did not validate: %s", edited.Error)
	}
	if !strings.Contains(edited.Document, "count: 2") {
		t.Errorf("the edit did not take:\n%s", edited.Document)
	}
	// M7's third criterion, in the place it actually matters: the console's own
	// round-trip, not a unit test's.
	for _, comment := range []string{"# Written in the console.", "# A comment the console must not eat."} {
		if !strings.Contains(edited.Document, comment) {
			t.Errorf("the console ate a comment: %q\n%s", comment, edited.Document)
		}
	}
	if !strings.Contains(edited.Document, "\n\nseeds:") {
		t.Errorf("the console reflowed the file, losing its paragraphs:\n%s", edited.Document)
	}

	// Launchable.
	var created struct {
		Name string `json:"name"`
	}
	c.must("POST", "/v1/campaigns", map[string]any{
		"document": edited.Document, "name": "console-run",
	}, &created)
	c.must("POST", "/v1/campaigns/"+created.Name+"/start", nil, nil)

	// Monitorable: the numbers the console leads with have to become real.
	deadline := time.Now().Add(90 * time.Second)
	var status campaignStatus
	for time.Now().Before(deadline) {
		c.must("GET", "/v1/campaigns/"+created.Name, nil, &status)
		if status.Metrics.Execs > 0 && status.Metrics.Coverage > 0 {
			break
		}
		time.Sleep(time.Second)
	}
	if status.Metrics.Execs == 0 {
		t.Fatal("the console watched a campaign that never executed anything")
	}
	t.Logf("console saw %d execs, %d edges, %d corpus entries",
		status.Metrics.Execs, status.Metrics.Coverage, status.Metrics.CorpusSize)

	// A 64-bit seed survives the trip. It is half of what a byte-identical
	// replay needs, and JSON numbers are doubles in the browser this is for.
	if status.Seed == 0 {
		t.Error("the console was given no seed")
	}
	var raw map[string]any
	c.must("GET", "/v1/campaigns/"+created.Name, nil, &raw)
	if _, isString := raw["seed"].(string); !isString {
		t.Errorf("the seed is sent as %T; a 64-bit value does not survive a JSON number", raw["seed"])
	}

	// The other monitoring views the console offers.
	for _, path := range []string{"/health", "/metrics/history", "/workers", "/safety", "/corpus"} {
		if err := c.do("GET", "/v1/campaigns/"+created.Name+path, nil, nil); err != nil {
			t.Errorf("the console cannot read %s: %v", path, err)
		}
	}

	// Triageable. Wait for a finding, then judge it the way the console does.
	var findings struct {
		Findings []struct {
			ID          int64  `json:"id"`
			Disposition string `json:"disposition"`
			Notes       string `json:"notes"`
			Diagnosis   string `json:"diagnosis"`
		} `json:"findings"`
	}
	deadline = time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		c.must("GET", "/v1/campaigns/"+created.Name+"/findings", nil, &findings)
		if len(findings.Findings) > 0 {
			break
		}
		time.Sleep(2 * time.Second)
	}
	if len(findings.Findings) == 0 {
		t.Fatal("no findings to triage; simple_parser's planted bugs were not reached")
	}

	id := findings.Findings[0].ID
	var judged struct {
		Disposition string `json:"disposition"`
		Notes       string `json:"notes"`
		Diagnosis   string `json:"diagnosis"`
	}
	c.must("POST", fmt.Sprintf("/v1/campaigns/%s/findings/%d/triage", created.Name, id),
		map[string]any{"disposition": "duplicate", "notes": "same as the one Ana filed"}, &judged)

	if judged.Disposition != "duplicate" {
		t.Errorf("the judgement did not take: %q", judged.Disposition)
	}
	if judged.Notes != "same as the one Ana filed" {
		t.Errorf("the note did not take: %q", judged.Notes)
	}

	// And re-running triage must not erase it. This is the whole reason a
	// person's judgement is not stored in the machine's field.
	if err := c.do("POST", fmt.Sprintf("/v1/campaigns/%s/findings/%d/replay", created.Name, id), nil, nil); err != nil {
		t.Logf("replay: %v", err)
	}
	var after struct {
		Disposition string `json:"disposition"`
		Notes       string `json:"notes"`
	}
	c.must("GET", fmt.Sprintf("/v1/campaigns/%s/findings/%d", created.Name, id), nil, &after)
	if after.Disposition != "duplicate" || after.Notes == "" {
		t.Errorf("re-running triage erased the judgement: disposition %q, notes %q",
			after.Disposition, after.Notes)
	}

	c.must("POST", "/v1/campaigns/"+created.Name+"/stop", nil, nil)
}

// M7's other half of "triage tomorrow": the console reaches a finished campaign
// from its store, with the file that produced it gone.
func TestTheConsoleOpensAFinishedCampaign(t *testing.T) {
	e := newEnvFor(t, "simple_parser")
	path := e.writeCampaign("archived", 1, 15*time.Second, "")
	e.mustRun(3*time.Minute, "run", path)

	// The daemon forgets it, and the file goes.
	e.mustRun(30*time.Second, "forget", "archived")
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}

	c := newConsole(t, e.dataDir)
	var loaded struct {
		Name string `json:"name"`
	}
	c.must("POST", "/v1/campaigns/load", map[string]any{"name": "archived"}, &loaded)
	if loaded.Name != "archived" {
		t.Fatalf("loaded %q", loaded.Name)
	}

	// And what it loaded is readable: the corpus and findings the run produced.
	var corpus struct {
		Entries []struct {
			Digest string `json:"digest"`
		} `json:"entries"`
	}
	c.must("GET", "/v1/campaigns/archived/corpus", nil, &corpus)
	if len(corpus.Entries) == 0 {
		t.Error("the loaded campaign has no corpus; its store was not opened")
	}
}
