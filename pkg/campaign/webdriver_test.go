package campaign

import (
	"strings"
	"testing"
)

// webCampaign writes a valid web campaign with the given driver block lines
// spliced in.
func webCampaign(t *testing.T, dir, extra string) string {
	t.Helper()
	return write(t, dir, "web.yaml", `
name: web
driver:
  kind: web
  url: http://127.0.0.1:8080/app
  oracles: [exception]
`+extra+`
safety:
  network: true
  scope:
    allow: ["127.0.0.1:8080"]
  authorization:
    operator: "tester@example.test"
    reference: "TEST-1"
    attestation: "authorised to test the declared scope"
seeds:
  inline: ["key tab\nkey enter"]
`)
}

func TestWebCampaignNeedsNoTargetPath(t *testing.T) {
	// The browser is the harness and the target is on the other side of a URL,
	// so demanding an executable would be demanding a file that does not exist
	// for this kind of campaign — the same reason an API campaign does not need
	// one.
	dir := t.TempDir()
	r, err := Load(webCampaign(t, dir, ""))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if r.Driver.Kind != DriverWeb {
		t.Fatalf("driver.kind = %q", r.Driver.Kind)
	}
	if r.Driver.Width != 1280 || r.Driver.Height != 800 {
		t.Errorf("viewport defaulted to %dx%d", r.Driver.Width, r.Driver.Height)
	}
	if r.Driver.BrowserSandbox == nil || !*r.Driver.BrowserSandbox {
		t.Error("the browser's own sandbox is not on by default, which is the layer " +
			"between a hostile page and the machine")
	}
}

func TestWebCampaignRequiresAURL(t *testing.T) {
	dir := t.TempDir()
	path := write(t, dir, "c.yaml", `
name: web
driver:
  kind: web
  oracles: [exception]
safety:
  network: true
  scope:
    allow: ["127.0.0.1:8080"]
  authorization:
    operator: "tester@example.test"
    reference: "TEST-1"
    attestation: "authorised to test the declared scope"
seeds:
  inline: ["key tab"]
`)
	_, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), "driver.url") {
		t.Fatalf("a web campaign with no URL was accepted: %v", err)
	}
}

func TestWebCampaignRefusesAURLNoBrowserCanOpen(t *testing.T) {
	dir := t.TempDir()
	path := write(t, dir, "c.yaml", `
name: web
driver:
  kind: web
  url: ftp://example.test/thing
  oracles: [exception]
safety:
  network: true
  scope:
    allow: ["127.0.0.1:8080"]
  authorization:
    operator: "tester@example.test"
    reference: "TEST-1"
    attestation: "authorised to test the declared scope"
seeds:
  inline: ["key tab"]
`)
	_, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), "driver.url") {
		t.Fatalf("ftp:// was accepted as a page: %v", err)
	}
}

func TestWebCampaignRequiresNetwork(t *testing.T) {
	// Not a warning: it does not work. A browser in a network namespace of its
	// own has its own loopback, so the debugging endpoint it announces is
	// unreachable and it could not load the page either. Failing at validation
	// beats a campaign that starts and cannot connect to anything.
	dir := t.TempDir()
	path := write(t, dir, "c.yaml", `
name: web
driver:
  kind: web
  url: http://127.0.0.1:8080/app
  oracles: [exception]
seeds:
  inline: ["key tab"]
`)
	_, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), "safety.network") {
		t.Fatalf("a web campaign without network access was accepted: %v", err)
	}
}

func TestWebViewportIsBounded(t *testing.T) {
	dir := t.TempDir()
	_, err := Load(webCampaign(t, dir, "  width: 4\n  height: 800\n"))
	if err == nil || !strings.Contains(err.Error(), "driver.width") {
		t.Fatalf("a four-pixel viewport was accepted: %v", err)
	}
}

func TestTheExceptionOracleIsAWebOracle(t *testing.T) {
	// It reports what the browser's protocol said, and only the web backend has
	// one. A terminal campaign asking for it would get an oracle that can never
	// fire, which is worse than an error because it looks configured.
	dir := t.TempDir()
	target(t, dir)
	path := write(t, dir, "c.yaml", `
name: tui
target:
  path: ./target
driver:
  kind: tui
  oracles: [exception]
seeds:
  inline: ["key tab"]
`)
	_, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), "driver.oracles") {
		t.Fatalf("a terminal campaign was given the exception oracle: %v", err)
	}
}

func TestATerminalCampaignIsUnaffectedByTheWebFields(t *testing.T) {
	// The regression this guards: adding a second backend must not change what
	// the first one validates. cols and rows still bound a terminal, and the
	// pixel viewport is not checked for one.
	dir := t.TempDir()
	target(t, dir)
	path := write(t, dir, "c.yaml", `
name: tui
target:
  path: ./target
driver:
  kind: tui
  cols: 4
seeds:
  inline: ["key tab"]
`)
	_, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), "driver.cols") {
		t.Fatalf("a four-column terminal was accepted: %v", err)
	}
}
