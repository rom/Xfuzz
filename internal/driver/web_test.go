package driver

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rom/Xfuzz/internal/safety"
	"github.com/rom/Xfuzz/internal/testenv"
	"github.com/rom/Xfuzz/pkg/executor"
)

// The page under test: a small application with a planted bug.
//
// The bug is the shape a web application actually fails in — an exception
// thrown inside an event handler. Nothing crashes, no process exits, the HTTP
// status is 200, and the only way to know it happened is to have been listening
// to the browser.
const plantedPage = `<!doctype html>
<html><head><title>Xfuzz test page</title>
<style>
 body { margin: 0; font: 16px sans-serif; }
 #q    { position: absolute; left: 0;    top: 0;    width: 200px; height: 40px; }
 #go   { position: absolute; left: 0;    top: 50px; width: 100px; height: 40px; }
 #ask  { position: absolute; left: 120px; top: 50px; width: 100px; height: 40px; }
 #panel{ position: absolute; left: 0;    top: 100px; }
 h1    { position: absolute; left: 0;    top: 150px; margin: 0; }
</style></head>
<body>
<input id="q" type="text" placeholder="type here">
<button id="go">go</button>
<button id="ask">ask</button>
<div id="panel" hidden><p>the panel is open</p></div>
<h1 id="heading">search</h1>
<script>
var q = document.getElementById('q');
q.addEventListener('keyup', function () {
  if (q.value === 'xyzzy') {
    // The planted bug: reachable only by typing one particular string.
    null.explode();
  }
});
document.getElementById('go').addEventListener('click', function () {
  document.getElementById('panel').hidden = false;
});
document.getElementById('ask').addEventListener('click', function () {
  window.alert('a modal nobody dismissed');
});
</script>
</body></html>`

// Where the page's controls are.
//
// Absolutely positioned in the fixture so a click lands where the test means
// it to. A campaign clicks wherever the mutator says, which is the point; a
// test that did the same would pass or fail on the browser's default margins.
const (
	fieldX, fieldY = 100, 20
	goX, goY       = 50, 70
	askX, askY     = 170, 70
)

// webSpawner is the spawner a web campaign needs.
//
// Network: true is not a test convenience. A browser in a network namespace of
// its own has its own loopback, so the debugging endpoint it announces on
// 127.0.0.1 is not the fuzzer's 127.0.0.1 and the connection is refused — and
// it could not reach the target URL either. A web campaign reaches the network
// by definition, which is why the worker sets this and why the scope guard is
// what constrains it.
func webSpawner() *safety.Spawner {
	s := safety.NewSpawner()
	s.Sandbox = &safety.Sandbox{Network: true}
	return s
}

// webFixture serves the page and returns a started driver.
func webFixture(t *testing.T) (*Web, string) {
	t.Helper()
	browser := testenv.Browser(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(plantedPage))
	}))
	t.Cleanup(srv.Close)

	d := NewWeb(webSpawner(), WebOptions{
		URL:     srv.URL,
		Browser: browser,
		// The browser's own sandbox is off here and only here. The suite runs
		// as root in a container, where Chromium refuses to start with it —
		// which is the browser's decision, not this driver's, and a campaign
		// hits the same wall with the browser's own message.
		BrowserSandbox: false,
		Settle:         80 * time.Millisecond,
		MaxSettle:      3 * time.Second,
		StartTimeout:   45 * time.Second,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			var dl net.Dialer
			return dl.DialContext(ctx, network, address)
		},
	})
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	if err := d.Start(ctx); err != nil {
		t.Fatalf("starting the browser: %v", err)
	}
	t.Cleanup(func() { d.Close() })
	// The first paint, which the tier waits for too: Driver.Run reads the state
	// the reset left behind before it sends anything.
	d.Settle(ctx)
	return d, srv.URL
}

func send(t *testing.T, d *Web, evs ...executor.Event) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	for _, e := range evs {
		if err := d.Send(ctx, e); err != nil {
			t.Fatalf("%v: %v", e, err)
		}
		d.Settle(ctx)
	}
}

func TestWebDriverReachesThePageAndReadsItsShape(t *testing.T) {
	d, _ := webFixture(t)
	state := string(d.State())
	for _, want := range []string{"Xfuzz test page", "h1#heading", "input#q[text=empty]", "button#go"} {
		if !strings.Contains(state, want) {
			t.Errorf("the state does not mention %q:\n%s", want, state)
		}
	}
	if !strings.Contains(state, "div#panel:hidden") {
		t.Errorf("a hidden element is not reported as hidden:\n%s", state)
	}
}

func TestWebStateSeparatesScreensButNotKeystrokes(t *testing.T) {
	// The property the whole state model rests on. Typing must not create a new
	// state — otherwise every sequence reaches somewhere new and the model
	// learns nothing — while opening a panel must.
	d, _ := webFixture(t)
	before := string(d.State())

	send(t, d, executor.Event{Kind: executor.EventClick, X: fieldX, Y: fieldY})
	send(t, d, executor.Event{Kind: executor.EventText, Text: "hello"})
	typed := string(d.State())

	send(t, d, executor.Event{Kind: executor.EventClick, X: goX, Y: goY})
	opened := string(d.State())

	if typed == before {
		// The input went from empty to set, which is a real difference and one
		// worth seeing: a form with something in it is a different screen from
		// an empty one.
		t.Logf("typing did not change the state, which is acceptable but means the "+
			"click may have missed the field:\n%s", typed)
	}
	if strings.Contains(typed, "hello") {
		t.Errorf("the typed text reached the fingerprint, so every keystroke is a "+
			"new state and the model learns nothing:\n%s", typed)
	}
	if opened == typed {
		t.Errorf("opening the panel did not change the state, so the campaign is "+
			"blind to the transition:\n%s", opened)
	}
	if !strings.Contains(opened, "the panel is open") {
		t.Errorf("the panel's text is not in the state:\n%s", opened)
	}
}

func TestWebDriverFindsThePlantedException(t *testing.T) {
	d, _ := webFixture(t)
	// Click the field, then type the string the bug is behind. Nothing crashes:
	// the process lives, the exit status is zero, and the only evidence is on
	// the protocol.
	send(t, d,
		executor.Event{Kind: executor.EventClick, X: fieldX, Y: fieldY},
		executor.Event{Kind: executor.EventText, Text: "xyzz"},
		executor.Event{Kind: executor.EventKey, Text: "y"},
	)
	if !d.Alive() {
		t.Fatal("the browser died, which is a harness failure rather than a finding")
	}
	got := string(d.Result().Stderr)
	if !strings.Contains(got, "uncaught") {
		t.Fatalf("the planted exception was not reported:\n%s", got)
	}
	if !strings.Contains(got, "explode") {
		t.Errorf("the report does not name what failed, so a finding would not be "+
			"actionable:\n%s", got)
	}
}

func TestWebDriverDoesNotInventExceptions(t *testing.T) {
	// The other half, and the half that would make the oracle useless: an
	// ordinary sequence must report nothing.
	d, _ := webFixture(t)
	send(t, d,
		executor.Event{Kind: executor.EventClick, X: fieldX, Y: fieldY},
		executor.Event{Kind: executor.EventText, Text: "ordinary"},
		executor.Event{Kind: executor.EventKey, Text: "enter"},
	)
	if got := string(d.Result().Stderr); got != "" {
		t.Fatalf("an ordinary sequence produced a finding:\n%s", got)
	}
}

func TestWebResetClearsWhatTheLastSequenceDid(t *testing.T) {
	d, _ := webFixture(t)
	send(t, d,
		executor.Event{Kind: executor.EventClick, X: goX, Y: goY},
		executor.Event{Kind: executor.EventClick, X: fieldX, Y: fieldY},
		executor.Event{Kind: executor.EventText, Text: "left behind"},
	)
	dirty := string(d.State())
	if !strings.Contains(dirty, "the panel is open") {
		t.Fatalf("the panel did not open, so this test proves nothing:\n%s", dirty)
	}

	if err := d.Reset(); err != nil {
		t.Fatalf("resetting: %v", err)
	}
	clean := string(d.State())
	if strings.Contains(clean, "the panel is open") {
		t.Errorf("the reset left the previous sequence's screen in place, so no "+
			"finding from this campaign would reproduce:\n%s", clean)
	}
	if !strings.Contains(clean, "input#q[text=empty]") {
		t.Errorf("the reset left text in the field:\n%s", clean)
	}
}

func TestWebResetClearsTheCollectedProblems(t *testing.T) {
	// A finding must belong to the sequence that produced it. Problems that
	// survived a reset would be attributed to every later sequence, and the
	// campaign would report the same bug for ever.
	d, _ := webFixture(t)
	send(t, d,
		executor.Event{Kind: executor.EventClick, X: fieldX, Y: fieldY},
		executor.Event{Kind: executor.EventText, Text: "xyzz"},
		executor.Event{Kind: executor.EventKey, Text: "y"},
	)
	if string(d.Result().Stderr) == "" {
		t.Fatal("the planted exception was not reported, so this test proves nothing")
	}
	if err := d.Reset(); err != nil {
		t.Fatalf("resetting: %v", err)
	}
	if got := string(d.Result().Stderr); got != "" {
		t.Fatalf("a problem from the previous sequence survived the reset:\n%s", got)
	}
}

func TestWebDriverDismissesAModalRatherThanStalling(t *testing.T) {
	// alert() blocks the renderer until something answers it. Without the
	// dialog handler every command after this point times out, and the campaign
	// stops making progress without failing — the worst failure mode there is.
	d, _ := webFixture(t)
	send(t, d, executor.Event{Kind: executor.EventClick, X: askX, Y: askY})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	done := make(chan []byte, 1)
	go func() { done <- d.State() }()
	select {
	case state := <-done:
		if len(state) == 0 {
			t.Fatal("the page could not be read after a dialog, so the modal was " +
				"never dismissed")
		}
	case <-ctx.Done():
		t.Fatal("reading the page after a dialog timed out: the modal blocked the " +
			"renderer and the campaign would stall here")
	}
}

func TestWebSkipsAKeyItCannotPress(t *testing.T) {
	// What a mutator produces constantly. Reporting it as a harness failure
	// would end the campaign on its first interesting mutation.
	d, _ := webFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err := d.Send(ctx, executor.Event{Kind: executor.EventKey, Text: "eykm-226"})
	if err == nil {
		t.Fatal("an unknown key was accepted")
	}
	if !isSkip(err) {
		t.Fatalf("an unknown key was reported as a harness failure: %v", err)
	}
	if !d.Alive() {
		t.Fatal("the browser died over an unknown key")
	}
}

func TestWebResizeIsAnInput(t *testing.T) {
	d, _ := webFixture(t)
	send(t, d, executor.Event{Kind: executor.EventResize, X: 420, Y: 700})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	s, err := d.cur.page.EvalString(ctx, "String(window.innerWidth)")
	if err != nil {
		t.Fatal(err)
	}
	if s != "420" {
		t.Fatalf("the viewport is %s wide, want 420: a resize event did nothing", s)
	}
}

func TestWebEndpointIsReachedThroughTheSuppliedDialer(t *testing.T) {
	// The connection to the browser goes through the safety layer's dialer, not
	// through net directly. That is what puts it in the audit log and what
	// makes the loopback rule enforceable; a backend that dialled for itself
	// would be outside both, and the architecture lint cannot see a call made
	// through the net package's own defaults.
	browser := testenv.Browser(t)
	var dialed int
	d := NewWeb(webSpawner(), WebOptions{
		Browser:        browser,
		BrowserSandbox: false,
		StartTimeout:   45 * time.Second,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			dialed++
			var dl net.Dialer
			return dl.DialContext(ctx, network, address)
		},
	})
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if err := d.Start(ctx); err != nil {
		t.Fatalf("starting the browser: %v", err)
	}
	defer d.Close()
	if dialed == 0 {
		t.Fatal("the debugging endpoint was reached without the supplied dialer")
	}
}

func TestWebRefusesToRunWithoutADialer(t *testing.T) {
	// A campaign that reached the browser outside the scope guard would be
	// unaudited, so the absence of a dialer is an error rather than a default.
	d := NewWeb(webSpawner(), WebOptions{Browser: testenv.Browser(t)})
	_, err := d.dial()(context.Background(), "tcp", "127.0.0.1:1")
	if err == nil {
		t.Fatal("a backend with no dialer connected anyway")
	}
	if !strings.Contains(err.Error(), "scope guard") {
		t.Fatalf("the refusal does not say why: %v", err)
	}
}

func isSkip(err error) bool {
	return err != nil && strings.Contains(err.Error(), executor.ErrSkipEvent.Error())
}

func TestFindBrowserNamesWhatItTried(t *testing.T) {
	// A campaign on a machine with no browser must be told what to install,
	// which is the difference between a one-line fix and a mystery.
	_, err := FindBrowser("this-browser-does-not-exist")
	if err == nil {
		t.Fatal("a browser that does not exist was accepted")
	}
	if !strings.Contains(err.Error(), "this-browser-does-not-exist") {
		t.Fatalf("the error does not name what was asked for: %v", err)
	}
}

// TestTheBrowserGetsAFreshHomeAndTemporaryDirectory pins the environment a
// harness browser runs in, which no test that needs a browser can check on a
// machine that has none — and which is what a whole platform's web tests failed
// on.
//
// Two things depend on it. Confinement allows the profile directory and little
// else, and a browser works out where its *default* profile would live from the
// home directory and creates it before it has read a command line: on macOS that
// failed as `Failed to get the path for 1001`, naming the user data directory
// while `--user-data-dir` pointed at a perfectly good one. And reproducibility:
// a browser pointed at the operator's home reads the operator's profile, and a
// finding that depends on their extensions and cookies does not reproduce
// anywhere else (ASR-0008).
func TestTheBrowserGetsAFreshHomeAndTemporaryDirectory(t *testing.T) {
	profile := t.TempDir()
	home := filepath.Join(profile, "home")
	tmp := filepath.Join(profile, "tmp")

	env := browserEnv(nil, home, tmp)
	got := map[string]string{}
	for _, e := range env {
		if k, v, ok := strings.Cut(e, "="); ok {
			got[k] = v
		}
	}
	if got["HOME"] != home {
		t.Errorf("HOME = %q, want the scratch home %q", got["HOME"], home)
	}
	if got["TMPDIR"] != tmp {
		t.Errorf("TMPDIR = %q, want the scratch temporary directory %q", got["TMPDIR"], tmp)
	}

	// And the campaign wins where it named one, which is the rule every session
	// variable follows: an operator who set HOME meant that directory.
	env = browserEnv([]string{"HOME=/somewhere/else"}, home, tmp)
	for _, e := range env {
		if e == "HOME="+home {
			t.Error("the campaign's own HOME was overridden by the scratch one")
		}
	}
}
