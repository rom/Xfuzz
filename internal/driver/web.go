package driver

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/rom/Xfuzz/internal/cdp"
	"github.com/rom/Xfuzz/internal/safety"
	"github.com/rom/Xfuzz/pkg/executor"
)

// The web backend: a browser driven over its own debugging protocol.
//
// ADR-0013 lists it among the driver adapters and it is the one whose mechanism
// is already built: every browser worth fuzzing ships a protocol that can
// navigate, dispatch a keystroke, click a point and hand back the document, and
// none of that needs a display server or an accessibility bus. What makes it
// the same tier as the terminal driver is that the fuzzer's side is identical —
// the same event sequence, the same corpus, the same state model over a
// fingerprint of what the interface shows.
//
// What is different is what "the target" means. A terminal campaign starts a
// program; a web campaign starts a *browser* and points it at a URL, and the
// program under test is on the other side of that URL. Three consequences run
// through this file. The browser is a harness, so its crash is a harness
// failure and not a finding. The page fails without the process dying — an
// uncaught exception, a renderer that crashed, a modal nobody dismissed — so
// the failures are collected from the protocol rather than from an exit status.
// And a campaign against a URL is a campaign that reaches the network, so the
// scope guard applies to it exactly as it does to the API tier (ADR-0012).

// WebOptions describe the browser and the page to drive.
type WebOptions struct {
	// URL is the page under test.
	URL string

	// Browser is the executable. Empty means probe for one.
	Browser string

	// Args are extra browser flags, appended after the ones this driver needs.
	Args []string
	Env  []string

	// Width and Height are the viewport, which is an input: a page that lays
	// out correctly at 1280 and misplaces a button at 400 has a bug only one of
	// them finds.
	Width, Height int

	// StartTimeout bounds launching the browser and reaching the first page.
	StartTimeout time.Duration

	// Settle is how long the page must be quiet before its state is read.
	Settle time.Duration

	// MaxSettle bounds the wait for a page that never goes quiet, which is what
	// an animation or a polling timer produces.
	MaxSettle time.Duration

	// Headed runs the browser with a window. Off by default: a campaign runs in
	// CI, where there is no display, and a headless browser is several times
	// faster besides.
	Headed bool

	// BrowserSandbox keeps the browser's own sandbox. On by default and worth
	// keeping: it is the layer between a hostile page and the machine, and it
	// is not the same layer as the one Xfuzz puts around the browser.
	BrowserSandbox bool

	// Dial opens the connection to the debugging endpoint. It is supplied so
	// that it passes the scope guard like every other outbound connection.
	Dial cdp.DialFunc

	// MaxStateBytes caps the fingerprint read from a page.
	MaxStateBytes int
}

// Defaults for a web campaign.
const (
	DefaultWebWidth        = 1280
	DefaultWebHeight       = 800
	DefaultWebStartTimeout = 30 * time.Second
	DefaultWebSettle       = 50 * time.Millisecond
	DefaultWebMaxSettle    = 2 * time.Second
	DefaultMaxStateBytes   = 256 << 10

	// stderrKeep caps how much of the browser's own noise is retained for a
	// launch failure. Chromium writes a great deal of it and none of it is the
	// campaign's business until something goes wrong.
	stderrKeep = 16 << 10
)

// MinBrowserProcesses is the process and thread budget a browser needs.
//
// A campaign's default cap is tens, which is generous for a parser and far
// below what a browser is: Chromium runs a process per renderer, per GPU
// service and per utility, and a few hundred threads across them. Below this
// the browser starts, announces its debugging endpoint, and then cannot fork a
// renderer — and the only symptom upstream is a protocol command that never
// answers, because the page it was addressed to does not exist.
//
// A floor rather than no limit at all: a runaway browser should still be
// bounded, and Linux counts this per user, so the number has to leave room for
// the fuzzer's own threads beside it.
const MinBrowserProcesses = 2048

// BrowserCandidates are the executables probed for when none is configured.
var BrowserCandidates = []string{
	"chromium", "chromium-browser", "google-chrome", "google-chrome-stable",
	"chrome", "msedge", "microsoft-edge",
}

// BrowserEnvVar names an override, for a browser that is installed somewhere
// no probe would look.
const BrowserEnvVar = "XFUZZ_BROWSER"

// FindBrowser returns the browser to drive, or an error naming what was tried.
func FindBrowser(configured string) (string, error) {
	if configured != "" {
		p, err := safety.FindProgram(configured)
		if err != nil {
			return "", fmt.Errorf("driver: %q is not an executable browser: %w", configured, err)
		}
		return p, nil
	}
	if env := os.Getenv(BrowserEnvVar); env != "" {
		p, err := safety.FindProgram(env)
		if err != nil {
			return "", fmt.Errorf("driver: %s is set to %q, which is not executable: %w",
				BrowserEnvVar, env, err)
		}
		return p, nil
	}
	for _, c := range BrowserCandidates {
		if p, err := safety.FindProgram(c); err == nil {
			return p, nil
		}
	}
	return "", fmt.Errorf("driver: no browser found (tried %s); set driver.browser or %s",
		strings.Join(BrowserCandidates, ", "), BrowserEnvVar)
}

// Web drives a web application through a browser's debugging protocol.
type Web struct {
	spawn *safety.Spawner
	opts  WebOptions

	// done is closed when the backend is closed, so a relaunch in flight stops
	// waiting rather than holding the worker open for its start timeout.
	done chan struct{}
	once sync.Once

	mu  sync.Mutex
	cur *webSession
}

// webSession is one browser. A fresh page per sequence is the reset; a fresh
// browser is only needed when the old one died.
type webSession struct {
	proc    executor.Handle
	conn    *cdp.Conn
	page    *cdp.Page
	dataDir string

	// cancel ends the context the browser process is bound to.
	//
	// A context of its own, not the caller's: Spawner.Start kills the process
	// when the context it was given is done, and the context that bounds
	// *starting* the browser is done the moment starting succeeded. Handing it
	// the launch context killed the browser microseconds after it came up, and
	// the symptom was every later command failing with an unexplained
	// end-of-file on the protocol connection.
	cancel context.CancelFunc

	// tail keeps the end of the browser's own output, which is where a browser
	// that will not do what it is asked says why.
	tail *tail

	mu        sync.Mutex
	problems  []string
	lastEvent time.Time

	// loaded is closed when the current page fires its load event. A fresh
	// channel per page, because a reset means waiting for the next one.
	loaded chan struct{}
	exit   executor.ProcResult
	exited bool
}

// NewWeb returns a web driver backend.
func NewWeb(spawner *safety.Spawner, opts WebOptions) *Web {
	if opts.Width <= 0 {
		opts.Width = DefaultWebWidth
	}
	if opts.Height <= 0 {
		opts.Height = DefaultWebHeight
	}
	if opts.StartTimeout <= 0 {
		opts.StartTimeout = DefaultWebStartTimeout
	}
	if opts.Settle <= 0 {
		opts.Settle = DefaultWebSettle
	}
	if opts.MaxSettle <= 0 {
		opts.MaxSettle = DefaultWebMaxSettle
	}
	if opts.MaxStateBytes <= 0 {
		opts.MaxStateBytes = DefaultMaxStateBytes
	}
	return &Web{spawn: spawner, opts: opts, done: make(chan struct{})}
}

// Name implements executor.DriverBackend.
func (d *Web) Name() string { return "web" }

// Supported reports whether a browser could be found.
func (d *Web) Supported() bool {
	_, err := FindBrowser(d.opts.Browser)
	return err == nil
}

// Start launches the browser and opens the page.
func (d *Web) Start(ctx context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.cur != nil {
		return nil
	}
	s, err := d.launch(ctx)
	if err != nil {
		return err
	}
	d.cur = s
	return nil
}

// launch starts a browser and attaches to a fresh page on the target URL.
func (d *Web) launch(ctx context.Context) (*webSession, error) {
	path, err := FindBrowser(d.opts.Browser)
	if err != nil {
		return nil, err
	}
	dataDir, err := os.MkdirTemp("", "xfuzz-web-")
	if err != nil {
		return nil, fmt.Errorf("driver: creating the browser's profile directory: %w", err)
	}
	// World-traversable, because the sandbox may run the browser as another
	// user and a profile directory it cannot enter is a browser that will not
	// start — with an error about the profile rather than about the sandbox.
	_ = os.Chmod(dataDir, 0o755)

	// A browser writes three kinds of thing, and only one of them is the profile
	// the command line names. Its temporary files go to TMPDIR, and — before it
	// has read a command line at all — it works out where its *default* profile
	// would live from the home directory and creates it. Both are somewhere
	// confinement does not allow, and the second is the one that kills it:
	// measured on macOS, Chromium dies with `Failed to get the path for 1001`,
	// which is the user data directory, while `--user-data-dir` names a
	// perfectly good one somewhere else.
	//
	// So both go inside the profile directory, which is the one place already
	// writable. That is not only a fix for confinement: a browser pointed at the
	// operator's home directory reads the operator's profile — their extensions,
	// their cookies, their settings — and a finding that depends on those does
	// not reproduce anywhere else (ASR-0008). A harness gets a fresh home.
	tmpDir := filepath.Join(dataDir, "tmp")
	homeDir := filepath.Join(dataDir, "home")
	for _, d := range []string{tmpDir, homeDir} {
		if err := os.Mkdir(d, 0o777); err != nil {
			os.RemoveAll(dataDir)
			return nil, fmt.Errorf("driver: creating the browser's scratch directory: %w", err)
		}
		_ = os.Chmod(d, 0o777)
	}

	// A pipe rather than a file: the endpoint is announced on standard error
	// and the announcement is what says the browser is ready. Polling an HTTP
	// endpoint instead would mean an outbound request before the scope guard
	// has anything to check, and a race about when to start polling.
	pr, pw, err := os.Pipe()
	if err != nil {
		os.RemoveAll(dataDir)
		return nil, fmt.Errorf("driver: creating the browser's output pipe: %w", err)
	}

	spec := executor.ProcSpec{
		Path: path,
		Args: append([]string{path}, d.browserArgs(dataDir)...),
		// A headless browser needs less of the session than a desktop
		// application does, and it still needs a home directory to put its
		// profile beside and a display when the campaign asked to watch it.
		// Everything the browser writes is under one path — see browserEnv.
		Env: browserEnv(d.opts.Env, homeDir, tmpDir),
		// The profile directory, and not because the browser cares where it
		// starts: the working directory is what a sandbox keeps writable.
		//
		// Confinement denies writes outside the working directory and whatever
		// the campaign added — the Linux helper by remounting the root
		// read-only, macOS by a Seatbelt profile — and a browser whose profile
		// it cannot write does not start. Measured on macOS, where it fails as
		// `Failed to get the path for 1001`, which names the user data
		// directory and nothing about a sandbox. So the one directory the
		// browser must write is the one directory confinement already allows.
		Dir:        dataDir,
		StderrFile: pw,
	}
	startCtx, cancelStart := context.WithTimeout(ctx, d.opts.StartTimeout)
	defer cancelStart()

	procCtx, cancelProc := context.WithCancel(context.Background())
	proc, err := d.spawn.Start(procCtx, spec)
	if err != nil {
		cancelProc()
		pr.Close()
		pw.Close()
		os.RemoveAll(dataDir)
		return nil, fmt.Errorf("driver: starting the browser: %w", err)
	}
	// The child owns the write end now. Holding it open here would stop the
	// pipe reporting end-of-file when the browser dies, so a failed launch
	// would hang until the start timeout instead of reporting why.
	pw.Close()

	s := &webSession{proc: proc, dataDir: dataDir, cancel: cancelProc, lastEvent: time.Now()}
	fail := func(err error) (*webSession, error) {
		pr.Close()
		s.stop()
		return nil, err
	}

	endpoint, noise, err := readEndpoint(pr, startCtx)
	if err != nil {
		return fail(fmt.Errorf("driver: the browser did not announce a debugging "+
			"endpoint: %w\nwhat it said instead:\n%s", err, noise))
	}
	// Kept from here on rather than discarded, and kept rather than merely
	// drained. A browser that will not do what it is asked usually said why on
	// its standard error, and the alternative — a protocol command that never
	// answers — is a diagnosis of nothing. The tail is bounded because a
	// browser writes a great deal.
	s.tail = newTail(stderrKeep)
	go func() {
		io.Copy(s.tail, pr)
		pr.Close()
	}()

	// From here on a failure includes what the browser said, because everything
	// below asks the browser to do something and a browser that cannot usually
	// explains itself where nobody was listening.
	withNoise := func(err error) (*webSession, error) {
		if said := s.tail.String(); said != "" {
			err = fmt.Errorf("%w\nwhat the browser said:\n%s", err, said)
		}
		s.stop()
		return nil, err
	}

	conn, err := cdp.Dial(startCtx, d.dial(), endpoint)
	if err != nil {
		return withNoise(err)
	}
	s.conn = conn
	conn.OnEvent(s.onEvent)

	page, err := conn.NewPage(startCtx, d.opts.Width, d.opts.Height)
	if err != nil {
		return withNoise(err)
	}
	s.page = page

	if d.opts.URL != "" {
		s.armLoad()
		if err := page.Navigate(startCtx, d.opts.URL); err != nil {
			return withNoise(err)
		}
		s.waitLoad(startCtx, d.opts.StartTimeout)
	}
	s.settle(startCtx, d.opts.Settle, d.opts.MaxSettle)
	go s.watch()
	return s, nil
}

// tail keeps the last n bytes written to it.
//
// A ring rather than a growing buffer: a browser in a bad state can write
// megabytes a second, and what explains the failure is the end.
type tail struct {
	mu   sync.Mutex
	buf  []byte
	n    int
	wrap bool
	pos  int
}

func newTail(n int) *tail { return &tail{buf: make([]byte, 0, n), n: n} }

func (t *tail) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, b := range p {
		if len(t.buf) < t.n {
			t.buf = append(t.buf, b)
			continue
		}
		t.buf[t.pos] = b
		t.pos = (t.pos + 1) % t.n
		t.wrap = true
	}
	return len(p), nil
}

func (t *tail) String() string {
	if t == nil {
		return ""
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.wrap {
		return strings.TrimSpace(string(t.buf))
	}
	return strings.TrimSpace(string(t.buf[t.pos:]) + string(t.buf[:t.pos]))
}

// browserEnv points the browser's home and temporary directories inside its
// profile, and then fills in the rest of the session as any harness gets it.
//
// Set before WithSessionEnv rather than after, which is what makes the campaign
// win: that function adds only what is missing, so a variable named here is one
// it will not override — and an operator who set HOME or TMPDIR meant those
// directories.
func browserEnv(env []string, home, tmp string) []string {
	out := append([]string(nil), env...)
	out = withVar(out, "HOME", home)
	out = withVar(out, "TMPDIR", tmp)
	return WithSessionEnv(out)
}

// withVar sets a variable unless it is already there.
func withVar(env []string, key, value string) []string {
	for _, e := range env {
		if k, _, ok := strings.Cut(e, "="); ok && k == key {
			return env
		}
	}
	return append(env, key+"="+value)
}

// browserArgs assembles the command line.
func (d *Web) browserArgs(dataDir string) []string {
	args := []string{
		// Port zero: the browser picks one and announces it, so two campaigns
		// on one machine cannot collide on a fixed port.
		"--remote-debugging-port=0",
		"--user-data-dir=" + dataDir,
		"--no-first-run",
		"--no-default-browser-check",
		"--disable-background-networking",
		"--disable-component-update",
		"--disable-default-apps",
		"--disable-sync",
		"--metrics-recording-only",
		"--mute-audio",
		fmt.Sprintf("--window-size=%d,%d", d.opts.Width, d.opts.Height),
	}
	if !d.opts.Headed {
		args = append(args, "--headless=new", "--disable-gpu")
	}
	if !d.opts.BrowserSandbox {
		args = append(args, "--no-sandbox", "--disable-dev-shm-usage")
	}
	args = append(args, d.opts.Args...)
	return append(args, "about:blank")
}

func (d *Web) dial() cdp.DialFunc {
	if d.opts.Dial != nil {
		return d.opts.Dial
	}
	// No dialer configured means no scope guard, which is a campaign
	// misconfiguration rather than a default. The worker always supplies one.
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		return nil, errors.New("driver: the web backend was given no dialer, so it " +
			"cannot connect to the browser without bypassing the scope guard")
	}
}

// endpointPrefix is what the browser prints when it is ready to be driven.
const endpointPrefix = "DevTools listening on "

// readEndpoint scans the browser's output for its debugging endpoint.
//
// Scanned rather than matched on the first line, because the browser writes a
// great deal before it gets there — a container without a session bus produces
// a dozen errors about it — and treating any of that as a failure would refuse
// to run on the machines campaigns actually run on.
func readEndpoint(r io.Reader, ctx context.Context) (endpoint, noise string, err error) {
	type result struct {
		endpoint string
		noise    string
		err      error
	}
	ch := make(chan result, 1)
	go func() {
		var kept strings.Builder
		sc := bufio.NewScanner(r)
		sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
		for sc.Scan() {
			line := sc.Text()
			if kept.Len() < stderrKeep {
				kept.WriteString(line)
				kept.WriteByte('\n')
			}
			if i := strings.Index(line, endpointPrefix); i >= 0 {
				ch <- result{endpoint: strings.TrimSpace(line[i+len(endpointPrefix):]),
					noise: kept.String()}
				return
			}
		}
		e := sc.Err()
		if e == nil {
			e = errors.New("the browser exited without announcing one")
		}
		ch <- result{noise: kept.String(), err: e}
	}()
	select {
	case r := <-ch:
		return r.endpoint, r.noise, r.err
	case <-ctx.Done():
		return "", "", ctx.Err()
	}
}

// onEvent records what the page did.
//
// Every event moves the settle clock, which is what makes waiting for quiet
// possible at all: the protocol reports a redraw, a request, a navigation and a
// timer, so silence on the connection is a good proxy for a page that has
// stopped changing.
func (s *webSession) onEvent(e cdp.Event) {
	s.mu.Lock()
	s.lastEvent = time.Now()
	s.mu.Unlock()

	switch e.Method {
	case "Runtime.exceptionThrown":
		s.problem("uncaught: " + exceptionText(e.Params))
	case "Page.loadEventFired":
		s.mu.Lock()
		if s.loaded != nil {
			close(s.loaded)
			s.loaded = nil
		}
		s.mu.Unlock()
	case "Inspector.targetCrashed":
		s.problem("crashed: the page's renderer process died")
	case "Page.javascriptDialogOpening":
		// Answered, and answered from another goroutine: this handler runs on
		// the connection's reader, and a command sent from here would wait for
		// a reply that only this goroutine can deliver. An unanswered dialog
		// blocks the renderer, so every later command in the sequence would
		// time out and the campaign would stall rather than move on.
		page := s.page
		if page != nil {
			go func() {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				_ = page.DismissDialog(ctx, false)
			}()
		}
	}
}

// exceptionText renders an uncaught exception for a finding.
func exceptionText(params []byte) string {
	var p struct {
		ExceptionDetails struct {
			Text       string `json:"text"`
			LineNumber int    `json:"lineNumber"`
			URL        string `json:"url"`
			Exception  *struct {
				Description string `json:"description"`
			} `json:"exception"`
		} `json:"exceptionDetails"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return string(params)
	}
	d := p.ExceptionDetails
	text := d.Text
	if d.Exception != nil && d.Exception.Description != "" {
		text = d.Exception.Description
	}
	if d.URL != "" {
		text += fmt.Sprintf(" (%s:%d)", d.URL, d.LineNumber)
	}
	return text
}

func (s *webSession) problem(text string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Bounded: a page that throws on every animation frame would otherwise
	// grow this without limit, and the first few are the ones that name the bug.
	if len(s.problems) < 64 {
		s.problems = append(s.problems, text)
	}
}

// watch reaps the browser so its exit is known without blocking a caller.
func (s *webSession) watch() {
	res, _ := s.proc.Wait()
	s.mu.Lock()
	s.exit, s.exited = res, true
	s.mu.Unlock()
}

// stop ends the browser and releases everything it held.
func (s *webSession) stop() {
	if s.cancel != nil {
		s.cancel()
	}
	if s.conn != nil {
		s.conn.Close()
	}
	if s.proc != nil {
		_ = s.proc.Kill()
	}
	if s.dataDir != "" {
		os.RemoveAll(s.dataDir)
		s.dataDir = ""
	}
}

// session returns the live browser, or an error saying it is gone.
func (d *Web) session() (*webSession, error) {
	d.mu.Lock()
	s := d.cur
	d.mu.Unlock()
	if s == nil {
		return nil, errors.New("driver: the browser was never started")
	}
	return s, nil
}

// Send implements executor.DriverBackend.
func (d *Web) Send(ctx context.Context, e executor.Event) error {
	s, err := d.session()
	if err != nil {
		return err
	}
	// Whatever this event turns out to be, the page has been poked: the settle
	// that follows must wait from now rather than from whenever the browser
	// last spoke.
	defer s.touch()

	switch e.Kind {
	case executor.EventKey:
		k, kerr := WebKey(e.Text)
		if kerr != nil {
			// The input named a key this backend cannot press. That is a
			// property of the input, not a failure of the harness.
			return fmt.Errorf("%w: %v", executor.ErrSkipEvent, kerr)
		}
		return s.page.SendKey(ctx, k)

	case executor.EventText:
		if e.Text == "" {
			return nil
		}
		return s.page.InsertText(ctx, e.Text)

	case executor.EventClick:
		return s.page.Click(ctx, e.X, e.Y)

	case executor.EventResize:
		w, h := e.X, e.Y
		if w < 1 || h < 1 {
			return fmt.Errorf("%w: a viewport of %dx%d", executor.ErrSkipEvent, w, h)
		}
		return s.page.SetSize(ctx, w, h)

	case executor.EventWait:
		// The tier does the waiting; there is nothing to send.
		return nil
	}
	return fmt.Errorf("%w: %v", executor.ErrSkipEvent, e)
}

// stateScript is the expression that fingerprints a page.
//
// A structural outline rather than the raw HTML, and the difference is the
// difference between a usable state model and none. Raw HTML changes on every
// keystroke — the value of the input the fuzzer just typed into is in it — so
// every sequence would reach a state nothing has seen and the model would learn
// nothing. What this reports is the shape: which elements exist, which are
// hidden, which has focus, whether a field has content, and the text the page
// shows. Two pages that differ only in what was typed fingerprint the same;
// two that differ by a dialog appearing do not.
const stateScript = `(function(){
  var out=[], limit=600;
  function walk(n,d){
    if(d>12||out.length>=limit) return;
    var kids=n.children||[];
    for(var i=0;i<kids.length;i++){
      if(out.length>=limit) return;
      var c=kids[i], t=(c.tagName||'').toLowerCase();
      if(t==='script'||t==='style'||t==='link'||t==='meta') continue;
      var s=t;
      if(c.id) s+='#'+c.id;
      if(typeof c.className==='string'&&c.className.trim()) s+='.'+c.className.trim().split(/\s+/).join('.');
      if(t==='input'||t==='textarea'||t==='select') s+='['+(c.type||t)+(c.value?'=set':'=empty')+(c.disabled?',disabled':'')+']';
      if(c===document.activeElement) s+=':focus';
      if(c.hidden||(c.offsetParent===null&&t!=='body')) s+=':hidden';
      out.push(new Array(d+1).join(' ')+s);
      walk(c,d+1);
    }
  }
  var root=document.body||document.documentElement;
  if(root) walk(root,0);
  var text='';
  try{ text=(document.body&&document.body.innerText)||''; }catch(e){}
  return (document.title||'')+'\n'+out.join('\n')+'\n--\n'+text;
})()`

// State implements executor.DriverBackend.
func (d *Web) State() []byte {
	s, err := d.session()
	if err != nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), d.opts.MaxSettle)
	defer cancel()
	out, err := s.page.EvalString(ctx, stateScript)
	if err != nil {
		// A page mid-navigation, or one whose renderer just died, cannot be
		// read. Reporting nothing is right: an empty state is a state, and it
		// is the one a crashed renderer is actually in.
		return nil
	}
	if len(out) > d.opts.MaxStateBytes {
		out = out[:d.opts.MaxStateBytes]
	}
	return []byte(out)
}

// Settle implements executor.Settler: wait until the page stops reporting.
func (d *Web) Settle(ctx context.Context) {
	s, err := d.session()
	if err != nil {
		return
	}
	s.settle(ctx, d.opts.Settle, d.opts.MaxSettle)
}

// touch marks the page as having just been poked.
//
// The settle clock is "how long since anything happened to this page", and an
// event the fuzzer delivered is something happening. Without this, settling
// after a keystroke measured the time since the *browser* last said something —
// which is already long when the page has been idle, so the wait returned
// instantly and an exception the keystroke caused arrived after the sequence
// had been judged. The finding was then attributed to the next sequence, whose
// reset had already thrown it away: measured as a planted bug that reproduced
// one time in three, and as a campaign needing two thousand executions to
// report what its first seed had already triggered.
func (s *webSession) touch() {
	s.mu.Lock()
	s.lastEvent = time.Now()
	s.mu.Unlock()
}

// armLoad prepares to wait for the next page's load event.
func (s *webSession) armLoad() {
	s.mu.Lock()
	s.loaded = make(chan struct{})
	s.mu.Unlock()
}

// waitLoad blocks until the page has loaded, or until ctx or the bound expires.
//
// The load event rather than a quiet interval, because quiet is a proxy and
// this is the real thing. A navigation commits before the document exists, so
// an event delivered on a quiet-only wait can land on a blank page — which
// looks exactly like a sequence that found nothing, and which was measured
// here: the same seed reached a planted bug in one execution with this wait and
// not at all without it.
//
// Bounded, and a timeout is not an error: a page that never fires load — one
// with a request that hangs — is still a page a campaign can type into.
func (s *webSession) waitLoad(ctx context.Context, max time.Duration) {
	s.mu.Lock()
	ch := s.loaded
	s.mu.Unlock()
	if ch == nil {
		return
	}
	timer := time.NewTimer(max)
	defer timer.Stop()
	select {
	case <-ch:
	case <-timer.C:
	case <-ctx.Done():
	}
}

// settle waits until the page has been quiet for `quiet`, giving up after
// `max`.
//
// Quiet on the protocol is the proxy for a page that has stopped changing: the
// browser reports a navigation, a request, a paint and a timer, so silence is
// as close to "finished" as a browser will say.
func (s *webSession) settle(ctx context.Context, quiet, max time.Duration) {
	deadline := time.Now().Add(max)
	for {
		s.mu.Lock()
		quietFor := time.Since(s.lastEvent)
		s.mu.Unlock()
		if quietFor >= quiet {
			return
		}
		remaining := quiet - quietFor
		if time.Now().Add(remaining).After(deadline) {
			// A page with an animation or a polling timer never goes quiet.
			// Waiting for it for ever would be a campaign that runs one input.
			remaining = time.Until(deadline)
			if remaining <= 0 {
				return
			}
		}
		timer := time.NewTimer(remaining)
		select {
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
			return
		}
		timer.Stop()
	}
}

// Alive implements executor.DriverBackend.
//
// Answered from the protocol connection rather than from the process: a browser
// whose connection is gone cannot be driven whether or not it is still running,
// and that is the question the tier is asking.
func (d *Web) Alive() bool {
	s, err := d.session()
	if err != nil {
		return false
	}
	select {
	case <-s.conn.Done():
		return false
	default:
		return true
	}
}

// Result implements executor.DriverBackend.
//
// The exit status is the *browser's*, and the browser is the harness. What
// carries a finding is Stderr: the uncaught exceptions, renderer crashes and
// failed navigations collected from the protocol, which are how a page fails
// while every process involved stays alive and exits zero.
func (d *Web) Result() executor.ProcResult {
	s, err := d.session()
	if err != nil {
		return executor.ProcResult{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	res := executor.ProcResult{}
	if s.exited {
		res = s.exit
	}
	if len(s.problems) > 0 {
		res.Stderr = []byte(strings.Join(s.problems, "\n"))
	}
	return res
}

// Reset implements executor.DriverBackend: a fresh page on the same browser.
//
// A page rather than a browser, because starting Chromium takes the better part
// of a second and a campaign resets on every sequence — the tier's throughput is
// its reset cost (ADR-0013). A new tab gets a new document, a new JavaScript
// context and a new event loop, which is the state a sequence needs cleared;
// what it does not clear on its own is storage for the origin, so that is asked
// for explicitly.
func (d *Web) Reset() error {
	ctx, cancel := closeCtx(d.done, d.opts.StartTimeout)
	defer cancel()
	return d.ResetWith(ctx)
}

// ResetWith implements executor.ContextResetter: the same reset, bounded by the
// sequence that asked for it.
func (d *Web) ResetWith(ctx context.Context) error {
	d.mu.Lock()
	s := d.cur
	d.mu.Unlock()

	if s != nil && d.Alive() {
		if err := d.newPage(ctx, s); err == nil {
			return nil
		}
		// The browser is alive on the connection but would not give a page.
		// Relaunching is the honest recovery; carrying on would fuzz whatever
		// the last sequence left behind.
	}
	if s != nil {
		s.stop()
	}
	fresh, err := d.launch(ctx)
	if err != nil {
		return err
	}
	d.mu.Lock()
	d.cur = fresh
	d.mu.Unlock()
	return nil
}

// newPage replaces the session's page with a fresh one.
func (d *Web) newPage(ctx context.Context, s *webSession) error {
	old := s.page
	page, err := s.conn.NewPage(ctx, d.opts.Width, d.opts.Height)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.problems = nil
	s.lastEvent = time.Now()
	s.mu.Unlock()
	s.page = page

	if old != nil {
		// After the new one exists, so a browser with no pages left does not
		// decide to exit between the two calls.
		_ = old.Close(ctx)
	}
	// Best effort: a browser that refuses to clear storage is still a usable
	// browser, and the alternative — failing the reset — would end the campaign
	// over a page's localStorage.
	if origin := originOf(d.opts.URL); origin != "" {
		_ = s.conn.Call(ctx, "", "Storage.clearDataForOrigin",
			map[string]any{"origin": origin, "storageTypes": "all"}, nil)
	}
	// A reset returns an interface that is ready to be typed into, the same
	// contract the terminal backend's reset has: it waits for the program's
	// first screen. Returning early made every sequence's first event land on a
	// document that did not exist yet.
	if d.opts.URL != "" {
		s.armLoad()
		if err := page.Navigate(ctx, d.opts.URL); err != nil {
			return err
		}
		s.waitLoad(ctx, d.opts.StartTimeout)
	}
	s.settle(ctx, d.opts.Settle, d.opts.MaxSettle)
	return nil
}

// originOf returns the scheme and authority of a URL, which is what storage is
// keyed by.
func originOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

// Close implements executor.DriverBackend.
func (d *Web) Close() error {
	d.once.Do(func() { close(d.done) })
	d.mu.Lock()
	s := d.cur
	d.cur = nil
	d.mu.Unlock()
	if s != nil {
		s.stop()
	}
	return nil
}
