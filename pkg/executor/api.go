package executor

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/rom/Xfuzz/pkg/codec"
	"github.com/rom/Xfuzz/pkg/feedback"
	"github.com/rom/Xfuzz/pkg/ir"
)

// API replays a captured HTTP session against a live service.
//
// It is the session tier's shape — a conversation rather than an input — with
// the two things a captured API session needs and a raw protocol session does
// not. Values the server produces are carried forward into later requests, so a
// mutated create still chains into the use that follows it (ADR-0014). And the
// responses are observed rather than merely read, because what makes an API bug
// is a status, a shape, or a latency rather than a signal.
//
// Everything it sends goes through the dialer it was given, which is the scope
// guard: an API campaign reaches out by definition, and ADR-0012 admits no
// exception for the tier whose whole job is reaching out.
type API struct {
	name string
	dial Dialer
	opts APIOptions

	// Output receives each response, so the objectives can read it.
	Output *feedback.OutputObserver

	// Responses, when set, is fed every response as it arrives — the same shape
	// the session tier uses for its state observer.
	Responses ResponseObserver

	execs uint64
	buf   []byte
}

// APIOptions configure the tier.
type APIOptions struct {
	// Address is where the service listens, as "tcp:host:port".
	Address string

	// TLS wraps the connection. A captured HTTPS session replays over TLS or
	// not at all: a service that expects it answers a plaintext request with a
	// framing error, which looks like a crashing parser and is not one.
	TLS bool

	// ServerName overrides the name checked against the certificate.
	ServerName string

	// Timeout bounds one whole session.
	Timeout time.Duration

	// PerRequest bounds one request within it.
	PerRequest time.Duration

	// Links are the data dependencies inference found: a value a response
	// produces and a later request has to carry.
	Links []Link

	// Substitute, when set, is applied to each request's bytes immediately
	// before they are sent. It is where redacted credentials become real ones,
	// and it is deliberately the last thing that happens — so a secret is in
	// memory for the length of one write and is never in the corpus, the store,
	// or a mutation.
	Substitute func([]byte) []byte

	// KeepAlive reuses one connection for the whole session. A captured session
	// is one client's conversation, and a server that keys anything on the
	// connection — a session cookie it set, a rate limit, a TLS session —
	// behaves differently when each request arrives on a new one.
	KeepAlive bool

	// FixLength recomputes Content-Length after mutation. On by default,
	// because a request whose declared length disagrees with its body is one the
	// server either hangs on or misframes, and neither is a finding. Turning it
	// off is how a campaign aims at request smuggling on purpose.
	FixLength bool
}

// Link is a data dependency carried between requests of one session.
//
// Declared here in the executor's own terms rather than imported from
// pkg/capture: the executor's job is to carry a value forward, and where the
// dependency was inferred from is not its business. It also means a campaign can
// supply links from anywhere — a person who knows the API, a plugin, a
// specification — without the tier changing.
type Link struct {
	// From is the request whose response produces the value, and Value is what
	// was seen there when the capture was taken.
	From  int
	Value string

	// To is the request that carries it.
	To int

	// Extract names where in the response to find the value now: a JSON pointer
	// into the body, or "header:Name". Empty means the recorded value is used
	// unchanged, which is right for a value that does not change between runs.
	Extract string
}

// DefaultAPITimeouts are what a campaign gets without saying.
const (
	DefaultAPISessionTimeout = 30 * time.Second
	DefaultAPIRequestTimeout = 10 * time.Second
)

// NewAPI returns the API tier.
func NewAPI(name string, dial Dialer, opts APIOptions) *API {
	if opts.Timeout <= 0 {
		opts.Timeout = DefaultAPISessionTimeout
	}
	if opts.PerRequest <= 0 {
		opts.PerRequest = DefaultAPIRequestTimeout
	}
	return &API{name: name, dial: dial, opts: opts, buf: make([]byte, 32<<10)}
}

// Name implements Executor.
func (e *API) Name() string { return e.name }

// Executions returns how many sessions have run.
func (e *API) Executions() uint64 { return e.execs }

// Capabilities implements Executor.
func (e *API) Capabilities() Caps {
	return Caps{
		Tier:        TierSession,
		Backend:     "blackbox",
		Granularity: GranularityNone,
		Platform:    runtime.GOOS + "/" + runtime.GOARCH,
		// A service is not deterministic in the way a parser is: it has clocks,
		// identifiers, and other clients. Claiming otherwise would let the
		// engine treat a differing replay as a corpus fault.
		Deterministic:   false,
		TimeoutEnforced: true,
	}
}

// Reset implements Executor. Each session opens its own connection, so there is
// nothing carried between them that this tier owns.
func (e *API) Reset(ResetPolicy) error { return nil }

// Close implements Executor.
func (e *API) Close() error { return nil }

// Run implements Executor: it replays one session.
func (e *API) Run(ctx context.Context, in Input, obs []feedback.Observer) (feedback.ExitKind, error) {
	if err := Arm(obs, in); err != nil {
		return feedback.ExitError, err
	}
	e.execs++

	ctx, cancel := context.WithTimeout(ctx, e.opts.Timeout)
	defer cancel()

	requests := e.requests(in)
	if len(requests) == 0 {
		return e.finish(obs, feedback.ExitOK, nil, 0)
	}

	// carried holds what earlier responses produced, keyed by the recorded
	// value it replaces. Substituting by value rather than by position is what
	// survives mutation: a mutator that moved a header still leaves the value
	// where a textual replacement finds it.
	carried := map[string]string{}

	var transcript bytes.Buffer
	var conn net.Conn
	defer func() {
		if conn != nil {
			conn.Close()
		}
	}()

	start := time.Now()
	var worst feedback.ExitKind
	var statuses []int

	for i, req := range requests {
		if ctx.Err() != nil {
			break
		}
		out := e.prepare(req, i, carried)

		reused := true
		if conn == nil || !e.opts.KeepAlive {
			if conn != nil {
				conn.Close()
			}
			c, err := e.connect(ctx)
			if err != nil {
				// The service is unreachable. That is the harness failing, not
				// the target misbehaving, and recording it as a finding is how
				// a fuzzer loses its credibility (ADR-0007).
				return feedback.ExitError, fmt.Errorf("executor %s: %w", e.name, err)
			}
			conn, reused = c, false
		}

		resp, rerr := e.exchange(ctx, conn, out)
		if rerr != nil && reused {
			// A keep-alive connection the service had already decided to close.
			//
			// This is not the service dying, it is the ordinary race every HTTP
			// client handles: the server closes an idle connection at the same
			// moment the client sends on it, and neither side did anything
			// wrong. Reported as a crash it becomes a finding filed against
			// whatever input happened to be in flight — which is a finding
			// nobody can reproduce, from a fuzzer that now cannot be trusted
			// about the ones that are real.
			//
			// So the request is sent again on a fresh connection, once. A
			// failure there is evidence: the service would not answer a new
			// connection either.
			conn.Close()
			c, cerr := e.connect(ctx)
			if cerr != nil {
				return feedback.ExitError, fmt.Errorf("executor %s: %w", e.name, cerr)
			}
			conn = c
			resp, rerr = e.exchange(ctx, conn, out)
		}
		if rerr != nil {
			// A connection that dies mid-session is the strongest black-box
			// signal an API campaign has: a service that stopped answering
			// stopped for a reason.
			transcript.WriteString(fmt.Sprintf("\n[request %d: %v]\n", i, rerr))
			worst = feedback.ExitCrash
			conn.Close()
			conn = nil
			break
		}
		statuses = append(statuses, resp.StatusCode)
		e.observe(resp, &transcript)
		e.carry(i, resp, carried)

		if e.Responses != nil {
			e.Responses.Response(transcript.Bytes())
		}
		if !e.opts.KeepAlive || resp.Close {
			conn.Close()
			conn = nil
		}
	}

	if ctx.Err() != nil && worst == feedback.ExitOK {
		worst = feedback.ExitTimeout
	}
	return e.finish(obs, worst, &transcript, time.Since(start), statuses...)
}

// prepare renders one request with its dependencies and secrets applied.
func (e *API) prepare(req []byte, index int, carried map[string]string) []byte {
	out := req
	for _, l := range e.opts.Links {
		if l.To != index {
			continue
		}
		now, ok := carried[l.Value]
		if !ok || now == l.Value || l.Value == "" {
			continue
		}
		out = bytes.ReplaceAll(out, []byte(l.Value), []byte(now))
	}
	if e.opts.FixLength {
		out = fixLength(out)
	}
	if e.opts.Substitute != nil {
		out = e.opts.Substitute(out)
	}
	return out
}

// carry records what a response produced, for the requests that depend on it.
func (e *API) carry(index int, resp *http.Response, carried map[string]string) {
	for _, l := range e.opts.Links {
		if l.From != index || l.Extract == "" {
			continue
		}
		if v, ok := extract(resp, l.Extract); ok && v != "" {
			carried[l.Value] = v
		}
	}
}

// extract reads one value out of a response.
func extract(resp *http.Response, spec string) (string, bool) {
	if name, ok := strings.CutPrefix(spec, "header:"); ok {
		v := resp.Header.Get(name)
		return v, v != ""
	}
	body, ok := resp.Body.(*capturedBody)
	if !ok {
		return "", false
	}
	return jsonPointer(body.data, spec)
}

// connect opens a connection through the guard.
func (e *API) connect(ctx context.Context) (net.Conn, error) {
	network, address, err := splitAddress(e.opts.Address)
	if err != nil {
		return nil, err
	}
	conn, err := e.dial.Dial(ctx, network, address)
	if err != nil {
		return nil, err
	}
	if !e.opts.TLS {
		return conn, nil
	}
	return wrapTLS(conn, e.opts.ServerName, address)
}

// exchange writes one request and reads its response.
func (e *API) exchange(ctx context.Context, conn net.Conn, req []byte) (*http.Response, error) {
	deadline := time.Now().Add(e.opts.PerRequest)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, err
	}
	if _, err := conn.Write(req); err != nil {
		return nil, err
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		return nil, err
	}
	return withCapturedBody(resp), nil
}

// observe writes a response into the transcript the objectives read.
func (e *API) observe(resp *http.Response, transcript *bytes.Buffer) {
	fmt.Fprintf(transcript, "HTTP %d\n", resp.StatusCode)
	for _, name := range []string{"Content-Type", "Location", "WWW-Authenticate"} {
		if v := resp.Header.Get(name); v != "" {
			fmt.Fprintf(transcript, "%s: %s\n", name, v)
		}
	}
	if b, ok := resp.Body.(*capturedBody); ok {
		transcript.Write(b.data)
	}
	transcript.WriteByte('\n')
}

// finish records what the session produced and harvests the observers.
func (e *API) finish(obs []feedback.Observer, ek feedback.ExitKind, transcript *bytes.Buffer,
	elapsed time.Duration, statuses ...int) (feedback.ExitKind, error) {

	if e.Output != nil {
		var body []byte
		if transcript != nil {
			body = transcript.Bytes()
		}
		// The worst status the session saw goes in the exit code, so an
		// objective that cares about 5xx can read it without parsing the
		// transcript.
		worst := 0
		for _, s := range statuses {
			if s > worst {
				worst = s
			}
		}
		e.Output.Record(body, nil, worst, 0)
	}
	for _, o := range obs {
		if err := o.Post(ek); err != nil {
			return feedback.ExitError, fmt.Errorf("harvesting %s: %w", o.Name(), err)
		}
	}
	recordDuration(obs, elapsed)
	return ek, nil
}

// requests divides a session into the requests to send.
//
// From the tree when there is one, and only from the bytes when there is not.
// The difference matters exactly when it is most needed: a mutation that changes
// a body's length leaves a declared Content-Length that no longer locates the
// request's end, so splitting the bytes cuts the first request short and the
// remainder does not parse as a second one — the session silently becomes one
// request. The tree has the boundaries structurally and cannot lose them, which
// is why Input carries both.
func (e *API) requests(in Input) [][]byte {
	if reqs, ok := requestsFromTree(in.Node); ok {
		return reqs
	}
	return splitSession(in.Bytes)
}

// requestsFromTree encodes each request node separately.
func requestsFromTree(root *ir.Node) ([][]byte, bool) {
	if root == nil || root.Kind != ir.KindRepeat {
		return nil, false
	}
	var out [][]byte
	found := false
	for _, child := range root.Children {
		if child.Kind != ir.KindStruct || child.Name != codec.HTTPRequest {
			// An opaque node: bytes the codec could not read, which the server
			// will be given as they are.
			if child.Kind == ir.KindBytes {
				out = append(out, ir.AppendEncode(nil, child))
			}
			continue
		}
		found = true
		out = append(out, ir.AppendEncode(nil, child))
	}
	if !found {
		return nil, false
	}
	return out, true
}

// splitSession divides a session's bytes into its requests.
//
// By the declared lengths, which is what a server does with the same bytes. Used
// only when there is no tree to take the boundaries from.
func splitSession(session []byte) [][]byte {
	var out [][]byte
	rest := session
	for len(rest) > 0 {
		end := requestEnd(rest)
		if end <= 0 {
			out = append(out, rest)
			break
		}
		out = append(out, rest[:end])
		rest = rest[end:]
	}
	return out
}

// requestEnd returns where one request ends, or -1.
func requestEnd(src []byte) int {
	head, sep := bytes.Index(src, []byte("\r\n\r\n")), 4
	if head < 0 {
		head, sep = bytes.Index(src, []byte("\n\n")), 2
	}
	if head < 0 {
		return -1
	}
	n := headerLength(src[:head+sep])
	if n < 0 {
		return head + sep
	}
	end := head + sep + n
	if end > len(src) {
		return len(src)
	}
	return end
}

func headerLength(head []byte) int {
	for _, line := range bytes.Split(head, []byte("\n")) {
		name, value, ok := bytes.Cut(line, []byte(":"))
		if !ok || !strings.EqualFold(strings.TrimSpace(string(name)), "content-length") {
			continue
		}
		n, err := strconv.Atoi(strings.TrimSpace(string(value)))
		if err != nil || n < 0 {
			return -1
		}
		return n
	}
	return -1
}

// fixLength recomputes one request's Content-Length from its body.
func fixLength(req []byte) []byte {
	head, sep := bytes.Index(req, []byte("\r\n\r\n")), 4
	if head < 0 {
		head, sep = bytes.Index(req, []byte("\n\n")), 2
	}
	if head < 0 {
		return req
	}
	body := req[head+sep:]
	lines := bytes.Split(req[:head+sep], []byte("\n"))
	found := false
	for i, line := range lines {
		name, _, ok := bytes.Cut(line, []byte(":"))
		if !ok || !strings.EqualFold(strings.TrimSpace(string(name)), "content-length") {
			continue
		}
		eol := ""
		if bytes.HasSuffix(line, []byte("\r")) {
			eol = "\r"
		}
		lines[i] = []byte(string(name) + ": " + strconv.Itoa(len(body)) + eol)
		found = true
	}
	if !found {
		return req
	}
	return append(bytes.Join(lines, []byte("\n")), body...)
}

// splitAddress reads "tcp:host:port" into its parts.
func splitAddress(addr string) (network, address string, err error) {
	network, address, ok := strings.Cut(addr, ":")
	if !ok || address == "" {
		return "", "", fmt.Errorf("executor: %q is not an address; write tcp:host:port", addr)
	}
	switch network {
	case "tcp", "tcp4", "tcp6", "unix":
	default:
		return "", "", fmt.Errorf("executor: %q is not a network this tier speaks", network)
	}
	return network, address, nil
}

// hostOf returns the host part of an address, for the TLS server name.
func hostOf(address string) string {
	if h, _, err := net.SplitHostPort(address); err == nil {
		return h
	}
	if u, err := url.Parse(address); err == nil && u.Host != "" {
		return u.Hostname()
	}
	return address
}
