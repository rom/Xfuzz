// Package record runs the capture proxy: the source of last resort when an
// operator has neither a HAR nor a packet trace.
//
// It lives under internal/ rather than beside the readers in pkg/capture for one
// reason: a proxy reaches out to whatever host the client asked for, and
// ADR-0012 requires every outbound connection to pass the scope guard. Reading a
// file someone else recorded needs no such thing, which is why the readers are
// public and this is not.
//
// See docs/adr/ADR-0014-traffic-replay-driven-api-fuzzing.md.
package record

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/rom/Xfuzz/internal/safety"
	"github.com/rom/Xfuzz/pkg/capture"
)

// Proxy records the HTTP traffic that passes through it.
//
// Plain HTTP is proxied and recorded directly. HTTPS arrives as a CONNECT and is
// recorded only when the operator supplied a certificate authority to sign
// interception certificates with — because reading it means terminating the
// client's TLS, which is a thing an operator has to set up on purpose and be
// aware they have done. Without one, a CONNECT is tunnelled through untouched
// and counted: a proxy that silently failed to record the encrypted half would
// produce a capture that looked complete and was not.
type Proxy struct {
	// Scope is the guard every upstream connection passes. Required: a proxy
	// with no scope forwards anywhere the client asks, which is precisely what
	// ADR-0012 exists to prevent.
	Scope *safety.Scope

	// CA signs interception certificates. Nil means HTTPS is tunnelled rather
	// than recorded.
	CA *Authority

	// UpstreamRoots are the authorities the proxy will accept from the server it
	// forwards to, and InsecureUpstream accepts any certificate at all.
	//
	// Both exist because the API worth recording is routinely one with an
	// internal certificate: a staging environment, a device on a lab network, a
	// service behind a corporate authority. Without a way to say so, the proxy
	// would refuse every one of them and the operator would be told only that
	// the upstream failed.
	//
	// InsecureUpstream is the blunt version and says what it gives up: with it
	// set, the proxy cannot tell the intended server from anything that answered
	// instead, so the traffic it records may not be the traffic it thinks. It is
	// a field rather than a default for that reason.
	UpstreamRoots    *x509.CertPool
	InsecureUpstream bool

	// MaxBodyBytes bounds what is kept from one message. A proxy is in the path
	// of a real client, so it can be handed a download of any size.
	MaxBodyBytes int64

	// Timeout bounds one upstream exchange.
	Timeout time.Duration

	mu        sync.Mutex
	exchanges []capture.Exchange
	tunnelled int
	refused   int

	ln net.Listener
	wg sync.WaitGroup

	// conns are the client connections currently open, so shutdown can close
	// them rather than waiting for clients that will never hang up.
	//
	// A proxy speaks HTTP/1.1 keep-alive, so a connection that has served a
	// request sits in a blocking read waiting for the next one. Closing only the
	// listener leaves every one of those goroutines parked and Close waiting
	// behind them forever — which presented as a test suite that ran to its
	// timeout with everything already passed.
	conns  map[net.Conn]struct{}
	closed bool
}

// DefaultMaxBodyBytes is how much of one message the proxy keeps.
const DefaultMaxBodyBytes = 4 << 20

// ErrNoScope reports a proxy with nothing to constrain where it will forward.
var ErrNoScope = errors.New("record: the proxy needs a scope; without one it forwards anywhere a client asks (ADR-0012)")

// Listen starts the proxy on addr and returns the address it bound.
func (p *Proxy) Listen(addr string) (string, error) {
	if p.Scope == nil {
		return "", ErrNoScope
	}
	if p.MaxBodyBytes <= 0 {
		p.MaxBodyBytes = DefaultMaxBodyBytes
	}
	if p.Timeout <= 0 {
		p.Timeout = 30 * time.Second
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return "", fmt.Errorf("record: listening on %s: %w", addr, err)
	}
	p.mu.Lock()
	p.conns = map[net.Conn]struct{}{}
	p.mu.Unlock()
	p.ln = ln
	p.wg.Add(1)
	go p.serve()
	return ln.Addr().String(), nil
}

// Close stops the proxy and waits for its connections to finish.
//
// Closing the open connections as well as the listener, because a client that
// is not talking is not a client that has gone away: HTTP/1.1 keeps connections
// alive, and a proxy goroutine blocked reading the next request from one will
// stay blocked for as long as the client holds it open.
func (p *Proxy) Close() error {
	if p.ln == nil {
		return nil
	}
	err := p.ln.Close()

	p.mu.Lock()
	p.closed = true
	for c := range p.conns {
		c.Close()
	}
	p.mu.Unlock()

	p.wg.Wait()
	return err
}

// track registers a connection for shutdown, and reports whether the proxy is
// still accepting. It answers false after Close, so a connection accepted in the
// race between the listener closing and the accept loop noticing is closed
// immediately rather than served by a proxy that is shutting down.
func (p *Proxy) track(c net.Conn) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return false
	}
	p.conns[c] = struct{}{}
	return true
}

func (p *Proxy) untrack(c net.Conn) {
	p.mu.Lock()
	delete(p.conns, c)
	p.mu.Unlock()
}

// Capture returns what has been recorded so far.
//
// A copy, and safe to call while the proxy is running: an operator watches a
// capture grow and starts a campaign from it without stopping the recording.
func (p *Proxy) Capture() *capture.Capture {
	p.mu.Lock()
	defer p.mu.Unlock()
	c := &capture.Capture{Exchanges: append([]capture.Exchange(nil), p.exchanges...)}
	if p.tunnelled > 0 {
		c.Notes = append(c.Notes, fmt.Sprintf(
			"%d HTTPS connection(s) were tunnelled without being recorded; supply a "+
				"certificate authority to record them", p.tunnelled))
	}
	if p.refused > 0 {
		c.Notes = append(c.Notes, fmt.Sprintf(
			"%d connection(s) were refused by the scope guard", p.refused))
	}
	return c
}

func (p *Proxy) serve() {
	defer p.wg.Done()
	for {
		conn, err := p.ln.Accept()
		if err != nil {
			return
		}
		if !p.track(conn) {
			conn.Close()
			return
		}
		p.wg.Add(1)
		go func() {
			defer p.wg.Done()
			defer p.untrack(conn)
			defer conn.Close()
			p.handle(conn)
		}()
	}
}

// handle serves one client connection, which may carry several requests.
func (p *Proxy) handle(conn net.Conn) {
	br := bufio.NewReader(conn)
	for {
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		if req.Method == http.MethodConnect {
			p.connect(conn, br, req)
			return
		}
		if err := p.forward(conn, req, "http"); err != nil {
			return
		}
	}
}

// forward proxies one ordinary request and records it.
func (p *Proxy) forward(w io.Writer, req *http.Request, scheme string) error {
	ctx, cancel := context.WithTimeout(context.Background(), p.Timeout)
	defer cancel()

	body, _ := io.ReadAll(io.LimitReader(req.Body, p.MaxBodyBytes))
	req.Body.Close()

	target := req.URL
	if !target.IsAbs() {
		target = &url.URL{Scheme: scheme, Host: req.Host, Path: req.URL.Path, RawQuery: req.URL.RawQuery}
	}

	// Every hop out goes through the guard's dialer, so a client asking the
	// proxy to reach somewhere the campaign never authorised is refused here
	// rather than at the far end (ADR-0012).
	client := &http.Client{
		Transport: &http.Transport{
			DialContext:     p.Scope.Dial,
			DialTLSContext:  p.dialTLS,
			IdleConnTimeout: p.Timeout,
		},
		// Recorded as sent: following a redirect here would put a request in the
		// capture that the client never made.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	out, err := http.NewRequestWithContext(ctx, req.Method, target.String(), strings.NewReader(string(body)))
	if err != nil {
		return writeError(w, http.StatusBadRequest, err)
	}
	for name, vals := range req.Header {
		for _, v := range vals {
			out.Header.Add(name, v)
		}
	}
	out.Header.Del("Proxy-Connection")

	start := time.Now()
	resp, err := client.Do(out)
	if err != nil {
		p.mu.Lock()
		p.refused++
		p.mu.Unlock()
		return writeError(w, http.StatusBadGateway, err)
	}
	elapsed := time.Since(start)
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, p.MaxBodyBytes))
	resp.Body.Close()

	p.record(req, body, resp, respBody, elapsed, target.String())

	// Relayed to the client verbatim, so the client sees what the server said
	// and the recording is invisible to it.
	var head strings.Builder
	fmt.Fprintf(&head, "HTTP/1.1 %d %s\r\n", resp.StatusCode, http.StatusText(resp.StatusCode))
	for name, vals := range resp.Header {
		if strings.EqualFold(name, "Transfer-Encoding") || strings.EqualFold(name, "Content-Length") {
			continue
		}
		for _, v := range vals {
			fmt.Fprintf(&head, "%s: %s\r\n", name, v)
		}
	}
	fmt.Fprintf(&head, "Content-Length: %d\r\n\r\n", len(respBody))
	if _, err := io.WriteString(w, head.String()); err != nil {
		return err
	}
	_, err = w.Write(respBody)
	return err
}

// dialTLS opens an upstream TLS connection through the guard.
//
// The transport would otherwise dial it itself and bypass the guard entirely,
// which is the kind of hole that is invisible until someone audits it.
func (p *Proxy) dialTLS(ctx context.Context, network, addr string) (net.Conn, error) {
	raw, err := p.Scope.Dial(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	host, _, _ := net.SplitHostPort(addr)
	return tls.Client(raw, &tls.Config{
		ServerName:         host,
		MinVersion:         tls.VersionTLS12,
		RootCAs:            p.UpstreamRoots,
		InsecureSkipVerify: p.InsecureUpstream,
	}), nil
}

func (p *Proxy) record(req *http.Request, reqBody []byte, resp *http.Response, respBody []byte,
	elapsed time.Duration, absolute string) {

	e := capture.Exchange{At: time.Now(), Source: "proxy"}
	e.Request = capture.Request{
		Method: req.Method,
		URL:    absolute,
		Proto:  req.Proto,
		Body:   reqBody,
	}
	for name, vals := range req.Header {
		for _, v := range vals {
			e.Request.Headers = append(e.Request.Headers, capture.Header{Name: name, Value: v})
		}
	}
	e.Response = capture.Response{
		Status:  resp.StatusCode,
		Proto:   resp.Proto,
		Body:    respBody,
		Elapsed: elapsed,
	}
	for name, vals := range resp.Header {
		for _, v := range vals {
			e.Response.Headers = append(e.Response.Headers, capture.Header{Name: name, Value: v})
		}
	}
	capture.SortHeaders(e.Request.Headers)
	capture.SortHeaders(e.Response.Headers)

	p.mu.Lock()
	p.exchanges = append(p.exchanges, e)
	p.mu.Unlock()
}

func writeError(w io.Writer, status int, err error) error {
	msg := err.Error()
	_, werr := fmt.Fprintf(w, "HTTP/1.1 %d %s\r\nContent-Length: %d\r\nContent-Type: text/plain\r\n\r\n%s",
		status, http.StatusText(status), len(msg), msg)
	return werr
}
