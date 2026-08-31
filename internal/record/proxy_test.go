package record_test

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/rom/Xfuzz/internal/record"
	"github.com/rom/Xfuzz/internal/safety"
)

// The proxy sits in the path of a real client and reaches out to a real server,
// so what it must get right is not the recording — that is bookkeeping — but the
// two things that are load-bearing: the client sees exactly what the server
// said, and every hop out passes the scope guard.

// echoServer answers with a body describing what it received, so a test can tell
// what actually reached it.
func echoServer(t *testing.T) *httptest.Server {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Seen-Method", r.Method)
		if r.URL.Path == "/fail" {
			w.WriteHeader(http.StatusInternalServerError)
		} else {
			w.WriteHeader(http.StatusCreated)
		}
		io.WriteString(w, `{"path":"`+r.URL.Path+`","body":"`+string(body)+`"}`)
	}))
	t.Cleanup(s.Close)
	return s
}

// startProxy runs a proxy whose scope allows only the given server.
//
// allow empty means the scope allows nothing, including loopback — which is the
// only way to test refusal here, because a scope allows the local host by
// default and every test server in this file is on it.
func startProxy(t *testing.T, allow string, ca *record.Authority) (*record.Proxy, string) {
	t.Helper()
	scope := safety.NewScope()
	scope.AllowLoopback = allow != ""
	if allow != "" {
		host, portStr, err := net.SplitHostPort(allow)
		if err != nil {
			t.Fatal(err)
		}
		port, err := strconv.ParseUint(portStr, 10, 16)
		if err != nil {
			t.Fatal(err)
		}
		if err := scope.Allow(host, safety.PortRange{Lo: uint16(port), Hi: uint16(port)}); err != nil {
			t.Fatal(err)
		}
	}
	p := &record.Proxy{Scope: scope, CA: ca, Timeout: 10 * time.Second}
	addr, err := p.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { p.Close() })
	return p, addr
}

// clientThrough returns an HTTP client that goes via the proxy.
func clientThrough(addr string) *http.Client {
	proxyURL, _ := url.Parse("http://" + addr)
	return &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
		Timeout:   15 * time.Second,
	}
}

func TestProxyRelaysAndRecords(t *testing.T) {
	srv := echoServer(t)
	p, addr := startProxy(t, hostPort(t, srv.URL), nil)

	resp, err := clientThrough(addr).Post(srv.URL+"/items", "application/json",
		strings.NewReader(`{"name":"widget"}`))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	// The client's view: what the server said, unchanged.
	if resp.StatusCode != http.StatusCreated {
		t.Errorf("client saw status %d, want the server's 201", resp.StatusCode)
	}
	if resp.Header.Get("X-Seen-Method") != "POST" {
		t.Errorf("the server's headers did not reach the client")
	}
	if !strings.Contains(string(body), `"path":"/items"`) {
		t.Errorf("client body %q", body)
	}

	// The recording's view: the same exchange.
	c := p.Capture()
	if c.Len() != 1 {
		t.Fatalf("recorded %d exchanges, want 1: %v", c.Len(), c.Notes)
	}
	e := c.Exchanges[0]
	if e.Request.Method != "POST" || e.Request.Path() != "/items" {
		t.Errorf("recorded %s %s", e.Request.Method, e.Request.Path())
	}
	if string(e.Request.Body) != `{"name":"widget"}` {
		t.Errorf("recorded request body %q", e.Request.Body)
	}
	if e.Response.Status != http.StatusCreated {
		t.Errorf("recorded status %d", e.Response.Status)
	}
	if e.Response.Elapsed == 0 {
		t.Error("no elapsed time recorded")
	}
	if e.Source != "proxy" {
		t.Errorf("source %q", e.Source)
	}
}

// TestProxyRefusesToForwardOutOfScope is the reason this package is under
// internal/. A proxy is a machine for reaching wherever a client asks, and
// ADR-0012 says every outbound connection passes the guard.
func TestProxyRefusesToForwardOutOfScope(t *testing.T) {
	srv := echoServer(t)
	// A scope with nothing allowed, loopback included. A scope allows the local
	// host by default — a campaign that cannot reach 127.0.0.1 cannot fuzz a
	// local server — so refusal can only be tested by turning that off.
	_, addr := startProxy(t, "", nil)

	resp, err := clientThrough(addr).Get(srv.URL + "/items")
	if err != nil {
		// A transport-level failure is also a refusal; either is acceptable.
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusCreated {
		t.Fatal("the proxy forwarded to a host the scope does not allow")
	}
	if resp.StatusCode != http.StatusBadGateway && resp.StatusCode != http.StatusForbidden {
		t.Errorf("refused with status %d, which does not read as a refusal", resp.StatusCode)
	}
}

func TestProxyNeedsAScope(t *testing.T) {
	p := &record.Proxy{}
	if _, err := p.Listen("127.0.0.1:0"); err == nil {
		t.Fatal("a proxy with no scope started")
	}
}

// TestProxyTunnelsHTTPSAndSaysItDidNotRecordIt is the honest half of the CONNECT
// decision: without an authority the traffic cannot be read, and a capture that
// looked complete while missing all of it would be worse than a smaller one.
func TestProxyTunnelsHTTPSAndSaysItDidNotRecordIt(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "secret")
	}))
	defer srv.Close()

	p, addr := startProxy(t, hostPort(t, srv.URL), nil)

	client := clientThrough(addr)
	client.Transport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	resp, err := client.Get(srv.URL + "/x")
	if err != nil {
		t.Fatalf("the tunnel did not carry the request: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "secret" {
		t.Errorf("the tunnelled response was %q", body)
	}

	c := p.Capture()
	if c.Len() != 0 {
		t.Errorf("recorded %d exchanges from a tunnel it cannot read", c.Len())
	}
	if !strings.Contains(strings.Join(c.Notes, "; "), "tunnelled") {
		t.Errorf("the capture does not say the HTTPS traffic went unrecorded: %v", c.Notes)
	}
}

// TestProxyRecordsHTTPSWithAnAuthority is interception working: the client
// trusts the generated authority, the proxy reads the requests, and the client
// still gets the server's real answer.
func TestProxyRecordsHTTPSWithAnAuthority(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
		io.WriteString(w, `{"path":"`+r.URL.Path+`"}`)
	}))
	defer srv.Close()

	certPEM, keyPEM, err := record.GenerateAuthority("xfuzz test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := record.NewAuthority(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	p, addr := startProxy(t, hostPort(t, srv.URL), ca)

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(certPEM) {
		t.Fatal("the generated authority is not a usable certificate")
	}
	// The upstream is httptest's self-signed server, which is the shape of every
	// internal API worth recording. The proxy is told to trust it explicitly.
	upstream := x509.NewCertPool()
	upstream.AddCert(srv.Certificate())
	p.UpstreamRoots = upstream

	client := clientThrough(addr)
	// The client trusts the proxy's authority, which is the deliberate step an
	// operator takes when they set one up.
	client.Transport.(*http.Transport).TLSClientConfig = &tls.Config{RootCAs: pool}

	resp, err := client.Get(srv.URL + "/secret/path")
	if err != nil {
		t.Fatalf("the intercepted request failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != http.StatusAccepted {
		t.Errorf("client saw %d, want the server's 202", resp.StatusCode)
	}
	if !strings.Contains(string(body), "/secret/path") {
		t.Errorf("client body %q", body)
	}

	c := p.Capture()
	if c.Len() != 1 {
		t.Fatalf("recorded %d exchanges from an intercepted connection: %v", c.Len(), c.Notes)
	}
	if got := c.Exchanges[0].Request.Path(); got != "/secret/path" {
		t.Errorf("recorded path %q", got)
	}
	if got := c.Exchanges[0].Request.URL; !strings.HasPrefix(got, "https://") {
		t.Errorf("recorded URL %q, which does not identify the scheme it was sent over", got)
	}
}

// TestAuthorityMustBeOne keeps the dangerous mistake from being possible by
// accident. Signing certificates for hosts the proxy does not own is
// interception, and it must take an authority the operator generated and
// installed on purpose — not whatever PEM happened to be on the path.
func TestAuthorityMustBeOne(t *testing.T) {
	if _, err := record.NewAuthority([]byte("not a pem"), []byte("nor this")); err == nil {
		t.Error("nonsense was accepted as an authority")
	}

	// A leaf certificate cannot sign. Accepting one would produce certificates
	// no client will ever trust, and the failure would appear as a handshake
	// error rather than as the configuration mistake it is.
	certPEM, keyPEM, err := record.GenerateLeafForTest()
	if err != nil {
		t.Skipf("cannot make a leaf certificate here: %v", err)
	}
	_, err = record.NewAuthority(certPEM, keyPEM)
	if err == nil {
		t.Fatal("a leaf certificate was accepted as an authority")
	}
	if !strings.Contains(err.Error(), "authority") {
		t.Errorf("the refusal does not say why: %v", err)
	}
}

func hostPort(t *testing.T, rawURL string) string {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	return u.Host
}
