package record

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
)

// CONNECT: the half of proxying that decides whether HTTPS is recorded.
//
// A client that wants HTTPS through a proxy asks for a tunnel and then speaks
// TLS through it. There are exactly two honest things the proxy can do with
// that, and it does whichever the operator set up:
//
// With an authority, it terminates the client's TLS with a certificate it signs
// for the requested host, reads the requests in the clear, and opens its own TLS
// connection upstream. The client sees the proxy's certificate, which is why the
// authority has to be installed in the client on purpose.
//
// Without one, it opens a plain tunnel and copies bytes. The traffic is not
// recorded, and that is counted and reported — a proxy that silently failed to
// record the encrypted half would produce a capture that looked complete and was
// not, and encrypted traffic is most of what a modern client sends.

// connect handles a CONNECT request.
func (p *Proxy) connect(client net.Conn, br *bufio.Reader, req *http.Request) {
	host := req.URL.Host
	if host == "" {
		host = req.Host
	}
	if _, _, err := net.SplitHostPort(host); err != nil {
		host = net.JoinHostPort(host, "443")
	}

	if p.CA == nil {
		p.tunnel(client, host)
		return
	}
	p.intercept(client, br, host)
}

// tunnel copies bytes between the client and the upstream without reading them.
func (p *Proxy) tunnel(client net.Conn, host string) {
	ctx, cancel := context.WithTimeout(context.Background(), p.Timeout)
	defer cancel()

	upstream, err := p.Scope.Dial(ctx, "tcp", host)
	if err != nil {
		p.mu.Lock()
		p.refused++
		p.mu.Unlock()
		writeError(client, http.StatusForbidden, err)
		return
	}
	defer upstream.Close()

	if _, err := io.WriteString(client, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	p.mu.Lock()
	p.tunnelled++
	p.mu.Unlock()

	done := make(chan struct{}, 2)
	go func() { io.Copy(upstream, client); done <- struct{}{} }()
	go func() { io.Copy(client, upstream); done <- struct{}{} }()
	<-done
}

// intercept terminates the client's TLS and records the requests inside it.
func (p *Proxy) intercept(client net.Conn, _ *bufio.Reader, host string) {
	name, _, _ := net.SplitHostPort(host)
	cert, err := p.CA.For(name)
	if err != nil {
		writeError(client, http.StatusInternalServerError, err)
		return
	}
	if _, err := io.WriteString(client, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}

	tlsConn := tls.Server(client, &tls.Config{
		Certificates: []tls.Certificate{*cert},
		MinVersion:   tls.VersionTLS12,
	})
	if err := tlsConn.Handshake(); err != nil {
		// The client rejected the certificate, which almost always means the
		// authority is not installed in it. Counted as a refusal so the note on
		// the capture says something an operator can act on.
		p.mu.Lock()
		p.refused++
		p.mu.Unlock()
		return
	}
	defer tlsConn.Close()

	inner := bufio.NewReader(tlsConn)
	for {
		req, err := http.ReadRequest(inner)
		if err != nil {
			return
		}
		// The requests inside a tunnel carry a path, not an absolute URL: the
		// authority was named by the CONNECT. Restoring it is what makes the
		// recorded exchange identify an endpoint.
		if req.Host == "" {
			req.Host = name
		}
		if err := p.forward(tlsConn, req, "https"); err != nil {
			return
		}
	}
}
