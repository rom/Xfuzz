package api

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// Listener describes where the daemon serves.
type Listener struct {
	// Socket is a Unix domain socket path. It is the default, and filesystem
	// permissions are the access control (ADR-0003).
	Socket string

	// Addr is a TCP address. Opt-in, and never the default: a fuzzing daemon
	// reachable over the network is a remote code execution service, since a
	// campaign names a binary to run.
	Addr string

	// Token is required on every request when serving over TCP.
	Token string
}

// ErrTCPNeedsToken is returned for a TCP listener with no token.
var ErrTCPNeedsToken = errors.New(
	"api: serving over TCP requires a token: a campaign file names a binary to execute, " +
		"so an unauthenticated daemon is a remote code execution service")

// Serve starts the API and blocks until the context is cancelled.
func Serve(ctx context.Context, s *Server, l Listener) error {
	ln, cleanup, err := listen(l)
	if err != nil {
		return err
	}
	defer cleanup()

	s.Token = l.Token
	srv := &http.Server{
		Handler: s,
		// A read timeout would cut the event stream off, so the write timeout
		// is the one left unset and the read side is bounded instead.
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		BaseContext:       func(net.Listener) context.Context { return ctx },
	}

	errc := make(chan error, 1)
	go func() {
		err := srv.Serve(ln)
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		errc <- err
	}()

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
		return nil
	}
}

// listen opens the configured listener.
func listen(l Listener) (net.Listener, func(), error) {
	switch {
	case l.Addr != "":
		if l.Token == "" {
			return nil, nil, ErrTCPNeedsToken
		}
		ln, err := net.Listen("tcp", l.Addr)
		return ln, func() {}, err

	case l.Socket != "":
		if err := os.MkdirAll(filepath.Dir(l.Socket), 0o700); err != nil {
			return nil, nil, err
		}
		// A stale socket from a daemon that was killed rather than stopped is
		// the commonest reason a restart fails. Removing it is safe because a
		// live daemon holds a lock file, not the socket, and connecting to a
		// dead socket fails immediately.
		if err := removeStaleSocket(l.Socket); err != nil {
			return nil, nil, err
		}
		ln, err := net.Listen("unix", l.Socket)
		if err != nil {
			return nil, nil, err
		}
		// Owner-only. This is the access control on the default transport, so
		// it is set explicitly rather than left to the umask, which a user may
		// have set to anything.
		if err := os.Chmod(l.Socket, 0o600); err != nil {
			ln.Close()
			return nil, nil, err
		}
		return ln, func() { os.Remove(l.Socket) }, nil

	default:
		return nil, nil, errors.New("api: no listener configured")
	}
}

// removeStaleSocket removes a socket nothing is listening on.
func removeStaleSocket(path string) error {
	if _, err := os.Stat(path); err != nil {
		return nil
	}
	conn, err := net.DialTimeout("unix", path, 250*time.Millisecond)
	if err == nil {
		conn.Close()
		return fmt.Errorf("api: a daemon is already listening on %s", path)
	}
	return os.Remove(path)
}

// DefaultSocket returns the daemon's socket path within a data directory.
func DefaultSocket(dataDir string) string { return filepath.Join(dataDir, "xfuzzd.sock") }
