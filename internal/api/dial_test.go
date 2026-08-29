package api

import (
	"context"
	"net"
)

// netConn keeps the test's dialer signature readable.
type netConn = net.Conn

func dialUnix(ctx context.Context, path string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "unix", path)
}
