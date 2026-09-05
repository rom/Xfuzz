package main

import "net"

// consoleURL is where a browser reaches the console on a TCP listener.
//
// A browser cannot open a Unix socket, so the console exists only on TCP, and
// the address the daemon was given is not always one a browser can be pointed
// at: a bare port or an unspecified host is written as loopback, which is
// where the person who started the daemon is.
func consoleURL(addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "http://" + addr + "/"
	}
	switch host {
	case "", "0.0.0.0", "::":
		host = "127.0.0.1"
	}
	return "http://" + net.JoinHostPort(host, port) + "/"
}
