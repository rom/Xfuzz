package executor

import (
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
)

// Support for the API tier: reading a response body more than once, resolving a
// JSON pointer, and wrapping a connection in TLS.

// MaxAPIBodyBytes bounds what is kept from one response.
//
// A service under test can answer with anything, including a stream that does
// not end, and the oracles read the first part of a body rather than all of it.
const MaxAPIBodyBytes = 1 << 20

// capturedBody holds a response body that has already been read.
//
// http.Response gives a stream that can be consumed once, and the API tier needs
// it twice: an oracle reads it to decide whether the response is a finding, and
// a data dependency reads it to carry a value into the next request. Reading it
// into memory once, bounded, is simpler than either replaying the stream or
// deciding the order those two happen in.
type capturedBody struct {
	data []byte
	pos  int
}

func (b *capturedBody) Read(p []byte) (int, error) {
	if b.pos >= len(b.data) {
		return 0, io.EOF
	}
	n := copy(p, b.data[b.pos:])
	b.pos += n
	return n, nil
}

func (b *capturedBody) Close() error { return nil }

// withCapturedBody reads a response's body into memory and puts it back.
func withCapturedBody(resp *http.Response) *http.Response {
	data, _ := io.ReadAll(io.LimitReader(resp.Body, MaxAPIBodyBytes))
	resp.Body.Close()
	resp.Body = &capturedBody{data: data}
	return resp
}

// jsonPointer resolves an RFC 6901 pointer against a JSON document.
//
// The pointer form is what the inference records, so what an operator reads in a
// link is what is looked up here. A pointer that does not resolve is not an
// error: the response shape changed, which is a normal thing for a service being
// fuzzed to do, and the dependency simply carries nothing this time.
func jsonPointer(body []byte, pointer string) (string, bool) {
	if len(body) == 0 || pointer == "" {
		return "", false
	}
	var doc any
	if err := json.Unmarshal(body, &doc); err != nil {
		return "", false
	}
	cur := doc
	for _, tok := range strings.Split(strings.TrimPrefix(pointer, "/"), "/") {
		tok = strings.ReplaceAll(strings.ReplaceAll(tok, "~1", "/"), "~0", "~")
		switch t := cur.(type) {
		case map[string]any:
			v, ok := t[tok]
			if !ok {
				return "", false
			}
			cur = v
		case []any:
			i, err := strconv.Atoi(tok)
			if err != nil || i < 0 || i >= len(t) {
				return "", false
			}
			cur = t[i]
		default:
			return "", false
		}
	}
	switch v := cur.(type) {
	case string:
		return v, true
	case float64:
		if v == float64(int64(v)) {
			return strconv.FormatInt(int64(v), 10), true
		}
		return strconv.FormatFloat(v, 'g', -1, 64), true
	case bool:
		return strconv.FormatBool(v), true
	}
	return "", false
}

// wrapTLS puts a TLS session on an already-open connection.
//
// On a connection the guard opened, never one this dials itself: the whole point
// of routing through the guard is that nothing reaches out around it, and a TLS
// helper that dialled would be the exception that made the rule decorative.
func wrapTLS(conn net.Conn, serverName, address string) (net.Conn, error) {
	name := serverName
	if name == "" {
		name = hostOf(address)
	}
	c := tls.Client(conn, &tls.Config{
		ServerName: name,
		MinVersion: tls.VersionTLS12,
		// A service under test routinely has a certificate signed by nobody the
		// host trusts — a staging environment, a lab device, a container with a
		// self-signed pair. Verification here would refuse exactly the targets
		// this tier exists for, and the connection has already passed the scope
		// guard, which is what governs *where* it may reach.
		InsecureSkipVerify: true,
	})
	return c, nil
}

// sortedStatuses is a small helper for reports.
func sortedStatuses(in []int) []int {
	out := append([]int(nil), in...)
	sort.Ints(out)
	return out
}
