// Package client talks to the daemon's API.
//
// The CLI holds no campaign state of its own: everything it shows comes from
// here, and everything it does is an API call (ADR-0003). That is what makes the
// parity test between the CLI and the API meaningful — there is nothing the CLI
// could do that the API cannot.
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Client is a connection to a daemon.
type Client struct {
	http *http.Client
	base string

	// Token is sent as a bearer token when set.
	Token string
}

// Options configure a client.
type Options struct {
	// Socket is the daemon's Unix socket. Preferred, and the default.
	Socket string

	// Addr is a TCP address instead.
	Addr string

	// Token authenticates the client.
	Token string

	// Timeout bounds a single request. It does not bound the event stream,
	// which is long-lived by definition.
	Timeout time.Duration
}

// DefaultTimeout bounds an ordinary request.
const DefaultTimeout = 30 * time.Second

// New returns a client.
func New(opts Options) (*Client, error) {
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}

	switch {
	case opts.Socket != "":
		socket := opts.Socket
		return &Client{
			base:  "http://unix",
			Token: opts.Token,
			http: &http.Client{
				Timeout: timeout,
				Transport: &http.Transport{
					DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
						var d net.Dialer
						return d.DialContext(ctx, "unix", socket)
					},
				},
			},
		}, nil

	case opts.Addr != "":
		base := opts.Addr
		if !strings.HasPrefix(base, "http://") && !strings.HasPrefix(base, "https://") {
			base = "http://" + base
		}
		return &Client{base: base, Token: opts.Token, http: &http.Client{Timeout: timeout}}, nil

	default:
		return nil, errors.New("client: no daemon address")
	}
}

// APIError is a failure the daemon reported.
type APIError struct {
	Status  int
	Message string
	Details []string
}

func (e *APIError) Error() string {
	var b strings.Builder
	b.WriteString(e.Message)
	for _, d := range e.Details {
		b.WriteString("\n  - " + d)
	}
	return b.String()
}

// NotFound reports whether the daemon said the thing does not exist.
func (e *APIError) NotFound() bool { return e.Status == http.StatusNotFound }

// Do performs a request and decodes the response into out.
func (c *Client) Do(ctx context.Context, method, path string, body, out any) error {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rdr = bytes.NewReader(b)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.base+path, rdr)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("client: %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()

	if err := checkAPIVersion(resp.Header.Get("X-Xfuzz-Api")); err != nil {
		return err
	}

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return err
	}
	if resp.StatusCode >= 400 {
		apiErr := &APIError{Status: resp.StatusCode, Message: strings.TrimSpace(string(raw))}
		var parsed struct {
			Error   string   `json:"error"`
			Details []string `json:"details"`
		}
		if json.Unmarshal(raw, &parsed) == nil && parsed.Error != "" {
			apiErr.Message, apiErr.Details = parsed.Error, parsed.Details
		}
		return apiErr
	}
	if out == nil || len(raw) == 0 {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("client: unreadable response to %s %s: %w", method, path, err)
	}
	return nil
}

// ErrVersionMismatch is returned when the daemon speaks a different API
// version than this client understands.
var ErrVersionMismatch = errors.New("client: the daemon speaks a different API version")

// checkAPIVersion refuses a daemon whose surface this build does not know.
//
// This is what the version header is for, and what it was not doing: a client
// that reads a daemon it does not understand does not fail, it *misreads*, and
// the failure surfaces somewhere unrelated. Measured when a campaign's seed
// changed from a JSON number to a string, because 64-bit values do not survive
// a browser's doubles: a stale CLI reported "cannot unmarshal string into Go
// struct field Status.seed", which says nothing about the actual problem.
//
// An empty header is accepted. It means something other than xfuzzd answered —
// a proxy's error page, most likely — and the response itself will say so more
// usefully than a version complaint would.
func checkAPIVersion(got string) error {
	if got == "" || got == APIVersion {
		return nil
	}
	return fmt.Errorf("%w: it speaks %s and this build speaks %s; "+
		"use the xfuzz that shipped with the daemon", ErrVersionMismatch, got, APIVersion)
}

// APIVersion is the surface this client understands.
//
// Declared here rather than imported from internal/api, because that package
// pulls in the daemon and a client binary has no business carrying one. The
// two are held equal by a test in internal/api, so drift is a build that fails
// rather than a mismatch discovered in the field.
const APIVersion = "1"

// maxResponseBytes bounds a response. Corpus payloads are the largest thing
// returned and they are inputs, not corpora.
const maxResponseBytes = 64 << 20

// Stream opens the event stream and calls fn for each event until the context
// ends or fn returns false.
//
// Server-sent events, so the framing is two lines and a blank one. There is no
// client library involved and nothing to keep in step with the server.
func (c *Client) Stream(ctx context.Context, kinds []string, campaign string, fn func(kind string, data []byte) bool) error {
	q := url.Values{}
	if len(kinds) > 0 {
		q.Set("kinds", strings.Join(kinds, ","))
	}
	if campaign != "" {
		q.Set("campaign", campaign)
	}
	path := "/v1/events"
	if len(q) > 0 {
		path += "?" + q.Encode()
	}

	req, err := http.NewRequestWithContext(ctx, "GET", c.base+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "text/event-stream")
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}

	// A client with a request timeout would cut the stream off on a quiet
	// campaign, so the stream gets a transport of its own.
	streamer := &http.Client{Transport: c.http.Transport}
	resp, err := streamer.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
		return &APIError{Status: resp.StatusCode, Message: strings.TrimSpace(string(raw))}
	}

	return readSSE(resp.Body, fn)
}

// Ping reports whether a daemon is answering.
func (c *Client) Ping(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	return c.Do(ctx, "GET", "/v1/info", nil, nil)
}
