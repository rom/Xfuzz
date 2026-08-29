// Package api exposes the daemon's services over HTTP/JSON, with server-sent
// events for live updates.
//
// This surface is the single source of truth for campaign state. The CLI and the
// web console are both clients of it, and a parity test asserts that neither has
// a capability the other lacks (ASR-0005).
//
// The transport is HTTP/JSON rather than gRPC (ADR-0024, which supersedes
// ADR-0003's transport choice while keeping its service decomposition). Event
// streaming is lossy by design: high-rate events are downsampled and batched
// server-side so a browser can never back-pressure the engine.
package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/rom/Xfuzz/internal/daemon"
)

// Service groups routes by responsibility, matching ARCHITECTURE section 9.
type Service string

// The services.
const (
	ServiceCampaign Service = "campaign"
	ServiceMetrics  Service = "metrics"
	ServiceCorpus   Service = "corpus"
	ServiceFinding  Service = "finding"
	ServiceEvent    Service = "event"
	ServiceAdmin    Service = "admin"
)

// Route is one API method.
//
// Routes are values rather than bare handler registrations so that the surface
// can be enumerated: the OpenAPI document, the parity test against the CLI, and
// the router itself are all generated from this one list. A surface that is only
// a series of mux.Handle calls cannot be checked against anything.
type Route struct {
	// Method and Path identify the route.
	Method string
	Path   string

	// Service is which group it belongs to.
	Service Service

	// Name is the method's stable identifier, used by the parity test and by
	// generated clients. It is what the CLI command must map to.
	Name string

	// Summary describes it in one line, for the OpenAPI document.
	Summary string

	// Mutating marks a route that changes state. Read-only routes are allowed
	// without a token when the daemon is on a Unix socket; mutating ones never
	// are, on any transport.
	Mutating bool

	handler http.HandlerFunc
}

// Server serves the API over a listener.
type Server struct {
	daemon *daemon.Daemon
	mux    *http.ServeMux
	routes []Route

	// Token, when set, is required on every request as a bearer token. It is
	// set for a TCP listener and optional for a Unix socket, where filesystem
	// permissions are the control (ADR-0003).
	Token string

	// EventQueue bounds a subscriber's queue. Small on purpose: a deep queue
	// does not stop a client falling behind, it only delays the moment anyone
	// notices.
	EventQueue int

	// KeepAlive is how often an idle event stream sends a comment, so an
	// intermediary does not decide the connection is dead.
	KeepAlive time.Duration
}

// NewServer returns a server over a daemon.
func NewServer(d *daemon.Daemon) *Server {
	s := &Server{
		daemon:     d,
		mux:        http.NewServeMux(),
		EventQueue: 256,
		KeepAlive:  20 * time.Second,
	}
	s.register()
	return s
}

// Routes returns the API surface, sorted, for the OpenAPI document and the
// parity test.
func (s *Server) Routes() []Route {
	out := append([]Route(nil), s.routes...)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Service != out[j].Service {
			return out[i].Service < out[j].Service
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// ServeHTTP implements http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Xfuzz-Api", APIVersion)

	if err := s.authorize(r); err != nil {
		writeError(w, http.StatusUnauthorized, err)
		return
	}
	s.mux.ServeHTTP(w, r)
}

// APIVersion identifies the surface. It changes when a route's meaning changes,
// which is what lets a client refuse a daemon it does not understand rather
// than misinterpreting it.
const APIVersion = "1"

// authorize checks the bearer token when one is configured.
func (s *Server) authorize(r *http.Request) error {
	if s.Token == "" {
		return nil
	}
	const prefix = "Bearer "
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, prefix) || !constantTimeEqual(h[len(prefix):], s.Token) {
		return errors.New("a valid bearer token is required")
	}
	return nil
}

// route registers one method.
func (s *Server) route(r Route) {
	s.routes = append(s.routes, r)
	pattern := r.Method + " " + r.Path
	s.mux.HandleFunc(pattern, r.handler)
}

// --- response helpers -------------------------------------------------------

// Error is the body of every failed response.
//
// One shape for every failure, because a client that has to guess whether an
// error is a string, an object, or an HTML page is a client that will guess
// wrong on the day it matters.
type Error struct {
	Error   string   `json:"error"`
	Details []string `json:"details,omitempty"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	// A write failure here means the client went away mid-response. There is
	// nothing to say to it and the status line is already sent.
	_ = enc.Encode(v)
}

func writeError(w http.ResponseWriter, status int, err error) {
	body := Error{Error: err.Error()}

	// A campaign file with nine problems reports nine problems. Flattening them
	// into one string would undo the work validation did to produce a list.
	var invalid *campaignInvalid
	if errors.As(err, &invalid) {
		body.Error = invalid.headline
		body.Details = invalid.details
	}
	writeJSON(w, status, body)
}

// statusFor maps a domain error to an HTTP status.
func statusFor(err error) int {
	switch {
	case errors.Is(err, daemon.ErrNoCampaign):
		return http.StatusNotFound
	case errors.Is(err, daemon.ErrNotRunning):
		return http.StatusConflict
	case errors.Is(err, daemon.ErrNoTriage):
		// The campaign turned triage off, so the capability is absent rather
		// than the request being wrong.
		return http.StatusConflict
	default:
		return http.StatusInternalServerError
	}
}

func decodeBody(r *http.Request, v any) error {
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, maxRequestBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("unreadable request body: %w", err)
	}
	return nil
}

// decodeOptional reads a request body that a client may leave out.
//
// An absent body means "use the campaign's own settings". A present but
// unreadable one is still an error: a client that sent a body with a
// misspelled field asked for something, and answering with the defaults would
// look like it worked.
func decodeOptional(r *http.Request, v any) error {
	if r.Body == nil || r.ContentLength == 0 {
		return nil
	}
	err := decodeBody(r, v)
	if errors.Is(err, io.EOF) {
		return nil
	}
	return err
}

// maxRequestBytes bounds a request body. Campaign documents are the largest
// thing posted here and they are configuration files, not corpora.
const maxRequestBytes = 4 << 20

// constantTimeEqual compares two tokens without leaking their length difference
// through timing.
func constantTimeEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := 0; i < len(a); i++ {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}
