package client

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A daemon this client does not understand is refused by name, rather than
// misread and reported as whatever the mismatch happened to break first.
func TestAMismatchedDaemonIsRefused(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Xfuzz-Api", "99")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	c, err := New(Options{Addr: srv.Listener.Addr().String()})
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	err = c.Do(context.Background(), "GET", "/v1/info", nil, &out)
	if !errors.Is(err, ErrVersionMismatch) {
		t.Fatalf("a daemon speaking version 99 was accepted: %v", err)
	}
	if !strings.Contains(err.Error(), "99") || !strings.Contains(err.Error(), APIVersion) {
		t.Errorf("the message names neither version: %v", err)
	}
}

// Something other than xfuzzd answering is not a version problem, and saying it
// is would send the reader looking for the wrong thing. The response itself
// says more than a version complaint could.
func TestAnUnversionedAnswerIsNotAVersionComplaint(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	c, err := New(Options{Addr: srv.Listener.Addr().String()})
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := c.Do(context.Background(), "GET", "/v1/info", nil, &out); err != nil {
		t.Fatalf("a response with no version header was refused: %v", err)
	}
}
