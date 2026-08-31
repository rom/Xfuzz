package executor_test

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rom/Xfuzz/pkg/codec"
	"github.com/rom/Xfuzz/pkg/executor"
	"github.com/rom/Xfuzz/pkg/feedback"
	"github.com/rom/Xfuzz/pkg/ir"
)

// A captured session replayed against a live service. What has to work is the
// chaining: a create that produces a new identifier, and a use that has to carry
// the new one rather than the recorded one. Everything else the tier does is
// bookkeeping around that.

// plainDialer is the scope guard's shape without the guard, for tests that are
// about the tier rather than about confinement.
type plainDialer struct{}

func (plainDialer) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, network, address)
}

// apiServer is a small service with an identifier it issues and then checks.
type apiServer struct {
	mu      sync.Mutex
	issued  string
	seen    []string
	slow    bool
	broken  bool
	nextID  int
	srv     *httptest.Server
	Address string
}

func newAPIServer(t *testing.T) *apiServer {
	t.Helper()
	s := &apiServer{}
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		body, _ := io.ReadAll(r.Body)

		switch {
		case r.URL.Path == "/items" && r.Method == "POST":
			s.nextID++
			s.issued = fmt.Sprintf("issued-identifier-%04d", s.nextID)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			fmt.Fprintf(w, `{"id":%q,"name":%q}`, s.issued, strings.TrimSpace(string(body)))

		case strings.HasPrefix(r.URL.Path, "/items/"):
			id := strings.TrimPrefix(r.URL.Path, "/items/")
			s.seen = append(s.seen, id)
			if s.broken {
				w.WriteHeader(http.StatusInternalServerError)
				io.WriteString(w, `{"error":"boom"}`)
				return
			}
			if s.slow {
				time.Sleep(200 * time.Millisecond)
			}
			if id != s.issued {
				w.WriteHeader(http.StatusNotFound)
				io.WriteString(w, `{"error":"no such item"}`)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{"id":"`+id+`","ok":true}`)

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(s.srv.Close)
	s.Address = "tcp:" + strings.TrimPrefix(s.srv.URL, "http://")
	return s
}

func (s *apiServer) lastSeen() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.seen) == 0 {
		return ""
	}
	return s.seen[len(s.seen)-1]
}

// The recorded session: create an item, then fetch it by the identifier the
// create returned. "recorded-identifier" is what the server issued when the
// capture was taken, and is not what it will issue now.
const recordedID = "recorded-identifier-0000"

func recordedSession() []byte {
	create := "POST /items HTTP/1.1\r\nHost: h\r\nContent-Length: 6\r\n\r\nwidget"
	use := "GET /items/" + recordedID + " HTTP/1.1\r\nHost: h\r\n\r\n"
	return []byte(create + use)
}

func TestAPIWithoutLinksSendsTheStaleIdentifier(t *testing.T) {
	srv := newAPIServer(t)
	out := feedback.NewOutputObserver("output")
	e := executor.NewAPI("api", plainDialer{}, executor.APIOptions{
		Address: srv.Address, FixLength: true,
	})
	e.Output = out

	ek, err := e.Run(t.Context(), executor.Input{Bytes: recordedSession()}, []feedback.Observer{out})
	if err != nil {
		t.Fatal(err)
	}
	if ek != feedback.ExitOK {
		t.Errorf("exit kind %v", ek)
	}
	// This is the failure mode dependency inference exists to prevent: the
	// session sends the identifier from the recording, and everything after the
	// create addresses an object that does not exist.
	if got := srv.lastSeen(); got != recordedID {
		t.Errorf("the service was asked for %q, want the stale %q", got, recordedID)
	}
	if !strings.Contains(out.Combined(), "404") {
		t.Errorf("without links the session should 404:\n%s", out.Combined())
	}
}

// TestAPICarriesAValueForward is the tier's reason to exist.
func TestAPICarriesAValueForward(t *testing.T) {
	srv := newAPIServer(t)
	out := feedback.NewOutputObserver("output")
	e := executor.NewAPI("api", plainDialer{}, executor.APIOptions{
		Address:   srv.Address,
		FixLength: true,
		Links: []executor.Link{{
			From: 0, To: 1, Value: recordedID, Extract: "/id",
		}},
	})
	e.Output = out

	if _, err := e.Run(t.Context(), executor.Input{Bytes: recordedSession()},
		[]feedback.Observer{out}); err != nil {
		t.Fatal(err)
	}

	got := srv.lastSeen()
	if got == recordedID {
		t.Fatal("the recorded identifier was sent; the link did not carry the new one")
	}
	if !strings.HasPrefix(got, "issued-identifier-") {
		t.Fatalf("the service was asked for %q", got)
	}
	if strings.Contains(out.Combined(), "404") {
		t.Errorf("the chained session still 404ed:\n%s", out.Combined())
	}
}

// TestAPICarriesAValueForwardAfterMutation is the same claim under the condition
// that makes it worth having. A campaign mutates the create's body; the server
// then issues a different identifier again, and the link still has to find and
// replace the one in the request that follows.
func TestAPICarriesAValueForwardAfterMutation(t *testing.T) {
	srv := newAPIServer(t)
	out := feedback.NewOutputObserver("output")
	e := executor.NewAPI("api", plainDialer{}, executor.APIOptions{
		Address:   srv.Address,
		FixLength: true,
		Links:     []executor.Link{{From: 0, To: 1, Value: recordedID, Extract: "/id"}},
	})
	e.Output = out

	// Mutated through the tree, which is how the engine does it: decode with the
	// codec, change a node, hand the executor both the tree and its encoding.
	// The mutation lengthens the body, so the declared Content-Length is now
	// stale — and the tree is what still knows where the first request ends.
	a := ir.NewArena()
	tree, err := codec.HTTP{}.Decode(a, recordedSession())
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range tree.Children[0].Children {
		if n.Name == codec.HTTPBody {
			n.Raw = []byte("a much longer widget name")
		}
	}
	encoded := ir.AppendEncode(nil, tree)
	if _, err := e.Run(t.Context(), executor.Input{Bytes: encoded, Node: tree},
		[]feedback.Observer{out}); err != nil {
		t.Fatal(err)
	}
	if got := srv.lastSeen(); !strings.HasPrefix(got, "issued-identifier-") {
		t.Errorf("after a length-changing mutation the service was asked for %q", got)
	}
	if strings.Contains(out.Combined(), "404") {
		t.Errorf("the chained session 404ed after mutation:\n%s", out.Combined())
	}
}

// TestAPISubstitutesSecretsLast checks the ordering the credential handling
// depends on: a secret enters the bytes immediately before the write and is
// never in anything the campaign stores.
func TestAPISubstitutesSecretsLast(t *testing.T) {
	var seen string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Get("Authorization")
	}))
	defer srv.Close()

	out := feedback.NewOutputObserver("output")
	e := executor.NewAPI("api", plainDialer{}, executor.APIOptions{
		Address:   "tcp:" + strings.TrimPrefix(srv.URL, "http://"),
		FixLength: true,
		Substitute: func(b []byte) []byte {
			return []byte(strings.ReplaceAll(string(b), "xfuzz-secret-abc", "Bearer real-token"))
		},
	})
	e.Output = out

	session := "GET /x HTTP/1.1\r\nHost: h\r\nAuthorization: xfuzz-secret-abc\r\n\r\n"
	if _, err := e.Run(t.Context(), executor.Input{Bytes: []byte(session)},
		[]feedback.Observer{out}); err != nil {
		t.Fatal(err)
	}
	if seen != "Bearer real-token" {
		t.Errorf("the service saw %q; the placeholder was not substituted", seen)
	}
}

// TestAPIReportsAnUnreachableServiceAsAHarnessFailure holds the line ADR-0007
// draws. A service that is not listening is not a bug in the input.
func TestAPIReportsAnUnreachableServiceAsAHarnessFailure(t *testing.T) {
	out := feedback.NewOutputObserver("output")
	e := executor.NewAPI("api", plainDialer{}, executor.APIOptions{
		Address:    "tcp:127.0.0.1:1",
		PerRequest: time.Second,
	})
	e.Output = out

	ek, err := e.Run(t.Context(), executor.Input{Bytes: recordedSession()}, []feedback.Observer{out})
	if err == nil {
		t.Fatal("an unreachable service produced no error")
	}
	if ek != feedback.ExitError {
		t.Errorf("exit kind %v; only ExitError keeps it out of the findings", ek)
	}
}

// TestAPIReportsTheWorstStatus is what the status objective reads.
func TestAPIReportsTheWorstStatus(t *testing.T) {
	srv := newAPIServer(t)
	srv.broken = true

	out := feedback.NewOutputObserver("output")
	e := executor.NewAPI("api", plainDialer{}, executor.APIOptions{
		Address: srv.Address, FixLength: true,
		Links: []executor.Link{{From: 0, To: 1, Value: recordedID, Extract: "/id"}},
	})
	e.Output = out
	if _, err := e.Run(t.Context(), executor.Input{Bytes: recordedSession()},
		[]feedback.Observer{out}); err != nil {
		t.Fatal(err)
	}
	if out.ExitCode() != 500 {
		t.Errorf("the session's worst status is %d, want 500", out.ExitCode())
	}

	obj := feedback.NewStatusObjective("status", out)
	found, f, err := obj.IsFinding(nil, feedback.ExitOK)
	if err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Fatal("a 500 was not reported")
	}
	if f.Kind != "server-error" {
		t.Errorf("finding kind %q", f.Kind)
	}
}
