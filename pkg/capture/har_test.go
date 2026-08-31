package capture_test

import (
	"strings"
	"testing"

	"github.com/rom/Xfuzz/pkg/capture"
)

// A HAR from a real browsing session is messier than the specification suggests:
// cancelled requests with no response, data: URLs that are not requests at all,
// bodies recorded as base64 or as form parameters rather than as text, and
// HTTP/2 pseudo-headers that describe the request line rather than being header
// fields. Each of those appears here, because dropping any of them silently
// would leave an operator wondering why their capture is smaller than the
// session they recorded.

const harDoc = `{
  "log": {
    "version": "1.2",
    "entries": [
      {
        "startedDateTime": "2026-03-01T10:00:02Z",
        "time": 42.5,
        "request": {
          "method": "POST", "url": "https://api.example.com/items",
          "httpVersion": "HTTP/2",
          "headers": [
            {"name": ":authority", "value": "api.example.com"},
            {"name": "Content-Type", "value": "application/json"},
            {"name": "Authorization", "value": "Bearer secret-token"}
          ],
          "postData": {"mimeType": "application/json", "text": "{\"name\":\"widget\"}"}
        },
        "response": {
          "status": 201, "httpVersion": "HTTP/2",
          "headers": [{"name": "Content-Type", "value": "application/json"}],
          "content": {"size": 20, "mimeType": "application/json", "text": "{\"id\":\"abc-123\"}"}
        }
      },
      {
        "startedDateTime": "2026-03-01T10:00:01Z",
        "time": 10,
        "request": {
          "method": "GET", "url": "https://api.example.com/health",
          "httpVersion": "HTTP/1.1", "headers": []
        },
        "response": {
          "status": 200, "httpVersion": "HTTP/1.1", "headers": [],
          "content": {"size": 2, "mimeType": "application/json", "text": "e30=", "encoding": "base64"}
        }
      },
      {
        "startedDateTime": "2026-03-01T10:00:03Z",
        "request": {
          "method": "POST", "url": "https://api.example.com/form",
          "headers": [{"name": "Content-Type", "value": "application/x-www-form-urlencoded"}],
          "postData": {
            "mimeType": "application/x-www-form-urlencoded",
            "params": [{"name": "a", "value": "1"}, {"name": "b", "value": "2"}]
          }
        },
        "response": {"status": 0, "headers": [], "content": {}}
      },
      {
        "request": {"method": "GET", "url": "data:image/png;base64,iVBOR", "headers": []},
        "response": {"status": 200, "headers": [], "content": {}}
      },
      {
        "request": {"method": "", "url": "", "headers": []},
        "response": {"status": 0, "headers": [], "content": {}}
      }
    ]
  }
}`

func TestReadHAR(t *testing.T) {
	c, err := capture.ReadHAR(strings.NewReader(harDoc))
	if err != nil {
		t.Fatal(err)
	}
	if c.Len() != 3 {
		t.Fatalf("read %d exchanges, want the 3 HTTP ones: %v", c.Len(), c.Notes)
	}

	// Ordered by time, not by position in the file: the health check was sent
	// first even though it is listed second.
	if got := c.Exchanges[0].Request.Path(); got != "/health" {
		t.Errorf("first exchange is %s; the capture was not sorted by time", got)
	}

	post := c.Exchanges[1]
	if post.Request.Method != "POST" || post.Request.Path() != "/items" {
		t.Errorf("second exchange is %s %s", post.Request.Method, post.Request.Path())
	}
	if string(post.Request.Body) != `{"name":"widget"}` {
		t.Errorf("body %q", post.Request.Body)
	}
	if post.Response.Status != 201 {
		t.Errorf("status %d", post.Response.Status)
	}
	if post.Response.Elapsed == 0 {
		t.Error("no elapsed time recorded; a latency oracle has nothing to compare against")
	}
	// The pseudo-header describes the request line and is not a header field.
	for _, h := range post.Request.Headers {
		if strings.HasPrefix(h.Name, ":") {
			t.Errorf("HTTP/2 pseudo-header %q kept as a header field", h.Name)
		}
	}
	if post.Request.Get("Authorization") != "Bearer secret-token" {
		t.Error("the Authorization header was not read")
	}

	// A base64 body is decoded; "e30=" is "{}".
	if got := string(c.Exchanges[0].Response.Body); got != "{}" {
		t.Errorf("base64 response body decoded to %q, want {}", got)
	}

	// A form body recorded only as parameters is rebuilt into the bytes the
	// server actually saw.
	form := c.Exchanges[2]
	if string(form.Request.Body) != "a=1&b=2" {
		t.Errorf("form body %q, want it rebuilt from the parameters", form.Request.Body)
	}
}

func TestReadHARReportsWhatItSkipped(t *testing.T) {
	c, err := capture.ReadHAR(strings.NewReader(harDoc))
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(c.Notes, "; ")
	for _, want := range []string{"not an HTTP URL", "no method or URL", "no response recorded"} {
		if !strings.Contains(joined, want) {
			t.Errorf("no note about %q; the notes are %q", want, joined)
		}
	}
}

func TestReadHARRefusesWhatIsNotOne(t *testing.T) {
	for _, tc := range []struct{ name, doc string }{
		{"not JSON", "hello"},
		{"JSON but not HAR", `{"hello": "world"}`},
		{"no entries", `{"log":{"version":"1.2","entries":[]}}`},
		{"only non-HTTP entries", `{"log":{"entries":[{"request":{"method":"GET","url":"data:x"}}]}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := capture.ReadHAR(strings.NewReader(tc.doc)); err == nil {
				t.Error("accepted")
			}
		})
	}
}

// TestCaptureHostsAndFilter covers what a campaign does before it fuzzes
// anything. A capture from a real session reaches a content delivery network, an
// analytics endpoint and an identity provider as well as the API under test, and
// under ADR-0012 fuzzing those is something an operator has to authorise on
// purpose.
func TestCaptureHostsAndFilter(t *testing.T) {
	c, err := capture.ReadHAR(strings.NewReader(harDoc))
	if err != nil {
		t.Fatal(err)
	}
	hosts := c.Hosts()
	if len(hosts) != 1 || hosts[0] != "api.example.com" {
		t.Errorf("hosts %v", hosts)
	}
	if got := c.Filter("other.example.com").Len(); got != 0 {
		t.Errorf("filtering to a host not in the capture kept %d exchanges", got)
	}
	if got := c.Filter("API.EXAMPLE.COM").Len(); got != 3 {
		t.Errorf("host matching is case sensitive; kept %d of 3", got)
	}
}

func TestRequestQueryKeepsOrderAndDuplicates(t *testing.T) {
	r := capture.Request{URL: "https://h/x?a=1&b=two%20words&a=2"}
	q := r.Query()
	if len(q) != 3 {
		t.Fatalf("read %d parameters, want 3 — duplicates are not collapsed", len(q))
	}
	if q[0].Name != "a" || q[0].Value != "1" || q[2].Value != "2" {
		t.Errorf("parameters %v; order and duplication are part of the request", q)
	}
	if q[1].Value != "two words" {
		t.Errorf("value %q was not unescaped", q[1].Value)
	}
}
