package capture

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"
)

// Reading HAR.
//
// HAR is what every browser's developer tools export and what every HTTP proxy
// can write, which makes it the format an operator is most likely to already
// have. It is JSON with a documented shape, so reading it is mostly a matter of
// being careful about the places the specification is permissive: bodies may be
// text or base64, timings may be absent or negative, and the file may or may not
// record when anything happened.
//
// Read leniently, report what was skipped. A HAR from a real browsing session
// contains entries with no response (a request that was cancelled), entries for
// resources that are not HTTP at all, and occasionally malformed ones. Refusing
// the file because one entry of nine hundred is odd would be useless; dropping
// them silently would leave an operator wondering why their capture is smaller
// than their session.

// harFile is the top level of a HAR document.
type harFile struct {
	Log struct {
		Version string     `json:"version"`
		Entries []harEntry `json:"entries"`
	} `json:"log"`
}

type harEntry struct {
	StartedDateTime string      `json:"startedDateTime"`
	Time            float64     `json:"time"`
	Request         harRequest  `json:"request"`
	Response        harResponse `json:"response"`
}

type harRequest struct {
	Method      string      `json:"method"`
	URL         string      `json:"url"`
	HTTPVersion string      `json:"httpVersion"`
	Headers     []harHeader `json:"headers"`
	PostData    *harPost    `json:"postData"`
}

type harResponse struct {
	Status      int         `json:"status"`
	HTTPVersion string      `json:"httpVersion"`
	Headers     []harHeader `json:"headers"`
	Content     harContent  `json:"content"`
}

type harHeader struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type harPost struct {
	MimeType string `json:"mimeType"`
	Text     string `json:"text"`
	Params   []struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	} `json:"params"`
}

type harContent struct {
	Size     int64  `json:"size"`
	MimeType string `json:"mimeType"`
	Text     string `json:"text"`
	Encoding string `json:"encoding"`
}

// MaxCaptureBytes bounds what a reader will take from a file it did not write.
//
// A capture comes from somewhere else — a browser, a colleague, a bug report —
// and its size is not something the fuzzer chose. Sixty-four megabytes is far
// more than any session worth seeding from and far less than enough to matter.
const MaxCaptureBytes = 64 << 20

// ReadHAR parses a HAR document.
func ReadHAR(r io.Reader) (*Capture, error) {
	data, err := io.ReadAll(io.LimitReader(r, MaxCaptureBytes+1))
	if err != nil {
		return nil, fmt.Errorf("capture: reading the HAR: %w", err)
	}
	if len(data) > MaxCaptureBytes {
		return nil, fmt.Errorf("capture: the HAR is larger than %d bytes", MaxCaptureBytes)
	}

	var f harFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("capture: this is not a HAR document: %w", err)
	}
	if len(f.Log.Entries) == 0 {
		return nil, fmt.Errorf("capture: the HAR has no entries")
	}

	c := &Capture{}
	skipped := map[string]int{}
	for i, e := range f.Log.Entries {
		if e.Request.Method == "" || e.Request.URL == "" {
			skipped["no method or URL"]++
			continue
		}
		if !strings.HasPrefix(strings.ToLower(e.Request.URL), "http") {
			// data: and blob: URLs appear in a browser's HAR and are not
			// requests to anything.
			skipped["not an HTTP URL"]++
			continue
		}

		ex := Exchange{Source: "har"}
		ex.Request = Request{
			Method:  e.Request.Method,
			URL:     e.Request.URL,
			Proto:   e.Request.HTTPVersion,
			Headers: harHeaders(e.Request.Headers),
			Body:    harBody(e.Request.PostData),
		}
		ex.Response = Response{
			Status:  e.Response.Status,
			Proto:   e.Response.HTTPVersion,
			Headers: harHeaders(e.Response.Headers),
			Body:    harContentBody(e.Response.Content),
		}
		if e.Time > 0 {
			ex.Response.Elapsed = time.Duration(e.Time * float64(time.Millisecond))
		}
		if e.StartedDateTime != "" {
			if t, terr := time.Parse(time.RFC3339, e.StartedDateTime); terr == nil {
				ex.At = t
			}
		}
		if ex.Response.Status == 0 {
			// A cancelled or in-flight request. The request is still a perfectly
			// good seed — it is a shape the server accepts — but nothing can be
			// said about the response, and an oracle that treated status 0 as an
			// observation would find a violation in every one of them.
			skipped["no response recorded"]++
		}
		_ = i
		c.Exchanges = append(c.Exchanges, ex)
	}
	if len(c.Exchanges) == 0 {
		return nil, fmt.Errorf("capture: the HAR's %d entries contained no HTTP requests",
			len(f.Log.Entries))
	}
	c.Notes = append(c.Notes, skipNotes(skipped)...)
	c.Sort()
	return c, nil
}

func harHeaders(in []harHeader) []Header {
	out := make([]Header, 0, len(in))
	for _, h := range in {
		if h.Name == "" || strings.HasPrefix(h.Name, ":") {
			// HTTP/2 pseudo-headers. They describe the request line rather than
			// being header fields, and the method and URL are already recorded.
			continue
		}
		out = append(out, Header{Name: h.Name, Value: h.Value})
	}
	return out
}

func harBody(p *harPost) []byte {
	if p == nil {
		return nil
	}
	if p.Text != "" {
		return []byte(p.Text)
	}
	// A HAR writer may split a form body into parameters and record no text. The
	// bytes the server saw are the encoded form, so they are rebuilt rather than
	// treated as an empty body.
	if len(p.Params) > 0 {
		var b strings.Builder
		for i, kv := range p.Params {
			if i > 0 {
				b.WriteByte('&')
			}
			b.WriteString(kv.Name)
			b.WriteByte('=')
			b.WriteString(kv.Value)
		}
		return []byte(b.String())
	}
	return nil
}

func harContentBody(c harContent) []byte {
	if c.Text == "" {
		return nil
	}
	if strings.EqualFold(c.Encoding, "base64") {
		if b, err := base64.StdEncoding.DecodeString(c.Text); err == nil {
			return b
		}
		// Declared base64 and is not. The text is kept rather than dropped: it
		// is still what the file recorded, and a response body is read by
		// oracles rather than replayed, so a wrong guess costs a misparse rather
		// than a wrong request.
	}
	return []byte(c.Text)
}

// skipNotes turns the skip tally into one note per reason.
func skipNotes(skipped map[string]int) []string {
	if len(skipped) == 0 {
		return nil
	}
	out := make([]string, 0, len(skipped))
	for reason, n := range skipped {
		out = append(out, fmt.Sprintf("%d entr%s skipped: %s", n, plural(n), reason))
	}
	return out
}

func plural(n int) string {
	if n == 1 {
		return "y"
	}
	return "ies"
}
