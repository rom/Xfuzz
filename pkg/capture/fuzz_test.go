package capture

import (
	"strings"
	"testing"
)

// FuzzRead fuzzes the capture readers.
//
// Untrusted for a reason the other parsers here do not have: a pcap is bytes
// somebody else put on a network, and a HAR is a file a browser wrote about
// them. Both arrive from outside the campaign, and the pcap path in particular
// reassembles TCP from adversary-controlled sequence numbers and lengths
// (ADR-0021, SECURITY.md section 3.5).
//
// The properties are the ones the rest of the system relies on. A capture that
// reads must be one Session can render and ReadSession can read back, because
// that round trip is how a recording becomes a seed. Redaction must remove
// every secret it claims to have found, because the redacted capture is what
// goes into a corpus and a store.
func FuzzRead(f *testing.F) {
	f.Add([]byte("GET /a HTTP/1.1\r\nHost: h\r\n\r\n"))
	f.Add([]byte("POST /a HTTP/1.1\r\nHost: h\r\nContent-Length: 3\r\n\r\nabc"))
	f.Add([]byte("POST /a HTTP/1.1\r\nHost: h\r\nAuthorization: Bearer abcdefghijkl\r\n\r\n"))
	f.Add([]byte(`{"log":{"entries":[{"request":{"method":"GET","url":"https://h/a"}}]}}`))
	f.Add([]byte(`{"log":{"entries":[]}}`))
	f.Add([]byte("\xd4\xc3\xb2\xa1"))
	f.Add([]byte("\xa1\xb2\xc3\xd4\x00\x02\x00\x04"))
	f.Add([]byte(""))
	f.Add([]byte("POST /a HTTP/1.1\r\nContent-Length: 99999999\r\n\r\nx"))
	f.Add([]byte("POST /a HTTP/1.1\r\nContent-Length: -1\r\n\r\nx"))

	f.Fuzz(func(t *testing.T, src []byte) {
		c, err := Read("fuzz", src)
		if err != nil {
			if c != nil {
				t.Fatal("a failed read returned a capture as well as an error")
			}
			return
		}
		if c == nil {
			t.Fatal("a successful read returned no capture")
		}
		if len(c.Exchanges) == 0 {
			t.Fatal("a successful read returned no exchanges; the readers refuse an " +
				"empty capture so that a campaign fails at load rather than at run")
		}

		// The seed a campaign replays. It has to be readable again, or a
		// capture that imported cannot be written out and used.
		session := c.Session()
		if len(session) == 0 {
			t.Fatal("a capture with exchanges rendered an empty session")
		}
		back, err := ReadSession(session)
		if err != nil {
			t.Fatalf("the session this capture rendered does not read back: %v\n%q",
				err, elideSession(session))
		}
		if len(back.Exchanges) != len(c.Exchanges) {
			t.Fatalf("%d exchanges rendered to a session that reads back as %d:\n%q",
				len(c.Exchanges), len(back.Exchanges), elideSession(session))
		}

		// Redaction is what keeps a credential out of the corpus and the store.
		// A secret it reports having found and left in the bytes is worse than
		// one it never looked for.
		red, secrets := Redact(c)
		whole := string(red.Session())
		for _, ph := range secrets.Placeholders() {
			value, ok := secrets.Value(ph)
			if !ok || value == "" {
				continue
			}
			if strings.Contains(whole, value) {
				t.Fatalf("the secret behind %s survives in the redacted session", ph)
			}
		}
		// And inference must not invent a dependency on nothing.
		for _, l := range Infer(red) {
			if l.From.Exchange >= l.To.Exchange {
				t.Fatalf("inferred %s: a request cannot take a value from a response "+
					"that had not happened", l)
			}
			if len(l.Value) < minLinkValue {
				t.Fatalf("inferred a link on %q, below the length that means anything", l.Value)
			}
		}
	})
}

func elideSession(b []byte) string {
	if len(b) <= 200 {
		return string(b)
	}
	return string(b[:200]) + "..."
}
