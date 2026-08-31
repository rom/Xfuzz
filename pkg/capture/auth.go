package capture

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// Credentials in a capture.
//
// Two problems, and they pull in the same direction. Fuzzing a bearer token
// produces nothing but 401s — every mutation is rejected before the request
// reaches any application logic, so the campaign spends its budget on the
// authentication layer and never gets past it. And a capture from a real session
// contains real credentials, which ASR-0010 makes something to handle with care
// rather than something to write to disk beside the corpus.
//
// So credentials are recognised, held fixed, and redacted at rest (ADR-0014).
// The seed a campaign stores carries a placeholder; the real value lives in a
// secrets table the operator keeps beside it and the executor substitutes back
// before sending. Losing the secrets file costs a campaign its authentication
// and costs nobody their tokens.
//
// Recognition is by shape and by name, so it is neither complete nor exact. A
// custom header carrying a session identifier under a name nobody has seen
// before will be missed, and a header called "X-Api-Version" may be caught. Both
// are recoverable — the campaign can be told about extra locations, and a
// wrongly-redacted value still round-trips through the secrets table — and the
// alternative, doing nothing unless certain, means writing tokens to disk.

// CredentialKind says why a value was recognised.
type CredentialKind uint8

// The kinds, which are also the order of confidence: a bearer token is
// unambiguous and a suspiciously long opaque query parameter is a guess.
const (
	CredAuthorization CredentialKind = iota
	CredCookie
	CredAPIKey
	CredTokenField
)

var credNames = [...]string{
	CredAuthorization: "authorization header",
	CredCookie:        "cookie",
	CredAPIKey:        "api key",
	CredTokenField:    "token field",
}

func (k CredentialKind) String() string {
	if int(k) < len(credNames) {
		return credNames[k]
	}
	return "credential"
}

// Credential is one recognised secret and where it was.
type Credential struct {
	Location Location
	Kind     CredentialKind

	// Value is the secret itself. It is here because the campaign needs it to
	// authenticate; it is what Redact takes out of anything written to disk.
	Value string
}

// headerCredentials are the header names whose values are secrets.
var headerCredentials = map[string]CredentialKind{
	"authorization":       CredAuthorization,
	"proxy-authorization": CredAuthorization,
	"cookie":              CredCookie,
	"x-api-key":           CredAPIKey,
	"api-key":             CredAPIKey,
	"x-auth-token":        CredAPIKey,
	"x-access-token":      CredAPIKey,
	"x-session-token":     CredAPIKey,
	"x-csrf-token":        CredAPIKey,
	"x-xsrf-token":        CredAPIKey,
}

// fieldCredentials are the names, in a query string or a JSON body, whose values
// are secrets. Matched on the last path element of a JSON pointer.
var fieldCredentials = map[string]CredentialKind{
	"access_token":  CredTokenField,
	"accesstoken":   CredTokenField,
	"refresh_token": CredTokenField,
	"refreshtoken":  CredTokenField,
	"id_token":      CredTokenField,
	"token":         CredTokenField,
	"api_key":       CredAPIKey,
	"apikey":        CredAPIKey,
	"secret":        CredTokenField,
	"client_secret": CredTokenField,
	"password":      CredTokenField,
	"passwd":        CredTokenField,
	"session":       CredTokenField,
	"sessionid":     CredTokenField,
	"session_id":    CredTokenField,
	"auth":          CredTokenField,
	"jwt":           CredTokenField,
	"signature":     CredTokenField,
}

// FindCredentials returns the secrets a capture carries.
func FindCredentials(c *Capture) []Credential {
	var out []Credential
	for i := range c.Exchanges {
		r := &c.Exchanges[i].Request
		for _, h := range r.Headers {
			kind, ok := headerCredentials[strings.ToLower(strings.TrimSpace(h.Name))]
			if !ok || h.Value == "" {
				continue
			}
			out = append(out, Credential{
				Location: Location{Exchange: i, Part: PartHeader, Name: h.Name},
				Kind:     kind, Value: secretPart(h.Value),
			})
		}
		for _, q := range r.Query() {
			if kind, ok := fieldCredentials[normaliseField(q.Name)]; ok && q.Value != "" {
				out = append(out, Credential{
					Location: Location{Exchange: i, Part: PartQuery, Name: q.Name},
					Kind:     kind, Value: q.Value,
				})
			}
		}
		for _, jv := range jsonValues(r.Body) {
			if kind, ok := fieldCredential(jv.pointer); ok && jv.value != "" {
				out = append(out, Credential{
					Location: Location{Exchange: i, Part: PartBody, Name: jv.pointer},
					Kind:     kind, Value: jv.value,
				})
			}
		}

		// The response too. A login answers with the token every later request
		// will carry, and a capture that redacted the requests and left the
		// response would have written the secret to disk anyway — beside the
		// placeholder that was supposed to hide it.
		resp := &c.Exchanges[i].Response
		for _, jv := range jsonValues(resp.Body) {
			if kind, ok := fieldCredential(jv.pointer); ok && jv.value != "" {
				out = append(out, Credential{
					Location: Location{Exchange: i, Part: PartBody, Name: jv.pointer},
					Kind:     kind, Value: jv.value,
				})
			}
		}
		for _, h := range resp.Headers {
			if strings.EqualFold(strings.TrimSpace(h.Name), "set-cookie") && h.Value != "" {
				_, value, _ := strings.Cut(firstField(h.Value), "=")
				if value != "" {
					out = append(out, Credential{
						Location: Location{Exchange: i, Part: PartHeader, Name: h.Name},
						Kind:     CredCookie, Value: value,
					})
				}
			}
		}
	}
	return out
}

// fieldCredential reports whether a JSON pointer's last element names a secret.
func fieldCredential(pointer string) (CredentialKind, bool) {
	last := pointer[strings.LastIndexByte(pointer, '/')+1:]
	kind, ok := fieldCredentials[normaliseField(last)]
	return kind, ok
}

// secretPart returns the part of an authorization header value that is actually
// secret.
//
// "Bearer eyJ..." is a scheme and a credential, and only the second is a secret.
// Redacting the whole value is wrong twice over: it hides which scheme was in
// use, which an operator reviewing the capture wants to see, and it means the
// bare token — which is what the response that issued it contains — is not
// recognised as the same string and survives redaction there.
func secretPart(value string) string {
	v := strings.TrimSpace(value)
	scheme, rest, ok := strings.Cut(v, " ")
	if !ok || rest == "" {
		return v
	}
	switch strings.ToLower(scheme) {
	case "bearer", "basic", "digest", "token", "apikey", "negotiate", "ntlm", "hoba", "mutual":
		return strings.TrimSpace(rest)
	}
	return v
}

func normaliseField(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.ReplaceAll(s, "-", "_")
	return s
}

// Secrets maps a placeholder to the value it stands for.
//
// Held in memory and written, if at all, to a file of the operator's choosing
// with restrictive permissions — never into the corpus, the store, or an export.
type Secrets struct {
	byPlaceholder map[string]string
	order         []string
}

// NewSecrets returns an empty table.
func NewSecrets() *Secrets {
	return &Secrets{byPlaceholder: map[string]string{}}
}

// Placeholder returns the stand-in for a value, adding it if new.
//
// Derived from the value rather than from a counter, so the same token appearing
// in forty requests gets one placeholder and the redacted capture still shows
// that they were the same token. A counter would make each occurrence look
// distinct, and a campaign reading the redacted seed would conclude that every
// request authenticated differently.
func (s *Secrets) Placeholder(value string) string {
	sum := sha256.Sum256([]byte(value))
	ph := "xfuzz-secret-" + hex.EncodeToString(sum[:6])
	if _, seen := s.byPlaceholder[ph]; !seen {
		s.byPlaceholder[ph] = value
		s.order = append(s.order, ph)
	}
	return ph
}

// Len returns how many distinct secrets are held.
func (s *Secrets) Len() int { return len(s.byPlaceholder) }

// Placeholders lists them in the order they were first seen.
func (s *Secrets) Placeholders() []string { return append([]string(nil), s.order...) }

// Value returns what a placeholder stands for.
func (s *Secrets) Value(placeholder string) (string, bool) {
	v, ok := s.byPlaceholder[placeholder]
	return v, ok
}

// Apply substitutes the real values back into bytes about to be sent.
//
// The one place secrets re-enter, immediately before the request leaves. It
// operates on the encoded request rather than on the tree so that a mutation
// which moved or duplicated a placeholder still resolves — and so that a
// placeholder a mutator invented, which stands for nothing, is left alone rather
// than resolving to some other campaign's token.
func (s *Secrets) Apply(b []byte) []byte {
	if len(s.byPlaceholder) == 0 {
		return b
	}
	out := string(b)
	// Longest first, so a placeholder that is a prefix of another cannot eat it.
	phs := s.Placeholders()
	sort.Slice(phs, func(i, j int) bool { return len(phs[i]) > len(phs[j]) })
	for _, ph := range phs {
		if strings.Contains(out, ph) {
			out = strings.ReplaceAll(out, ph, s.byPlaceholder[ph])
		}
	}
	return []byte(out)
}

// ApplySession substitutes secrets into a whole session, request by request.
//
// Split first, substitute second, and recompute each request's length before
// moving to the next. The order is forced: a request's boundary is found from
// its declared length, so substituting into the flat stream first would leave
// lengths that no longer locate the boundaries — and the repair would then read
// the beginning of the next request as the end of this one's body. Measured that
// way round, a three-request session came back with the first request's length
// fifteen bytes long and the second request's opening line inside its body.
func (s *Secrets) ApplySession(session []byte) []byte {
	if s.Len() == 0 {
		return session
	}
	var out []byte
	rest := session
	for len(rest) > 0 {
		head, body, consumed, ok := splitRequest(rest)
		if !ok {
			out = append(out, s.Apply(rest)...)
			break
		}
		head = s.Apply(head)
		body = s.Apply(body)
		out = append(out, rewriteLength(head, len(body))...)
		out = append(out, body...)
		rest = rest[consumed:]
	}
	return out
}

// Redact returns a copy of the capture with every recognised credential replaced
// by a placeholder, and the table needed to put them back.
//
// A copy, because the original is what the executor authenticates with and the
// redacted one is what is written down. Conflating the two is how a token ends
// up in a corpus export.
func Redact(c *Capture) (*Capture, *Secrets) {
	creds := FindCredentials(c)
	secrets := NewSecrets()
	if len(creds) == 0 {
		return c, secrets
	}

	// The distinct secret values, longest first, so replacing one cannot damage
	// another that contains it.
	values := map[string]bool{}
	for _, cr := range creds {
		values[cr.Value] = true
	}
	list := make([]string, 0, len(values))
	for v := range values {
		list = append(list, v)
	}
	sort.Slice(list, func(i, j int) bool {
		if len(list[i]) != len(list[j]) {
			return len(list[i]) > len(list[j])
		}
		return list[i] < list[j]
	})
	for _, v := range list {
		secrets.Placeholder(v)
	}

	out := &Capture{Notes: c.Notes, Exchanges: make([]Exchange, len(c.Exchanges))}
	for i, e := range c.Exchanges {
		red := e
		red.Request.Headers = append([]Header(nil), e.Request.Headers...)
		red.Response.Headers = append([]Header(nil), e.Response.Headers...)

		// Accumulating, not recomputing. Rebuilding each body from the original
		// on every iteration means only the last secret of several survives the
		// loop — which does not fail, it just leaves the earlier ones in the
		// file that was supposed to have none.
		reqBody := string(e.Request.Body)
		respBody := string(e.Response.Body)
		for _, v := range list {
			ph := secrets.Placeholder(v)
			red.Request.URL = strings.ReplaceAll(red.Request.URL, v, ph)
			for j := range red.Request.Headers {
				red.Request.Headers[j].Value = strings.ReplaceAll(red.Request.Headers[j].Value, v, ph)
			}
			reqBody = strings.ReplaceAll(reqBody, v, ph)

			// The response too: a login's response carries the token the next
			// request sends, and redacting only the request would leave the
			// secret in the capture beside a placeholder that hides it.
			for j := range red.Response.Headers {
				red.Response.Headers[j].Value = strings.ReplaceAll(red.Response.Headers[j].Value, v, ph)
			}
			respBody = strings.ReplaceAll(respBody, v, ph)
		}
		red.Request.Body = []byte(reqBody)
		red.Response.Body = []byte(respBody)
		out.Exchanges[i] = red
	}
	out.Notes = append(out.Notes,
		fmt.Sprintf("%d credential(s) in %d distinct value(s) were redacted",
			len(creds), secrets.Len()))
	return out, secrets
}
