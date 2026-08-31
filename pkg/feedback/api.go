package feedback

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Oracles for a service, which fails differently from a parser.
//
// A parser tells you it is broken by crashing. A service almost never crashes —
// it is behind a supervisor, it has a request handler wrapped in a recover, and
// the process outlives anything one request can do to it. What it does instead
// is answer 500, or answer 200 with a body that violates its own contract, or
// take four seconds over something that took forty milliseconds a thousand times
// before, or hand identity B an object belonging to identity A.
//
// None of those is a signal. All of them are bugs, and ADR-0014 names them as
// the reason API fuzzing needs oracles beyond crash detection.

// StatusObjective reports server errors.
//
// 5xx and nothing else. A 4xx is the service telling a fuzzer that the fuzzer
// sent nonsense, which is the expected outcome of nearly every mutation and
// would bury a campaign in findings; a 5xx is the service telling you it could
// not cope, which is the definition of the class.
type StatusObjective struct {
	name string
	obs  *OutputObserver

	// Ignore lists statuses that are not findings on this service. Some APIs
	// answer 501 for an endpoint they have not implemented and 503 while a
	// dependency is restarting, and a campaign that filed those would spend its
	// triage budget on them.
	Ignore map[int]bool
}

// NewStatusObjective returns an objective over the response transcript.
func NewStatusObjective(name string, obs *OutputObserver) *StatusObjective {
	return &StatusObjective{name: name, obs: obs, Ignore: map[int]bool{}}
}

// Name implements Objective.
func (o *StatusObjective) Name() string { return o.name }

// IsFinding implements Objective.
func (o *StatusObjective) IsFinding(_ []Observer, ek ExitKind) (bool, Finding, error) {
	if o.obs == nil {
		return false, Finding{}, nil
	}
	// The tier records the worst status the session saw in the exit code, which
	// is where an objective can read it without parsing a transcript.
	status := o.obs.ExitCode()
	if status < 500 || status > 599 || o.Ignore[status] {
		return false, Finding{}, nil
	}
	_ = ek
	return true, Finding{
		Kind:    "server-error",
		Summary: fmt.Sprintf("the service answered %d %s", status, statusText(status)),
		Detail:  o.obs.Combined(),
	}, nil
}

// SchemaObjective reports a response whose shape violates what the service has
// been observed to produce.
//
// Learned rather than declared, because a specification is exactly what an API
// campaign is assumed not to have (ADR-0014). The shapes a response takes are
// recorded per endpoint and per status during the campaign's own run, and a
// response that introduces a field of a different type from every previous one —
// a string where a number has always been, a null where an object has always
// been — is reported.
//
// It is deliberately narrow. A *new* field is not a violation: services add
// them, and a fuzzer that reported every one would report a finding for the
// first response of every endpoint. A field whose *type* changed is a different
// thing: it means one code path serialises differently from another, which is
// where the bugs of this class live.
type SchemaObjective struct {
	name string
	obs  *OutputObserver

	// seen records the type each JSON pointer has taken.
	seen map[string]string

	// warmup is how many responses are observed before anything is reported, so
	// the first response of a campaign is not a violation of a schema built
	// from nothing.
	Warmup int
	n      int
}

// NewSchemaObjective returns a response-shape objective.
func NewSchemaObjective(name string, obs *OutputObserver) *SchemaObjective {
	return &SchemaObjective{name: name, obs: obs, seen: map[string]string{}, Warmup: 8}
}

// Name implements Objective.
func (o *SchemaObjective) Name() string { return o.name }

// IsFinding implements Objective.
func (o *SchemaObjective) IsFinding(_ []Observer, _ ExitKind) (bool, Finding, error) {
	if o.obs == nil {
		return false, Finding{}, nil
	}
	body := jsonPart(o.obs.Combined())
	if body == "" {
		return false, Finding{}, nil
	}
	shape := jsonShape([]byte(body))
	if len(shape) == 0 {
		return false, Finding{}, nil
	}
	o.n++

	var changed []string
	for _, ptr := range sortedKeys(shape) {
		was, ok := o.seen[ptr]
		if !ok {
			o.seen[ptr] = shape[ptr]
			continue
		}
		if was != shape[ptr] {
			changed = append(changed, fmt.Sprintf("%s was %s and is now %s", ptr, was, shape[ptr]))
			// Recorded as the new type, so the same change is reported once
			// rather than on every response after it.
			o.seen[ptr] = shape[ptr]
		}
	}
	if len(changed) == 0 || o.n <= o.Warmup {
		return false, Finding{}, nil
	}
	return true, Finding{
		Kind:    "schema-violation",
		Summary: "a response field changed type: " + strings.Join(changed, "; "),
		Detail:  body,
	}, nil
}

// LatencyObjective reports a response far slower than the service's own norm.
//
// Against its own norm rather than a threshold, because "slow" for an API is a
// property of that API: forty milliseconds is alarming for a health check and
// unremarkable for a report. The mean and variance are learned during the run,
// which also means the objective says nothing until it has seen enough to have
// a norm at all.
//
// Slow responses are worth finding because they are where algorithmic complexity
// bugs live: a query that is linear for every input the service has seen and
// quadratic for the one a fuzzer just constructed.
type LatencyObjective struct {
	name string
	obs  *TimingObserver

	// Factor is how many times the mean counts as an outlier.
	Factor float64

	// Warmup is how many responses establish the norm.
	Warmup int

	n    int
	mean float64
}

// NewLatencyObjective returns a latency objective.
func NewLatencyObjective(name string, obs *TimingObserver) *LatencyObjective {
	return &LatencyObjective{name: name, obs: obs, Factor: 10, Warmup: 32}
}

// Name implements Objective.
func (o *LatencyObjective) Name() string { return o.name }

// IsFinding implements Objective.
func (o *LatencyObjective) IsFinding(_ []Observer, _ ExitKind) (bool, Finding, error) {
	if o.obs == nil {
		return false, Finding{}, nil
	}
	d := o.obs.Elapsed()
	if d <= 0 {
		return false, Finding{}, nil
	}
	ms := float64(d) / float64(time.Millisecond)

	o.n++
	if o.n <= o.Warmup {
		o.mean += (ms - o.mean) / float64(o.n)
		return false, Finding{}, nil
	}
	if o.mean <= 0 || ms < o.Factor*o.mean {
		// Folded into the norm only when it is not an outlier, so one slow
		// response does not raise the bar for the next.
		o.mean += (ms - o.mean) / float64(o.n)
		return false, Finding{}, nil
	}
	return true, Finding{
		Kind: "latency",
		Summary: fmt.Sprintf("the service took %.0fms against a mean of %.0fms over %d responses",
			ms, o.mean, o.n-1),
	}, nil
}

// AuthorizationObjective reports a request that succeeded when it should not
// have.
//
// This is the class ADR-0014 says captured traffic makes reachable and a
// specification does not: a capture carries identity, so a session recorded as
// identity A can be replayed with identity B's credentials, and a request that
// still succeeds is one whose authorization check does not exist. BOLA and IDOR
// are exactly that, and they are invisible to crash fuzzing.
//
// The judgement is a comparison, not a rule. What makes a replay a finding is
// that the *same* request answered 200 for the identity that owns the object and
// also answered 200 for one that does not; a service answering 200 to everyone
// for a public endpoint is not a finding, and the only way to tell them apart is
// to have seen the endpoint refuse somebody.
type AuthorizationObjective struct {
	name string
	obs  *OutputObserver

	// Identity is which identity's credentials the current session is using,
	// and Expected is what the service should answer for it. Both are set by
	// the campaign before each session rather than inferred, because only the
	// campaign knows whose token it just substituted.
	Identity string
	Expected AuthOutcome

	// refused records the endpoints that have refused *some* identity, which is
	// what distinguishes a protected resource from a public one.
	refused map[string]bool
}

// AuthOutcome is what a replay under a given identity ought to produce.
type AuthOutcome uint8

// The outcomes.
const (
	// AuthUnknown means the campaign is not making a claim about this session,
	// which is the state for every ordinary fuzzing session.
	AuthUnknown AuthOutcome = iota

	// AuthAllowed means this identity owns the objects the session touches.
	AuthAllowed

	// AuthDenied means it does not, and every request that touches them should
	// be refused.
	AuthDenied
)

// NewAuthorizationObjective returns an authorization objective.
func NewAuthorizationObjective(name string, obs *OutputObserver) *AuthorizationObjective {
	return &AuthorizationObjective{name: name, obs: obs, refused: map[string]bool{}}
}

// Name implements Objective.
func (o *AuthorizationObjective) Name() string { return o.name }

// Observe records what an endpoint answered for an identity, which is how the
// objective learns that the endpoint refuses anybody at all.
func (o *AuthorizationObjective) Observe(endpoint string, status int) {
	if status == 401 || status == 403 {
		o.refused[endpoint] = true
	}
}

// Protected reports whether an endpoint has ever refused an identity.
func (o *AuthorizationObjective) Protected(endpoint string) bool { return o.refused[endpoint] }

// IsFinding implements Objective.
func (o *AuthorizationObjective) IsFinding(_ []Observer, _ ExitKind) (bool, Finding, error) {
	if o.obs == nil || o.Expected != AuthDenied {
		return false, Finding{}, nil
	}
	status := o.obs.ExitCode()
	if status == 0 || status >= 400 {
		// Refused, or nothing to judge. Either is the correct outcome for an
		// identity that should not have access.
		return false, Finding{}, nil
	}
	return true, Finding{
		Kind: "authorization",
		Summary: fmt.Sprintf("a session replayed as %q, which should not have access, "+
			"answered %d", o.Identity, status),
		Detail: o.obs.Combined(),
	}, nil
}

// jsonPart returns the JSON document inside a transcript, if there is one.
func jsonPart(transcript string) string {
	i := strings.IndexAny(transcript, "{[")
	if i < 0 {
		return ""
	}
	return strings.TrimSpace(transcript[i:])
}

// jsonShape maps each pointer in a document to the name of its type.
func jsonShape(body []byte) map[string]string {
	var doc any
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil
	}
	out := map[string]string{}
	var walk func(prefix string, v any)
	walk = func(prefix string, v any) {
		if len(out) > 512 {
			return
		}
		switch t := v.(type) {
		case map[string]any:
			out[prefix] = "object"
			for k, e := range t {
				walk(prefix+"/"+k, e)
			}
		case []any:
			out[prefix] = "array"
			// The element type, not each element's: an array of ten objects has
			// one shape, and recording ten would make its length part of the
			// schema.
			if len(t) > 0 {
				walk(prefix+"/*", t[0])
			}
		case string:
			out[prefix] = "string"
		case float64:
			out[prefix] = "number"
		case bool:
			out[prefix] = "boolean"
		case nil:
			out[prefix] = "null"
		}
	}
	walk("", doc)
	return out
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// statusText names a status without importing net/http into the core.
func statusText(code int) string {
	switch code {
	case 500:
		return "Internal Server Error"
	case 501:
		return "Not Implemented"
	case 502:
		return "Bad Gateway"
	case 503:
		return "Service Unavailable"
	case 504:
		return "Gateway Timeout"
	}
	return "status " + strconv.Itoa(code)
}
