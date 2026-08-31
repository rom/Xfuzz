package worker

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/rom/Xfuzz/pkg/campaign"
	"github.com/rom/Xfuzz/pkg/capture"
	"github.com/rom/Xfuzz/pkg/executor"
	"github.com/rom/Xfuzz/pkg/feedback"
)

// buildAPI assembles the T7-adjacent API tier and the oracles that judge it.
//
// The api block's presence is what makes a campaign an API campaign, the same
// way a session block makes one stateful. What it adds over the session tier is
// the two things a captured API session needs and a raw protocol session does
// not: values the service produced carried into later requests, and responses
// judged rather than merely read (ADR-0014).
func (b *built) buildAPI(ctx context.Context, cfg *campaign.Resolved) error {
	a := cfg.API
	network, _, err := campaign.SplitAddress(b.sessionAddr)
	if err != nil {
		return fmt.Errorf("worker: api address: %w", err)
	}
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return fmt.Errorf("worker: api.address is %s; HTTP replay needs a TCP address", network)
	}

	opts := executor.APIOptions{
		Address:    b.sessionAddr,
		TLS:        a.TLS,
		ServerName: a.ServerName,
		Timeout:    a.Timeout.Std(),
		PerRequest: a.PerRequest.Std(),
		KeepAlive:  a.KeepAlive != nil && *a.KeepAlive,
		FixLength:  a.FixLength != nil && *a.FixLength,
	}

	if a.Capture != "" {
		links, seed, cerr := b.loadCapture(a)
		if cerr != nil {
			return cerr
		}
		opts.Links = links
		b.captureSeed = seed
	}
	if a.Secrets != "" {
		sub, serr := loadSecrets(a.Secrets)
		if serr != nil {
			return serr
		}
		// Substitution happens immediately before the write, which is what
		// keeps a credential out of the corpus, the store and every mutation.
		opts.Substitute = sub
	}

	// The scope guard is the dialer, exactly as it is for the session tier:
	// the architecture lint means an executor in pkg/ has no other way to
	// reach the network (ADR-0012).
	api := executor.NewAPI("api", b.scope, opts)
	api.Output = b.output
	// No Start: the tier connects per session and has nothing to hold open, so
	// the only thing a start would do is fail before the service is up.
	_ = ctx
	b.executor = api
	b.tier = "api"
	b.closers = append(b.closers, closer{"api tier", api.Close})
	return nil
}

// loadCapture reads a recorded session, redacts it, and infers the values that
// chain between its requests.
//
// Redaction first, and it is not a formality: the seed goes into the corpus and
// the store, and a token that reaches either is a token in a file somebody will
// eventually share. The real values go back in immediately before each write,
// through the substitution function, and nowhere else.
func (b *built) loadCapture(a *campaign.API) ([]executor.Link, []byte, error) {
	src, err := os.ReadFile(a.Capture)
	if err != nil {
		return nil, nil, fmt.Errorf("worker: reading the capture: %w", err)
	}
	c, err := capture.Read(a.Capture, src)
	if err != nil {
		return nil, nil, fmt.Errorf("worker: %w", err)
	}
	if len(c.Exchanges) == 0 {
		return nil, nil, fmt.Errorf("worker: %s holds no requests", a.Capture)
	}

	redacted, secrets := capture.Redact(c)
	b.captureNote = fmt.Sprintf("%d request(s) from %s", len(c.Exchanges), a.Capture)
	if secrets.Len() > 0 {
		b.captureNote += fmt.Sprintf("; %d credential(s) redacted", secrets.Len())
	}

	var links []executor.Link
	if a.Links == campaign.APILinksInfer {
		links = linksFrom(capture.Infer(redacted))
		b.captureNote += fmt.Sprintf("; %d dependenc(ies) inferred", len(links))
	}
	return links, redacted.Session(), nil
}

// linksFrom converts inferred dependencies into what the tier carries.
//
// The two shapes differ because they answer different questions. A capture link
// says where a value was produced and where it was used, in enough detail for a
// person to read it; a tier link says which response to take a value out of and
// which recorded string to replace with it. Only body values can be re-read —
// a value the campaign saw in a path segment of an earlier request is not
// something the *service* produced — so a link whose source is not a JSON body
// carries no extraction and the recorded value is sent unchanged.
func linksFrom(ls capture.Links) []executor.Link {
	out := make([]executor.Link, 0, len(ls))
	for _, l := range ls {
		e := executor.Link{From: l.From.Exchange, To: l.To.Exchange, Value: l.Value}
		if l.From.Part == capture.PartBody {
			e.Extract = l.From.Name
		}
		out = append(out, e)
	}
	return out
}

// loadSecrets reads the placeholder-to-value file `xfuzz capture` writes.
//
// A separate file from the capture so the capture can be committed: the
// redacted session holds placeholders and this holds the credentials. It is
// read once at startup and held in memory, never written anywhere.
func loadSecrets(path string) (func([]byte) []byte, error) {
	src, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("worker: reading the secrets: %w", err)
	}
	pairs := map[string]string{}
	for n, line := range strings.Split(string(src), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("worker: %s line %d is not placeholder=value", path, n+1)
		}
		pairs[strings.TrimSpace(key)] = value
	}
	if len(pairs) == 0 {
		return nil, fmt.Errorf("worker: %s holds no placeholder=value pairs", path)
	}
	return func(in []byte) []byte {
		out := string(in)
		for k, v := range pairs {
			out = strings.ReplaceAll(out, k, v)
		}
		return []byte(out)
	}, nil
}

// apiObjectives builds the response oracles a campaign asked for.
//
// They are additive to the ordinary ones rather than a replacement: a service
// that does crash is still a finding, and the reason this list exists is that a
// service almost never does.
func apiObjectives(cfg *campaign.Resolved, out *feedback.OutputObserver,
	timing *feedback.TimingObserver) []feedback.Objective {

	if cfg.API == nil {
		return nil
	}
	var objs []feedback.Objective
	for _, name := range cfg.API.Oracles {
		switch name {
		case campaign.APIOracleStatus:
			o := feedback.NewStatusObjective("api-status", out)
			for _, code := range cfg.API.IgnoreStatus {
				o.Ignore[code] = true
			}
			objs = append(objs, o)
		case campaign.APIOracleSchema:
			objs = append(objs, feedback.NewSchemaObjective("api-schema", out))
		case campaign.APIOracleLatency:
			if timing != nil {
				objs = append(objs, feedback.NewLatencyObjective("api-latency", timing))
			}
		case campaign.APIOracleAuthorization:
			o := feedback.NewAuthorizationObjective("api-authorization", out)
			o.Identity = cfg.API.Identity
			switch cfg.API.Expect {
			case campaign.APIExpectAllowed:
				o.Expected = feedback.AuthAllowed
			case campaign.APIExpectDenied:
				o.Expected = feedback.AuthDenied
			default:
				o.Expected = feedback.AuthUnknown
			}
			objs = append(objs, o)
		}
	}
	return objs
}

// apiTimingNeeded reports whether the campaign asked for the latency oracle,
// which is the only thing that needs a timing observer on this tier.
func apiTimingNeeded(cfg *campaign.Resolved) bool {
	if cfg.API == nil {
		return false
	}
	for _, name := range cfg.API.Oracles {
		if name == campaign.APIOracleLatency {
			return true
		}
	}
	return false
}
