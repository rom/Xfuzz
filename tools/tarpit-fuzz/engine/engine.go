// Package engine drives dumb + smart fuzzing campaigns against a running
// instance of rom/tarpit-honeypot.
//
// The tarpit-honeypot ships 197 TCP + 118 UDP protocol handlers (315 in all),
// each listening on its own port when the full-target config is deployed. The
// honeypot's own tarpit-testharness covers ~34 of them; this fuzzer covers the
// remainder. It is external — it connects to a running sensor over the
// network — so it exercises the deployed binary exactly as an attacker would
// reach it, rather than linking against handler source.
//
// A protocol is one entry in the registry: transport, default port, a seed the
// honeypot's parser will recognise, and an optional smart generator. "Dumb"
// drops random bytes or seed-with-byte-mutations; "smart" uses the generator
// to produce malformed-but-recognisable frames. After each payload the engine
// re-dials the endpoint to see whether the sensor is still alive. A dialed
// connection that is refused (or that times out when the handler was accepting
// before) is a crash candidate; any run surviving the whole schedule is the
// sensor's resilience claim backed by evidence.
package engine

import (
	"context"
	"crypto/tls"
	"fmt"
	"hash/fnv"
	"math/rand"
	"net"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// Protocol is one fuzzing target.
//
// Values are declared in the registry and remain immutable at run time. A
// protocol that cannot be enumerated on the target this run (the port is
// closed, or the honeypot was built without the handler) is skipped at dial
// time, not here — this keeps the catalogue the same across deployments.
type Protocol struct {
	// Name matches the honeypot's handler identifier (e.g. "modbus",
	// "dns"). It is what a config toggle refers to.
	Name string

	// Transport is "tcp" or "udp". A protocol served on both (DNS, SNMP) is
	// registered twice under distinct Name values ("dns"/"dns_udp" etc.).
	Transport string

	// DefaultPort is the port the honeypot's example configs listen on. The
	// config may override it per protocol.
	DefaultPort int

	// TLS wraps the connection. The honeypot presents a self-signed cert
	// shaped by its archetype; verification is off for the same reason the
	// session tier's is: the connection has already been dialled on purpose.
	TLS bool

	// ServerFirst flags a service that speaks before the client (SSH, FTP,
	// SMTP, Telnet). The engine reads and discards the banner before sending
	// a fuzz payload, so the first bytes it sends are a real request rather
	// than mid-handshake noise.
	ServerFirst bool

	// Seeds are a small pool of recognisable packets. Dumb mutation starts
	// from one of these; smart generation may consult them. A protocol with
	// no seed still fuzzes — the mutator falls back to pure random bytes,
	// which reaches the "parser must not panic on anything" claim.
	Seeds [][]byte

	// Smart, when non-nil, produces one protocol-aware malformed payload per
	// call. The caller passes a per-iteration PRNG so a seed value makes a
	// run reproducible.
	Smart func(rng *rand.Rand) []byte
}

// Config controls one run.
type Config struct {
	// Target is the honeypot's host. Each protocol's port is its own.
	Target string

	// LivenessURL, when set, is an HTTP endpoint the sensor's management
	// stack serves (the honeypot's /healthz on 8088 by default). The engine
	// polls it between iterations as a cheaper liveness check than re-dialing
	// every listener. Empty means the per-endpoint re-dial is the only check.
	LivenessURL string

	// Iterations is how many payloads to send per protocol per round.
	Iterations int

	// Rounds repeats the whole schedule. Multiple rounds spread any
	// state-dependent bug beyond the first seed.
	Rounds int

	// Concurrency caps the number of protocols fuzzed in parallel. A honeypot
	// with heavy per-connection state (SSH interactive, FTP file capture)
	// stays responsive under a smaller number; higher values find
	// cross-protocol races.
	Concurrency int

	// Timeout bounds one send/receive exchange.
	Timeout time.Duration

	// Seed is the top-level PRNG seed. Recorded in the report so a crash is
	// reproducible with --seed.
	Seed int64

	// Kinds selects which fuzzers to run. Empty means both.
	Kinds []Kind

	// Enabled restricts the run to these protocol names. Empty means every
	// registered protocol.
	Enabled map[string]bool

	// Disabled subtracts from the enabled set. Useful on the command line as
	// "--disable udp:profinet" without replacing the whole enable list.
	Disabled map[string]bool
}

// Kind picks a fuzzer for one round.
type Kind string

// The two fuzzers.
const (
	// KindDumb sends protocol-unaware input: a random byte run, a seed with
	// bit flips, a seed truncated or extended with garbage, a well-known
	// corrupting pattern. The claim it tests is "the parser never panics".
	KindDumb Kind = "dumb"

	// KindSmart sends input the parser will accept past its first checks: the
	// right magic, the right framing, plausible fields — then a corrupted one
	// buried inside. The claim is "a plausible-looking message can never
	// escape the parser".
	KindSmart Kind = "smart"
)

// Engine runs a configured campaign.
type Engine struct {
	cfg       Config
	catalogue []Protocol
	// mu guards findings and counters; a run has at most Concurrency writers.
	mu           sync.Mutex
	findings     []Finding
	skippedNames []string
	stats        stats
}

// stats is the counters a run reports.
type stats struct {
	sent      uint64
	skipped   uint64
	dialfail  uint64
	responses uint64
	crashes   uint64
	hangs     uint64
}

// addSkipped records one skipped protocol by name. Guarded by the same mutex
// as findings since both are written from worker goroutines.
func (e *Engine) addSkipped(name string) {
	e.mu.Lock()
	e.skippedNames = append(e.skippedNames, name)
	e.mu.Unlock()
}

// Finding is one anomaly worth a line in the report.
type Finding struct {
	// Protocol names the registry entry.
	Protocol string

	// Kind is dumb or smart.
	Kind Kind

	// Iteration is which payload caused it; replayable with --seed + this.
	Iteration int

	// Reason is what the engine observed: "liveness lost", "connection refused
	// after N inputs", "endpoint stopped responding".
	Reason string

	// Payload is the exact bytes sent. Short payloads are kept in full; a
	// long one is truncated with its full length recorded.
	Payload []byte

	// PayloadLen is the full length, even when Payload is truncated.
	PayloadLen int

	// Elapsed is the wall-clock time between sending and seeing the anomaly.
	Elapsed time.Duration

	// At is when the finding was filed.
	At time.Time
}

// Summary is what the engine reports at the end of a run.
type Summary struct {
	// Protocols is the catalogue size, before Enabled/Disabled filtering.
	Protocols int

	// Ran is the number of protocols actually exercised.
	Ran int

	// Sent is the payload count across every protocol.
	Sent uint64

	// Skipped is the protocols the dial check could not reach.
	Skipped uint64

	// Responses is how many times a protocol answered. A silent protocol
	// (syslog, dhcpv6-relay) does not count a non-reply as a failure.
	Responses uint64

	// Crashes counts findings whose Reason names a lost liveness.
	Crashes uint64

	// Hangs counts findings whose Reason names a stuck endpoint.
	Hangs uint64

	// SkippedList names the protocols the dial check could not reach at
	// run start. Reporting them is what turns "is my config wrong?" into
	// a one-line answer: a honeypot the operator thinks binds a port but
	// the catalogue cannot reach is named rather than quietly counted.
	SkippedList []string

	// Findings is the ranked list. Crashes first, hangs next, other anomalies
	// last.
	Findings []Finding

	// Elapsed is the whole run's wall-clock time.
	Elapsed time.Duration
}

// New returns an engine ready to run the given protocol set.
func New(cfg Config, catalogue []Protocol) *Engine {
	if cfg.Iterations <= 0 {
		cfg.Iterations = 128
	}
	if cfg.Rounds <= 0 {
		cfg.Rounds = 1
	}
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 8
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 800 * time.Millisecond
	}
	if cfg.Seed == 0 {
		cfg.Seed = time.Now().UnixNano()
	}
	if len(cfg.Kinds) == 0 {
		cfg.Kinds = []Kind{KindDumb, KindSmart}
	}
	cat := append([]Protocol(nil), catalogue...)
	sort.Slice(cat, func(i, j int) bool {
		if cat[i].Transport != cat[j].Transport {
			return cat[i].Transport < cat[j].Transport
		}
		return cat[i].Name < cat[j].Name
	})
	return &Engine{cfg: cfg, catalogue: cat}
}

// Run executes the campaign.
func (e *Engine) Run(ctx context.Context) Summary {
	start := time.Now()
	enabled := e.filtered()

	sem := make(chan struct{}, e.cfg.Concurrency)
	var wg sync.WaitGroup
	for round := 0; round < e.cfg.Rounds; round++ {
		for _, p := range enabled {
			if ctx.Err() != nil {
				break
			}
			p, round := p, round
			sem <- struct{}{}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer func() { <-sem }()
				e.runOne(ctx, p, round)
			}()
		}
	}
	wg.Wait()

	e.mu.Lock()
	defer e.mu.Unlock()
	return Summary{
		Protocols:   len(e.catalogue),
		Ran:         len(enabled),
		Sent:        atomic.LoadUint64(&e.stats.sent),
		Skipped:     atomic.LoadUint64(&e.stats.skipped),
		Responses:   atomic.LoadUint64(&e.stats.responses),
		Crashes:     atomic.LoadUint64(&e.stats.crashes),
		Hangs:       atomic.LoadUint64(&e.stats.hangs),
		SkippedList: append([]string(nil), e.skippedNames...),
		Findings:    append([]Finding(nil), e.findings...),
		Elapsed:     time.Since(start),
	}
}

// filtered applies Enabled and Disabled to the catalogue.
func (e *Engine) filtered() []Protocol {
	out := make([]Protocol, 0, len(e.catalogue))
	for _, p := range e.catalogue {
		if len(e.cfg.Enabled) > 0 && !e.cfg.Enabled[p.Name] && !e.cfg.Enabled[p.Transport+":"+p.Name] {
			continue
		}
		if e.cfg.Disabled[p.Name] || e.cfg.Disabled[p.Transport+":"+p.Name] {
			continue
		}
		out = append(out, p)
	}
	return out
}

// runOne fuzzes one protocol for one round.
func (e *Engine) runOne(ctx context.Context, p Protocol, round int) {
	// A dial check up front: a port nothing listens on is a configuration
	// problem, not a finding. The honeypot's full-target config lists every
	// handler on a port; a protocol missing from that deployment just
	// records a skip.
	if !e.endpointReachable(ctx, p) {
		atomic.AddUint64(&e.stats.skipped, 1)
		e.addSkipped(p.Transport + ":" + p.Name)
		return
	}

	rng := caseRand(e.cfg.Seed, fmt.Sprintf("%s/%s/%d", p.Transport, p.Name, round))
	for _, kind := range e.cfg.Kinds {
		if ctx.Err() != nil {
			return
		}
		e.fuzz(ctx, p, kind, rng)
	}
}

// fuzz sends Iterations payloads of one kind and watches liveness.
func (e *Engine) fuzz(ctx context.Context, p Protocol, kind Kind, rng *rand.Rand) {
	gen := newGenerator(kind, p, rng)
	for i := 0; i < e.cfg.Iterations; i++ {
		if ctx.Err() != nil {
			return
		}
		payload := gen.next()
		start := time.Now()
		got, err := e.exchange(ctx, p, payload)
		atomic.AddUint64(&e.stats.sent, 1)
		if err == nil && len(got) > 0 {
			atomic.AddUint64(&e.stats.responses, 1)
		}
		// Liveness after every payload: the per-exchange error is noise (a
		// malformed frame is meant to drop the connection), what matters is
		// whether the next dial succeeds.
		if !e.alive(ctx, p) {
			e.recordFinding(Finding{
				Protocol: p.Transport + ":" + p.Name, Kind: kind,
				Iteration: i, Reason: "liveness lost after payload",
				Payload: truncatePayload(payload), PayloadLen: len(payload),
				Elapsed: time.Since(start), At: time.Now(),
			})
			atomic.AddUint64(&e.stats.crashes, 1)
			return
		}
	}
	// A listener that no longer accepts after a clean run is an anomaly even
	// without a crash: the handler has decided this client is unwelcome and
	// the operator should see that.
	if !e.endpointReachable(ctx, p) {
		e.recordFinding(Finding{
			Protocol: p.Transport + ":" + p.Name, Kind: kind,
			Iteration: e.cfg.Iterations,
			Reason:    "endpoint stopped accepting connections",
			At:        time.Now(),
		})
		atomic.AddUint64(&e.stats.hangs, 1)
	}
}

// exchange dials, writes, reads once, and closes. Errors on any step are
// returned to the caller to decide whether they matter — a dumb payload that
// closes the connection is expected, not a finding.
func (e *Engine) exchange(ctx context.Context, p Protocol, payload []byte) ([]byte, error) {
	conn, err := e.dial(ctx, p)
	if err != nil {
		atomic.AddUint64(&e.stats.dialfail, 1)
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(e.cfg.Timeout))
	if p.ServerFirst {
		buf := make([]byte, 2048)
		_, _ = conn.Read(buf) // banner may or may not arrive; either is fine
	}
	if _, err := conn.Write(payload); err != nil {
		return nil, err
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if n == 0 {
		return nil, err
	}
	return buf[:n], err
}

// alive is the liveness check after a payload. For TCP the dial itself is the
// signal: a port that refuses a connection means the handler did not come
// back. For UDP the dial always "succeeds"; a configured HTTP /healthz is the
// only cheap way to tell whether the sensor as a whole is still up, so the
// UDP path uses that when available and falls back to the dial.
func (e *Engine) alive(ctx context.Context, p Protocol) bool {
	if e.cfg.LivenessURL != "" {
		return e.healthz(ctx)
	}
	return e.endpointReachable(ctx, p)
}

// healthz is the one-shot HTTP probe of the honeypot's management endpoint.
func (e *Engine) healthz(ctx context.Context) bool {
	ctx, cancel := context.WithTimeout(ctx, e.cfg.Timeout)
	defer cancel()
	d := net.Dialer{}
	host, err := hostOfURL(e.cfg.LivenessURL)
	if err != nil {
		return true
	}
	conn, err := d.DialContext(ctx, "tcp", host)
	if err != nil {
		return false
	}
	_ = conn.SetDeadline(time.Now().Add(e.cfg.Timeout))
	path := pathOfURL(e.cfg.LivenessURL)
	req := "GET " + path + " HTTP/1.0\r\nHost: " + host + "\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		conn.Close()
		return false
	}
	buf := make([]byte, 256)
	n, _ := conn.Read(buf)
	conn.Close()
	return n > 0
}

// endpointReachable reports whether a TCP dial or UDP write succeeds.
func (e *Engine) endpointReachable(ctx context.Context, p Protocol) bool {
	conn, err := e.dial(ctx, p)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// dial opens a transport-appropriate connection, possibly wrapped in TLS.
func (e *Engine) dial(ctx context.Context, p Protocol) (net.Conn, error) {
	dctx, cancel := context.WithTimeout(ctx, e.cfg.Timeout)
	defer cancel()
	d := net.Dialer{}
	addr := fmt.Sprintf("%s:%d", e.cfg.Target, p.DefaultPort)
	conn, err := d.DialContext(dctx, p.Transport, addr)
	if err != nil {
		return nil, err
	}
	if !p.TLS {
		return conn, nil
	}
	tlsConn := tls.Client(conn, &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // a honeypot's self-signed cert is what is under test
		MinVersion:         tls.VersionTLS12,
	})
	if err := tlsConn.HandshakeContext(dctx); err != nil {
		conn.Close()
		return nil, err
	}
	return tlsConn, nil
}

// recordFinding appends to the findings list under the mutex. Called from
// worker goroutines.
func (e *Engine) recordFinding(f Finding) {
	e.mu.Lock()
	e.findings = append(e.findings, f)
	e.mu.Unlock()
}

// caseRand is a per-case deterministic PRNG. Given the same seed and the same
// case id, it produces the same payload sequence, which is what makes a crash
// reproducible.
func caseRand(seed int64, id string) *rand.Rand {
	h := fnv.New64a()
	_, _ = h.Write([]byte(id))
	return rand.New(rand.NewSource(seed ^ int64(h.Sum64()))) //nolint:gosec // reproducibility, not crypto
}

// truncatePayload keeps the beginning of a long payload for the report. The
// full length is recorded separately so the summary is not lying about size.
func truncatePayload(b []byte) []byte {
	const max = 256
	if len(b) <= max {
		return append([]byte(nil), b...)
	}
	out := make([]byte, max)
	copy(out, b[:max])
	return out
}

// hostOfURL extracts host:port from an HTTP URL.
func hostOfURL(u string) (string, error) {
	// A tiny parser: good enough for the one URL the config carries, and
	// avoids pulling in net/url for a startup helper.
	const scheme = "http://"
	if len(u) < len(scheme) || u[:len(scheme)] != scheme {
		return "", fmt.Errorf("livenessURL needs http:// scheme: %q", u)
	}
	rest := u[len(scheme):]
	for i, c := range rest {
		if c == '/' {
			rest = rest[:i]
			break
		}
	}
	if _, _, err := net.SplitHostPort(rest); err != nil {
		rest = rest + ":80"
	}
	return rest, nil
}

// pathOfURL returns the path portion, defaulting to "/".
func pathOfURL(u string) string {
	const scheme = "http://"
	if len(u) < len(scheme) || u[:len(scheme)] != scheme {
		return "/"
	}
	rest := u[len(scheme):]
	for i, c := range rest {
		if c == '/' {
			return rest[i:]
		}
	}
	return "/"
}
