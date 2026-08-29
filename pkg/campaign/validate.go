package campaign

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
)

// Problem is one thing wrong with a campaign file.
type Problem struct {
	// Field is the dotted path to the offending key, so an editor can jump to
	// it and a person can find it without counting braces.
	Field string

	// Msg says what is wrong.
	Msg string

	// Hint says what to do about it, when there is something specific to say.
	// A validation message that only says "invalid" makes the reader guess.
	Hint string
}

func (p Problem) String() string {
	s := p.Field + ": " + p.Msg
	if p.Hint != "" {
		s += " (" + p.Hint + ")"
	}
	return s
}

// Invalid is the error returned for a campaign that cannot run.
type Invalid struct {
	Path     string
	Problems []Problem
}

func (e *Invalid) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "campaign: %s has %d problem", e.Path, len(e.Problems))
	if len(e.Problems) != 1 {
		b.WriteByte('s')
	}
	for _, p := range e.Problems {
		b.WriteString("\n  - " + p.String())
	}
	return b.String()
}

// Validate reports everything wrong with a resolved campaign at once.
//
// All of it, not the first thing: a person fixing a campaign file wants the
// list, and a validator that stops at the first problem turns one edit into
// five round trips.
func (r *Resolved) Validate() error {
	var ps []Problem
	add := func(field, msg, hint string) {
		ps = append(ps, Problem{Field: field, Msg: msg, Hint: hint})
	}

	if strings.TrimSpace(r.Name) == "" {
		add("name", "is required", "it is the handle every command takes")
	} else if !validName(r.Name) {
		add("name", fmt.Sprintf("%q contains characters that are not letters, digits, dot, dash or underscore", r.Name),
			"the name appears in paths and URLs")
	}

	r.validateTarget(add)
	r.validateFormat(add)
	r.validateFeedback(add)
	r.validateWorkers(add)
	r.validateSafety(add)
	r.validateTriage(add)
	r.validateStop(add)
	r.validateSeeds(add)
	r.validateSession(add)

	if len(ps) == 0 {
		return nil
	}
	sort.SliceStable(ps, func(i, j int) bool { return ps[i].Field < ps[j].Field })
	return &Invalid{Path: r.Path, Problems: ps}
}

type addFunc func(field, msg, hint string)

func (r *Resolved) validateTarget(add addFunc) {
	t := r.Target
	if t.Path == "" {
		add("target.path", "is required", "the campaign has nothing to run")
		return
	}
	if fi, err := os.Stat(t.Path); err != nil {
		add("target.path", fmt.Sprintf("%s cannot be read: %v", t.Path, err), "")
	} else if fi.IsDir() {
		add("target.path", t.Path+" is a directory", "")
	} else if fi.Mode()&0o111 == 0 {
		add("target.path", t.Path+" is not executable", "chmod +x it, or point at the right file")
	}

	switch t.Executor {
	case ExecutorAuto, ExecutorForkServer, ExecutorSubprocess, ExecutorInProc:
	default:
		add("target.executor", fmt.Sprintf("%q is not a delivery tier", t.Executor),
			"one of auto, forkserver, subprocess, inproc")
	}
	switch t.Input {
	case InputStdin, InputFile, InputArg:
	default:
		add("target.input", fmt.Sprintf("%q is not an input mode", t.Input),
			"one of stdin, file, arg")
	}

	// @@ is AFL's placeholder for the input file. Naming a file mode without
	// the placeholder, or the placeholder without file mode, is the mistake
	// that produces a campaign where every execution reads an empty file.
	hasPlaceholder := false
	for _, a := range t.Args {
		if strings.Contains(a, "@@") {
			hasPlaceholder = true
		}
	}
	if t.Input == InputFile && !hasPlaceholder {
		add("target.args", "input is file but no argument contains @@",
			"@@ is replaced with the input file path")
	}
	if t.Input != InputFile && hasPlaceholder {
		add("target.input", fmt.Sprintf("an argument contains @@ but input is %q", t.Input),
			"set input: file")
	}
	if r.WasSet("target.timeout") && t.Timeout <= 0 {
		add("target.timeout", "must be positive",
			"a campaign with no timeout stalls on the first input that loops")
	}
	if t.Dir != "" {
		if fi, err := os.Stat(t.Dir); err != nil || !fi.IsDir() {
			add("target.dir", t.Dir+" is not a directory", "")
		}
	}
}

func (r *Resolved) validateFormat(add addFunc) {
	f := r.Format
	switch f.Codec {
	case "raw", "png":
	default:
		add("format.codec", fmt.Sprintf("%q is not a built-in codec", f.Codec), "one of raw, png")
	}
	if f.Grammar != "" {
		if _, err := os.Stat(f.Grammar); err != nil {
			add("format.grammar", fmt.Sprintf("%s cannot be read: %v", f.Grammar, err), "")
		}
	}
	if f.Dictionary != "" {
		if _, err := os.Stat(f.Dictionary); err != nil {
			add("format.dictionary", fmt.Sprintf("%s cannot be read: %v", f.Dictionary, err), "")
		}
	}
	if r.WasSet("format.max_input_bytes") && f.MaxInputBytes <= 0 {
		add("format.max_input_bytes", "must be positive", "")
	}
	for _, s := range f.Suppress {
		switch s {
		case "length", "count", "offset", "checksum":
		default:
			add("format.suppress", fmt.Sprintf("%q is not a derivation", s),
				"one of length, count, offset, checksum")
		}
	}
}

func (r *Resolved) validateFeedback(add addFunc) {
	f := r.Feedback
	switch f.Coverage {
	case "sancov", "blackbox", "none":
	default:
		add("feedback.coverage", fmt.Sprintf("%q is not a coverage backend", f.Coverage),
			"one of sancov, blackbox, none")
	}
	if r.WasSet("feedback.map_size") && (f.MapSize <= 0 || f.MapSize&(f.MapSize-1) != 0) {
		add("feedback.map_size", fmt.Sprintf("%d is not a power of two", f.MapSize),
			"the edge index is masked, so a non-power-of-two size would fold edges together")
	}
	if len(f.Objectives) == 0 {
		add("feedback.objectives", "is empty",
			"a campaign with nothing to find cannot report anything")
	}
	for _, o := range f.Objectives {
		switch o {
		case "crash", "hang", "oom", "sanitizer":
		default:
			add("feedback.objectives", fmt.Sprintf("%q is not an objective", o),
				"one of crash, hang, oom, sanitizer")
		}
	}
	if f.Coverage == "none" && !f.Novelty {
		add("feedback.coverage", "is none and novelty is off",
			"the campaign would keep nothing it finds; set novelty: true for a black-box target")
	}
}

func (r *Resolved) validateWorkers(add addFunc) {
	w := r.Workers
	if r.WasSet("workers.count") && w.Count < 1 {
		add("workers.count", "must be at least 1", "")
	}
	if w.Count > maxWorkers {
		add("workers.count", fmt.Sprintf("%d exceeds the %d-worker limit", w.Count, maxWorkers),
			"this is a single-node design; see ADR-0015")
	}
	seen := map[string]bool{}
	for i, s := range w.Strategies {
		field := "workers.strategies[" + strconv.Itoa(i) + "]"
		if s.Name == "" {
			add(field+".name", "is required", "strategies are named so reports can tell them apart")
		} else if seen[s.Name] {
			add(field+".name", fmt.Sprintf("%q is used twice", s.Name), "")
		}
		seen[s.Name] = true
		switch s.Schedule {
		case "", "fast", "rand", "roundrobin":
		default:
			add(field+".schedule", fmt.Sprintf("%q is not a power schedule", s.Schedule),
				"one of fast, rand, roundrobin")
		}
	}
	if w.SyncInterval < 0 {
		add("workers.sync_interval", "cannot be negative", "")
	}
}

func (r *Resolved) validateSafety(add addFunc) {
	s := r.Safety
	switch s.Isolation {
	case "none", "minimal", "moderate", "strong":
	default:
		add("safety.isolation", fmt.Sprintf("%q is not an isolation level", s.Isolation),
			"one of none, minimal, moderate, strong")
	}
	if s.MemoryLimit < 0 {
		add("safety.memory_limit", "cannot be negative", "")
	}
	if s.ProcessLimit < 0 {
		add("safety.process_limit", "cannot be negative", "")
	}

	for i, a := range s.Scope.Allow {
		if _, _, err := ParseAllow(a); err != nil {
			add("safety.scope.allow["+strconv.Itoa(i)+"]", err.Error(), "")
		}
	}

	// A campaign that leaves the host needs both an allowlist and an
	// authorization record, and it is far better to be told at validation than
	// after the first packet (ADR-0012).
	if s.Network {
		if len(s.Scope.Allow) == 0 {
			add("safety.scope.allow", "is required when safety.network is set",
				"a campaign that leaves the host must say where it may go")
		}
		if s.Authorization == nil {
			add("safety.authorization", "is required when safety.network is set",
				"operator, reference, and attestation, recorded before the first packet")
		}
	}
	if a := s.Authorization; a != nil {
		if strings.TrimSpace(a.Operator) == "" {
			add("safety.authorization.operator", "is required", "")
		}
		if strings.TrimSpace(a.Reference) == "" {
			add("safety.authorization.reference", "is required",
				"an engagement identifier, ticket, or approval reference")
		}
		if strings.TrimSpace(a.Attestation) == "" {
			add("safety.authorization.attestation", "is required",
				"a statement that you are authorised to test the declared scope")
		}
	}
}

func (r *Resolved) validateTriage(add addFunc) {
	t := r.Triage
	if r.WasSet("triage.trials") && t.Trials < 1 {
		add("triage.trials", "must be at least 1",
			"a finding nobody re-ran is not a bug report")
	}
	if t.MinimizeBudget < 0 {
		add("triage.minimize_budget", "cannot be negative", "")
	}
	switch t.Strategy {
	case "chain", "frames", "marker", "coverage", "signal":
	default:
		add("triage.strategy", fmt.Sprintf("%q is not a bucketing strategy", t.Strategy),
			"one of chain, frames, marker, coverage, signal")
	}
	if t.Strategy == "coverage" && r.Feedback.Coverage == "none" {
		add("triage.strategy", "is coverage but feedback.coverage is none",
			"coverage bucketing has nothing to bucket on")
	}
}

func (r *Resolved) validateStop(add addFunc) {
	if r.Stop.IsZero() {
		// Not an error. An interactive campaign that runs until interrupted is
		// legitimate, and refusing it would make the tool tiresome for the
		// exploratory case. It is reported by `explain` and by the API so that
		// a CI user notices before their pipeline hangs.
		return
	}
	if r.Stop.After < 0 {
		add("stop.after", "cannot be negative", "")
	}
	if r.Stop.Findings < 0 {
		add("stop.findings", "cannot be negative", "")
	}
	if r.Stop.NoNewCoverage < 0 {
		add("stop.no_new_coverage", "cannot be negative", "")
	}
}

func (r *Resolved) validateSeeds(add addFunc) {
	s := r.Seeds
	switch s.Format {
	case "auto", "afl", "libfuzzer", "raw":
	default:
		add("seeds.format", fmt.Sprintf("%q is not a corpus layout", s.Format),
			"one of auto, afl, libfuzzer, raw")
	}
	for i, d := range s.Dirs {
		if fi, err := os.Stat(d); err != nil || !fi.IsDir() {
			add("seeds.dirs["+strconv.Itoa(i)+"]", d+" is not a readable directory", "")
		}
	}
	if len(s.Dirs) == 0 && len(s.Inline) == 0 && s.Generate == 0 {
		add("seeds", "no seeds are configured",
			"set seeds.dirs, seeds.inline, or seeds.generate with a grammar")
	}
	if s.Generate > 0 && r.Format.Grammar == "" {
		add("seeds.generate", "requires format.grammar",
			"generation needs a grammar to generate from")
	}
	if s.Generate < 0 {
		add("seeds.generate", "cannot be negative", "")
	}
}

// maxWorkers bounds the worker count.
//
// Not a technical limit but a mistake filter: `count: 1000` on a laptop is a
// typo, and the failure it produces — thousands of processes competing for
// cores — looks like the tool being broken rather than the file being wrong.
const maxWorkers = 256

func validName(s string) bool {
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '-' || r == '_' || r == '.':
		default:
			return false
		}
	}
	return true
}

// ParseAllow splits a scope entry into its destination and its ports.
//
// The syntax is "host", "host:80", "10.0.0.0/8:80,8000-8999" — a CIDR and a
// port list have to coexist, and the colon that separates them is also the one
// inside an IPv6 address, so the split is on the last colon that follows a
// closing bracket or a dot.
func ParseAllow(entry string) (dest string, ports []string, err error) {
	entry = strings.TrimSpace(entry)
	if entry == "" {
		return "", nil, fmt.Errorf("empty scope entry")
	}

	dest = entry
	if i := strings.LastIndexByte(entry, ':'); i > 0 {
		head, tail := entry[:i], entry[i+1:]
		// An IPv6 literal is bracketed when it carries ports, so an unbracketed
		// address with several colons is an address, not an address and a port.
		if strings.HasSuffix(head, "]") || !strings.Contains(head, ":") {
			switch {
			case tail != "" && isPortList(tail):
				dest, ports = head, strings.Split(tail, ",")
			case looksLikePorts(tail):
				// Digits, commas and dashes after a colon can only have been
				// meant as ports. Folding them into the destination instead —
				// which is what an unchecked fallthrough does — would turn
				// "10.0.0.1:99999" into a host named "10.0.0.1:99999" that
				// never matches anything, and the operator would be told their
				// scope was fine.
				return "", nil, fmt.Errorf("%q: %s is not a valid port list", entry, tail)
			}
		}
	}
	dest = strings.TrimSuffix(strings.TrimPrefix(dest, "["), "]")
	if dest == "" {
		return "", nil, fmt.Errorf("%q has no destination", entry)
	}
	for _, p := range ports {
		lo, hi, found := strings.Cut(p, "-")
		if err := checkPort(lo); err != nil {
			return "", nil, fmt.Errorf("%q: %w", entry, err)
		}
		if found {
			if err := checkPort(hi); err != nil {
				return "", nil, fmt.Errorf("%q: %w", entry, err)
			}
			l, _ := strconv.Atoi(lo)
			h, _ := strconv.Atoi(hi)
			if l > h {
				return "", nil, fmt.Errorf("%q: port range %s-%s runs backwards", entry, lo, hi)
			}
		}
	}
	return dest, ports, nil
}

// looksLikePorts reports whether a string was evidently intended as a port list,
// whether or not it is a valid one.
func looksLikePorts(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if (r < '0' || r > '9') && r != ',' && r != '-' {
			return false
		}
	}
	return true
}

func isPortList(s string) bool {
	for _, p := range strings.Split(s, ",") {
		lo, hi, found := strings.Cut(p, "-")
		if checkPort(lo) != nil {
			return false
		}
		if found && checkPort(hi) != nil {
			return false
		}
	}
	return true
}

func checkPort(s string) error {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("%q is not a port", s)
	}
	return nil
}

// validateSession checks a stateful campaign's session and state blocks.
func (r *Resolved) validateSession(add addFunc) {
	if r.Session == nil {
		// Not a session campaign. A state block without one is a mistake worth
		// naming, though: it configures machinery nothing will run.
		if r.State != nil {
			add("state", "is set but there is no session block",
				"state guidance applies to protocol sessions; add session.address or remove the state block")
		}
		return
	}
	s := r.Session

	switch {
	case strings.TrimSpace(s.Address) == "":
		add("session.address", "is required for a session campaign",
			"where the target listens: tcp:127.0.0.1:9000 or unix:/run/target.sock")
	default:
		if _, _, err := SplitAddress(s.Address); err != nil {
			add("session.address", err.Error(),
				"tcp:HOST:PORT or unix:PATH, with {worker} for the worker index")
		}
	}

	// Every worker runs its own copy of the target, so an address without
	// {worker} means the second worker binds what the first already holds. The
	// campaign starts, one worker dies on every session, and the throughput is
	// quietly a fraction of what was asked for.
	if r.Workers != nil && r.Workers.Count > 1 &&
		s.Managed != nil && *s.Managed && !strings.Contains(s.Address, "{worker}") {
		add("session.address", "is the same for every worker",
			"put {worker} in it, or workers will contend for one address and one server")
	}

	switch s.Framing {
	case "idle", "line", "none":
	default:
		add("session.framing", fmt.Sprintf("%q is not a framing mode", s.Framing),
			"one of idle, line, none")
	}

	switch s.Reset {
	case "none", "reconnect", "restart":
	case "snapshot":
		add("session.reset", "snapshot is not implemented",
			"it needs KVM-based checkpointing, which ADR-0006 defers past v1; "+
				"use restart for correctness or reconnect for speed")
	default:
		add("session.reset", fmt.Sprintf("%q is not a reset policy", s.Reset),
			"one of none, reconnect, restart")
	}

	// A restart replaces the target process, which needs there to be one.
	if s.Reset == "restart" && (s.Managed == nil || !*s.Managed) {
		add("session.reset", "is restart but the target is not managed",
			"set session.managed and target.path, or use reconnect")
	}
	if s.Managed != nil && *s.Managed && (r.Target == nil || r.Target.Path == "") {
		add("session.managed", "is set but target.path is empty",
			"name the server to start, or unset it to fuzz one that is already running")
	}

	if s.MaxMessages < 0 {
		add("session.max_messages", "cannot be negative", "")
	}
	if r.WasSet("session.read_limit") && s.ReadLimit <= 0 {
		add("session.read_limit", "must be positive",
			"a target that answers one byte with a gigabyte is a finding, not a reason to run out of memory")
	}
	if s.QuietPeriod < 0 || s.ConnectTimeout < 0 || s.ReadTimeout < 0 || s.SessionTimeout < 0 {
		add("session", "has a negative timeout", "")
	}
	if s.SessionTimeout > 0 && s.ReadTimeout > 0 && s.SessionTimeout < s.ReadTimeout {
		add("session.session_timeout", "is shorter than session.read_timeout",
			"a session that cannot outlast one reply can never send a second message")
	}

	r.validateState(add)
}

// validateState checks the state block of a session campaign.
func (r *Resolved) validateState(add addFunc) {
	if r.State == nil {
		return
	}
	st := r.State

	switch st.Fn {
	case "status", "http", "fingerprint", "constant", "none":
	default:
		add("state.fn", fmt.Sprintf("%q is not a state function", st.Fn),
			"one of status, http, fingerprint, constant")
	}
	for _, n := range st.Normalise {
		switch n {
		case "digits", "quoted", "space":
		default:
			add("state.normalise", fmt.Sprintf("%q is not a normalisation step", n),
				"one of digits, quoted, space")
		}
	}
	// Normalisation is what fingerprinting does; naming steps for any other
	// state function configures nothing, and a setting that does nothing is
	// worse than a missing one because it reads as if it works.
	if len(st.Normalise) > 0 && st.Fn != "fingerprint" && r.WasSet("state.normalise") {
		add("state.normalise", fmt.Sprintf("is set but state.fn is %q", st.Fn),
			"normalisation applies to the fingerprint function only")
	}
	if r.Session != nil && r.Session.Framing == "none" && st.Guide != nil && *st.Guide {
		add("state.guide", "is on but session.framing is none",
			"nothing reads a reply, so there is no response to label; "+
				"use idle or line framing, or turn state guidance off")
	}
	if st.Explore < 0 || st.Explore > 1 {
		add("state.explore", fmt.Sprintf("%v is outside 0..1", st.Explore), "it is a probability")
	}
	if st.TailBias < 0 || st.TailBias > 1 {
		add("state.tail_bias", fmt.Sprintf("%v is outside 0..1", st.TailBias), "it is a probability")
	}
	for _, d := range st.Declare {
		if _, _, err := ParseTransition(d); err != nil {
			add("state.declare", err.Error(), `each entry is "from->to"`)
		}
	}
}
