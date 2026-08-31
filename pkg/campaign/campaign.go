// Package campaign defines the declarative campaign file — the only interface
// for defining what a campaign does.
//
// A campaign is YAML with a published JSON Schema. The CLI runs, inspects, and
// validates these files; the web console is a comment-preserving visual editor
// over the same format. Neither holds configuration state of its own (ADR-0016).
//
// The types here are the source of truth for three things that must never
// disagree: what the parser accepts, what the JSON Schema publishes, and what
// `xfuzz explain` renders. They are generated from these structs rather than
// maintained alongside them.
package campaign

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// File is a campaign definition as written.
//
// Every field is optional at the parsing stage and required-ness is decided by
// Validate, so that a file with three mistakes reports three mistakes rather
// than stopping at the first. A configuration error found one at a time is a
// configuration error found slowly.
type File struct {
	// Version is the campaign file format version. Absent means the current one.
	Version int `yaml:"version,omitempty" json:"version,omitempty" doc:"Campaign file format version."`

	// Name identifies the campaign. It is the handle every command takes and
	// must be unique within a store.
	Name string `yaml:"name" json:"name" doc:"Campaign name, unique within a store."`

	// Description is free text for whoever reads the file next.
	Description string `yaml:"description,omitempty" json:"description,omitempty" doc:"Free-text description."`

	// Seed pins the campaign's root RNG seed. Absent or zero draws one and
	// records it in the store.
	//
	// It lives in the file rather than behind a `--seed` flag because
	// ASR-0008's second acceptance criterion is about "the same campaign file
	// and seed": if the seed is a flag, the artefact that says what ran is
	// incomplete, and ADR-0016 exists to prevent exactly that. Pinning it makes
	// a campaign a replayable experiment rather than one that happens once.
	//
	// A plain integer here, because YAML holds a 64-bit one exactly and the
	// published JSON Schema says `"type": "integer"`. The IEEE-double problem
	// is real but it belongs to JSON, and it is solved where JSON is actually
	// spoken: `internal/api.Seed64` on the way in and `daemon.Status.Seed` on
	// the way out. Encoding it as a string here as well would contradict the
	// schema this project ships and reject a document that validates against
	// it.
	Seed uint64 `yaml:"seed,omitempty" json:"seed,omitempty" doc:"Root RNG seed. Absent draws one; pinning it makes the campaign reproducible."`

	// Include lists other campaign files merged in before this one, so a house
	// safety scope or a standard mutator set is reused rather than copied.
	Include []string `yaml:"include,omitempty" json:"include,omitempty" doc:"Files merged in before this one, in order."`

	// Profiles are named overlays. Exactly the same shape as the file itself,
	// applied on top when selected, so a profile can adjust anything a file can
	// set and nothing else.
	Profiles map[string]*File `yaml:"profiles,omitempty" json:"profiles,omitempty" doc:"Named overlays, applied on top when selected."`

	Target   *Target   `yaml:"target,omitempty" json:"target,omitempty" doc:"What to fuzz and how to deliver input to it."`
	Seeds    *Seeds    `yaml:"seeds,omitempty" json:"seeds,omitempty" doc:"Where the starting corpus comes from."`
	Format   *Format   `yaml:"format,omitempty" json:"format,omitempty" doc:"How bytes are interpreted as structure."`
	Mutation *Mutation `yaml:"mutation,omitempty" json:"mutation,omitempty" doc:"Which operators run and how they are weighted."`
	Feedback *Feedback `yaml:"feedback,omitempty" json:"feedback,omitempty" doc:"What counts as interesting."`
	Session  *Session  `yaml:"session,omitempty" json:"session,omitempty" doc:"Protocol sessions: where the target listens, how replies are framed, and what resets between sessions."`
	API      *API      `yaml:"api,omitempty" json:"api,omitempty" doc:"API replay: where the service listens, which capture seeds it, and which oracles judge the responses."`
	Driver   *Driver   `yaml:"driver,omitempty" json:"driver,omitempty" doc:"A user interface driven by events: the terminal size, how long to let it redraw, and which oracles judge it."`
	State    *State    `yaml:"state,omitempty" json:"state,omitempty" doc:"The protocol state machine, declared or inferred, and how it guides the campaign."`
	Workers  *Workers  `yaml:"workers,omitempty" json:"workers,omitempty" doc:"How many workers and what strategies they run."`
	Safety   *Safety   `yaml:"safety,omitempty" json:"safety,omitempty" doc:"Isolation, resource limits, network scope, authorization."`
	Storage  *Storage  `yaml:"storage,omitempty" json:"storage,omitempty" doc:"Where the corpus and findings live, and their budgets."`
	Triage   *Triage   `yaml:"triage,omitempty" json:"triage,omitempty" doc:"How findings are verified, minimised, and bucketed."`
	Health   *Health   `yaml:"health,omitempty" json:"health,omitempty" doc:"Thresholds the health diagnostics judge against."`
	Stop     *Stop     `yaml:"stop,omitempty" json:"stop,omitempty" doc:"Termination conditions. A campaign must be able to end."`

	// Extensions are out-of-process plugins. A list rather than a map because
	// order is what decides which of two feedbacks judges first, and a map's
	// order is whatever the parser felt like.
	Extensions []Extension `yaml:"extensions,omitempty" json:"extensions,omitempty" doc:"Out-of-process plugins and the extension points each supplies."`

	// Scripts are campaign-local Starlark. Separate from extensions because
	// they are not processes: nothing is spawned, nothing is confined, and the
	// isolation is the interpreter's rather than the operating system's.
	Scripts []Script `yaml:"scripts,omitempty" json:"scripts,omitempty" doc:"Campaign-local Starlark and the extension points each supplies."`
}

// Target is what the campaign fuzzes.
type Target struct {
	// Path is the executable.
	Path string `yaml:"path" json:"path" doc:"Path to the target executable."`

	// Args is the argument vector after the program name. The token @@ is
	// replaced with the input file path, following AFL's convention — a
	// convention worth keeping because every harness script in existence
	// already uses it.
	Args []string `yaml:"args,omitempty" json:"args,omitempty" doc:"Arguments after the program name. @@ is replaced with the input file path."`

	// Env sets environment variables for the target.
	Env map[string]string `yaml:"env,omitempty" json:"env,omitempty" doc:"Environment variables for the target."`

	// Dir is the target's working directory. It must be reachable by the
	// identity the sandbox gives the target.
	Dir string `yaml:"dir,omitempty" json:"dir,omitempty" doc:"Working directory for the target."`

	// Executor selects the delivery tier: forkserver, pool, subprocess, inproc,
	// or emulated.
	// Empty picks the fastest tier the target supports, which is what a person
	// wants and would otherwise have to work out themselves.
	Executor string `yaml:"executor,omitempty" json:"executor,omitempty" doc:"Delivery tier: auto, forkserver, pool, subprocess, inproc, or emulated."`

	// Input selects how the input reaches the target: stdin, file, or arg.
	Input string `yaml:"input,omitempty" json:"input,omitempty" doc:"How input is delivered: stdin, file, or arg."`

	// Timeout bounds one execution.
	Timeout Duration `yaml:"timeout,omitempty" json:"timeout,omitempty" doc:"Per-execution timeout."`
}

// Seeds is where the starting corpus comes from.
type Seeds struct {
	// Dirs are corpus directories to import.
	Dirs []string `yaml:"dirs,omitempty" json:"dirs,omitempty" doc:"Corpus directories to import."`

	// Format is the layout of those directories: auto, afl, libfuzzer, or raw.
	Format string `yaml:"format,omitempty" json:"format,omitempty" doc:"Corpus layout: auto, afl, libfuzzer, or raw."`

	// Inline are literal seeds, for a campaign whose starting inputs are small
	// enough to live in the file and be reviewed with it.
	Inline []string `yaml:"inline,omitempty" json:"inline,omitempty" doc:"Literal seed inputs, as strings."`

	// MaxFileSize caps an imported seed.
	MaxFileSize Size `yaml:"max_file_size,omitempty" json:"max_file_size,omitempty" doc:"Largest seed file to import, in bytes."`

	// Generate asks the grammar for this many seeds when no corpus is supplied.
	// A campaign with a grammar and no seeds is not stuck; it generates.
	Generate int `yaml:"generate,omitempty" json:"generate,omitempty" doc:"Seeds to generate from the grammar when no corpus is given."`
}

// Format is how bytes are interpreted as structure.
type Format struct {
	// Codec names a built-in codec: raw or png.
	Codec string `yaml:"codec,omitempty" json:"codec,omitempty" doc:"Built-in codec: raw or png."`

	// Grammar is a path to an .xfg schema. With one, mutation is structural and
	// derived fields are recomputed; without one, it is byte-level.
	Grammar string `yaml:"grammar,omitempty" json:"grammar,omitempty" doc:"Path to an .xfg grammar."`

	// Dictionary is a path to an AFL-format token dictionary.
	Dictionary string `yaml:"dictionary,omitempty" json:"dictionary,omitempty" doc:"Path to an AFL-format dictionary."`

	// MaxInputBytes bounds how far mutation may inflate an input.
	MaxInputBytes Size `yaml:"max_input_bytes,omitempty" json:"max_input_bytes,omitempty" doc:"Largest input mutation may produce."`

	// Suppress leaves chosen derivations inconsistent on purpose, so the
	// campaign also reaches the target's validation code (ASR-0014).
	Suppress []string `yaml:"suppress,omitempty" json:"suppress,omitempty" doc:"Derivations to leave inconsistent: length, count, offset, checksum."`
}

// Mutation selects and weights operators.
type Mutation struct {
	// Operators restricts the operator set by name. Empty means all of them.
	Operators []string `yaml:"operators,omitempty" json:"operators,omitempty" doc:"Operator names to enable. Empty enables all."`

	// Weights adjusts an operator's selection weight.
	Weights map[string]int `yaml:"weights,omitempty" json:"weights,omitempty" doc:"Per-operator selection weights."`

	// Stack is how many operators are applied per mutation round.
	Stack int `yaml:"stack,omitempty" json:"stack,omitempty" doc:"Operators applied per mutation."`

	// TrimBudget bounds executions spent shrinking one newly admitted entry.
	// Zero disables trimming.
	TrimBudget int `yaml:"trim_budget,omitempty" json:"trim_budget,omitempty" doc:"Executions spent trimming each new corpus entry. 0 disables."`
}

// Feedback is what counts as interesting.
type Feedback struct {
	// Coverage selects the instrumentation.
	//
	// sancov reads the map an instrumented build writes and is by far the
	// fastest. ptrace-bb, qemu and frida are the binary-only backends: they need
	// no rebuild and work on a stripped executable, at one to two orders of
	// magnitude the cost (ADR-0002). blackbox is exit status, output and timing
	// alone, and none turns coverage off.
	Coverage string `yaml:"coverage,omitempty" json:"coverage,omitempty" doc:"Coverage backend: sancov, ptrace-bb, qemu, frida, blackbox, or none."`

	// MapSize is the coverage map size in bytes. It must match what the target
	// was instrumented against.
	MapSize Size `yaml:"map_size,omitempty" json:"map_size,omitempty" doc:"Coverage map size in bytes."`

	// Novelty adds output-novelty feedback, for a target with no
	// instrumentation but informative output.
	Novelty bool `yaml:"novelty,omitempty" json:"novelty,omitempty" doc:"Treat novel output as interesting."`

	// CmpLog turns on comparison-operand substitution: the target's own
	// comparisons are read back and written into the input, which is what gets a
	// campaign past a magic number or a checksum (ADR-0007).
	//
	// It needs a target built with the comparison instrumentation, which
	// xfuzz-cc installs by default, and it costs a second shared region and a
	// handful of executions per corpus entry. Off unless asked for, because on a
	// target with no constants to match it spends those executions and admits
	// nothing.
	CmpLog bool `yaml:"cmplog,omitempty" json:"cmplog,omitempty" doc:"Substitute the target's own comparison operands into the input."`

	// ValueProfile treats a comparison that nearly passed as new coverage, so a
	// campaign can climb a comparison it cannot jump. It reads the same table
	// CmpLog does and is enabled with it.
	ValueProfile bool `yaml:"value_profile,omitempty" json:"value_profile,omitempty" doc:"Treat getting closer to passing a comparison as new coverage."`

	// Objectives selects what counts as a finding.
	Objectives []string `yaml:"objectives,omitempty" json:"objectives,omitempty" doc:"What counts as a finding: crash, hang, oom, sanitizer."`

	// Directed aims the campaign at particular places in the target, so that an
	// input which reached no new code but got closer is kept and favoured.
	Directed *Directed `yaml:"directed,omitempty" json:"directed,omitempty" doc:"Aim the campaign at particular locations in the target."`
}

// Directed turns a coverage-guided campaign into a directed one.
//
// Its presence is what selects direction, in the same way the session block
// selects a stateful campaign (ADR-0016): a separate mode switch would let a
// file name targets and not use them, or ask for direction and give nowhere to
// go, and both look valid and cannot work.
type Directed struct {
	// Targets are the places to aim at, in whichever form the evidence came in:
	// a function name, a file and line from a patch, or an address from a crash
	// report.
	Targets []string `yaml:"targets" json:"targets" doc:"Where to aim: a function name, file.c:123, or 0xADDRESS."`

	// Weight is how much closeness is worth in the schedule. Zero takes the
	// default; direction that is kept but never spent does not arrive.
	Weight float64 `yaml:"weight,omitempty" json:"weight,omitempty" doc:"How much the schedule favours seeds closer to the target."`

	// MinReachable refuses to start when too small a share of the recovered
	// blocks can reach any target.
	//
	// A campaign directed at a function reachable only through a computed call
	// sees a handful of blocks with distances and every input scoring the same,
	// which looks exactly like a directed campaign that is not yet making
	// progress. Refusing is better than running for a week and finding out.
	MinReachable float64 `yaml:"min_reachable,omitempty" json:"min_reachable,omitempty" doc:"Refuse to start if less than this fraction of blocks can reach a target."`
}

// Session turns a campaign into a stateful one.
//
// Its presence is what selects the session tier: a campaign with a session block
// fuzzes conversations, and one without fuzzes inputs. That is deliberate — a
// separate "mode" switch would let a file ask for sessions and give no address,
// or give an address and fuzz files, and both are configurations that look valid
// and cannot work (ADR-0016).
type Session struct {
	// Address is where the target listens: "tcp:127.0.0.1:9000" or
	// "unix:/run/target.sock".
	//
	// {worker} is replaced with the worker's index. Workers each run their own
	// copy of the target, so without a per-worker address the second worker
	// binds a port the first already holds and the campaign silently runs at
	// one worker's throughput — or worse, both fuzz one server and no finding
	// is attributable to the session that caused it.
	Address string `yaml:"address" json:"address" doc:"Where the target listens: tcp:HOST:PORT or unix:PATH. {worker} is replaced with the worker index."`

	// Managed says whether Xfuzz starts the target itself.
	//
	// True by default when the campaign names a target.path. A campaign against
	// a server somebody else is running sets it false, and then a crash cannot
	// be detected from a process status — only from the connection dropping —
	// which the isolation report says out loud.
	Managed *bool `yaml:"managed,omitempty" json:"managed,omitempty" doc:"Start the target process. Defaults to true when target.path is set."`

	// Framing decides when a reply is complete: idle, line, or none.
	Framing string `yaml:"framing,omitempty" json:"framing,omitempty" doc:"When a reply is complete: idle, line, or none."`

	// QuietPeriod is how long idle framing waits for more data before calling a
	// reply finished. It is the ceiling on a stateful campaign's throughput.
	QuietPeriod Duration `yaml:"quiet_period,omitempty" json:"quiet_period,omitempty" doc:"How long idle framing waits before a reply is complete."`

	// Reset is what happens between sessions: none, reconnect, restart, or
	// snapshot. It is an explicit contract because the fuzzer's correctness
	// assumptions depend on which one holds (ASR-0002, ADR-0006).
	Reset string `yaml:"reset,omitempty" json:"reset,omitempty" doc:"Between sessions: none, reconnect, restart, or snapshot."`

	// ConnectTimeout, ReadTimeout and SessionTimeout bound establishing a
	// connection, one reply, and a whole session. All three are needed: a
	// target can refuse to accept, accept and never answer, or answer every
	// message slowly enough that the session never ends.
	ConnectTimeout Duration `yaml:"connect_timeout,omitempty" json:"connect_timeout,omitempty" doc:"Bound on establishing a connection."`
	ReadTimeout    Duration `yaml:"read_timeout,omitempty" json:"read_timeout,omitempty" doc:"Bound on one reply."`
	SessionTimeout Duration `yaml:"session_timeout,omitempty" json:"session_timeout,omitempty" doc:"Bound on a whole session."`

	// ReadLimit bounds one reply in bytes.
	ReadLimit int `yaml:"read_limit,omitempty" json:"read_limit,omitempty" doc:"Maximum bytes retained from one reply."`

	// MaxMessages bounds how long a session may grow. Sequence mutators
	// duplicate and insert, so without a bound a campaign converges on sessions
	// of ten thousand messages that take a second each and explore nothing.
	MaxMessages int `yaml:"max_messages,omitempty" json:"max_messages,omitempty" doc:"Maximum messages in one session."`
}

// API turns a campaign into an API campaign (ADR-0014).
//
// Its presence selects the API tier, the same way a session block selects the
// session tier and for the same reason: a mode switch would let a file ask for
// API fuzzing and give no address, or give an address and fuzz files, and both
// are configurations that look valid and cannot work.
//
// It is the session tier's shape with the two things a captured API session
// needs and a raw protocol session does not — values carried from one response
// into a later request, and responses that are judged rather than merely read.
type API struct {
	// Address is where the service listens: "tcp:127.0.0.1:8080".
	//
	// The address the requests are *sent* to, which is not necessarily the host
	// they name: a capture taken against production replays against a local
	// copy, and the Host header still says what it said.
	Address string `yaml:"address" json:"address" doc:"Where the service listens: tcp:HOST:PORT. {worker} is replaced with the worker index."`

	// TLS wraps the connection, and ServerName is what the handshake claims.
	TLS        bool   `yaml:"tls,omitempty" json:"tls,omitempty" doc:"Wrap the connection in TLS."`
	ServerName string `yaml:"server_name,omitempty" json:"server_name,omitempty" doc:"Server name for the TLS handshake. Defaults to the address's host."`

	// Capture is a HAR, a pcap, or a raw session file to seed from.
	//
	// The primary source, per ADR-0014: a capture carries the requests a client
	// actually sends, the values that chain between them, and the identity they
	// were sent as — none of which a specification has. An imported OpenAPI
	// grammar reaches endpoints a capture never exercised and is a poor
	// substitute for one.
	Capture string `yaml:"capture,omitempty" json:"capture,omitempty" doc:"A HAR, pcap, or raw session file to seed the campaign from."`

	// Links says how a value the service produced is carried into later
	// requests: infer, or none.
	//
	// Without it a replayed session asks for the identifier from the recording,
	// gets a 404, and every request after the first addresses an object that
	// does not exist — which is the failure inference exists to prevent.
	Links string `yaml:"links,omitempty" json:"links,omitempty" doc:"How values chain between requests: infer or none."`

	// Secrets is a file of placeholder-to-value pairs, written by `xfuzz
	// capture`, substituted immediately before each request is sent.
	//
	// Separate from the capture so the capture can be committed: the redacted
	// session holds placeholders and this holds the credentials, which is what
	// keeps a token out of the corpus, the store and every mutation.
	Secrets string `yaml:"secrets,omitempty" json:"secrets,omitempty" doc:"File of placeholder=value pairs, substituted immediately before each request."`

	// Identity names whose credentials the session is being replayed with, and
	// Expect says what should happen: allowed, denied, or unknown.
	//
	// The pair is what makes the authorization oracle possible, and ADR-0014
	// names it as the class captured traffic makes reachable and a
	// specification does not.
	Identity string `yaml:"identity,omitempty" json:"identity,omitempty" doc:"Whose credentials this campaign replays with."`
	Expect   string `yaml:"expect,omitempty" json:"expect,omitempty" doc:"What that identity should get: allowed, denied, or unknown."`

	// PerRequest bounds one request and Timeout the whole session.
	PerRequest Duration `yaml:"per_request,omitempty" json:"per_request,omitempty" doc:"Bound on one request and its response."`
	Timeout    Duration `yaml:"timeout,omitempty" json:"timeout,omitempty" doc:"Bound on a whole session."`

	// KeepAlive sends the whole session on one connection.
	KeepAlive *bool `yaml:"keep_alive,omitempty" json:"keep_alive,omitempty" doc:"Send the whole session on one connection. Defaults to true."`

	// FixLength recomputes Content-Length before each request is written.
	//
	// On by default and effectively required: a mutation that changes a body's
	// size leaves a declared length that no server reads correctly, and a
	// decimal length is not something the grammar layer can derive.
	FixLength *bool `yaml:"fix_length,omitempty" json:"fix_length,omitempty" doc:"Recompute Content-Length before each request. Defaults to true."`

	// Oracles are what judges a response: status, schema, latency,
	// authorization.
	//
	// A service almost never crashes — it is behind a supervisor, its handler
	// has a recover, and the process outlives anything one request can do to it
	// — so crash detection alone finds nothing.
	Oracles []string `yaml:"oracles,omitempty" json:"oracles,omitempty" doc:"Response oracles: status, schema, latency, authorization."`

	// IgnoreStatus lists statuses the status oracle must not report. Some
	// services answer 501 for an endpoint they have not implemented and 503
	// while a dependency restarts, and a campaign that filed those would spend
	// its triage budget on them.
	IgnoreStatus []int `yaml:"ignore_status,omitempty" json:"ignore_status,omitempty" doc:"Statuses the status oracle ignores."`
}

// Driver turns a campaign into a user-interface campaign (ADR-0013).
//
// Its presence selects the T7 tier, on the same principle as the session and
// API blocks. The input is a sequence of interaction events rather than data,
// the interface is stateful so the same keystroke means different things at
// different moments, and the whole thing runs five orders of magnitude slower
// than a parser — which is why almost everything here is a bound.
type Driver struct {
	// Kind is the backend: tui, web or gui-atspi.
	//
	// The two desktop backends ADR-0013 also names — UI Automation on Windows
	// and the accessibility API on macOS — need a platform this project cannot
	// test on, and the macOS one needs C in the fuzzer, which ADR-0017 keeps
	// out. Neither is implemented (ADR-0034).
	Kind string `yaml:"kind,omitempty" json:"kind,omitempty" doc:"Driver backend: tui, web or gui-atspi."`

	// URL is the page a web campaign drives.
	//
	// The target of a web campaign is on the other side of it: the browser is
	// the harness, so target.path names the browser only when it is not on
	// PATH, and what is under test is whatever answers here.
	URL string `yaml:"url,omitempty" json:"url,omitempty" doc:"The page a web campaign drives."`

	// Browser is the executable to drive. Empty means probe for one.
	Browser string `yaml:"browser,omitempty" json:"browser,omitempty" doc:"Browser executable for a web campaign; empty probes for one."`

	// BrowserArgs are extra flags appended to the browser's command line.
	BrowserArgs []string `yaml:"browser_args,omitempty" json:"browser_args,omitempty" doc:"Extra browser flags."`

	// BrowserSandbox keeps the browser's own sandbox, which is a different
	// layer from the one Xfuzz puts around the browser: it is what stands
	// between a hostile page and the machine. On by default, and worth leaving
	// on — a browser that refuses to start without it says so in its own words.
	BrowserSandbox *bool `yaml:"browser_sandbox,omitempty" json:"browser_sandbox,omitempty" doc:"Keep the browser's own sandbox. Defaults to true."`

	// Headed runs the browser with a window, for watching a campaign.
	Headed bool `yaml:"headed,omitempty" json:"headed,omitempty" doc:"Run the browser with a visible window."`

	// Cols and Rows are the terminal size, which is an input: a program that
	// draws correctly at eighty columns and misaligns at forty has a bug only
	// one of them finds. A web campaign sizes its viewport with width and
	// height instead, since a browser measures in pixels.
	Cols int `yaml:"cols,omitempty" json:"cols,omitempty" doc:"Terminal width in columns."`
	Rows int `yaml:"rows,omitempty" json:"rows,omitempty" doc:"Terminal height in rows."`

	// Width and Height are a web campaign's viewport in pixels, and are an
	// input for the same reason: a page that lays out correctly at 1280 and
	// misplaces a button at 400 has a bug only one of them finds.
	Width  int `yaml:"width,omitempty" json:"width,omitempty" doc:"Viewport width in pixels, for a web campaign."`
	Height int `yaml:"height,omitempty" json:"height,omitempty" doc:"Viewport height in pixels, for a web campaign."`

	// Settle is how long the interface must be quiet before its screen counts
	// as drawn. It is the tier's throughput and it cannot be avoided: an
	// interface redraws asynchronously, so observing immediately after a
	// keystroke reads the screen as it was.
	Settle Duration `yaml:"settle,omitempty" json:"settle,omitempty" doc:"How long the interface must be quiet before its screen is read."`

	// StartTimeout bounds the first screen and Timeout a whole sequence.
	StartTimeout Duration `yaml:"start_timeout,omitempty" json:"start_timeout,omitempty" doc:"Bound on the program's first screen."`
	Timeout      Duration `yaml:"timeout,omitempty" json:"timeout,omitempty" doc:"Bound on one whole event sequence."`

	// MaxEvents bounds one sequence, since a mutator will grow it. At a tenth
	// of a second per event an unbounded sequence is a campaign that runs one
	// input for an hour.
	MaxEvents int `yaml:"max_events,omitempty" json:"max_events,omitempty" doc:"Maximum events in one sequence."`

	// MaxOutputBytes caps how much a runaway program may draw before the driver
	// stops feeding the emulator. A redraw loop produces megabytes a second and
	// every byte of it is parsed.
	MaxOutputBytes Size `yaml:"max_output_bytes,omitempty" json:"max_output_bytes,omitempty" doc:"Most a program may draw in one sequence before the driver stops reading."`

	// Reset is what happens between sequences: restart or none.
	//
	// Restarting is the only reset an interface has and it is the dominant cost
	// of the tier. Without it every sequence starts wherever the last one left
	// off and no finding reproduces.
	Reset string `yaml:"reset,omitempty" json:"reset,omitempty" doc:"Between sequences: restart or none."`

	// Guide treats a novel screen and a novel transition between screens as new
	// coverage, which for a black-box interface is the only signal there is.
	Guide *bool `yaml:"guide,omitempty" json:"guide,omitempty" doc:"Treat new screens and transitions as interesting. Defaults to true."`

	// Normalise lists what a screen fingerprint removes before hashing:
	// digits, spinner, runs, space.
	//
	// The tuning knob, and ADR-0013 says it has two bad failure modes. Too weak
	// and a clock in the corner gives the program a new state every second; too
	// aggressive and two dialogs become one state and the campaign is blind to
	// the transition between them.
	Normalise []string `yaml:"normalise,omitempty" json:"normalise,omitempty" doc:"What a screen fingerprint removes: digits, spinner, runs, space."`

	// Oracles are what judges the interface: diagnostic, unresponsive, trap,
	// exception.
	Oracles []string `yaml:"oracles,omitempty" json:"oracles,omitempty" doc:"Interface oracles: diagnostic, unresponsive, trap, exception."`
}

// State configures the protocol state machine (ADR-0006).
type State struct {
	// Fn labels a response: status, http, fingerprint, or constant.
	Fn string `yaml:"fn,omitempty" json:"fn,omitempty" doc:"How a response becomes a state label: status, http, fingerprint, or constant."`

	// Normalise lists what the fingerprint function removes before hashing:
	// digits, quoted, space.
	//
	// The tuning knob for inference quality, and the one that matters. Too
	// little and every nonce is a state; too much and distinct states merge
	// (ADR-0006).
	Normalise []string `yaml:"normalise,omitempty" json:"normalise,omitempty" doc:"What fingerprinting removes before hashing: digits, quoted, space."`

	// Script names the Starlark state function to use, as NAME:FUNCTION, when
	// fn is "script". A protocol nobody has heard of still has a shape, and
	// someone who knows it can write "the third byte is the status" faster
	// than they can explain it to an inference heuristic.
	Script string `yaml:"script,omitempty" json:"script,omitempty" doc:"Starlark state function as NAME:FUNCTION, when fn is script."`

	// Guide adds state and transition novelty to the feedback stack. On by
	// default for a session campaign: it is the reason ADR-0006 exists.
	Guide *bool `yaml:"guide,omitempty" json:"guide,omitempty" doc:"Treat new states and transitions as interesting. Defaults to true."`

	// Declare is the protocol's own state machine, as "from->to" transitions.
	//
	// Optional, and additive rather than a replacement: inference still runs,
	// and what a declaration adds is an expectation. A transition outside it is
	// the target accepting a move its own protocol forbids, which is reported
	// rather than treated as ordinary exploration.
	Declare []string `yaml:"declare,omitempty" json:"declare,omitempty" doc:"Declared transitions as \"from->to\". Moves outside them are reported."`

	// Explore is how often the scheduler aims for a rarely-visited state rather
	// than mutating wherever the session allows.
	Explore float64 `yaml:"explore,omitempty" json:"explore,omitempty" doc:"How often to aim for a rare state, 0..1."`

	// TailBias is how often an aimed mutation lands at or after the targeted
	// state rather than before it.
	TailBias float64 `yaml:"tail_bias,omitempty" json:"tail_bias,omitempty" doc:"How often an aimed mutation lands at or after the target state, 0..1."`

	// Learn asks the campaign to work out the protocol's state machine before
	// it starts fuzzing, by driving the target on purpose.
	Learn *Learn `yaml:"learn,omitempty" json:"learn,omitempty" doc:"Infer the protocol's state machine before fuzzing, and seed the corpus from it."`
}

// Learn configures active automata learning (ADR-0035).
//
// The difference from the inference beside it is what the fuzzer does with its
// executions. Inference labels whatever the mutator happened to send; learning
// chooses the sequences, and what comes back is a machine with a path to every
// state it found. Those paths are what a stateful campaign is short of: a corpus
// seeded with them starts from every reachable state rather than from the
// handshake.
//
// It costs executions before the campaign begins — one reset and one session
// per question — which is why every bound here exists and why it is off unless
// asked for.
type Learn struct {
	// Alphabet caps how many distinct messages to learn over, taken from the
	// campaign's seeds. Everything scales with it: the table has a column per
	// symbol before it has anything else.
	Alphabet int `yaml:"alphabet,omitempty" json:"alphabet,omitempty" doc:"How many distinct seed messages to learn over."`

	// MaxQueries and MaxStates bound the learning. Reaching either returns what
	// was learned so far, reported as partial rather than presented as complete.
	MaxQueries int `yaml:"max_queries,omitempty" json:"max_queries,omitempty" doc:"Most sessions to run while learning."`
	MaxStates  int `yaml:"max_states,omitempty" json:"max_states,omitempty" doc:"Most states to infer before stopping."`

	// Words and MaxLength bound the search for a counterexample, which is where
	// the algorithm's exactness becomes a sample: no oracle can prove a program
	// equivalent to a machine.
	Words     int `yaml:"words,omitempty" json:"words,omitempty" doc:"How many random sequences to check the machine against."`
	MaxLength int `yaml:"max_length,omitempty" json:"max_length,omitempty" doc:"Longest sequence the check uses."`

	// Seed, when set, makes the sequences the learner tries reproducible
	// independently of the campaign seed.
	Seed uint64 `yaml:"seed,omitempty" json:"seed,omitempty" doc:"Seed for the sequences learning tries. 0 uses the campaign's."`

	// Dot writes the learned machine to this path, in Graphviz's language. A
	// learned machine is something a person looks at, and that is most of its
	// value beside its use as a seed source.
	Dot string `yaml:"dot,omitempty" json:"dot,omitempty" doc:"Write the learned machine here as a Graphviz diagram."`
}

// Workers is how the campaign is parallelised.
type Workers struct {
	// Count is how many worker processes to run. Zero means one per physical
	// core.
	Count int `yaml:"count,omitempty" json:"count,omitempty" doc:"Worker processes. 0 means one per core."`

	// Strategies assigns different behaviour to different workers. Workers take
	// strategies round-robin, so three strategies across eight workers is a
	// sensible thing to write. Strategy diversity beats N identical workers.
	Strategies []Strategy `yaml:"strategies,omitempty" json:"strategies,omitempty" doc:"Per-worker strategy overlays, assigned round-robin."`

	// SyncInterval is how often a worker publishes and collects corpus entries.
	SyncInterval Duration `yaml:"sync_interval,omitempty" json:"sync_interval,omitempty" doc:"How often workers exchange corpus entries."`
}

// Strategy is one worker's deviation from the campaign's defaults.
type Strategy struct {
	Name     string    `yaml:"name" json:"name" doc:"Strategy name, for reports."`
	Schedule string    `yaml:"schedule,omitempty" json:"schedule,omitempty" doc:"Power schedule: fast, rand, or roundrobin."`
	Mutation *Mutation `yaml:"mutation,omitempty" json:"mutation,omitempty" doc:"Mutation overrides for workers running this strategy."`
}

// Safety is the confinement and scope policy.
type Safety struct {
	// Isolation is the minimum acceptable level: none, minimal, moderate, or
	// strong. A host that cannot reach it refuses the campaign.
	Isolation string `yaml:"isolation,omitempty" json:"isolation,omitempty" doc:"Minimum isolation level: none, minimal, moderate, strong."`

	// Network keeps the target in the host network namespace. Required for a
	// target that talks to the network, and audited as an escape hatch.
	Network bool `yaml:"network,omitempty" json:"network,omitempty" doc:"Leave the target in the host network namespace."`

	// Writable lists paths the target may write beyond its workdir.
	Writable []string `yaml:"writable,omitempty" json:"writable,omitempty" doc:"Extra writable paths under the read-only root."`

	// MemoryLimit, ProcessLimit, FileSizeLimit and CPULimit bound one target.
	MemoryLimit   Size     `yaml:"memory_limit,omitempty" json:"memory_limit,omitempty" doc:"Per-target memory cap in bytes."`
	ProcessLimit  int      `yaml:"process_limit,omitempty" json:"process_limit,omitempty" doc:"Per-target process cap."`
	FileSizeLimit Size     `yaml:"file_size_limit,omitempty" json:"file_size_limit,omitempty" doc:"Largest file the target may write."`
	CPULimit      Duration `yaml:"cpu_limit,omitempty" json:"cpu_limit,omitempty" doc:"Per-target CPU time cap."`

	// Scope is the network allowlist. A campaign that leaves the host without
	// one refuses to start.
	Scope *Scope `yaml:"scope,omitempty" json:"scope,omitempty" doc:"Network allowlist for campaigns that leave the host."`

	// Authorization is required before a remote campaign sends a packet.
	Authorization *Authorization `yaml:"authorization,omitempty" json:"authorization,omitempty" doc:"Who authorised this campaign, and under what reference."`
}

// Scope is the network allowlist.
type Scope struct {
	// Allow lists destinations as host, address, or CIDR, each optionally with
	// ports: "10.0.0.0/8:80,8000-8999".
	Allow []string `yaml:"allow,omitempty" json:"allow,omitempty" doc:"Allowed destinations: host, address, or CIDR, optionally with :ports."`

	// Loopback permits connections to the local host. On by default, so local
	// experimentation stays frictionless.
	Loopback *bool `yaml:"loopback,omitempty" json:"loopback,omitempty" doc:"Permit loopback. Defaults to true."`

	// AcknowledgePublic records that the operator accepts that this scope
	// reaches public address space. Without it, such a scope is refused.
	AcknowledgePublic bool `yaml:"acknowledge_public,omitempty" json:"acknowledge_public,omitempty" doc:"Acknowledge that the scope reaches public address space."`
}

// Authorization is the record a remote campaign carries.
type Authorization struct {
	Operator    string `yaml:"operator" json:"operator" doc:"Who is running this campaign."`
	Reference   string `yaml:"reference" json:"reference" doc:"Engagement identifier, ticket, or approval reference."`
	Attestation string `yaml:"attestation" json:"attestation" doc:"Statement that the operator is authorised to test the declared scope."`
}

// Storage is where campaign state lives.
type Storage struct {
	// Dir is the store root. Empty puts it under the daemon's data directory.
	Dir string `yaml:"dir,omitempty" json:"dir,omitempty" doc:"Store directory. Empty uses the daemon's data directory."`

	// MaxCorpusBytes and MaxCorpusEntries cap the corpus. Culling is reported,
	// never silent.
	MaxCorpusBytes   Size  `yaml:"max_corpus_bytes,omitempty" json:"max_corpus_bytes,omitempty" doc:"Corpus size cap in bytes. 0 is unlimited."`
	MaxCorpusEntries int64 `yaml:"max_corpus_entries,omitempty" json:"max_corpus_entries,omitempty" doc:"Corpus entry cap. 0 is unlimited."`

	// CheckpointInterval is how often resume state is written. It is also how
	// much a kill costs.
	CheckpointInterval Duration `yaml:"checkpoint_interval,omitempty" json:"checkpoint_interval,omitempty" doc:"How often resume state is written."`

	// DistillInterval is how often the corpus is re-measured and reduced to the
	// smallest subset that still reaches everything it reached.
	//
	// Off by default, and deliberately: it costs one execution per entry, which
	// on a fast target is a second and on the driver tier is minutes. What it
	// buys is a corpus that stays a corpus — a long campaign admits an entry
	// whenever it sees anything new, and most of what it admits after the first
	// hour is a slightly different route to somewhere it has already been. The
	// caps above cull by size; this culls by redundancy, which is the question
	// a person asks when they want the seeds rather than the sediment.
	DistillInterval Duration `yaml:"distill_interval,omitempty" json:"distill_interval,omitempty" doc:"How often to reduce the corpus to a minimal covering subset. 0 never does."`
}

// Health is where a campaign disagrees with the defaults about what "unhealthy"
// means.
//
// The thresholds behind the diagnostics are judgements, not constants: a target
// that is legitimately a little non-deterministic, or one so slow that ten
// executions a second is a good day, is not broken. ASR-0008 requires the
// stability threshold in particular to be configurable, because a target below
// it must raise a diagnostic rather than silently corrupt a corpus — and a
// diagnostic that fires on every run of a known-noisy target is one that gets
// ignored on the run that mattered.
//
// Only the thresholds a campaign has a real reason to move. The rest stay
// where internal/metrics puts them: a knob for every check would be a
// configuration surface nobody could reason about, and each one here has an
// ASR behind it.
type Health struct {
	// MinStability is the share of executions that must reproduce their own
	// coverage before the campaign is judged to be chasing noise (ASR-0008).
	MinStability float64 `yaml:"min_stability,omitempty" json:"min_stability,omitempty" doc:"Share of executions that must reproduce their coverage. Default 0.90."`

	// MaxOverhead is the share of wall-clock time the fuzzer may spend on its
	// own bookkeeping rather than on the target (ASR-0007).
	MaxOverhead float64 `yaml:"max_overhead,omitempty" json:"max_overhead,omitempty" doc:"Share of time the fuzzer may spend on itself. Default 0.10."`

	// MinExecsPerSecond is a rate below which something is wrong with the
	// executor rather than with the target.
	MinExecsPerSecond float64 `yaml:"min_execs_per_second,omitempty" json:"min_execs_per_second,omitempty" doc:"Rate below which the executor is judged broken. Default 10."`

	// CoverageStall is how long without new coverage counts as stalled.
	CoverageStall Duration `yaml:"coverage_stall,omitempty" json:"coverage_stall,omitempty" doc:"How long without new coverage counts as stalled. Default 30m."`
}

// Triage is how findings are turned into bug reports.
type Triage struct {
	// Enabled runs triage. On by default: a campaign that reports every
	// crashing input reports the same bug ten thousand times.
	Enabled *bool `yaml:"enabled,omitempty" json:"enabled,omitempty" doc:"Run triage. Defaults to true."`

	// Trials is how many times a reproducer is re-run to verify it.
	Trials int `yaml:"trials,omitempty" json:"trials,omitempty" doc:"Verification runs per finding."`

	// Minimize shrinks reproducers. On by default.
	Minimize *bool `yaml:"minimize,omitempty" json:"minimize,omitempty" doc:"Minimise reproducers. Defaults to true."`

	// MinimizeBudget bounds executions spent on one reproducer.
	MinimizeBudget int `yaml:"minimize_budget,omitempty" json:"minimize_budget,omitempty" doc:"Executions spent minimising one reproducer."`

	// Strategy selects bucketing: chain, frames, marker, coverage, or signal.
	Strategy string `yaml:"strategy,omitempty" json:"strategy,omitempty" doc:"Bucketing strategy: chain, frames, marker, coverage, or signal."`

	// Markers are line prefixes that identify a failure in the target's own
	// words, in addition to the generic ones.
	//
	// A program that names its own failures gives better evidence of which bug
	// this is than any signal number, and every codebase names them
	// differently: "MYPROJ-FATAL", "check failed:", a company prefix. Without
	// this, such a target's bugs all bucket together under one signal.
	Markers []string `yaml:"markers,omitempty" json:"markers,omitempty" doc:"Extra line prefixes that name a failure in the target's own words."`
}

// Stop is when the campaign ends.
//
// Termination is a first-class part of the file rather than a flag, because CI
// usage requires a campaign to end deterministically (ASR-0015) and a budget
// passed on a command line is not part of the artefact that describes the run.
type Stop struct {
	// After is a wall-clock budget.
	After Duration `yaml:"after,omitempty" json:"after,omitempty" doc:"Wall-clock budget."`

	// Execs is an execution budget, which unlike time is the same on every host.
	Execs uint64 `yaml:"execs,omitempty" json:"execs,omitempty" doc:"Execution budget."`

	// Findings stops after this many distinct buckets. Distinct, not raw
	// findings: stopping after ten thousand reports of one bug is not stopping
	// after ten thousand bugs.
	Findings int `yaml:"findings,omitempty" json:"findings,omitempty" doc:"Stop after this many distinct finding buckets."`

	// NoNewCoverage stops when no new coverage has been found for this long. It
	// is the condition that says "this campaign has stopped learning", which is
	// usually what a person means by "long enough".
	NoNewCoverage Duration `yaml:"no_new_coverage,omitempty" json:"no_new_coverage,omitempty" doc:"Stop after this long without new coverage."`
}

// IsZero reports whether no termination condition is set.
func (s *Stop) IsZero() bool {
	return s == nil || (s.After == 0 && s.Execs == 0 && s.Findings == 0 && s.NoNewCoverage == 0)
}

// Duration is a time.Duration that reads and writes as "30s", "2h", "7d".
//
// A bare number would be ambiguous — seconds or milliseconds is a coin flip in
// configuration formats — and time.Duration's own text form does not accept
// days, which is the unit a fuzzing budget is usually written in.
type Duration time.Duration

// Std returns the standard duration.
func (d Duration) Std() time.Duration { return time.Duration(d) }

func (d Duration) String() string {
	if d == 0 {
		return "0s"
	}
	td := time.Duration(d)
	if td%(24*time.Hour) == 0 {
		return fmt.Sprintf("%dd", td/(24*time.Hour))
	}
	return td.String()
}

// UnmarshalYAML implements yaml.Unmarshaler.
func (d *Duration) UnmarshalYAML(unmarshal func(any) error) error {
	var s string
	if err := unmarshal(&s); err != nil {
		var n int64
		if err2 := unmarshal(&n); err2 == nil {
			return fmt.Errorf("campaign: %d is not a duration; write it with a unit, such as %ds", n, n)
		}
		return err
	}
	parsed, err := ParseDuration(s)
	if err != nil {
		return err
	}
	*d = parsed
	return nil
}

// MarshalYAML implements yaml.Marshaler.
func (d Duration) MarshalYAML() (any, error) { return d.String(), nil }

// MarshalJSON implements json.Marshaler.
func (d Duration) MarshalJSON() ([]byte, error) { return []byte(`"` + d.String() + `"`), nil }

// UnmarshalJSON implements json.Unmarshaler.
func (d *Duration) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	parsed, err := ParseDuration(s)
	if err != nil {
		return err
	}
	*d = parsed
	return nil
}

// ParseDuration accepts Go's duration syntax plus a day unit.
func ParseDuration(s string) (Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, nil
	}
	if rest, ok := strings.CutSuffix(s, "d"); ok {
		var days float64
		if _, err := fmt.Sscanf(rest, "%g", &days); err == nil {
			return Duration(time.Duration(days * float64(24*time.Hour))), nil
		}
	}
	td, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("campaign: %q is not a duration (want something like 30s, 10m, 2h, or 7d)", s)
	}
	return Duration(td), nil
}

// Size is a byte count that may be written with a unit.
//
// A campaign file is read and edited by people, and "2147483648" is a number
// nobody checks. It is also a number people get wrong by a factor of a thousand
// in either direction, which for a memory limit is the difference between a
// campaign that works and one that dies on its first execution.
//
// A plain number is still accepted and still means bytes, so every campaign
// file written before this keeps working.
type Size int64

// Bytes returns the count.
func (z Size) Bytes() int64 { return int64(z) }

// String renders a size in the largest unit that divides it exactly, so a
// round-trip through the file does not turn 2GB into 2147483648.
func (z Size) String() string {
	n := int64(z)
	if n == 0 {
		return "0"
	}
	for _, u := range sizeUnits {
		if n%u.scale == 0 {
			return strconv.FormatInt(n/u.scale, 10) + u.suffix
		}
	}
	return strconv.FormatInt(n, 10)
}

// sizeUnits are the suffixes, largest first. Powers of 1024 throughout: a
// memory limit and a file size are both measured that way, and mixing the two
// conventions in one file is how a limit ends up 7% wrong for no reason anybody
// can see.
var sizeUnits = []struct {
	suffix string
	scale  int64
}{
	{"TB", 1 << 40}, {"GB", 1 << 30}, {"MB", 1 << 20}, {"KB", 1 << 10},
}

// ParseSize reads a byte count, with or without a unit.
func ParseSize(s string) (Size, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, nil
	}
	upper := strings.ToUpper(s)
	for _, u := range sizeUnits {
		// Both "2GB" and "2G", because both are what people type.
		for _, suffix := range []string{u.suffix, u.suffix[:1]} {
			rest, ok := strings.CutSuffix(upper, suffix)
			if !ok {
				continue
			}
			n, err := strconv.ParseFloat(strings.TrimSpace(rest), 64)
			if err != nil {
				return 0, sizeError(s)
			}
			return Size(n * float64(u.scale)), nil
		}
	}
	rest := strings.TrimSuffix(upper, "B")
	n, err := strconv.ParseInt(strings.TrimSpace(rest), 10, 64)
	if err != nil {
		return 0, sizeError(s)
	}
	return Size(n), nil
}

func sizeError(s string) error {
	return fmt.Errorf("campaign: %q is not a size (want a number of bytes, or one with a unit such as 512KB, 64MB or 2GB)", s)
}

// UnmarshalYAML implements yaml.Unmarshaler.
func (z *Size) UnmarshalYAML(unmarshal func(any) error) error {
	var n int64
	if err := unmarshal(&n); err == nil {
		*z = Size(n)
		return nil
	}
	var str string
	if err := unmarshal(&str); err != nil {
		return err
	}
	parsed, err := ParseSize(str)
	if err != nil {
		return err
	}
	*z = parsed
	return nil
}

// MarshalYAML implements yaml.Marshaler.
func (z Size) MarshalYAML() (any, error) { return z.String(), nil }

// MarshalJSON implements json.Marshaler.
//
// A string, like Duration, so that the API and the console show what the file
// says rather than a number the reader has to divide.
func (z Size) MarshalJSON() ([]byte, error) { return []byte(`"` + z.String() + `"`), nil }

// UnmarshalJSON implements json.Unmarshaler.
func (z *Size) UnmarshalJSON(b []byte) error {
	str := strings.Trim(string(b), `"`)
	parsed, err := ParseSize(str)
	if err != nil {
		return err
	}
	*z = parsed
	return nil
}

// Extension is one plugin process and the extension points it supplies.
//
// The command is named here rather than discovered, and the extensions are
// listed rather than taken wholesale. Both are deliberate: a campaign file is
// the complete description of what a campaign does (ADR-0016), and "whatever
// that program happens to provide" is not a description. Listing them is also
// what makes a typo a refusal at startup rather than a feedback that silently
// never fires.
type Extension struct {
	// Name labels the plugin. It qualifies every extension the plugin
	// provides, so two plugins may offer the same extension name.
	Name string `yaml:"name" json:"name" doc:"Label for this plugin, used to qualify its extensions."`

	// Command is the plugin executable.
	Command string `yaml:"command" json:"command" doc:"Path to the plugin program."`

	// Args is the complete argv, including argv[0], following the same
	// convention as target.args.
	Args []string `yaml:"args,omitempty" json:"args,omitempty" doc:"Arguments after the program name."`

	// Env and Dir are the plugin's environment and working directory.
	Env map[string]string `yaml:"env,omitempty" json:"env,omitempty" doc:"Environment variables for the plugin."`
	Dir string            `yaml:"dir,omitempty" json:"dir,omitempty" doc:"Working directory for the plugin."`

	// Config is passed to the plugin at startup, uninterpreted. It is how a
	// campaign configures a plugin without this file knowing what the settings
	// mean.
	Config map[string]string `yaml:"config,omitempty" json:"config,omitempty" doc:"Settings handed to the plugin at startup."`

	// Feedbacks, Objectives and Mutators name what to take from this plugin.
	Feedbacks  []string `yaml:"feedbacks,omitempty" json:"feedbacks,omitempty" doc:"Feedbacks to take from this plugin."`
	Objectives []string `yaml:"objectives,omitempty" json:"objectives,omitempty" doc:"Objectives to take from this plugin."`
	Mutators   []string `yaml:"mutators,omitempty" json:"mutators,omitempty" doc:"Mutators to take from this plugin."`

	// Timeout bounds one call. A plugin that exceeds it is killed, because a
	// synchronous protocol has no other answer to a peer that stopped talking.
	Timeout Duration `yaml:"timeout,omitempty" json:"timeout,omitempty" doc:"Bound on one call to the plugin."`

	// Batch is how many variants a plugin mutator is asked for at once.
	Batch int `yaml:"batch,omitempty" json:"batch,omitempty" doc:"Variants a plugin mutator produces per call."`

	// Input sends the executed bytes with each judgement. Off by default: it
	// is the largest cost on the path and most extensions judge what an
	// execution did rather than what it was.
	Input bool `yaml:"input,omitempty" json:"input,omitempty" doc:"Send the executed bytes to this plugin."`
}

// Script is one Starlark file and the extension points it supplies.
//
// The third tier (ADR-0010), for the logic that is true of this target and no
// other. An oracle that says "the length field must match what was read" is
// four lines and belongs in the campaign, not in a plugin someone has to build.
type Script struct {
	// Name labels the script. It qualifies the extensions it provides and
	// names it in errors.
	Name string `yaml:"name" json:"name" doc:"Label for this script, used to qualify its extensions."`

	// Path is the .star file, relative to the campaign file or absolute.
	Path string `yaml:"path" json:"path" doc:"Path to the Starlark file."`

	// Config is readable inside the script as the config dict.
	Config map[string]string `yaml:"config,omitempty" json:"config,omitempty" doc:"Settings the script reads as config."`

	// Objectives and Mutators name the functions to take from this script.
	//
	// No feedbacks. A feedback's value is the novelty state it accumulates,
	// and Starlark freezes a module's globals after it loads, so a script
	// cannot accumulate anything. That is not a gap to fill later with a
	// workaround — it is what makes the tier hermetic, and a feedback that
	// needs memory belongs to the plugin tier, where a process can remember.
	Objectives []string `yaml:"objectives,omitempty" json:"objectives,omitempty" doc:"Oracle functions to take from this script."`
	Mutators   []string `yaml:"mutators,omitempty" json:"mutators,omitempty" doc:"Mutator functions to take from this script."`

	// Steps and Allocs bound one call. A hermetic language can still loop
	// forever and still build a gigabyte string; these are what stop it.
	Steps  uint64 `yaml:"steps,omitempty" json:"steps,omitempty" doc:"Computation steps one call may take."`
	Allocs int64  `yaml:"allocs,omitempty" json:"allocs,omitempty" doc:"Bytes one call may allocate."`

	// Batch is how many variants a script mutator produces per call.
	Batch int `yaml:"batch,omitempty" json:"batch,omitempty" doc:"Variants a script mutator produces per call."`
}
