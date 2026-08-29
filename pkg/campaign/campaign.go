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
	Workers  *Workers  `yaml:"workers,omitempty" json:"workers,omitempty" doc:"How many workers and what strategies they run."`
	Safety   *Safety   `yaml:"safety,omitempty" json:"safety,omitempty" doc:"Isolation, resource limits, network scope, authorization."`
	Storage  *Storage  `yaml:"storage,omitempty" json:"storage,omitempty" doc:"Where the corpus and findings live, and their budgets."`
	Triage   *Triage   `yaml:"triage,omitempty" json:"triage,omitempty" doc:"How findings are verified, minimised, and bucketed."`
	Stop     *Stop     `yaml:"stop,omitempty" json:"stop,omitempty" doc:"Termination conditions. A campaign must be able to end."`
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

	// Executor selects the delivery tier: forkserver, subprocess, or inproc.
	// Empty picks the fastest tier the target supports, which is what a person
	// wants and would otherwise have to work out themselves.
	Executor string `yaml:"executor,omitempty" json:"executor,omitempty" doc:"Delivery tier: auto, forkserver, subprocess, or inproc."`

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
	MaxFileSize int64 `yaml:"max_file_size,omitempty" json:"max_file_size,omitempty" doc:"Largest seed file to import, in bytes."`

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
	MaxInputBytes int `yaml:"max_input_bytes,omitempty" json:"max_input_bytes,omitempty" doc:"Largest input mutation may produce."`

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
	// Coverage selects the instrumentation: sancov, blackbox, or none.
	Coverage string `yaml:"coverage,omitempty" json:"coverage,omitempty" doc:"Coverage backend: sancov, blackbox, or none."`

	// MapSize is the coverage map size in bytes. It must match what the target
	// was instrumented against.
	MapSize int `yaml:"map_size,omitempty" json:"map_size,omitempty" doc:"Coverage map size in bytes."`

	// Novelty adds output-novelty feedback, for a target with no
	// instrumentation but informative output.
	Novelty bool `yaml:"novelty,omitempty" json:"novelty,omitempty" doc:"Treat novel output as interesting."`

	// Objectives selects what counts as a finding.
	Objectives []string `yaml:"objectives,omitempty" json:"objectives,omitempty" doc:"What counts as a finding: crash, hang, oom, sanitizer."`
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
	MemoryLimit   int64    `yaml:"memory_limit,omitempty" json:"memory_limit,omitempty" doc:"Per-target memory cap in bytes."`
	ProcessLimit  int      `yaml:"process_limit,omitempty" json:"process_limit,omitempty" doc:"Per-target process cap."`
	FileSizeLimit int64    `yaml:"file_size_limit,omitempty" json:"file_size_limit,omitempty" doc:"Largest file the target may write."`
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
	MaxCorpusBytes   int64 `yaml:"max_corpus_bytes,omitempty" json:"max_corpus_bytes,omitempty" doc:"Corpus size cap in bytes. 0 is unlimited."`
	MaxCorpusEntries int64 `yaml:"max_corpus_entries,omitempty" json:"max_corpus_entries,omitempty" doc:"Corpus entry cap. 0 is unlimited."`

	// CheckpointInterval is how often resume state is written. It is also how
	// much a kill costs.
	CheckpointInterval Duration `yaml:"checkpoint_interval,omitempty" json:"checkpoint_interval,omitempty" doc:"How often resume state is written."`
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
