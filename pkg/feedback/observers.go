package feedback

import (
	"fmt"
	"hash/maphash"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// OutputObserver captures what a target wrote and how it exited.
//
// This is the black-box signal: with no instrumentation available, the exit
// status, the output, and how long it took are all a fuzzer has. ASR-0003
// requires that to be a supported mode rather than a failure state, so these
// observers are not a fallback bolted on — they are how the same engine runs
// against a stripped binary.
type OutputObserver struct {
	name     string
	stdout   []byte
	stderr   []byte
	exitCode int
	signal   int
}

// NewOutputObserver returns an output observer.
func NewOutputObserver(name string) *OutputObserver { return &OutputObserver{name: name} }

// Name implements Observer.
func (o *OutputObserver) Name() string { return o.name }

// Pre implements Observer.
func (o *OutputObserver) Pre() error { o.Reset(); return nil }

// Post implements Observer.
func (o *OutputObserver) Post(ExitKind) error { return nil }

// Reset implements Observer.
func (o *OutputObserver) Reset() {
	o.stdout, o.stderr = o.stdout[:0], o.stderr[:0]
	o.exitCode, o.signal = 0, 0
}

// Record stores the results of an execution.
func (o *OutputObserver) Record(stdout, stderr []byte, exitCode, signal int) {
	o.stdout = append(o.stdout[:0], stdout...)
	o.stderr = append(o.stderr[:0], stderr...)
	o.exitCode, o.signal = exitCode, signal
}

// Stdout, Stderr, ExitCode and Signal expose what was recorded.
func (o *OutputObserver) Stdout() []byte { return o.stdout }
func (o *OutputObserver) Stderr() []byte { return o.stderr }
func (o *OutputObserver) ExitCode() int  { return o.exitCode }
func (o *OutputObserver) Signal() int    { return o.signal }

// Combined returns stdout and stderr together, which is where sanitizer reports
// and language runtime traces end up.
func (o *OutputObserver) Combined() string {
	if len(o.stdout) == 0 {
		return string(o.stderr)
	}
	if len(o.stderr) == 0 {
		return string(o.stdout)
	}
	return string(o.stdout) + string(o.stderr)
}

// hashSeed is fixed rather than random so that a campaign's novelty decisions
// are reproducible across processes (ASR-0008). Go's default maphash seed is
// randomised per process, which would make two identical runs disagree.
var hashSeed = maphash.MakeSeed()

// NoveltyFeedback admits inputs that produce an output or exit status never seen
// before. It is the black-box substitute for coverage.
//
// It is coarse by nature: a target whose output embeds a timestamp or a pointer
// looks novel on every execution and fills the corpus with noise. Campaigns
// against such targets need a normaliser, which is what Normalise is for.
type NoveltyFeedback struct {
	name string
	obs  *OutputObserver
	seen map[uint64]struct{}

	// Normalise strips volatile content — timestamps, addresses, process ids —
	// before hashing. Without it, novelty against a chatty target is noise.
	Normalise func([]byte) []byte

	pending uint64
	hasNew  bool
}

// NewNoveltyFeedback returns an output-novelty feedback.
func NewNoveltyFeedback(name string, obs *OutputObserver) *NoveltyFeedback {
	return &NoveltyFeedback{name: name, obs: obs, seen: map[uint64]struct{}{}}
}

// Name implements Feedback.
func (f *NoveltyFeedback) Name() string { return f.name }

// Distinct returns how many distinct outputs have been recorded.
func (f *NoveltyFeedback) Distinct() int { return len(f.seen) }

// IsInteresting implements Feedback.
func (f *NoveltyFeedback) IsInteresting(_ []Observer, ek ExitKind) (bool, Score, error) {
	var h maphash.Hash
	h.SetSeed(hashSeed)
	body := f.obs.stderr
	if f.Normalise != nil {
		body = f.Normalise(body)
	}
	h.Write(body)
	out := f.obs.stdout
	if f.Normalise != nil {
		out = f.Normalise(out)
	}
	h.Write(out)
	h.WriteByte(byte(ek))
	h.WriteByte(byte(f.obs.exitCode))
	sum := h.Sum64()

	f.pending = sum
	_, known := f.seen[sum]
	f.hasNew = !known
	if known {
		return false, Score{}, nil
	}
	return true, Score{NewSignal: 1, Novelty: 1}, nil
}

// Append implements Feedback.
func (f *NoveltyFeedback) Append() {
	if f.hasNew {
		f.seen[f.pending] = struct{}{}
		f.hasNew = false
	}
}

// Discard implements Feedback.
func (f *NoveltyFeedback) Discard() { f.hasNew = false }

// TimingObserver measures how long an execution took.
type TimingObserver struct {
	name    string
	start   time.Time
	elapsed time.Duration
}

// NewTimingObserver returns a timing observer.
func NewTimingObserver(name string) *TimingObserver { return &TimingObserver{name: name} }

// Name implements Observer.
func (o *TimingObserver) Name() string { return o.name }

// Pre implements Observer.
func (o *TimingObserver) Pre() error { o.start = time.Now(); return nil }

// Post implements Observer.
func (o *TimingObserver) Post(ExitKind) error {
	o.elapsed = time.Since(o.start)
	return nil
}

// Reset implements Observer.
func (o *TimingObserver) Reset() { o.elapsed = 0 }

// Elapsed returns the most recent execution time.
func (o *TimingObserver) Elapsed() time.Duration { return o.elapsed }

// Record sets the elapsed time directly, for executors that measure it
// themselves.
func (o *TimingObserver) Record(d time.Duration) { o.elapsed = d }

// SlowFeedback admits inputs that take unusually long, which is how algorithmic
// complexity bugs are found.
//
// Enabling it forfeits determinism: execution time depends on machine load, so
// two runs of the same campaign will not admit the same inputs. That is a real
// cost against ASR-0008 and the reason it is opt-in rather than part of the
// default stack. A campaign using it should say so in its findings.
type SlowFeedback struct {
	name string
	obs  *TimingObserver

	// Factor is how many times the running mean an execution must exceed.
	Factor float64

	// MinSamples is how many executions to observe before judging anything, so
	// the first slow input is not compared against an empty baseline.
	MinSamples int

	mean    float64
	samples int
	pending time.Duration
	fired   bool
}

// NewSlowFeedback returns a timing outlier feedback.
func NewSlowFeedback(name string, obs *TimingObserver) *SlowFeedback {
	return &SlowFeedback{name: name, obs: obs, Factor: 4, MinSamples: 100}
}

// Name implements Feedback.
func (f *SlowFeedback) Name() string { return f.name }

// Mean returns the running average execution time.
func (f *SlowFeedback) Mean() time.Duration { return time.Duration(f.mean) }

// IsInteresting implements Feedback.
func (f *SlowFeedback) IsInteresting(_ []Observer, _ ExitKind) (bool, Score, error) {
	d := f.obs.elapsed
	f.pending = d
	f.fired = false
	if f.samples < f.MinSamples {
		return false, Score{}, nil
	}
	if f.mean <= 0 || float64(d) < f.mean*f.Factor {
		return false, Score{}, nil
	}
	f.fired = true
	return true, Score{NewSignal: 1, Custom: float64(d) / f.mean}, nil
}

// Append implements Feedback. The mean is updated whether or not the input was
// kept, so the baseline tracks the target rather than only its outliers.
func (f *SlowFeedback) Append() { f.observe() }

// Discard implements Feedback.
func (f *SlowFeedback) Discard() { f.observe() }

func (f *SlowFeedback) observe() {
	f.samples++
	f.mean += (float64(f.pending) - f.mean) / float64(f.samples)
	f.fired = false
}

// --- objectives -------------------------------------------------------------

// CrashObjective records executions that ended in a fatal signal.
type CrashObjective struct {
	name string
	obs  *OutputObserver // optional; supplies the signal number and output
}

// NewCrashObjective returns a crash objective. obs may be nil.
func NewCrashObjective(name string, obs *OutputObserver) *CrashObjective {
	return &CrashObjective{name: name, obs: obs}
}

// Name implements Objective.
func (o *CrashObjective) Name() string { return o.name }

// IsFinding implements Objective.
func (o *CrashObjective) IsFinding(_ []Observer, ek ExitKind) (bool, Finding, error) {
	if ek != ExitCrash {
		return false, Finding{}, nil
	}
	f := Finding{Kind: "crash", Summary: "target terminated abnormally"}
	if o.obs != nil {
		f.Signal = o.obs.signal
		f.Detail = o.obs.Combined()
		if name, ok := signalNames[o.obs.signal]; ok {
			f.Summary = "fatal signal " + name
		} else if o.obs.signal != 0 {
			f.Summary = fmt.Sprintf("fatal signal %d", o.obs.signal)
		}
	}
	return true, f, nil
}

var signalNames = map[int]string{
	4: "SIGILL", 6: "SIGABRT", 7: "SIGBUS", 8: "SIGFPE", 11: "SIGSEGV", 31: "SIGSYS",
}

// HangObjective records executions that exceeded their time budget.
type HangObjective struct{ name string }

// NewHangObjective returns a hang objective.
func NewHangObjective(name string) *HangObjective { return &HangObjective{name: name} }

// Name implements Objective.
func (o *HangObjective) Name() string { return o.name }

// IsFinding implements Objective.
func (o *HangObjective) IsFinding(_ []Observer, ek ExitKind) (bool, Finding, error) {
	if ek != ExitTimeout {
		return false, Finding{}, nil
	}
	return true, Finding{Kind: "hang", Summary: "target exceeded its time budget"}, nil
}

// OOMObjective records executions that exceeded their memory budget.
type OOMObjective struct{ name string }

// NewOOMObjective returns an out-of-memory objective.
func NewOOMObjective(name string) *OOMObjective { return &OOMObjective{name: name} }

// Name implements Objective.
func (o *OOMObjective) Name() string { return o.name }

// IsFinding implements Objective.
func (o *OOMObjective) IsFinding(_ []Observer, ek ExitKind) (bool, Finding, error) {
	if ek != ExitOOM {
		return false, Finding{}, nil
	}
	return true, Finding{Kind: "oom", Summary: "target exceeded its memory budget"}, nil
}

var (
	sanitizerLine  = regexp.MustCompile(`(?m)^.*?(?:ERROR|WARNING|runtime error): ((?:Address|Leak|Memory|Thread|UndefinedBehavior)Sanitizer:? *)?(.*)$`)
	sanitizerFrame = regexp.MustCompile(`(?m)^\s*#(\d+) 0x[0-9a-f]+ in ([^\s]+)(?: ([^\s]+))?`)
)

// SanitizerObjective recognises a sanitizer diagnostic in a target's output.
//
// It fires on a clean exit as well as a crash: LeakSanitizer and UBSan report
// without aborting, so requiring a fatal signal would miss whole classes of bug.
type SanitizerObjective struct {
	name string
	obs  *OutputObserver
}

// NewSanitizerObjective returns a sanitizer objective.
func NewSanitizerObjective(name string, obs *OutputObserver) *SanitizerObjective {
	return &SanitizerObjective{name: name, obs: obs}
}

// Name implements Objective.
func (o *SanitizerObjective) Name() string { return o.name }

// IsFinding implements Objective.
func (o *SanitizerObjective) IsFinding(_ []Observer, ek ExitKind) (bool, Finding, error) {
	if ek == ExitError {
		return false, Finding{}, nil
	}
	out := o.obs.Combined()
	if !strings.Contains(out, "Sanitizer") && !strings.Contains(out, "runtime error:") {
		return false, Finding{}, nil
	}
	return true, ParseSanitizer(out), nil
}

// ParseSanitizer extracts a finding from sanitizer output.
//
// The frames matter more than the message: bucketing distinct bugs apart
// depends on them, and a report reduced to its first line merges every overflow
// in a program into one finding (ASR-0011).
func ParseSanitizer(out string) Finding {
	f := Finding{Kind: "sanitizer", Detail: out}

	if m := sanitizerLine.FindStringSubmatch(out); m != nil {
		f.Summary = strings.TrimSpace(m[2])
		// Trim the space before the colon: the captured group ends "Sanitizer: ".
		if tool := strings.TrimSuffix(strings.TrimSpace(m[1]), ":"); tool != "" {
			f.Kind = strings.ToLower(strings.TrimSuffix(tool, "Sanitizer"))
			if f.Kind == "" {
				f.Kind = "sanitizer"
			}
		}
	}
	if f.Summary == "" {
		f.Summary = "sanitizer report"
	}

	for _, m := range sanitizerFrame.FindAllStringSubmatch(out, -1) {
		depth, _ := strconv.Atoi(m[1])
		frame := m[2]
		if m[3] != "" {
			frame += " " + m[3]
		}
		if depth == len(f.Frames) {
			f.Frames = append(f.Frames, frame)
		}
	}
	return f
}

// OracleObjective adapts an arbitrary predicate, which is how a campaign
// expresses a bug that is not a crash: a wrong answer, a violated invariant, an
// authorization check that passed when it should not have.
type OracleObjective struct {
	name string
	kind string
	fn   func(obs []Observer, ek ExitKind) (bool, string)
}

// NewOracleObjective wraps a predicate as an objective.
func NewOracleObjective(name, kind string, fn func([]Observer, ExitKind) (bool, string)) *OracleObjective {
	return &OracleObjective{name: name, kind: kind, fn: fn}
}

// Name implements Objective.
func (o *OracleObjective) Name() string { return o.name }

// IsFinding implements Objective.
func (o *OracleObjective) IsFinding(obs []Observer, ek ExitKind) (bool, Finding, error) {
	hit, summary := o.fn(obs, ek)
	if !hit {
		return false, Finding{}, nil
	}
	return true, Finding{Kind: o.kind, Summary: summary}, nil
}

// AnyObjective fires when any of its children does, so a campaign declares one
// list of the bugs it is looking for.
type AnyObjective struct {
	name string
	objs []Objective
}

// NewAnyObjective combines objectives.
func NewAnyObjective(name string, objs ...Objective) *AnyObjective {
	return &AnyObjective{name: name, objs: objs}
}

// Name implements Objective.
func (o *AnyObjective) Name() string { return o.name }

// IsFinding implements Objective. Children are consulted in order, so list the
// more specific ones first: a sanitizer report says far more than "it crashed".
func (o *AnyObjective) IsFinding(obs []Observer, ek ExitKind) (bool, Finding, error) {
	for _, child := range o.objs {
		hit, f, err := child.IsFinding(obs, ek)
		if err != nil {
			return false, Finding{}, err
		}
		if hit {
			return true, f, nil
		}
	}
	return false, Finding{}, nil
}
