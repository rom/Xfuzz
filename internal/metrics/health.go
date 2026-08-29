package metrics

import (
	"fmt"
	"sort"
	"time"
)

// Severity ranks a diagnostic.
type Severity int

// Severities, least serious first.
const (
	// SeverityInfo is worth knowing and not worth acting on.
	SeverityInfo Severity = iota

	// SeverityWarn is a campaign that is working less well than it could.
	SeverityWarn

	// SeverityBroken is a campaign that is not fuzzing at all. It looks busy
	// from the outside, which is the whole reason these exist.
	SeverityBroken
)

var severityNames = [...]string{SeverityInfo: "info", SeverityWarn: "warn", SeverityBroken: "broken"}

func (s Severity) String() string {
	if int(s) < len(severityNames) && severityNames[s] != "" {
		return severityNames[s]
	}
	return fmt.Sprintf("Severity(%d)", int(s))
}

// Diagnostic is a named health finding about a campaign.
//
// Named, because "your campaign is unhealthy" is not actionable and "0% of
// executions reach the harness — the target is failing before it reads input" is.
// The defining failure of a fuzzing tool is looking busy while finding nothing,
// and the only defence is a set of checks that say, in words, which of the
// specific ways that happens is happening.
type Diagnostic struct {
	// Name identifies the check, stable across versions so it can be silenced
	// or alerted on.
	Name string `json:"name"`

	Severity Severity `json:"severity"`

	// Summary is one sentence stating what is wrong, with the number in it.
	Summary string `json:"summary"`

	// Remedy is what to do about it. A diagnostic with no remedy is a
	// complaint.
	Remedy string `json:"remedy"`
}

func (d Diagnostic) String() string {
	s := fmt.Sprintf("[%s] %s: %s", d.Severity, d.Name, d.Summary)
	if d.Remedy != "" {
		s += " — " + d.Remedy
	}
	return s
}

// Thresholds are the boundaries the checks use.
//
// Exposed and named rather than buried as literals, because they are judgements
// about what "unhealthy" means and a campaign against an unusual target may
// legitimately disagree.
type Thresholds struct {
	// MinStability is the share of executions that must be deterministic.
	// Below this a coverage-guided campaign is chasing noise rather than paths.
	MinStability float64

	// MaxOverhead is the share of wall-clock time the fuzzer may spend on its
	// own bookkeeping (ASR-0007).
	MaxOverhead float64

	// MaxHarnessErrorRate is the share of executions that may fail as harness
	// errors rather than target behaviour.
	MaxHarnessErrorRate float64

	// MaxMapDensity is how full the coverage map may get before distinct edges
	// start colliding.
	MaxMapDensity float64

	// CoverageStall is how long without new coverage counts as stalled.
	CoverageStall time.Duration

	// MinExecsPerSecond is a rate below which something is wrong with the
	// executor rather than with the target.
	MinExecsPerSecond float64

	// Grace is how long a campaign is left alone before it is judged. Every
	// check is meaningless in the first seconds of a run.
	Grace time.Duration

	// StartupGrace is how long a campaign that has executed nothing is given
	// the benefit of the doubt about its own startup rather than its target.
	// Longer than Grace, because a campaign is judged well before it takes
	// this long to build a corpus and get a sandboxed target listening.
	StartupGrace time.Duration
}

// DefaultThresholds are the boundaries used when a campaign does not set its own.
func DefaultThresholds() Thresholds {
	return Thresholds{
		MinStability:        0.90,
		MaxOverhead:         0.10,
		MaxHarnessErrorRate: 0.01,
		MaxMapDensity:       0.50,
		CoverageStall:       30 * time.Minute,
		MinExecsPerSecond:   10,
		Grace:               30 * time.Second,
		StartupGrace:        90 * time.Second,
	}
}

// Health runs every diagnostic against a snapshot.
//
// elapsed is how long the campaign has been running, which several checks need:
// a campaign three seconds old has no coverage and no rate, and reporting that
// as broken would teach people to ignore the diagnostics — which would cost more
// than the checks are worth. phase is the same argument at the other end of a
// campaign's life.
// Phase is whether the campaign is still fuzzing.
//
// It changes what an observation means rather than what it is. Every worker
// silent is a broken campaign while one is meant to be running and is simply
// what a finished campaign looks like, and a diagnostic that cannot tell the
// two apart teaches people to ignore the whole panel.
type Phase int

const (
	// PhaseRunning is a campaign that is meant to be fuzzing right now.
	PhaseRunning Phase = iota

	// PhaseStopped is a campaign that has finished, been stopped, or is
	// paused. Its diagnostics are a post-mortem: what the run was like, not
	// what is wrong with it now.
	PhaseStopped
)

func Health(s Snapshot, elapsed time.Duration, t Thresholds, phase Phase) []Diagnostic {
	var out []Diagnostic
	add := func(name string, sev Severity, summary, remedy string) {
		out = append(out, Diagnostic{Name: name, Severity: sev, Summary: summary, Remedy: remedy})
	}

	if elapsed < t.Grace {
		return nil
	}

	// The three ways a campaign is not fuzzing at all. Each looks identical
	// from the outside — a busy process and a rising execution count — and each
	// has a different cause.
	if s.Execs == 0 {
		// Two causes, and blaming the wrong one sends the reader to the wrong
		// place. A campaign that has been up for a while and executed nothing
		// has a target that will not start. A campaign whose whole life was
		// shorter than a campaign's startup — building the corpus, spawning a
		// sandboxed target, waiting for a server to listen — never got as far
		// as trying. Measured on a loaded host: a forty-five-second stateful
		// campaign reached its time budget having executed nothing, and was
		// told its target was broken when it was not.
		remedy := "the target is failing to start; check the isolation report and the target's own output"
		if elapsed < t.StartupGrace {
			remedy = "the campaign's budget may be shorter than its own startup; " +
				"give it longer, or check the isolation report if it still executes nothing"
		}
		add("no-executions", SeverityBroken, "no executions have completed", remedy)
		return out
	}
	if s.Coverage == 0 {
		add("no-coverage", SeverityBroken,
			"the coverage map is empty after "+s.execsPhrase(),
			"the target is not instrumented, or was built against a different runtime; "+
				"rebuild it with xfuzz-cc, or set feedback.coverage to blackbox")
	}
	if rate := s.harnessErrorRate(); rate > 0.5 {
		add("harness-failing", SeverityBroken,
			fmt.Sprintf("%.0f%% of executions fail before the target sees the input", 100*rate),
			"the delivery mode is probably wrong; check target.input and target.args")
	} else if rate > t.MaxHarnessErrorRate {
		add("harness-errors", SeverityWarn,
			fmt.Sprintf("%.1f%% of executions fail as harness errors", 100*rate),
			"these are not findings and not the target's fault; check the executor tier")
	}

	if s.CorpusSize == 0 && s.Execs > 1000 {
		add("empty-corpus", SeverityBroken,
			"nothing has been admitted to the corpus after "+s.execsPhrase(),
			"every input is being rejected as uninteresting; check that the feedback stack "+
				"matches the instrumentation")
	}

	// The ways a campaign is fuzzing badly.
	if s.Stability > 0 && s.Stability < t.MinStability {
		add("unstable", SeverityWarn,
			fmt.Sprintf("stability is %.0f%%", 100*s.Stability),
			"the target is non-deterministic — a clock, a random seed, an address, a thread — "+
				"so coverage guidance is chasing noise rather than paths")
	}
	if s.Overhead > t.MaxOverhead {
		add("overhead", SeverityWarn,
			fmt.Sprintf("%.0f%% of wall-clock time is spent outside the target", 100*s.Overhead),
			"the executor tier is probably too slow for this target; a fork server is "+
				"several times faster than a subprocess")
	}
	if s.MapDensity > t.MaxMapDensity {
		add("map-saturated", SeverityWarn,
			fmt.Sprintf("the coverage map is %.0f%% full", 100*s.MapDensity),
			"distinct edges are colliding and the campaign is losing the ability to tell "+
				"paths apart; raise feedback.map_size and rebuild")
	}
	if s.ExecsPerS > 0 && s.ExecsPerS < t.MinExecsPerSecond {
		add("slow", SeverityWarn,
			fmt.Sprintf("%.1f executions per second", s.ExecsPerS),
			"check the per-execution timeout and whether the target is doing setup work "+
				"that a fork server would do once")
	}
	if !s.LastNewCoverage.IsZero() && t.CoverageStall > 0 {
		if stalled := s.At.Sub(s.LastNewCoverage); stalled > t.CoverageStall {
			add("coverage-stalled", SeverityInfo,
				fmt.Sprintf("no new coverage for %s", stalled.Round(time.Minute)),
				"the campaign has stopped learning; more seeds, a grammar, or a dictionary "+
					"is usually what moves it")
		}
	}
	if s.TriageDropped > 0 {
		add("triage-backlog", SeverityInfo,
			fmt.Sprintf("%d findings were dropped from the triage queue", s.TriageDropped),
			"findings are arriving faster than they can be verified; they are almost "+
				"certainly duplicates, but the count is reported rather than hidden")
	}
	if phase == PhaseRunning && s.Workers > 0 && s.WorkersHealthy < s.Workers {
		add("workers-down", SeverityWarn,
			fmt.Sprintf("%d of %d workers are not reporting", s.Workers-s.WorkersHealthy, s.Workers),
			"a worker that keeps dying usually means the target crashes on startup "+
				"under the sandbox rather than on an input")
	}

	sort.SliceStable(out, func(i, j int) bool { return out[i].Severity > out[j].Severity })
	return out
}

// Worst returns the most serious severity present.
func Worst(ds []Diagnostic) Severity {
	worst := SeverityInfo
	for _, d := range ds {
		if d.Severity > worst {
			worst = d.Severity
		}
	}
	return worst
}

func (s Snapshot) harnessErrorRate() float64 {
	if s.Execs == 0 {
		return 0
	}
	return float64(s.HarnessError) / float64(s.Execs)
}

func (s Snapshot) execsPhrase() string {
	switch {
	case s.Execs == 1:
		return "1 execution"
	case s.Execs < 1000:
		return fmt.Sprintf("%d executions", s.Execs)
	case s.Execs < 1_000_000:
		return fmt.Sprintf("%.0fk executions", float64(s.Execs)/1000)
	default:
		return fmt.Sprintf("%.1fM executions", float64(s.Execs)/1_000_000)
	}
}
