package plugin

import (
	"time"

	"github.com/rom/Xfuzz/pkg/feedback"
)

// The shapes an observer may expose. A plugin sees an execution through these
// and nothing else.
//
// Small local interfaces rather than a switch over the concrete observer types,
// for two reasons. Importing every package that defines an observer would drag
// the state machine, the codecs and eventually the executors into a package
// whose whole job is a pipe. And an observer written next year, in a package
// that does not exist yet, becomes visible to plugins by implementing a method
// rather than by an edit here.
type (
	outputSource interface {
		Stdout() []byte
		Stderr() []byte
		ExitCode() int
		Signal() int
	}
	coverageSource interface {
		Covered() int
		Signature() uint64
		Backend() string
	}
	timingSource interface {
		Elapsed() time.Duration
	}
	stateSource interface {
		StateLabels() []string
	}
	inputSource interface {
		Input() []byte
	}
)

// Observe renders one execution as an Observation.
//
// The input is included only when the campaign wired an observer that holds it.
// Copying every input across the boundary is the single largest cost on this
// path and most extensions judge what an execution did rather than what it was,
// so it is opted into rather than paid for by default.
func Observe(obs []feedback.Observer, ek feedback.ExitKind) Observation {
	o := Observation{Exit: ek.String()}
	for _, ob := range obs {
		if s, ok := ob.(outputSource); ok {
			o.Stdout, o.Stderr = s.Stdout(), s.Stderr()
			o.ExitCode, o.Signal = s.ExitCode(), s.Signal()
		}
		if s, ok := ob.(coverageSource); ok {
			o.Edges, o.Signature, o.Backend = s.Covered(), s.Signature(), s.Backend()
		}
		if s, ok := ob.(timingSource); ok {
			o.DurationNS = int64(s.Elapsed())
		}
		if s, ok := ob.(stateSource); ok {
			o.States = s.StateLabels()
		}
		if s, ok := ob.(inputSource); ok {
			o.Input = s.Input()
		}
	}
	return o
}

// score converts a verdict into the score the scheduler consumes.
func (v Verdict) score() feedback.Score {
	return feedback.Score{
		NewSignal: v.NewSignal,
		Novelty:   clamp01(v.Novelty),
		Distance:  v.Distance,
		Custom:    v.Custom,
	}
}

// clamp01 bounds a plugin's novelty to the range the rest of the engine assumes.
//
// Feedback.Score documents Novelty as 0..1 and the scheduler weighs it against
// other feedbacks on that assumption. A plugin returning 400 would not be
// unusually interesting, it would silently dominate every schedule; clamping
// keeps a plugin's mistake inside the plugin.
func clamp01(f float64) float64 {
	switch {
	case f != f: // NaN, which would poison every comparison it reached
		return 0
	case f < 0:
		return 0
	case f > 1:
		return 1
	}
	return f
}

// finding converts a wire finding into the engine's.
func (f *Finding) finding() feedback.Finding {
	if f == nil {
		return feedback.Finding{}
	}
	return feedback.Finding{
		Kind:    f.Kind,
		Signal:  f.Signal,
		Summary: f.Summary,
		Detail:  f.Detail,
		Frames:  f.Frames,
	}
}
