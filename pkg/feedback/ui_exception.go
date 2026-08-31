package feedback

import (
	"strings"
)

// UIExceptionObjective reports what an interface's own runtime said went wrong.
//
// It is the web counterpart of the diagnostic oracle, and it exists as a
// separate objective because the evidence arrives by a different route. A
// terminal program's stack trace lands on the screen, so a pattern over the
// screen finds it. A web application's does not: an uncaught exception is
// reported to the debugging protocol and nowhere else, the page carries on
// looking exactly as it did, the process does not exit, and every status code
// involved is 200.
//
// So the backend collects those reports and puts them where an execution's
// standard error goes, and this objective says that anything there is a
// finding. No patterns: unlike a screen, which contains whatever the target
// chose to draw, this channel carries only what the runtime itself reported as
// unhandled. A pattern list would be a way of ignoring some of them.
type UIExceptionObjective struct {
	name string
	obs  *OutputObserver

	// reported dedupes by the first line, so a page that throws on every
	// animation frame files one finding rather than one per sequence.
	reported map[string]bool
}

// NewUIExceptionObjective returns an objective over an interface's reported
// exceptions.
func NewUIExceptionObjective(name string, obs *OutputObserver) *UIExceptionObjective {
	return &UIExceptionObjective{name: name, obs: obs, reported: map[string]bool{}}
}

// Name implements Objective.
func (o *UIExceptionObjective) Name() string { return o.name }

// IsFinding implements Objective.
func (o *UIExceptionObjective) IsFinding(_ []Observer, _ ExitKind) (bool, Finding, error) {
	if o.obs == nil {
		return false, Finding{}, nil
	}
	// The stderr half, which for a driver is what the backend collected rather
	// than anything the process wrote: the T7 tier records the interface state
	// as stdout.
	text := strings.TrimSpace(string(o.obs.Stderr()))
	if text == "" {
		return false, Finding{}, nil
	}
	first := text
	if i := strings.IndexByte(first, '\n'); i >= 0 {
		first = first[:i]
	}
	if o.reported[first] {
		return false, Finding{}, nil
	}
	o.reported[first] = true

	return true, Finding{
		// Named like the other interface oracles, because the kind is what a
		// finding is filed and counted under: "oracle" would have put this in
		// with everything else that judges by policy rather than by a crash.
		Kind:    "ui-exception",
		Summary: "the interface reported an unhandled error: " + trimLine(first),
		Detail:  text,
		// The reported line, as the frame a bucket is keyed on. Two sequences
		// that reach the same exception in the same place are the same bug, and
		// two that reach different ones are not (ASR-0011).
		Frames: []string{first},
	}, nil
}

// trimLine keeps a summary to one readable line.
func trimLine(s string) string {
	const max = 160
	s = strings.TrimSpace(s)
	if len(s) > max {
		return s[:max] + "…"
	}
	return s
}
