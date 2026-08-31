package feedback

import (
	"fmt"
	"regexp"
	"strings"
)

// Oracles for a user interface, which fails differently again.
//
// A parser tells you it is broken by crashing and a service by answering 500. An
// interface does neither. It puts a stack trace in a dialog and carries on; it
// stops repainting and leaves the last screen there, which looks exactly like a
// screen; it reaches a modal nothing dismisses and waits for a person who is not
// coming. None of the three is a signal, all three are bugs, and ADR-0013 names
// them as the reason GUI fuzzing needs oracles beyond crash detection.
//
// The two that need history read it through StateTrace rather than through a
// state model, because pkg/state imports this package and cannot be imported
// back. The labels are enough: what these oracles ask is whether the interface
// changed, and whether it ever came back.

// StateTrace is anything that can say which states an execution passed through.
//
// Structural, and satisfied by state.Observer, which grew the method for the
// out-of-process plugin boundary (ADR-0010) and provides it here for free.
type StateTrace interface {
	StateLabels() []string
}

// UIDiagnosticObjective reports a diagnostic that reached the screen.
//
// This is the "unhandled exception dialog" of ADR-0013, in the form a terminal
// program takes: a program whose standard error *is* the terminal puts its
// stack trace where its interface was. It is the highest-value oracle the tier
// has, because a language runtime that catches an error at the top of the event
// loop and prints it keeps running — the process does not die, no signal is
// raised, and crash detection sees a completely ordinary execution.
//
// The patterns are the cost of that. A text editor displaying a file that
// contains the word "panic:" matches, which is why Patterns is a field rather
// than a constant and why the summary quotes what matched.
type UIDiagnosticObjective struct {
	name string
	obs  *OutputObserver

	// Patterns are what counts as a diagnostic. Replacing them replaces the
	// defaults entirely, which is what a campaign against a program that draws
	// stack traces on purpose needs.
	Patterns []*regexp.Regexp

	// reported dedupes, so a program left showing its stack trace does not file
	// the same finding on every sequence that ends there.
	reported map[string]bool
}

// DefaultUIDiagnostics are the shapes a runtime's unhandled error takes on
// screen. Between them they cover Go, Python, Java, Rust, C++, C and the
// sanitizers, which is most of what has a terminal interface.
func DefaultUIDiagnostics() []*regexp.Regexp {
	return []*regexp.Regexp{
		regexp.MustCompile(`panic: `),
		regexp.MustCompile(`goroutine \d+ \[`),
		regexp.MustCompile(`Traceback \(most recent call last\)`),
		regexp.MustCompile(`Exception in thread`),
		regexp.MustCompile(`(?i)unhandled (exception|error)`),
		regexp.MustCompile(`java\.lang\.[A-Za-z]+(Exception|Error)`),
		regexp.MustCompile(`thread '[^']*' panicked at`),
		regexp.MustCompile(`terminate called after throwing`),
		regexp.MustCompile(`(?i)segmentation fault`),
		regexp.MustCompile(`(?i)assertion .{0,80}failed`),
		regexp.MustCompile(`\*\*\* stack smashing detected \*\*\*`),
		regexp.MustCompile(`(AddressSanitizer|UndefinedBehaviorSanitizer|ThreadSanitizer|LeakSanitizer)`),
	}
}

// NewUIDiagnosticObjective returns an objective over the observed screen.
func NewUIDiagnosticObjective(name string, obs *OutputObserver) *UIDiagnosticObjective {
	return &UIDiagnosticObjective{
		name: name, obs: obs,
		Patterns: DefaultUIDiagnostics(),
		reported: map[string]bool{},
	}
}

// Name implements Objective.
func (o *UIDiagnosticObjective) Name() string { return o.name }

// IsFinding implements Objective.
func (o *UIDiagnosticObjective) IsFinding(_ []Observer, _ ExitKind) (bool, Finding, error) {
	if o.obs == nil {
		return false, Finding{}, nil
	}
	// The screen and whatever the program wrote beside it, together.
	//
	// The screen alone was enough for a terminal program, whose standard error
	// *is* its interface — a Python traceback lands where the interface was.
	// It is not enough for anything else: a desktop application's toolkit
	// catches the exception and prints it to a standard error nobody is
	// looking at, and the widget tree afterwards says nothing went wrong. Both
	// halves, so the oracle finds the diagnostic wherever the platform put it.
	screen := o.obs.Combined()
	for _, re := range o.Patterns {
		loc := re.FindStringIndex(screen)
		if loc == nil {
			continue
		}
		line := lineAround(screen, loc[0])
		if o.reported[line] {
			return false, Finding{}, nil
		}
		o.reported[line] = true
		return true, Finding{
			Kind:    "ui-diagnostic",
			Summary: "the interface is showing a diagnostic: " + trim(line, 120),
			Detail:  screen,
			Frames:  screenFrames(screen),
		}, nil
	}
	return false, Finding{}, nil
}

// UIUnresponsiveObjective reports an interface that stopped changing while
// events kept arriving.
//
// The failure this catches has no other symptom. The process is alive, nothing
// crashed, the last screen is still on the terminal and looks exactly like a
// screen — and every keystroke since has gone nowhere. A campaign without this
// oracle records those executions as ordinary ones and keeps typing at a program
// that stopped listening.
//
// It needs the earlier part of the sequence to have worked, which is what
// separates a program that hung from a program that simply ignores keys it does
// not bind. A screen that never changed at all is not evidence of anything.
type UIUnresponsiveObjective struct {
	name  string
	trace StateTrace

	// Streak is how many consecutive events must leave the interface unchanged.
	// Eight, by default: a TUI legitimately ignores a handful of keys in a row,
	// and no responsive one ignores eight after having answered earlier ones.
	Streak int

	// Exemplar, when set, returns the screen a state label stands for.
	//
	// Without it a report names a hash, which is exactly the "bug filed against
	// state 7" problem the Label type's own documentation warns about: a person
	// reading the finding cannot tell which screen the program was stuck on. The
	// state model keeps one screen per label for this.
	Exemplar func(label string) (string, bool)

	reported map[string]bool
}

// NewUIUnresponsiveObjective returns an objective over an execution's states.
func NewUIUnresponsiveObjective(name string, trace StateTrace) *UIUnresponsiveObjective {
	return &UIUnresponsiveObjective{name: name, trace: trace, Streak: 8, reported: map[string]bool{}}
}

// Name implements Objective.
func (o *UIUnresponsiveObjective) Name() string { return o.name }

// IsFinding implements Objective.
func (o *UIUnresponsiveObjective) IsFinding(_ []Observer, ek ExitKind) (bool, Finding, error) {
	if o.trace == nil || o.Streak < 1 {
		return false, Finding{}, nil
	}
	labels := o.trace.StateLabels()
	if len(labels) < o.Streak+2 {
		return false, Finding{}, nil
	}
	last := labels[len(labels)-1]

	// The tail must be a run of self-loops on the final state.
	streak := 0
	for i := len(labels) - 1; i > 0 && labels[i] == last; i-- {
		streak++
	}
	if streak <= o.Streak {
		return false, Finding{}, nil
	}
	// And something must have changed before it, or the interface was never
	// responsive in the first place and this is a static screen rather than a
	// hang.
	if !changedBefore(labels, len(labels)-streak) {
		return false, Finding{}, nil
	}
	if o.reported[last] {
		return false, Finding{}, nil
	}
	o.reported[last] = true

	summary := fmt.Sprintf("the interface stopped changing at state %s and ignored the "+
		"next %d events", last, streak-1)
	if ek == ExitTimeout {
		summary += ", then the sequence timed out"
	}
	return true, Finding{
		Kind:    "ui-unresponsive",
		Summary: summary,
		Detail:  withExemplar(o.Exemplar, last, labels),
	}, nil
}

func changedBefore(labels []string, upto int) bool {
	for i := 1; i < upto && i < len(labels); i++ {
		if labels[i] != labels[i-1] {
			return true
		}
	}
	return false
}

// UITrapObjective reports a state with no path back.
//
// ADR-0013 calls it an unrecoverable state, and it is the failure mode that
// makes an interface unusable without ever making it crash: a modal nothing
// dismisses, a mode with no exit, a prompt that rejects every answer. A person
// hitting one closes the program and files a bug; a fuzzer hitting one records a
// normal execution and moves on.
//
// The judgement is a comparison across sequences rather than a rule, for the
// same reason the authorization oracle's is. A screen that a sequence happened
// to end on is not a trap — every sequence ends somewhere. A screen the campaign
// has entered several times, spent several events in, and never once left, is.
type UITrapObjective struct {
	name  string
	trace StateTrace

	// MinEntries is how many sequences must have reached a state before it can
	// be called a trap.
	MinEntries int

	// MinTail is how many events must have been delivered after reaching it
	// without getting back. One keystroke proves nothing; several is somebody
	// trying to leave.
	MinTail int

	// Exemplar, when set, returns the screen a state label stands for, so the
	// finding can show the screen nothing dismisses rather than its hash.
	Exemplar func(label string) (string, bool)

	home     string
	entries  map[string]int
	escaped  map[string]bool
	reported map[string]bool
}

// NewUITrapObjective returns an unrecoverable-state objective.
func NewUITrapObjective(name string, trace StateTrace) *UITrapObjective {
	return &UITrapObjective{
		name: name, trace: trace,
		MinEntries: 3, MinTail: 4,
		entries:  map[string]int{},
		escaped:  map[string]bool{},
		reported: map[string]bool{},
	}
}

// Name implements Objective.
func (o *UITrapObjective) Name() string { return o.name }

// Home returns the state every sequence starts from, once one has been seen.
func (o *UITrapObjective) Home() string { return o.home }

// Escaped reports whether any sequence has ever returned home after reaching a
// state. It is the oracle's evidence, exposed so a report can say why.
func (o *UITrapObjective) Escaped(label string) bool { return o.escaped[label] }

// IsFinding implements Objective.
func (o *UITrapObjective) IsFinding(_ []Observer, _ ExitKind) (bool, Finding, error) {
	if o.trace == nil {
		return false, Finding{}, nil
	}
	labels := o.trace.StateLabels()
	// [start, screen after reset, screen after event 1, ...]. Anything shorter
	// than that carries no information.
	if len(labels) < 3 {
		return false, Finding{}, nil
	}
	if o.home == "" {
		// The screen a reset leaves the program showing. Every sequence begins
		// there, which is what makes it the known-good state to measure a way
		// back to.
		o.home = labels[1]
	}

	// One entry per state per sequence, and an escape when the sequence returned
	// home after reaching it.
	firstAt := map[string]int{}
	for i := 1; i < len(labels); i++ {
		if _, seen := firstAt[labels[i]]; !seen {
			firstAt[labels[i]] = i
			o.entries[labels[i]]++
		}
	}
	for label, at := range firstAt {
		for j := at + 1; j < len(labels); j++ {
			if labels[j] == o.home {
				o.escaped[label] = true
				break
			}
		}
	}

	last := labels[len(labels)-1]
	tail := len(labels) - firstAt[last] - 1
	switch {
	case last == o.home || last == "start":
		return false, Finding{}, nil
	case o.escaped[last]:
		return false, Finding{}, nil
	case o.entries[last] < o.MinEntries:
		return false, Finding{}, nil
	case tail < o.MinTail:
		return false, Finding{}, nil
	case o.reported[last]:
		return false, Finding{}, nil
	}
	o.reported[last] = true
	return true, Finding{
		Kind: "ui-trap",
		Summary: fmt.Sprintf("state %s has been reached %d times and never left: "+
			"%d events after reaching it did not get back to %s",
			last, o.entries[last], tail, o.home),
		Detail: withExemplar(o.Exemplar, last, labels),
	}, nil
}

// withExemplar renders a finding's detail: the path the sequence took, and the
// screen it ended on when the campaign can supply one.
func withExemplar(lookup func(string) (string, bool), label string, labels []string) string {
	path := strings.Join(labels, " -> ")
	if lookup == nil {
		return path
	}
	screen, ok := lookup(label)
	if !ok || screen == "" {
		return path
	}
	return path + "\n\n" + label + ":\n" + screen
}

// lineAround returns the whole line containing an offset.
func lineAround(s string, at int) string {
	if at < 0 || at > len(s) {
		return ""
	}
	start := strings.LastIndexByte(s[:at], '\n') + 1
	end := strings.IndexByte(s[at:], '\n')
	if end < 0 {
		return strings.TrimSpace(s[start:])
	}
	return strings.TrimSpace(s[start : at+end])
}

// screenFrames pulls out lines that look like stack frames, so a screen-borne
// crash buckets the way a real one does.
//
// Best effort by design. Triage buckets on whatever frames it is given and on
// the summary when it is given none, so a diagnostic this cannot parse is still
// a finding with a stable identity — it just shares a bucket with others whose
// first line matches.
func screenFrames(screen string) []string {
	var out []string
	for _, line := range strings.Split(screen, "\n") {
		t := strings.TrimSpace(line)
		switch {
		case t == "":
		case strings.HasPrefix(t, "at "), // Java
			strings.HasPrefix(t, "File \""), // Python
			strings.Contains(t, ".go:"),     // Go
			strings.Contains(t, " in "),     // Rust and the sanitizers
			strings.HasPrefix(t, "#"):       // gdb and glibc
			out = append(out, trim(t, 200))
		}
		if len(out) >= 16 {
			break
		}
	}
	return out
}

func trim(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
