package state

import "strings"

// A screen is a state, and a terminal program is a state machine whose states
// are screens. That is not an analogy: ADR-0013 says the UI state graph is the
// same object as the protocol state machine, and this file is what makes it
// literally true — the same Model, the same Trace, the same Feedback, the same
// scheduler, with a state function that reads a screen instead of a reply.
//
// What is genuinely different is the normalisation. A protocol reply varies in
// its session ids and its counters; a screen varies in its clock, its spinner,
// its progress bar and its scroll position, and a fingerprint that did not
// account for those would give every second of a running program a new state.
// Too aggressive and distinct screens merge; too weak and every clock tick is a
// new state — which is why the pipeline is named steps a campaign can change and
// why the model keeps an exemplar screen per label.

// ScreenNormalisers is the pipeline for a user interface.
//
// Digits first, which covers the clock, the counters, the byte totals and the
// percentages in one step. Then the two things a screen has that a protocol
// reply does not: an animation frame, and a run of repeated characters that is
// usually a progress bar. Whitespace last, because the earlier steps leave gaps
// behind them.
func ScreenNormalisers() []Normaliser {
	return []Normaliser{CollapseDigits{}, CollapseSpinner{}, CollapseRuns{}, CollapseSpace{}}
}

// ScreenFn labels a screen by its normalised shape.
//
// A fingerprint rather than a status token, because a screen has no status
// field: what says which state a program is in is the whole of what it drew.
type ScreenFn struct{ FingerprintFn }

// NewScreenFn returns the state function for a user interface.
func NewScreenFn() *ScreenFn {
	return &ScreenFn{FingerprintFn{Normalisers: ScreenNormalisers()}}
}

// Name implements StateFn.
func (f *ScreenFn) Name() string { return "screen" }

// spinnerRunes are the animation frames a program cycles through while it is
// working.
//
// Only the ones that are unambiguously decorative. The ASCII spinner — | / - \
// — is handled separately and much more narrowly, because those four characters
// are also box drawing, path separators and dashes, and replacing every one of
// them would erase most of what a TUI puts on screen.
const spinnerRunes = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏⣾⣽⣻⢿⡿⣟⣯⣷◐◓◑◒◴◷◶◵◜◝◞◟▖▘▝▗"

// CollapseSpinner replaces an animation frame with a fixed marker.
//
// A spinner is the purest form of the problem this normalisation exists for: it
// changes ten times a second, it means nothing about which screen the program is
// showing, and without this every frame of it is a state of its own.
type CollapseSpinner struct{}

func (CollapseSpinner) Name() string { return "spinner" }

// Normalise implements Normaliser.
func (CollapseSpinner) Normalise(b []byte) []byte {
	s := string(b)
	if !strings.ContainsAny(s, spinnerRunes) && !strings.ContainsAny(s, `|/-\`) {
		return b
	}
	var out strings.Builder
	out.Grow(len(b))
	runes := []rune(s)
	for i, r := range runes {
		if strings.ContainsRune(spinnerRunes, r) {
			out.WriteByte('@')
			continue
		}
		// An ASCII spinner is one of four characters standing alone between
		// spaces. Anything else made of those characters is a border, a path or
		// a dash, and collapsing it would erase most of what a program draws.
		if strings.ContainsRune(`|/-\`, r) && isolated(runes, i) {
			out.WriteByte('@')
			continue
		}
		out.WriteRune(r)
	}
	return []byte(out.String())
}

// isolated reports whether the rune at i has a space or an edge on both sides.
func isolated(runes []rune, i int) bool {
	before := i == 0 || runes[i-1] == ' ' || runes[i-1] == '\n'
	after := i == len(runes)-1 || runes[i+1] == ' ' || runes[i+1] == '\n'
	return before && after
}

// CollapseRuns replaces a run of three or more filler characters with one
// marker.
//
// This is the progress bar, and it is worth a step of its own because a bar is
// the second most common thing on a screen that changes without meaning
// anything: a download at 30% and the same download at 70% are the same screen,
// and a fingerprint that disagrees turns one state into a hundred.
//
// Which is why the run is over an *alphabet* rather than over one repeated
// character. "[████░░░░]" and "[███████░]" repeat different characters in
// different proportions and are the same bar; a rule that only collapsed
// identical runs would give a bar as many states as it has positions, which is
// the failure it exists to prevent.
//
// It is safe on the borders and separators it also matches. A rule of dashes is
// the same rule of dashes on every screen, so collapsing it changes every
// fingerprint equally and distinguishes nothing less than it did before.
// Alphanumerics are left alone: "aaa" in a text field is content.
type CollapseRuns struct{}

func (CollapseRuns) Name() string { return "runs" }

// isBar reports whether a rune is one a progress bar is drawn from: the Unicode
// block elements and geometric shapes, and the ASCII characters used for the
// same job.
func isBar(r rune) bool {
	switch {
	case r >= 0x2580 && r <= 0x25A1: // block elements and filled squares
		return true
	case r >= 0x2588 && r <= 0x258F:
		return true
	}
	return strings.ContainsRune("#=-*.", r)
}

// Normalise implements Normaliser.
func (CollapseRuns) Normalise(b []byte) []byte {
	runes := []rune(string(b))
	var out strings.Builder
	out.Grow(len(b))
	for i := 0; i < len(runes); {
		// A bar first, because it is the longer match: a run of mixed filler is
		// one bar, and stopping at each change of character would leave the
		// proportions in the fingerprint.
		if j := runEnd(runes, i, isBar); j-i >= 3 {
			out.WriteRune('\u25ac')
			i = j
			continue
		}
		r := runes[i]
		j := runEnd(runes, i, func(c rune) bool { return c == r })
		if j-i >= 3 && !isAlphanumeric(r) && r != '\n' {
			out.WriteRune(r)
			out.WriteByte('*')
			i = j
			continue
		}
		for ; i < j; i++ {
			out.WriteRune(r)
		}
	}
	return []byte(out.String())
}

func runEnd(runes []rune, i int, in func(rune) bool) int {
	if !in(runes[i]) {
		return i
	}
	j := i
	for j < len(runes) && in(runes[j]) {
		j++
	}
	return j
}

func isAlphanumeric(r rune) bool {
	return r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z'
}
