package engine

import (
	"strings"
	"testing"

	"github.com/rom/Xfuzz/internal/triage"
	"github.com/rom/Xfuzz/pkg/feedback"
)

// TestTheLiveMarkerAndTriagesAgreeOnTheRulesTheyShare pins the one claim both
// marker functions make about each other.
//
// There are two implementations on purpose: this one runs on the hot path from
// whatever the target happened to print, and triage's runs from a minimised
// reproducer and an execution it watched itself. They differ deliberately —
// this one takes the first non-empty line and caps at 64 bytes, triage searches
// for a known prefix and allows 160 — and where they disagree triage is right.
//
// What they must not differ on is the normalisation, because both feed a bucket
// key and a divergence there files one bug twice. The v0.1 audit found the
// engine's copy still admitting control characters after triage's had been
// fixed, with nothing to notice: two functions claiming in their comments to
// apply the same rules, and no test comparing them.
func TestTheLiveMarkerAndTriagesAgreeOnTheRulesTheyShare(t *testing.T) {
	cases := []struct {
		name   string
		detail string
	}{
		{"an address", "panic: bad access at 0x7ffd1234"},
		{"a long counter", "assertion failed: seq 1234567 out of range"},
		{"a short number kept", "XFUZZ-BUG-3 reached"},
		{"an escape sequence", "panic: \x1b[2J\x1b[H runtime error"},
		{"a bare control byte", "panic: bad\x00index"},
		{"a carriage return mid-message", "panic: bad index\rgoroutine 1"},
		{"utf-8 survives", "panic: naïve résumé handling"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			live := markerOf(c.detail)
			cls := triage.Classify(triage.Outcome{
				Exit: feedback.ExitCrash, Signal: 6, Output: c.detail,
			})

			// Neither may carry anything a terminal acts on. This is the rule
			// that had drifted, and it is the one with a security argument
			// behind it: the marker is printed to an operator and comes from a
			// program being driven into undefined behaviour (SECURITY.md).
			for _, m := range []struct{ what, s string }{{"live", live}, {"triage", cls.Marker}} {
				for _, r := range m.s {
					if r < 0x20 || r == 0x7f {
						t.Errorf("%s marker contains %q, which a terminal will act on: %q",
							m.what, r, m.s)
					}
				}
			}

			// And on the shared normalisation: whatever one replaces, so does
			// the other. Compared as "does it still contain the volatile text"
			// rather than for equality, because the two are allowed to differ
			// in where they start and how much they keep.
			if strings.Contains(c.detail, "0x7ffd1234") {
				if strings.Contains(live, "7ffd1234") || strings.Contains(cls.Marker, "7ffd1234") {
					t.Errorf("an address survived: live %q, triage %q", live, cls.Marker)
				}
			}
			if strings.Contains(c.detail, "1234567") {
				if strings.Contains(live, "1234567") || strings.Contains(cls.Marker, "1234567") {
					t.Errorf("a long counter survived: live %q, triage %q", live, cls.Marker)
				}
			}
			// A short number is part of what the message says and must survive
			// both, or bugs the target told apart are merged.
			if strings.Contains(c.detail, "XFUZZ-BUG-3") && !strings.Contains(live, "3") {
				t.Errorf("a short number was collapsed: %q", live)
			}
			// Multi-byte runes must not be cut. A mangled message is one
			// somebody has to read.
			if strings.Contains(c.detail, "naïve") && !strings.Contains(live, "naïve") {
				t.Errorf("utf-8 did not survive: %q", live)
			}
		})
	}
}
