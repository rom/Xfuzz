package campaign

import (
	"strings"
	"testing"
)

// FuzzParse fuzzes the campaign file parser.
//
// Untrusted because a campaign file is the whole interface for defining a
// campaign (ADR-0016), which means it is the thing people send each other and
// the thing an API client posts. ASR-0010 states plainly that a campaign file
// may be hostile.
//
// Parse rather than Load, because Parse is the network-facing half: it refuses
// includes precisely so that a document arriving over a socket cannot name a
// path on the daemon's filesystem, and that refusal is part of what is under
// test here.
func FuzzParse(f *testing.F) {
	f.Add([]byte("name: c\ntarget:\n  path: /bin/true\nseeds:\n  inline: [\"a\"]\n"))
	f.Add([]byte("name: c\nprofiles:\n  quick:\n    stop:\n      after: 1m\n"))
	f.Add([]byte("name: c\nextensions:\n  - name: p\n    command: ./p\n    feedbacks: [f]\n"))
	f.Add([]byte("name: c\nscripts:\n  - name: s\n    path: s.star\n    objectives: [check]\n"))
	f.Add([]byte("include: [/etc/passwd]\n"))
	f.Add([]byte("name: c\nstop:\n  after: 99999999999999999999h\n"))
	f.Add([]byte("!!binary AAAA"))
	f.Add([]byte("{"))
	f.Add([]byte(""))

	f.Fuzz(func(t *testing.T, src []byte) {
		cfg, err := Parse(src, "fuzz.yaml")
		if err != nil {
			if strings.TrimSpace(err.Error()) == "" {
				t.Fatal("the parser refused the document with an empty message")
			}
			return
		}
		if cfg == nil {
			t.Fatal("the parser returned neither a campaign nor an error")
		}

		// The refusal that matters. A document that arrived over the network
		// must never be able to make the daemon read a path it names, so a
		// parse that succeeds must have no includes left in it.
		if len(cfg.Include) > 0 {
			t.Fatalf("a parsed document kept its includes: %v", cfg.Include)
		}

		// Validation must be total. Every campaign that parses is handed to
		// Validate, and a panic there is the same defect one layer along.
		_ = cfg.Validate()

		// And it must survive its own presentation: the console and `explain`
		// render whatever parsed, so a document that parses and cannot be
		// rendered is a crash in a viewer rather than a rejected file.
		_ = cfg.ExplainString()
	})
}
