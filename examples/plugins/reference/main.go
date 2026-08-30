// Command reference is a worked example of an Xfuzz plugin.
//
// It provides one of each extension point, because the interesting part of the
// protocol is what differs between them: a feedback keeps state and has to be
// told whether the engine kept the input, an objective keeps none, and a
// mutator is asked for a batch rather than for one variant.
//
// Run it under a campaign like this:
//
//	extensions:
//	  - name: reference
//	    command: ./reference
//	    config:
//	      marker: "assertion failed"
//	    feedbacks: [chatty]
//	    objectives: [marker]
//	    mutators: [repeat]
//	    input: true
//
// A plugin in another language reimplements pkg/plugin's framing — four
// big-endian length bytes and a JSON object — and nothing else. See
// docs/adr/ADR-0025-length-prefixed-json-over-stdio-for-plugins.md.
package main

import (
	"bytes"
	"fmt"
	"os"

	"github.com/rom/Xfuzz/pkg/plugin"
	"github.com/rom/Xfuzz/pkg/rng"
)

func main() {
	p := &reference{}
	if err := plugin.Serve(plugin.Plugin{
		Name:    "reference",
		Version: "1",
		Start:   p.start,

		Feedbacks:  map[string]plugin.Judger{"chatty": p},
		Objectives: map[string]plugin.Oracle{"marker": plugin.OracleFunc(p.judgeMarker)},
		Mutators:   map[string]plugin.Varier{"repeat": plugin.VaryFunc(p.repeat)},
	}); err != nil {
		// Standard error is outside the protocol precisely so that this line
		// is safe to write. The host captures it and quotes it back.
		fmt.Fprintln(os.Stderr, "reference plugin:", err)
		os.Exit(1)
	}
}

type reference struct {
	marker string

	// longest is the feedback's novelty state: the most output any admitted
	// execution has produced.
	longest int

	// candidate is what the most recent judgement would make longest, held
	// until the engine says whether it kept the input. Without the two-step a
	// feedback folds in every input it merely found interesting, and an input
	// the composition rejected would never look interesting again.
	candidate int
}

// start receives the campaign seed and this plugin's settings.
func (r *reference) start(seed uint64, config map[string]string) error {
	r.marker = config["marker"]
	if r.marker == "" {
		r.marker = "assertion failed"
	}
	return nil
}

// Judge implements a feedback: an execution is interesting when the target said
// more than it ever has before.
//
// A poor feedback on its own — it is a demonstration, not a recommendation —
// but it is stateful, which is the part worth showing.
func (r *reference) Judge(batch []plugin.Observation) ([]plugin.Verdict, error) {
	out := make([]plugin.Verdict, len(batch))
	best := r.longest
	for i, ob := range batch {
		n := len(ob.Stdout) + len(ob.Stderr)
		if n > best {
			out[i] = plugin.Verdict{Interesting: true, NewSignal: n - best, Novelty: 1}
			best = n
		}
	}
	r.candidate = best
	return out, nil
}

// Commit settles the last judgement. The host sends it with the next call
// rather than in a round trip of its own.
func (r *reference) Commit(keep bool) {
	if keep {
		r.longest = r.candidate
	}
	r.candidate = r.longest
}

// marker implements an objective: the target printed something that names its
// own failure.
//
// This is the case that justifies the tier. Every project has a phrase its code
// prints when an invariant breaks, and no fuzzer can know what it is.
func (r *reference) judgeMarker(batch []plugin.Observation) ([]plugin.Verdict, error) {
	out := make([]plugin.Verdict, len(batch))
	for i, ob := range batch {
		said := append(append([]byte(nil), ob.Stdout...), ob.Stderr...)
		if !bytes.Contains(said, []byte(r.marker)) {
			continue
		}
		out[i].Finding = &plugin.Finding{
			Kind:    "oracle",
			Summary: "the target printed " + r.marker,
			Detail:  string(said),
		}
	}
	return out, nil
}

// repeat implements a mutator: duplicate a run of bytes.
//
// Every random choice comes from the seed the host supplied and nothing else.
// A plugin that reached for its own entropy would make the campaign
// unreproducible, and a crash nobody can reproduce is not a finding.
func (r *reference) repeat(input []byte, seed uint64, count, maxBytes int) ([][]byte, error) {
	if len(input) == 0 || count <= 0 {
		return nil, nil
	}
	rnd := rng.New(seed)

	out := make([][]byte, 0, count)
	for len(out) < count {
		at := rnd.Intn(len(input))
		n := 1 + rnd.Intn(len(input)-at)
		if maxBytes > 0 && len(input)+n > maxBytes {
			// Told the bound, so respect it rather than have the host discard
			// the work. The host enforces it too; a plugin is not trusted.
			continue
		}
		v := make([]byte, 0, len(input)+n)
		v = append(v, input[:at+n]...)
		v = append(v, input[at:]...)
		out = append(out, v)
	}
	return out, nil
}
