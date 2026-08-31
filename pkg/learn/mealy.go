// Package learn infers a protocol's state machine by asking it questions.
//
// ADR-0006 chose an explicit state machine with state feedback, and deferred
// active automata learning by name: the campaign watches what a target says and
// infers states from it, rather than driving the target on purpose to find out
// what states exist. This is the deferred half.
//
// The difference is what the fuzzer does with its executions. Passive inference
// takes whatever sequences the mutator happened to produce and labels the
// responses; a state it never stumbled into is a state it never learns about.
// Active learning *chooses* the sequences — it asks "what happens after this
// exact prefix, followed by this exact suffix" — and the answer is a machine
// with a named path to every state it found. Those paths are the thing a
// stateful campaign is short of: a corpus seeded with them starts from every
// reachable state rather than from the handshake.
//
// The algorithm is Angluin's L*, in its Mealy-machine form. A Mealy machine
// rather than a DFA because a protocol answers every message with something:
// the observable is not "was this word accepted" but "what did it say", which
// is one output symbol per input symbol.
//
// What this does not do is prove anything. L* is exact given a perfect
// equivalence oracle, and there is no perfect equivalence oracle for a program
// nobody has a model of — so the one here samples, and the machine it returns
// is the best explanation of the queries that were asked. That limit is the
// reason this reports how it was checked rather than claiming correctness.
package learn

import (
	"fmt"
	"sort"
	"strings"
)

// Mealy is a learned state machine: one output symbol per input symbol.
type Mealy struct {
	// Alphabet is the input symbols, in the order learning used.
	Alphabet []string

	// Trans and Out are indexed by state: the next state and the output for
	// each input symbol.
	Trans []map[string]int
	Out   []map[string]string

	// Access is the shortest input word that reaches each state, which is what
	// makes a learned machine useful to a fuzzer rather than merely
	// interesting: it is a recipe for getting there.
	Access [][]string
}

// States returns how many states the machine has.
func (m *Mealy) States() int { return len(m.Trans) }

// Run replays a word from the initial state and returns the output word.
//
// One output per input, which is what makes a mismatch against the real target
// a counterexample: the two disagree at a position, and the prefix up to that
// position is the shortest thing that distinguishes them.
func (m *Mealy) Run(word []string) []string {
	out := make([]string, 0, len(word))
	s := 0
	for _, a := range word {
		o, ok := m.Out[s][a]
		if !ok {
			// A symbol the machine never saw. Reporting an empty output rather
			// than panicking keeps a comparison against the target meaningful:
			// they differ here, which is exactly what the caller wants to know.
			out = append(out, "")
			continue
		}
		out = append(out, o)
		s = m.Trans[s][a]
	}
	return out
}

// Transitions returns how many transitions carry a distinct output, which is a
// better measure of what was learned than the state count alone: a machine with
// six states and one output has learned that the target ignores everything.
func (m *Mealy) Transitions() int {
	seen := map[string]bool{}
	for s := range m.Out {
		for a, o := range m.Out[s] {
			seen[fmt.Sprintf("%d/%s/%s", s, a, o)] = true
		}
	}
	return len(seen)
}

// Dot renders the machine in Graphviz's language.
//
// A learned machine is something a person looks at — that is most of its value
// beside its use as a seed source — and every tool that draws graphs reads this.
func (m *Mealy) Dot() string {
	var b strings.Builder
	b.WriteString("digraph learned {\n")
	b.WriteString("  rankdir=LR;\n")
	b.WriteString("  node [shape=circle];\n")
	b.WriteString("  start [shape=point];\n")
	b.WriteString("  start -> s0;\n")
	for s := range m.Trans {
		label := fmt.Sprintf("s%d", s)
		if s < len(m.Access) && len(m.Access[s]) > 0 {
			label += "\\n" + strings.Join(m.Access[s], " ")
		}
		fmt.Fprintf(&b, "  s%d [label=%q];\n", s, label)
	}
	for s := range m.Trans {
		// Sorted, so the same machine renders the same way twice: a diagram
		// that reorders itself between runs cannot be compared with the last
		// one.
		syms := make([]string, 0, len(m.Trans[s]))
		for a := range m.Trans[s] {
			syms = append(syms, a)
		}
		sort.Strings(syms)
		for _, a := range syms {
			fmt.Fprintf(&b, "  s%d -> s%d [label=%q];\n", s, m.Trans[s][a],
				a+" / "+m.Out[s][a])
		}
	}
	b.WriteString("}\n")
	return b.String()
}

// Reachable returns the access word for every state, shortest first.
//
// This is what a campaign seeds its corpus with: one sequence per state, each
// the cheapest way the learner found to get there.
func (m *Mealy) Reachable() [][]string {
	out := append([][]string(nil), m.Access...)
	sort.SliceStable(out, func(i, j int) bool { return len(out[i]) < len(out[j]) })
	return out
}
