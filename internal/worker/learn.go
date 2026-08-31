package worker

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"unicode"

	"github.com/rom/Xfuzz/pkg/campaign"
	"github.com/rom/Xfuzz/pkg/corpus"
	"github.com/rom/Xfuzz/pkg/executor"
	"github.com/rom/Xfuzz/pkg/feedback"
	"github.com/rom/Xfuzz/pkg/ir"
	"github.com/rom/Xfuzz/pkg/learn"
	"github.com/rom/Xfuzz/pkg/state"
)

// Active learning, before the fuzzing starts.
//
// ADR-0006 chose inference and deferred this; ADR-0035 is where it landed. The
// difference is what the campaign does with its executions. Inference labels
// whatever sequences the mutator happened to produce, so a state it never
// stumbled into is a state it never learns about. Learning chooses the
// sequences, and what comes back is a machine with a path to every state it
// found.
//
// Those paths are the point. A stateful campaign's hardest problem is reaching
// the interesting states at all — a protocol that needs a handshake, an
// authentication and a mode change spends most of a budget rediscovering the
// prefix — and a corpus seeded with one sequence per state starts from all of
// them.

// learnAndSeed runs the learner and adds what it found to the corpus.
//
// Failures here do not end the campaign. Learning is an optimisation: a
// campaign that could not learn is a campaign that fuzzes from its own seeds,
// which is what it would have done anyway. What it must not do is fail quietly,
// so every outcome is reported.
func (w *Worker) learnAndSeed(ctx context.Context) {
	cfg := w.opts.Config
	if cfg.State == nil || cfg.State.Learn == nil || w.built == nil {
		return
	}
	b := w.built
	if b.state == nil || b.state.Observer == nil {
		w.report("warn", "learning needs state guidance, which this campaign has turned off")
		return
	}

	alphabet, messages := learnAlphabet(b.engine.Corpus(), cfg.State.Learn.Alphabet)
	if len(alphabet) < 2 {
		w.report("warn", fmt.Sprintf("learning found %d distinct messages in the "+
			"campaign's seeds, which is not enough to learn a machine over",
			len(alphabet)))
		return
	}

	l := cfg.State.Learn
	seed := l.Seed
	if seed == 0 {
		seed = w.opts.Seed
	}
	teacher := &sessionTeacher{
		exec:     b.executor,
		obs:      b.observers(),
		states:   b.state.Observer,
		messages: messages,
	}

	m, rep, err := learn.Learn(ctx, teacher, learn.Options{
		Alphabet:         alphabet,
		MaxQueries:       l.MaxQueries,
		MaxStates:        l.MaxStates,
		EquivalenceWords: l.Words,
		MaxWordLength:    l.MaxLength,
		Seed:             seed,
	})
	if err != nil {
		w.report("warn", "learning: "+err.Error())
		return
	}

	note := fmt.Sprintf("learned %d states and %d distinct transitions from %d sessions "+
		"(%d answered from the table), checked against %d sequences",
		m.States(), m.Transitions(), rep.Queries, rep.Cached, rep.Checked)
	if rep.Partial {
		note += "; incomplete: " + rep.Why
	}
	w.report("info", note)

	if l.Dot != "" {
		if err := os.WriteFile(l.Dot, []byte(m.Dot()), 0o600); err != nil {
			w.report("warn", "writing the learned machine: "+err.Error())
		} else {
			w.report("info", "wrote the learned machine to "+l.Dot)
		}
	}

	added := 0
	for _, access := range m.Reachable() {
		if len(access) == 0 {
			continue
		}
		if err := b.engine.AddSeed(ctx, wordBytes(access, messages), "learned"); err != nil {
			w.report("warn", "seeding from the learned machine: "+err.Error())
			break
		}
		added++
	}
	if added > 0 {
		w.report("info", fmt.Sprintf("seeded the corpus with %d sequences, one for each "+
			"state the machine reaches", added))
	}
}

// learnAlphabet takes the distinct messages the campaign's seeds contain.
//
// The seeds rather than a list in the campaign file, because the messages a
// protocol takes are already in the example somebody supplied — asking them to
// write the alphabet out again is asking them to describe what they have
// already shown. What a campaign does configure is how many to take: the
// observation table has a column per symbol before it has anything else.
//
// Ordered by how often a message appears and then by its bytes, so the same
// corpus produces the same alphabet: the machine a campaign learns must not
// depend on map iteration order (ASR-0008).
func learnAlphabet(c *corpus.Corpus, max int) ([]string, map[string][]byte) {
	type msg struct {
		bytes []byte
		count int
	}
	seen := map[string]*msg{}
	for i := 0; i < c.Len(); i++ {
		root := c.At(i).Input
		if root == nil || root.Kind != ir.KindRepeat {
			continue
		}
		for _, child := range root.Children {
			raw := ir.AppendEncode(nil, child)
			if len(raw) == 0 {
				continue
			}
			k := string(raw)
			if m, ok := seen[k]; ok {
				m.count++
				continue
			}
			seen[k] = &msg{bytes: raw, count: 1}
		}
	}

	keys := make([]string, 0, len(seen))
	for k := range seen {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if seen[keys[i]].count != seen[keys[j]].count {
			return seen[keys[i]].count > seen[keys[j]].count
		}
		return keys[i] < keys[j]
	})
	if max > 0 && len(keys) > max {
		keys = keys[:max]
	}

	names := make([]string, 0, len(keys))
	messages := make(map[string][]byte, len(keys))
	used := map[string]bool{}
	for i, k := range keys {
		name := symbolName(seen[k].bytes, i, used)
		names = append(names, name)
		messages[name] = seen[k].bytes
		used[name] = true
	}
	return names, messages
}

// symbolName gives a message a short readable name.
//
// Readable because the learned machine is something a person looks at, and a
// diagram whose edges are labelled m0 through m7 says nothing about the
// protocol it describes. Unreadable messages fall back to a number rather than
// to mangled bytes.
func symbolName(raw []byte, i int, used map[string]bool) string {
	field := strings.TrimSpace(string(raw))
	if i := strings.IndexAny(field, " \t\r\n"); i > 0 {
		field = field[:i]
	}
	clean := strings.Map(func(r rune) rune {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '-' || r == '_' || r == '/' {
			return r
		}
		return -1
	}, field)
	if len(clean) > 16 {
		clean = clean[:16]
	}
	if clean == "" {
		clean = fmt.Sprintf("m%d", i)
	}
	name := clean
	for n := 2; used[name]; n++ {
		name = fmt.Sprintf("%s~%d", clean, n)
	}
	return name
}

// wordBytes turns a sequence of symbols into the bytes of a session.
func wordBytes(word []string, messages map[string][]byte) []byte {
	var out []byte
	for _, sym := range word {
		out = append(out, messages[sym]...)
	}
	return out
}

// sessionTeacher answers a membership query by running a session.
//
// The output alphabet is the campaign's own state labels, which is what makes
// this fit at all: the state function a campaign already configured to say
// "this response means authenticated" is exactly the function a Mealy machine's
// output needs.
type sessionTeacher struct {
	exec     executor.Executor
	obs      []feedback.Observer
	states   *state.Observer
	messages map[string][]byte
}

// closedSymbol stands for a message the target never answered.
//
// A target that closed the connection part-way has said something — it said
// "not that, not here" — and dropping the symbol would make the answer shorter
// than the question, which is not a Mealy answer at all. Naming it keeps the
// machine total and puts the refusal where it happened.
const closedSymbol = "closed"

// Output implements learn.Teacher.
func (t *sessionTeacher) Output(ctx context.Context, word []string) ([]string, error) {
	raw := wordBytes(word, t.messages)

	// A fresh session per query: L* assumes every question is asked from the
	// same starting state, and a teacher answering from wherever the last one
	// left off would describe nothing.
	if err := t.exec.Reset(executor.ResetRestart); err != nil {
		return nil, fmt.Errorf("resetting between queries: %w", err)
	}
	if _, err := t.exec.Run(ctx, executor.Input{Bytes: raw}, t.obs); err != nil {
		return nil, err
	}

	labels := t.states.StateLabels()
	out := make([]string, len(word))
	// Aligned from the end: a session's trace may carry a label for a banner
	// the target sent before anything was asked, and the answers to the
	// questions are the last ones.
	offset := len(labels) - len(word)
	for i := range word {
		j := offset + i
		if j < 0 || j >= len(labels) {
			out[i] = closedSymbol
			continue
		}
		out[i] = labels[j]
	}
	return out, nil
}

// learnConfigured reports whether the campaign asked to learn.
func learnConfigured(cfg *campaign.Resolved) bool {
	return cfg.State != nil && cfg.State.Learn != nil
}
