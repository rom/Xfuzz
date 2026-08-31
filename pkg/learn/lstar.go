package learn

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/rom/Xfuzz/pkg/rng"
)

// Teacher is the target being learned.
//
// One method, and the shape of it is the whole cost model: every call is a
// reset followed by one message per symbol. On a protocol session that is a
// connection and a handshake; on the driver tier it is restarting a program.
// Learning asks thousands of these, so the learner caches every answer and
// bounds how many it will ask — and a caller who cannot afford the bound gets a
// partial machine and is told so, rather than a campaign that never starts.
type Teacher interface {
	// Output runs a word from the target's initial state and returns one output
	// symbol per input symbol.
	//
	// The target is reset first: L* assumes every query starts from the same
	// place, and a teacher that answered from wherever the last query left off
	// would produce a machine describing nothing.
	Output(ctx context.Context, word []string) ([]string, error)
}

// Options bound the learning.
type Options struct {
	// Alphabet is the input symbols to learn over. Everything scales with its
	// size — the table has a column per symbol before it has anything else — so
	// a campaign learns over the messages it means to fuzz rather than over
	// every message a protocol defines.
	Alphabet []string

	// MaxQueries caps how many words are run against the target, cache misses
	// only. Reaching it returns what has been learned so far, marked partial.
	MaxQueries int

	// MaxStates caps the hypothesis. A target whose state depends on a counter
	// — a sequence number, a nonce, a retry budget — has no finite machine, and
	// without a cap the learner would chase it until the budget ran out.
	MaxStates int

	// EquivalenceWords and MaxWordLength bound the search for a counterexample.
	// This is where L*'s guarantee becomes a sample: there is no oracle that
	// can prove a program equivalent to a machine, so the learner tries words
	// and reports how many.
	EquivalenceWords int
	MaxWordLength    int

	// Seed makes the sampling reproducible. Two runs of the same campaign
	// against the same target must ask the same questions (ASR-0008).
	Seed uint64
}

// Defaults for learning a protocol.
const (
	DefaultMaxQueries       = 5000
	DefaultMaxStates        = 32
	DefaultEquivalenceWords = 200
	DefaultMaxWordLength    = 12
)

func (o *Options) fill() {
	if o.MaxQueries <= 0 {
		o.MaxQueries = DefaultMaxQueries
	}
	if o.MaxStates <= 0 {
		o.MaxStates = DefaultMaxStates
	}
	if o.EquivalenceWords <= 0 {
		o.EquivalenceWords = DefaultEquivalenceWords
	}
	if o.MaxWordLength <= 0 {
		o.MaxWordLength = DefaultMaxWordLength
	}
}

// Report says what the learning cost and how far it got.
type Report struct {
	// Queries is how many words actually reached the target, and Cached how
	// many were answered from the table. The ratio is the reason learning is
	// affordable at all.
	Queries int
	Cached  int

	// Rounds is how many hypotheses were built, which is one more than the
	// number of counterexamples found.
	Rounds int

	// Checked is how many words the equivalence search tried against the final
	// hypothesis without finding a disagreement. It is the strength of the
	// claim, and it is a sample rather than a proof.
	Checked int

	// Partial reports that a bound was reached before the learning settled, so
	// the machine explains the queries that were asked and may not explain the
	// next one.
	Partial bool
	Why     string
}

// ErrNoAlphabet is returned when there is nothing to learn over.
var ErrNoAlphabet = errors.New("learn: an empty alphabet has nothing to ask about")

// Learn infers a Mealy machine for a target.
//
// Angluin's L*, in the Mealy form: an observation table whose rows are access
// sequences and whose columns are distinguishing suffixes. The columns start as
// the single symbols, which is what makes the table consistent by construction
// for a Mealy machine — so the loop only has to close it, and the whole
// consistency machinery the DFA version needs is not here because it cannot
// fire.
func Learn(ctx context.Context, t Teacher, opts Options) (*Mealy, Report, error) {
	opts.fill()
	if len(opts.Alphabet) == 0 {
		return nil, Report{}, ErrNoAlphabet
	}

	l := &learner{t: t, opts: opts, cache: map[string][]string{}, rows: map[string][]string{}}
	// S starts with the empty word: the initial state, whose access sequence is
	// nothing at all.
	l.s = [][]string{{}}
	for _, a := range opts.Alphabet {
		l.e = append(l.e, []string{a})
	}

	var rep Report
	r := rng.New(opts.Seed)

	for {
		if err := l.close(ctx); err != nil {
			return l.hypothesis(), l.report(&rep, err), nil
		}
		m := l.hypothesis()
		rep.Rounds++

		// A bound on the rounds as well as on the queries.
		//
		// Each round must make the table strictly finer, so the count is bounded
		// by the states the target has — but "must" is an argument about the
		// algorithm, and this is a fuzzer pointed at a program that may not be a
		// machine at all. A round that costs nothing because every word is
		// cached would otherwise spin without spending the query budget that is
		// supposed to stop it.
		if rep.Rounds > maxRounds(opts) {
			rep.Partial, rep.Why = true, fmt.Sprintf(
				"stopped after %d rounds without settling: the target is answering "+
					"differently to the same question, so no finite machine describes it",
				rep.Rounds)
			l.fill(&rep)
			return m, rep, nil
		}

		if len(m.Trans) >= opts.MaxStates {
			rep.Partial, rep.Why = true, fmt.Sprintf(
				"stopped at %d states, the configured maximum: a target whose state "+
					"depends on a counter has no finite machine", opts.MaxStates)
			l.fill(&rep)
			return m, rep, nil
		}

		cx, checked, err := l.findCounterexample(ctx, m, r)
		rep.Checked = checked
		if err != nil {
			return m, l.report(&rep, err), nil
		}
		if cx == nil {
			l.fill(&rep)
			return m, rep, nil
		}
		// Every suffix of the counterexample becomes a distinguishing column.
		//
		// Suffixes and not prefixes, and the difference is the difference
		// between terminating and not. Angluin's original adds the
		// counterexample's prefixes to the rows, which works for a DFA whose
		// columns grow with it; in the Mealy form the columns start as the
		// alphabet, and adding rows alone cannot separate two states that agree
		// on every single symbol. The learner then finds the same counterexample
		// for ever — and because every word in it is already cached, it spins
		// without spending a query. Measured on a three-state machine whose
		// first two states differ only two symbols later: it never finished.
		//
		// A suffix that distinguishes the counterexample splits at least one
		// state, so each round makes the table strictly finer.
		if !l.addSuffixes(cx) {
			rep.Partial, rep.Why = true, "a counterexample was found that no new suffix "+
				"of it explains, which means the target answered the same question two "+
				"different ways: it is not deterministic from a reset"
			l.fill(&rep)
			return m, rep, nil
		}
	}
}

// maxRounds bounds the hypothesis-and-counterexample loop.
func maxRounds(o Options) int { return o.MaxStates*len(o.Alphabet) + 16 }

// learner holds the observation table.
type learner struct {
	t    Teacher
	opts Options

	s [][]string // access sequences, prefix-closed
	e [][]string // distinguishing suffixes

	cache map[string][]string

	// rows memoises the table itself, not just the queries behind it.
	//
	// The suffixes never change in the Mealy form — E is the single symbols and
	// counterexamples add access sequences rather than suffixes — so a row, once
	// computed, is final. Without this the closing loop recomputes every row on
	// every pass: still correct, because the queries are cached, and measured at
	// a hundred thousand table lookups for three hundred sessions.
	rows map[string][]string

	queries int
	cached  int
	stopped error
}

func key(word []string) string { return strings.Join(word, "\x00") }

// ask runs a word, from the cache where it can.
func (l *learner) ask(ctx context.Context, word []string) ([]string, error) {
	k := key(word)
	if out, ok := l.cache[k]; ok {
		l.cached++
		return out, nil
	}
	if l.queries >= l.opts.MaxQueries {
		return nil, errBudget
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	out, err := l.t.Output(ctx, word)
	if err != nil {
		return nil, err
	}
	if len(out) != len(word) {
		return nil, fmt.Errorf("learn: the target answered %d symbols to a word of %d; "+
			"a Mealy teacher answers exactly one output per input", len(out), len(word))
	}
	l.queries++
	l.cache[k] = out
	return out, nil
}

// errBudget ends learning without ending the campaign.
var errBudget = errors.New("the query budget was reached")

// row returns the table row for an access sequence: the output of each suffix
// after it.
func (l *learner) row(ctx context.Context, s []string) ([]string, error) {
	if r, ok := l.rows[key(s)]; ok {
		return r, nil
	}
	out := make([]string, 0, len(l.e))
	for _, e := range l.e {
		word := append(append([]string(nil), s...), e...)
		res, err := l.ask(ctx, word)
		if err != nil {
			return nil, err
		}
		// The outputs the suffix produced, which is what distinguishes states:
		// what came before is the same for every column of this row.
		out = append(out, key(res[len(s):]))
	}
	l.rows[key(s)] = out
	return out, nil
}

// close adds access sequences until every one-symbol extension matches a row
// already in S.
func (l *learner) close(ctx context.Context) error {
	for {
		known := map[string]bool{}
		for _, s := range l.s {
			r, err := l.row(ctx, s)
			if err != nil {
				return err
			}
			known[key(r)] = true
		}
		added := false
		for _, s := range l.s {
			for _, a := range l.opts.Alphabet {
				ext := append(append([]string(nil), s...), a)
				r, err := l.row(ctx, ext)
				if err != nil {
					return err
				}
				if known[key(r)] {
					continue
				}
				l.s = append(l.s, ext)
				known[key(r)] = true
				added = true
			}
		}
		if !added {
			return nil
		}
		if len(l.s) > l.opts.MaxStates*len(l.opts.Alphabet)+l.opts.MaxStates {
			// A guard rather than a policy: the state cap is checked on the
			// hypothesis, and this stops a pathological table from growing
			// between checks.
			return errBudget
		}
	}
}

// hypothesis builds the machine the table describes.
func (l *learner) hypothesis() *Mealy {
	m := &Mealy{Alphabet: append([]string(nil), l.opts.Alphabet...)}

	// One state per distinct row, in the order the access sequences were added,
	// so state 0 is the initial state and the numbering is reproducible.
	index := map[string]int{}
	var reps [][]string
	for _, s := range l.s {
		r, err := l.row(context.Background(), s)
		if err != nil {
			// Every row here is cached: close asked for all of them before this
			// runs. A miss means the budget ended mid-table, and the states
			// found so far are still a machine.
			break
		}
		k := key(r)
		if _, seen := index[k]; seen {
			continue
		}
		index[k] = len(reps)
		reps = append(reps, s)
	}
	if len(reps) == 0 {
		reps = [][]string{{}}
		index[""] = 0
	}

	for _, s := range reps {
		m.Access = append(m.Access, append([]string(nil), s...))
		m.Trans = append(m.Trans, map[string]int{})
		m.Out = append(m.Out, map[string]string{})
	}
	for i, s := range reps {
		for _, a := range l.opts.Alphabet {
			ext := append(append([]string(nil), s...), a)
			r, err := l.row(context.Background(), ext)
			if err != nil {
				continue
			}
			next, ok := index[key(r)]
			if !ok {
				// An extension whose row is not in S: the table was not closed
				// when the budget ran out. Pointing at the initial state is the
				// honest placeholder — the machine is marked partial.
				next = 0
			}
			m.Trans[i][a] = next

			// The output of a single symbol is the column for that symbol,
			// which E always has because it started as the single symbols.
			out, err := l.ask(context.Background(), append(append([]string(nil), s...), a))
			if err != nil {
				continue
			}
			m.Out[i][a] = out[len(out)-1]
		}
	}
	return m
}

// findCounterexample looks for a word the hypothesis gets wrong.
//
// Sampling, because there is no oracle that can prove a program equivalent to a
// machine. Words are drawn at random up to a bounded length, which finds the
// disagreements that are reachable by a short path — and those are the ones a
// fuzzer would have found anyway, so a machine that survives them is a machine
// worth seeding from.
func (l *learner) findCounterexample(ctx context.Context, m *Mealy, r *rng.Rand) ([]string, int, error) {
	checked := 0
	for i := 0; i < l.opts.EquivalenceWords; i++ {
		n := 1 + r.Intn(l.opts.MaxWordLength)
		word := make([]string, 0, n)
		for j := 0; j < n; j++ {
			word = append(word, l.opts.Alphabet[r.Intn(len(l.opts.Alphabet))])
		}
		got, err := l.ask(ctx, word)
		if err != nil {
			return nil, checked, err
		}
		checked++
		want := m.Run(word)
		for k := range word {
			if got[k] != want[k] {
				// The prefix up to and including the disagreement is enough:
				// everything after it is explained by a state the hypothesis
				// already has wrong.
				return word[:k+1], checked, nil
			}
		}
	}
	return nil, checked, nil
}

// addSuffixes makes every suffix of a counterexample a distinguishing column,
// and reports whether any of them was new.
//
// The row memo goes with them: a row is one answer per column, so a new column
// invalidates every row. The *query* cache stays — the words behind the old
// columns are the same words — which is why a new column costs arithmetic
// rather than sessions.
func (l *learner) addSuffixes(cx []string) bool {
	have := map[string]bool{}
	for _, e := range l.e {
		have[key(e)] = true
	}
	added := false
	for i := 0; i < len(cx); i++ {
		suf := append([]string(nil), cx[i:]...)
		if have[key(suf)] {
			continue
		}
		l.e = append(l.e, suf)
		have[key(suf)] = true
		added = true
	}
	if added {
		l.rows = map[string][]string{}
	}
	return added
}

func (l *learner) fill(rep *Report) {
	rep.Queries, rep.Cached = l.queries, l.cached
}

// report finishes a run that ended early.
func (l *learner) report(rep *Report, err error) Report {
	l.fill(rep)
	rep.Partial = true
	switch {
	case errors.Is(err, errBudget):
		rep.Why = fmt.Sprintf("stopped after %d queries, the configured maximum: "+
			"the machine explains what was asked and may not explain the next question",
			l.opts.MaxQueries)
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		rep.Why = "the campaign stopped while learning"
	default:
		rep.Why = "the target stopped answering: " + err.Error()
	}
	return *rep
}
