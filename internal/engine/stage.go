package engine

import (
	"context"

	"github.com/rom/Xfuzz/pkg/corpus"
	"github.com/rom/Xfuzz/pkg/feedback"
	"github.com/rom/Xfuzz/pkg/ir"
	"github.com/rom/Xfuzz/pkg/mutate"
	"github.com/rom/Xfuzz/pkg/state"
)

// Stages: the ordered ways of deriving new inputs from one corpus entry.
//
// Until v0.3 there was one way — apply the mutation scheduler and see what
// happens — and it was written directly into the loop. ADR-0007 requires two
// more that are not mutations at all: comparison-operand substitution, which
// derives an input from what the target *did* rather than from randomness, and
// concolic solving, which derives one from a solver. Neither fits inside a
// mutation scheduler, and both need the same execute-and-judge machinery.
//
// So the loop spends a seed's energy across a list of stages instead of on one
// of them. The list is ordered and the order matters: the cheap deterministic
// stage runs before the expensive random one, because a substitution that
// unlocks a magic number makes every subsequent mutation more valuable, and
// spending the energy first and substituting afterwards would waste it on an
// input that could not get past the gate.

// stage is one way of deriving candidate inputs from a corpus entry.
//
// Unexported because ADR-0010 places extensibility at the feedback and mutator
// tiers, not here: a third-party stage would be arbitrary code between the
// scheduler and the corpus, with the campaign's determinism guarantee resting on
// it. The two stages ADR-0007 names are both in this package.
type stage interface {
	name() string

	// run spends part of a seed's budget and reports what it admitted and the
	// best score it saw. stop asks the engine to end the campaign, which only a
	// first finding under StopOnFirstFinding does.
	run(ctx context.Context, e *Engine, s stageInput) (stageResult, error)
}

// stageInput is what a stage is given.
type stageInput struct {
	parent *corpus.Testcase
	aim    state.Aim
	energy int
	budget Budget
}

// stageResult is what a stage produced.
type stageResult struct {
	admitted int
	best     feedback.Score
	stop     bool
}

// merge folds one stage's result into the seed's total.
func (r *stageResult) merge(o stageResult) {
	r.admitted += o.admitted
	if o.best.NewSignal > r.best.NewSignal {
		r.best = o.best
	}
	r.stop = r.stop || o.stop
}

// havocStage is mutation: the stage that was the whole loop.
//
// It applies the mutation scheduler to the parent, encodes the result, and
// judges it, as many times as the seed's energy allows. Everything a
// coverage-guided campaign does without help from the target is here.
type havocStage struct{}

func (havocStage) name() string { return "havoc" }

func (havocStage) run(ctx context.Context, e *Engine, s stageInput) (stageResult, error) {
	var res stageResult

	for k := 0; k < s.energy; k++ {
		if ctx.Err() != nil {
			return res, nil
		}
		if s.budget.MaxExecs > 0 && e.stats.Execs >= s.budget.MaxExecs {
			return res, nil
		}

		e.arena.Reset()
		tree := e.arena.Clone(s.parent.Input)
		e.mctx.Root = tree
		e.mctx.Donor = e.pickDonor(s.parent)

		// Which part of the input to change. For a stateless campaign that is
		// the whole thing; for a session it is one message, chosen by aiming at
		// a state worth exploring past (ADR-0006). The mutation scheduler
		// restricts itself to the root it is given, so this is the whole of the
		// state-then-message split.
		target, aimed := tree, state.Label("")
		if e.cfg.State != nil {
			target, aimed = e.cfg.State.Target(s.aim, s.parent.ID, tree, e.mctx.Nodes)
		}

		ops := e.cfg.Mutators.Mutate(e.mctx, target)
		if len(ops) == 0 {
			continue
		}

		encoded, ferr := e.fixer.Fix(tree, e.cfg.Suppress)
		if ferr != nil {
			// A mutation produced a tree whose derivations cannot be resolved.
			// That is a normal outcome of structural mutation, not an error:
			// skip the input and carry on.
			continue
		}

		v, err := e.evaluate(ctx, s.parent, candidate{
			tree: tree, encoded: encoded, ops: ops, aimed: aimed,
		})
		if err != nil {
			return res, err
		}
		if v.admitted {
			res.admitted++
		}
		if v.interesting && v.score.NewSignal > res.best.NewSignal {
			res.best = v.score
		}
		e.cfg.Mutators.RecordOutcome(ops, v.interesting, v.finding)

		if v.finding && s.budget.StopOnFirstFinding {
			res.stop = true
			return res, nil
		}
	}
	return res, nil
}

// stagesFor assembles the stage list a campaign will run.
//
// Ordered cheapest-and-most-informed first. The comparison stage costs a handful
// of executions and each one is aimed at a specific gate the target has already
// told the fuzzer about; havoc costs the seed's whole energy budget on guesses.
// Running the informed stage first means the guesses are made on an input that
// has already got past whatever the substitution unlocked.
func stagesFor(cfg Config) []stage {
	var out []stage
	if cfg.Cmp != nil {
		out = append(out, &cmpLogStage{})
	}
	out = append(out, havocStage{})
	return out
}

// decode turns candidate bytes into the tree the corpus and the executor want.
//
// A stage that works on bytes — which the comparison stage does, because a
// comparison operand is a run of bytes and not a node — still has to produce a
// structure, or a session campaign would deliver its candidate as one long
// message instead of a conversation and a structured corpus would store an
// entry it cannot mutate. Failure is not an error: bytes that the codec cannot
// read are a candidate not worth executing, which is a normal outcome of
// splicing a constant into the middle of a format.
func decodeCandidate(e *Engine, b []byte) (*ir.Node, bool) {
	node, err := e.cfg.Codec.Decode(nil, b)
	if err != nil {
		return nil, false
	}
	return node, true
}

// substitutionOps records how a candidate was produced, for corpus provenance.
//
// The corpus records which mutator made each entry, and an entry that arrived by
// substitution rather than by mutation must not be attributed to whichever
// mutator ran last — that is what the provenance is for, and a wrong attribution
// is worse than none.
func substitutionOps(name string) []mutate.Op {
	return []mutate.Op{{Mutator: name}}
}
