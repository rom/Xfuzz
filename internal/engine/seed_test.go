package engine

import (
	"context"
	"strings"
	"testing"

	"github.com/rom/Xfuzz/pkg/codec"
	"github.com/rom/Xfuzz/pkg/corpus"
	"github.com/rom/Xfuzz/pkg/executor"
	"github.com/rom/Xfuzz/pkg/feedback"
	"github.com/rom/Xfuzz/pkg/mutate"
	"github.com/rom/Xfuzz/pkg/state"
)

// A seed is an execution, and an execution is judged.
//
// It was not, and the gap was quiet in exactly the way that matters: an
// operator who hands the fuzzer a reproducer as a seed — the obvious thing to
// do with one — got a campaign that admitted it to the corpus and said nothing,
// until a mutation happened to rediscover the same bug. On a fast tier that is
// a few thousand executions and looks like nothing; on the driver tier, where
// the seed usually *is* the reproducer somebody is trying to minimise, it can
// be never.

// echoExecutor runs nothing: it records the input and reports a clean exit,
// which is what an execution against an oracle-judged target looks like.
type echoExecutor struct{ last []byte }

func (e *echoExecutor) Name() string { return "echo" }

func (e *echoExecutor) Run(_ context.Context, in executor.Input, obs []feedback.Observer) (feedback.ExitKind, error) {
	if err := executor.Arm(obs, in); err != nil {
		return feedback.ExitError, err
	}
	e.last = append(e.last[:0], in.Bytes...)
	for _, o := range obs {
		if err := o.Post(feedback.ExitOK); err != nil {
			return feedback.ExitError, err
		}
	}
	return feedback.ExitOK, nil
}

func (e *echoExecutor) Reset(executor.ResetPolicy) error { return nil }
func (e *echoExecutor) Capabilities() executor.Caps      { return executor.Caps{Tier: executor.TierInProc} }
func (e *echoExecutor) Close() error                     { return nil }

// wordObjective reports a finding when the executed input contains a word. It
// stands in for every oracle that judges by inspection rather than by a crash —
// the API status oracle, the interface oracles, the web exception oracle.
type wordObjective struct {
	exec *echoExecutor
	word string
}

func (o *wordObjective) Name() string { return "word" }

func (o *wordObjective) IsFinding([]feedback.Observer, feedback.ExitKind) (bool, feedback.Finding, error) {
	if !strings.Contains(string(o.exec.last), o.word) {
		return false, feedback.Finding{}, nil
	}
	return true, feedback.Finding{
		Kind: "oracle", Summary: "the input contained " + o.word, Frames: []string{o.word},
	}, nil
}

func newSeedEngine(t *testing.T) (*Engine, *echoExecutor) {
	t.Helper()
	ex := &echoExecutor{}
	out := feedback.NewOutputObserver("output")
	eng, err := New(Config{
		CampaignSeed:  1,
		Executor:      ex,
		Observers:     []feedback.Observer{out},
		Feedback:      feedback.NewNoveltyFeedback("novelty", out),
		Objective:     &wordObjective{exec: ex, word: "boom"},
		Corpus:        corpus.New(),
		Schedule:      corpus.NewFastScheduler(),
		Mutators:      mutate.Default(),
		Codec:         codec.Raw{},
		MaxInputBytes: 4096,
	})
	if err != nil {
		t.Fatalf("building the engine: %v", err)
	}
	t.Cleanup(func() { eng.Close() })
	return eng, ex
}

func TestASeedThatIsAlreadyAFindingIsReported(t *testing.T) {
	eng, _ := newSeedEngine(t)
	if err := eng.AddSeed(context.Background(), []byte("a boom here"), "test"); err != nil {
		t.Fatalf("AddSeed: %v", err)
	}
	if got := len(eng.Findings()); got != 1 {
		t.Fatalf("a seed that is itself a finding produced %d findings, want 1", got)
	}
	if got := eng.Findings()[0].Summary; !strings.Contains(got, "boom") {
		t.Errorf("the finding does not describe what was found: %q", got)
	}
}

func TestAnOrdinarySeedIsNotAFinding(t *testing.T) {
	// The other half, and the half that would fill a findings list with every
	// seed a campaign was ever given.
	eng, _ := newSeedEngine(t)
	if err := eng.AddSeed(context.Background(), []byte("harmless"), "test"); err != nil {
		t.Fatalf("AddSeed: %v", err)
	}
	if got := len(eng.Findings()); got != 0 {
		t.Fatalf("an ordinary seed produced %d findings", got)
	}
}

func TestALoadedCorpusEntryThatIsAFindingIsReported(t *testing.T) {
	// The path the worker actually takes. It does not call AddSeed: it loads
	// the corpus, and a campaign with a state model then runs each entry once
	// to give it a trace. That pass ran the entry without judging it — which is
	// how a driver campaign whose very first seed reproduced a bug ran for its
	// whole budget without saying so. Measured before the fix on a web campaign
	// against a page with a planted exception: no finding in four minutes; after
	// it, reported from the seed.
	ex := &echoExecutor{}
	out := feedback.NewOutputObserver("output")
	eng, err := New(Config{
		CampaignSeed:  1,
		Executor:      ex,
		Observers:     []feedback.Observer{out},
		Feedback:      feedback.NewNoveltyFeedback("novelty", out),
		Objective:     &wordObjective{exec: ex, word: "boom"},
		Corpus:        corpus.New(),
		Schedule:      corpus.NewFastScheduler(),
		Mutators:      mutate.Default(),
		Codec:         codec.Raw{},
		MaxInputBytes: 4096,
		// A state model is what makes the tracing pass run at all, and every
		// driver campaign has one: guidance is on by default.
		State: state.NewGuidance(state.NewFingerprintFn()),
	})
	if err != nil {
		t.Fatalf("building the engine: %v", err)
	}
	defer eng.Close()

	entry := corpus.NewTestcase(nil, []byte("a boom here"))
	loaded, _, err := eng.LoadCorpus([]*corpus.Testcase{entry})
	if err != nil {
		t.Fatalf("LoadCorpus: %v", err)
	}
	if loaded != 1 {
		t.Fatalf("loaded %d entries, want 1", loaded)
	}
	if got := len(eng.Findings()); got != 1 {
		t.Fatalf("a loaded entry that is a finding produced %d findings, want 1", got)
	}
}
