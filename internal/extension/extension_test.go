package extension

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rom/Xfuzz/internal/safety"
	"github.com/rom/Xfuzz/internal/testenv"
	"github.com/rom/Xfuzz/pkg/campaign"
	"github.com/rom/Xfuzz/pkg/feedback"
	"github.com/rom/Xfuzz/pkg/ir"
	"github.com/rom/Xfuzz/pkg/mutate"
	"github.com/rom/Xfuzz/pkg/plugin"
)

// load starts a set of plugins for real: spawned through the safety layer,
// confined, and talking over their own pipes.
func load(t *testing.T, exts ...campaign.Extension) *Set {
	t.Helper()
	cfg := &campaign.Resolved{}
	cfg.Extensions = exts

	set, err := Load(context.Background(), safety.NewSpawner(), cfg, 0xfeedfacecafebeef, "test")
	if err != nil {
		t.Fatalf("loading the plugins: %v", err)
	}
	t.Cleanup(func() { set.Close() })
	return set
}

func reference(t *testing.T) string {
	t.Helper()
	return testenv.BuildPlugin(t, testenv.ReachableDir(t), "reference")
}

func observed(stdout, stderr string) []feedback.Observer {
	out := feedback.NewOutputObserver("output")
	out.Record([]byte(stdout), []byte(stderr), 0, 0)
	return []feedback.Observer{out}
}

func TestARealPluginProcessSuppliesAllThreeExtensionPoints(t *testing.T) {
	cmd := reference(t)
	set := load(t, campaign.Extension{
		Name:       "ref",
		Command:    cmd,
		Config:     map[string]string{"marker": "PANIC"},
		Feedbacks:  []string{"chatty"},
		Objectives: []string{"marker"},
		Mutators:   []string{"repeat"},
		Input:      true,
	})

	if got := len(set.Feedbacks()); got != 1 {
		t.Fatalf("feedbacks = %d, want 1", got)
	}
	if got := len(set.Objectives()); got != 1 {
		t.Fatalf("objectives = %d, want 1", got)
	}
	if got := len(set.Mutators()); got != 1 {
		t.Fatalf("mutators = %d, want 1", got)
	}
	if !set.WantsInput() {
		t.Error("the plugin asked for the input and the set does not know it")
	}

	fb := set.Feedbacks()[0]
	if got, want := fb.Name(), "ref:chatty"; got != want {
		t.Errorf("feedback name = %q, want %q", got, want)
	}

	// The feedback is stateful, and the state only means something because the
	// engine settles each judgement. Short output after long output is not
	// interesting; long output after short output is.
	interesting, _, err := fb.IsInteresting(observed("", "a longer line of output"), feedback.ExitOK)
	if err != nil {
		t.Fatal(err)
	}
	if !interesting {
		t.Fatal("the first execution produced output and was not interesting")
	}
	fb.Append()

	interesting, _, err = fb.IsInteresting(observed("", "short"), feedback.ExitOK)
	if err != nil {
		t.Fatal(err)
	}
	if interesting {
		t.Error("shorter output was interesting; the plugin's novelty state did not survive the commit")
	}

	// The objective fires on the marker the campaign configured, which is the
	// case that justifies the tier: no fuzzer can know what a project prints
	// when its own invariant breaks.
	obj := set.Objectives()[0]
	is, found, err := obj.IsFinding(observed("", "PANIC: chunk table corrupt"), feedback.ExitOK)
	if err != nil {
		t.Fatal(err)
	}
	if !is {
		t.Fatal("the configured marker did not produce a finding")
	}
	if !strings.Contains(found.Summary, "PANIC") {
		t.Errorf("finding = %+v, want the marker in the summary", found)
	}
	if is, _, _ := obj.IsFinding(observed("", "all is well"), feedback.ExitOK); is {
		t.Error("an ordinary execution was reported as a finding")
	}

	// And the mutator produces something different from what it was given.
	a := ir.NewArena()
	n := a.Alloc(ir.KindBytes, "payload")
	n.Raw = a.CopyBytes([]byte("hello world"))
	c := mutate.NewCtx(1, 0, a)
	if !set.Mutators()[0].Mutate(c, n) {
		t.Fatal("the plugin mutator produced nothing")
	}
	if string(n.Raw) == "hello world" {
		t.Error("the mutator returned the input unchanged")
	}

	if calls, inside := set.Stats(); calls == 0 || inside <= 0 {
		t.Errorf("stats = %d calls in %s; the extension overhead is not being measured", calls, inside)
	}
	if err := set.Err(); err != nil {
		t.Errorf("the set reports a failure after a clean run: %v", err)
	}
}

func TestAPluginThatIsNotThereFailsTheCampaignAtStartup(t *testing.T) {
	cfg := &campaign.Resolved{}
	cfg.Extensions = []campaign.Extension{{
		Name: "missing", Command: "/nonexistent/plugin", Feedbacks: []string{"anything"},
	}}

	_, err := Load(context.Background(), safety.NewSpawner(), cfg, 1, "test")
	if err == nil {
		t.Fatal("a campaign naming a plugin that does not exist started anyway")
	}
	if !strings.Contains(err.Error(), "missing") {
		t.Errorf("the failure does not name the extension: %v", err)
	}
}

func TestAnExtensionThePluginDoesNotProvideStopsTheCampaign(t *testing.T) {
	cfg := &campaign.Resolved{}
	cfg.Extensions = []campaign.Extension{{
		Name: "ref", Command: reference(t), Feedbacks: []string{"chatty", "not-a-feedback"},
	}}

	set, err := Load(context.Background(), safety.NewSpawner(), cfg, 1, "test")
	if err == nil {
		set.Close()
		t.Fatal("a campaign asking for an extension the plugin does not provide started anyway")
	}
	if !strings.Contains(err.Error(), "chatty") {
		t.Errorf("the failure does not say what is available: %v", err)
	}
}

func TestAPartlyLoadedSetLeavesNoPluginsRunning(t *testing.T) {
	cmd := reference(t)
	cfg := &campaign.Resolved{}
	cfg.Extensions = []campaign.Extension{
		{Name: "first", Command: cmd, Feedbacks: []string{"chatty"}},
		{Name: "second", Command: "/nonexistent/plugin", Feedbacks: []string{"chatty"}},
	}

	if _, err := Load(context.Background(), safety.NewSpawner(), cfg, 1, "test"); err == nil {
		t.Fatal("a set with an unstartable plugin loaded")
	}
	// The first plugin started and must not have been left behind. It reads
	// its standard input, so the proof is that the pipe was closed: a plugin
	// still running would hold the process table entry this test cannot see,
	// but a leaked one would keep the whole set's goroutines alive under the
	// race detector, which is what actually catches this.
}

func TestAPluginThatDiesEndsTheCampaignWithItsOwnWords(t *testing.T) {
	dir := testenv.ReachableDir(t)
	cmd := testenv.BuildAt(t, filepath.Join(dir, "dying"), "./internal/extension/testdata/dying")

	set := load(t, campaign.Extension{
		Name: "flaky", Command: cmd, Objectives: []string{"boom"},
		Timeout: campaign.Duration(2 * time.Second),
	})

	obj := set.Objectives()[0]
	_, _, err := obj.IsFinding(observed("", "anything"), feedback.ExitOK)
	if err == nil {
		t.Fatal("a judgement by a plugin that exits mid-call succeeded")
	}
	if !errors.Is(err, plugin.ErrFailed) {
		t.Errorf("the error does not wrap ErrFailed: %v", err)
	}
	if !strings.Contains(err.Error(), "the model file is gone") {
		t.Errorf("the plugin's dying words were lost; the host reported: %v", err)
	}
	if set.Err() == nil {
		t.Error("the set does not report the failure the worker will ask it for")
	}
}

// --- the script tier --------------------------------------------------------

func TestTheWorkedExampleScriptSuppliesAnOracleAMutatorAndAStateFunction(t *testing.T) {
	cfg := &campaign.Resolved{Path: filepath.Join(testenv.RepoRoot(t), "campaign.yaml")}
	cfg.Scripts = []campaign.Script{{
		Name:       "oracle",
		Path:       "examples/scripts/oracle.star",
		Config:     map[string]string{"forbidden": "root:x:0:0"},
		Objectives: []string{"leaked_secret"},
		Mutators:   []string{"flip_high_bit"},
	}}
	cfg.State = &campaign.State{Fn: "script", Script: "oracle:label"}

	set, err := Load(context.Background(), safety.NewSpawner(), cfg, 0xabcdef, "test")
	if err != nil {
		t.Fatalf("loading the script: %v", err)
	}
	t.Cleanup(func() { set.Close() })

	if got := len(set.Objectives()); got != 1 {
		t.Fatalf("objectives = %d, want 1", got)
	}
	is, found, err := set.Objectives()[0].IsFinding(
		observed("", "leaked root:x:0:0 from the config file"), feedback.ExitOK)
	if err != nil {
		t.Fatal(err)
	}
	if !is {
		t.Fatal("the oracle did not fire on the string the campaign forbade")
	}
	if !strings.Contains(found.Summary, "echoed") {
		t.Errorf("finding = %+v", found)
	}

	// The mutator produces something, from the seed and nothing else.
	a := ir.NewArena()
	n := a.Alloc(ir.KindBytes, "payload")
	n.Raw = a.CopyBytes([]byte("hello world"))
	if !set.Mutators()[0].Mutate(mutate.NewCtx(3, 0, a), n) {
		t.Fatal("the script mutator produced nothing")
	}
	if string(n.Raw) == "hello world" {
		t.Error("the mutator returned the input unchanged")
	}

	// And the state function labels a response.
	fn, err := set.StateFn("oracle:label")
	if err != nil {
		t.Fatal(err)
	}
	if got := fn.Label([]byte{7, 0, 0}); got != "status-7" {
		t.Errorf("label = %q, want status-7", got)
	}

	if err := set.Err(); err != nil {
		t.Errorf("the set reports a failure after a clean run: %v", err)
	}
}

func TestAScriptThatIsNotThereFailsTheCampaignAtStartup(t *testing.T) {
	cfg := &campaign.Resolved{}
	cfg.Scripts = []campaign.Script{{
		Name: "gone", Path: "/nonexistent/oracle.star", Objectives: []string{"check"},
	}}
	_, err := Load(context.Background(), safety.NewSpawner(), cfg, 1, "test")
	if err == nil {
		t.Fatal("a campaign naming a script that does not exist started anyway")
	}
	if !strings.Contains(err.Error(), "gone") {
		t.Errorf("the failure does not name the script: %v", err)
	}
}

func TestAFunctionTheScriptDoesNotDefineStopsTheCampaign(t *testing.T) {
	cfg := &campaign.Resolved{Path: filepath.Join(testenv.RepoRoot(t), "campaign.yaml")}
	cfg.Scripts = []campaign.Script{{
		Name: "oracle", Path: "examples/scripts/oracle.star", Objectives: []string{"leaked_secrets"},
	}}
	_, err := Load(context.Background(), safety.NewSpawner(), cfg, 1, "test")
	if err == nil {
		t.Fatal("a campaign asking for a function the script does not define started anyway")
	}
	if !strings.Contains(err.Error(), "leaked_secret") {
		t.Errorf("the failure does not say what is available: %v", err)
	}
}
