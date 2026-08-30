package script

import (
	"errors"
	"strings"
	"testing"

	"github.com/rom/Xfuzz/pkg/feedback"
	"github.com/rom/Xfuzz/pkg/ir"
	"github.com/rom/Xfuzz/pkg/mutate"
)

func load(t *testing.T, src string, tune ...func(*Options)) *Script {
	t.Helper()
	opts := Options{Seed: 0x0123456789abcdef, Config: map[string]string{"marker": "BOOM"}}
	for _, f := range tune {
		f(&opts)
	}
	s, err := Load("oracle.star", []byte(src), opts)
	if err != nil {
		t.Fatalf("loading the script: %v", err)
	}
	return s
}

func observed(stdout, stderr string, ek feedback.ExitKind) []feedback.Observer {
	out := feedback.NewOutputObserver("output")
	out.Record([]byte(stdout), []byte(stderr), 0, 0)
	in := feedback.NewInputObserver("input")
	in.RecordInput([]byte("the input"))
	cov := feedback.NewCoverageMap("coverage", 32)
	cov.SetBackend("sancov")
	cov.Buffer()[1] = 1
	return []feedback.Observer{out, cov, in}
}

func TestAnOracleWrittenInFourLines(t *testing.T) {
	s := load(t, `
def check(x):
    if config["marker"] in x.stderr:
        return finding(summary = "the target said " + config["marker"], detail = x.stderr)
    return None
`)
	o, err := s.NewObjective("check")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := o.Name(), "oracle.star:check"; got != want {
		t.Errorf("name = %q, want %q", got, want)
	}

	is, found, err := o.IsFinding(observed("", "assertion: BOOM at chunk 3", feedback.ExitOK), feedback.ExitOK)
	if err != nil {
		t.Fatal(err)
	}
	if !is {
		t.Fatal("the oracle did not fire on its own marker")
	}
	if found.Kind != "oracle" || !strings.Contains(found.Summary, "BOOM") {
		t.Errorf("finding = %+v, want an oracle finding naming the marker", found)
	}
	if !strings.Contains(found.Detail, "chunk 3") {
		t.Errorf("the detail lost the target's output: %q", found.Detail)
	}

	if is, _, _ := o.IsFinding(observed("", "all quiet", feedback.ExitOK), feedback.ExitOK); is {
		t.Error("the oracle fired on an execution that said nothing interesting")
	}
}

func TestAnOracleSeesEveryFieldOfAnExecution(t *testing.T) {
	s := load(t, `
def check(x):
    return finding(summary = "%s/%d/%d/%s/%s" % (x.exit, x.edges, x.signal, x.backend, x.input))
`)
	o, err := s.NewObjective("check")
	if err != nil {
		t.Fatal(err)
	}
	_, found, err := o.IsFinding(observed("out", "err", feedback.ExitTimeout), feedback.ExitTimeout)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"timeout", "/1/", "sancov", "the input"} {
		if !strings.Contains(found.Summary, want) {
			t.Errorf("the observation is missing %q: %s", want, found.Summary)
		}
	}
}

func TestABareStringIsAFindingBecauseThatIsWhatPeopleWriteFirst(t *testing.T) {
	s := load(t, `
def check(x):
    if x.exit == "crash":
        return "it crashed and the oracle noticed"
    return None
`)
	o, _ := s.NewObjective("check")
	is, found, err := o.IsFinding(observed("", "", feedback.ExitCrash), feedback.ExitCrash)
	if err != nil {
		t.Fatal(err)
	}
	if !is || found.Kind != "oracle" {
		t.Fatalf("a returned string did not become an oracle finding: %v %+v", is, found)
	}
	if found.Summary != "it crashed and the oracle noticed" {
		t.Errorf("summary = %q", found.Summary)
	}
}

func TestAnOracleThatReturnsNonsenseIsAnErrorRatherThanAGuess(t *testing.T) {
	s := load(t, "def check(x):\n    return 17\n")
	o, _ := s.NewObjective("check")
	_, _, err := o.IsFinding(observed("", "", feedback.ExitOK), feedback.ExitOK)
	if err == nil {
		t.Fatal("an oracle returning a number was accepted")
	}
	if !strings.Contains(err.Error(), "return None") {
		t.Errorf("the error does not say what to return: %v", err)
	}
	// Sticky: the same bug on the next execution must not repeat the message
	// on every execution for the rest of the campaign.
	if _, _, again := o.IsFinding(observed("", "", feedback.ExitOK), feedback.ExitOK); again == nil {
		t.Error("a broken oracle started working again")
	}
}

func TestAMisspelledFieldIsAnErrorRatherThanNone(t *testing.T) {
	s := load(t, "def check(x):\n    return x.stdrr\n")
	o, _ := s.NewObjective("check")
	_, _, err := o.IsFinding(observed("", "", feedback.ExitOK), feedback.ExitOK)
	if err == nil {
		t.Fatal("a misspelled field produced no error; the oracle would silently never fire")
	}
	if !strings.Contains(err.Error(), "stderr") {
		t.Errorf("the error does not suggest the field that exists: %v", err)
	}
}

func TestALoopingScriptIsStoppedByItsStepBudget(t *testing.T) {
	s := load(t, `
def check(x):
    n = 0
    for i in range(1000000000):
        n += i
    return None
`, func(o *Options) { o.Limits = Limits{Steps: 50000, Quantum: 1000} })

	o, _ := s.NewObjective("check")
	_, _, err := o.IsFinding(observed("", "", feedback.ExitOK), feedback.ExitOK)
	if err == nil {
		t.Fatal("a script looping a billion times ran to completion")
	}
	if !errors.Is(err, ErrBudget) {
		t.Errorf("the error does not wrap ErrBudget: %v", err)
	}
	if !strings.Contains(err.Error(), "50000 steps") {
		t.Errorf("the error does not name the budget: %v", err)
	}
}

func TestAScriptThatEatsMemoryIsStoppedByItsAllocationBudget(t *testing.T) {
	// Starlark's own guard is a hard gigabyte per single operation, which stops
	// one enormous multiply and nothing else. Concatenating in a loop stays
	// under it on every step and passes it in total, which is exactly the case
	// the allocation budget exists for.
	s := load(t, `
def check(x):
    s = "x" * 4096
    acc = []
    for i in range(1000000):
        acc.append(s * 64)
    return None
`, func(o *Options) { o.Limits = Limits{Steps: 1 << 30, Allocs: 8 << 20, Quantum: 256} })

	o, _ := s.NewObjective("check")
	_, _, err := o.IsFinding(observed("", "", feedback.ExitOK), feedback.ExitOK)
	if err == nil {
		t.Fatal("a script allocating without bound ran to completion")
	}
	if !errors.Is(err, ErrBudget) {
		t.Errorf("the error does not wrap ErrBudget: %v", err)
	}
	if !strings.Contains(err.Error(), "bytes") {
		t.Errorf("the error does not name the allocation budget: %v", err)
	}
}

func TestTheBudgetIsPerCallRatherThanPerScript(t *testing.T) {
	s := load(t, `
def check(x):
    n = 0
    for i in range(200):
        n += i
    return None
`, func(o *Options) { o.Limits = Limits{Steps: 5000, Quantum: 64} })

	o, _ := s.NewObjective("check")
	obs := observed("", "", feedback.ExitOK)
	// Each call is well within the budget; a hundred of them must not add up
	// to an exhausted one, or a campaign would fail after enough executions.
	for i := 0; i < 100; i++ {
		if _, _, err := o.IsFinding(obs, feedback.ExitOK); err != nil {
			t.Fatalf("call %d failed although each is inside the budget: %v", i, err)
		}
	}
}

func TestAScriptCannotReachOutsideItself(t *testing.T) {
	// The hermeticity claim, checked rather than asserted. Starlark has no
	// filesystem, network or clock; what a host can hand it is load(), and
	// this one does not.
	for _, tc := range []struct{ name, src string }{
		{"load", `load("other.star", "helper")` + "\ndef check(x):\n    return None\n"},
		{"open", "def check(x):\n    return open(\"/etc/passwd\")\n"},
		{"time", "def check(x):\n    return time.now()\n"},
		{"exec", "def check(x):\n    return exec(\"ls\")\n"},
		{"while", "def check(x):\n    while True:\n        pass\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, err := Load("x.star", []byte(tc.src), Options{})
			if err != nil {
				return // refused at load, which is the best outcome
			}
			o, err := s.NewObjective("check")
			if err != nil {
				return
			}
			if _, _, err := o.IsFinding(observed("", "", feedback.ExitOK), feedback.ExitOK); err == nil {
				t.Errorf("a script reached %s and was not stopped", tc.name)
			}
		})
	}
}

func TestAScriptSeesTheCampaignSeedAtFullWidth(t *testing.T) {
	s := load(t, `
def check(x):
    return "%d" % seed
`)
	o, _ := s.NewObjective("check")
	_, found, err := o.IsFinding(observed("", "", feedback.ExitOK), feedback.ExitOK)
	if err != nil {
		t.Fatal(err)
	}
	if found.Summary != "81985529216486895" {
		t.Errorf("seed = %s, want 81985529216486895: a 64-bit seed did not survive the bridge", found.Summary)
	}
}

func TestAScriptCannotKeepStateBetweenCalls(t *testing.T) {
	// The honest limit of this tier, and the reason feedbacks belong to the
	// plugin one. Module globals are frozen after load, so a script that tried
	// to accumulate novelty state fails loudly rather than silently doing
	// nothing.
	s := load(t, `
seen = []

def check(x):
    seen.append(x.exit)
    return None
`)
	o, _ := s.NewObjective("check")
	_, _, err := o.IsFinding(observed("", "", feedback.ExitOK), feedback.ExitOK)
	if err == nil {
		t.Fatal("a script mutated a module global; the tier is not as hermetic as documented")
	}
	if !strings.Contains(err.Error(), "frozen") {
		t.Errorf("the failure does not explain itself: %v", err)
	}
}

func TestPrintGoesToABufferRatherThanTheWorkersOutput(t *testing.T) {
	s := load(t, `
def check(x):
    print("looked at", x.exit)
    return None
`)
	o, _ := s.NewObjective("check")
	if _, _, err := o.IsFinding(observed("", "", feedback.ExitCrash), feedback.ExitCrash); err != nil {
		t.Fatal(err)
	}
	said := s.Printed()
	if len(said) != 1 || !strings.Contains(said[0], "crash") {
		t.Errorf("printed = %v, want one line naming the exit kind", said)
	}
}

// --- the mutator ------------------------------------------------------------

func TestAScriptMutatorRewritesAPayload(t *testing.T) {
	s := load(t, `
def vary(input, seed, count, max_bytes):
    out = []
    for i in range(count):
        out.append(input + bytes([(seed + i) % 256]))
    return out
`)
	m, err := s.NewMutator("vary")
	if err != nil {
		t.Fatal(err)
	}
	m.SetBatch(4)

	a := ir.NewArena()
	c := mutate.NewCtx(1, 0, a)
	seed := []byte("payload")

	node := func() *ir.Node {
		n := a.Alloc(ir.KindBytes, "payload")
		n.Raw = a.CopyBytes(seed)
		return n
	}
	n := node()
	if !m.CanApply(c, n) {
		t.Fatal("the mutator declined a plain payload node")
	}
	if !m.Mutate(c, n) {
		t.Fatal("the mutator produced nothing")
	}
	if len(n.Raw) != len(seed)+1 || string(n.Raw[:len(seed)]) != "payload" {
		t.Errorf("payload = %q, want the input with a byte appended", n.Raw)
	}
	if m.Err() != nil {
		t.Errorf("the mutator failed: %v", m.Err())
	}
}

func TestAScriptMutatorThatRaisesStopsOfferingItself(t *testing.T) {
	s := load(t, `
def vary(input, seed, count, max_bytes):
    fail("the dictionary is empty")
`)
	m, _ := s.NewMutator("vary")

	a := ir.NewArena()
	n := a.Alloc(ir.KindBytes, "payload")
	n.Raw = a.CopyBytes([]byte("abcd"))
	c := mutate.NewCtx(1, 0, a)

	if m.Mutate(c, n) {
		t.Fatal("a raising mutator reported a mutation")
	}
	if m.Err() == nil {
		t.Fatal("the failure left no trace; the campaign would run on with a dead operator")
	}
	if !strings.Contains(m.Err().Error(), "the dictionary is empty") {
		t.Errorf("the script's own words were lost: %v", m.Err())
	}
	if m.CanApply(c, n) {
		t.Error("a failed operator still offers itself to the scheduler")
	}
}

func TestAScriptMutatorRespectsTheSchemasBounds(t *testing.T) {
	s := load(t, `
def vary(input, seed, count, max_bytes):
    return [input + b"much too long", b"IHDR"]
`)
	m, _ := s.NewMutator("vary")

	a := ir.NewArena()
	n := a.Alloc(ir.KindBytes, "payload")
	n.Raw = a.CopyBytes([]byte("IEND"))
	n.MinLen, n.MaxLen = 4, 4
	c := mutate.NewCtx(1, 0, a)

	if !m.Mutate(c, n) {
		t.Fatal("nothing was applied although one variant fitted")
	}
	if string(n.Raw) != "IHDR" {
		t.Errorf("payload = %q, want IHDR: an out-of-bounds variant was used", n.Raw)
	}
}

// --- the state function -----------------------------------------------------

func TestAStateFunctionLabelsAResponse(t *testing.T) {
	s := load(t, `
def label(resp):
    if len(resp) < 3:
        return None
    return "status-" + str(list(resp.elems())[0])
`)
	f, err := s.NewStateFn("label")
	if err != nil {
		t.Fatal(err)
	}
	if got := f.Label([]byte{5, 1, 1}); got != "status-5" {
		t.Errorf("label = %q, want status-5", got)
	}
	// "Cannot tell" is a first-class answer: the trace records Unknown rather
	// than a guess.
	if got := f.Label([]byte{5}); got != "" {
		t.Errorf("label = %q, want an empty label for a response it cannot read", got)
	}
	if f.Err() != nil {
		t.Errorf("returning None was treated as a failure: %v", f.Err())
	}
}

func TestABrokenScriptIsRefusedAtLoadWithALineNumber(t *testing.T) {
	_, err := Load("broken.star", []byte("def check(x)\n    return None\n"), Options{})
	if err == nil {
		t.Fatal("a script that does not parse was loaded")
	}
	if !strings.Contains(err.Error(), "broken.star:2") {
		t.Errorf("the error does not name the file and line: %v", err)
	}
}

func TestAFunctionTheScriptDoesNotDefineIsRefusedAtStartup(t *testing.T) {
	s := load(t, "def check(x):\n    return None\n")
	if _, err := s.NewObjective("chekc"); err == nil {
		t.Fatal("a misspelled function name was accepted")
	} else if !strings.Contains(err.Error(), "check") {
		t.Errorf("the refusal does not say what is available: %v", err)
	}
}
