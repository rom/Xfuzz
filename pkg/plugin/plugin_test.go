package plugin

import (
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rom/Xfuzz/pkg/feedback"
	"github.com/rom/Xfuzz/pkg/ir"
	"github.com/rom/Xfuzz/pkg/mutate"
	"github.com/rom/Xfuzz/pkg/rng"
)

// harness runs a plugin over a pair of pipes, which is the same protocol a real
// plugin process speaks — only the pipes come from io.Pipe rather than from a
// spawned process. What that buys is a test of the protocol that does not
// depend on a compiler being present.
type harness struct {
	host *Host

	toPlugin   *io.PipeWriter
	fromPlugin *io.PipeReader

	mu     sync.Mutex
	stderr strings.Builder
	served chan error
}

func (h *harness) say(s string) {
	h.mu.Lock()
	h.stderr.WriteString(s)
	h.mu.Unlock()
}

func (h *harness) diagnose() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.stderr.String()
}

// dial starts a plugin and connects a host to it.
func dial(t *testing.T, p Plugin, tune ...func(*Options)) *harness {
	t.Helper()

	pluginIn, hostOut := io.Pipe()
	hostIn, pluginOut := io.Pipe()
	h := &harness{toPlugin: hostOut, fromPlugin: hostIn, served: make(chan error, 1)}

	go func() { h.served <- ServeOn(pluginIn, pluginOut, p) }()

	opts := Options{
		Label:  "test",
		Engine: "test-engine",
		Seed:   0x0123456789abcdef,
		Transport: Transport{
			Stdin:    hostOut,
			Stdout:   hostIn,
			Diagnose: h.diagnose,
			Kill: func() error {
				hostIn.Close()
				hostOut.Close()
				return nil
			},
		},
		CallTimeout:      2 * time.Second,
		HandshakeTimeout: 2 * time.Second,
	}
	for _, f := range tune {
		f(&opts)
	}

	host, err := Dial(opts)
	if err != nil {
		t.Fatalf("dialling the plugin: %v", err)
	}
	t.Cleanup(func() { host.Close() })
	h.host = host
	return h
}

// counting is a feedback that remembers what it was told and how it was
// settled, so a test can see the protocol from the plugin's side.
type counting struct {
	mu       sync.Mutex
	judged   int
	commits  []bool
	seenKeep bool
}

func (c *counting) Judge(batch []Observation) ([]Verdict, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.judged += len(batch)
	out := make([]Verdict, len(batch))
	for i, ob := range batch {
		out[i] = Verdict{Interesting: ob.Exit == "crash", NewSignal: ob.Edges, Novelty: 0.5}
	}
	return out, nil
}

func (c *counting) Commit(keep bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.commits = append(c.commits, keep)
	c.seenKeep = keep
}

func (c *counting) settled() []bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]bool(nil), c.commits...)
}

func observers(exit feedback.ExitKind) []feedback.Observer {
	out := feedback.NewOutputObserver("output")
	out.Record([]byte("hello"), []byte("boom"), 1, 11)
	cov := feedback.NewCoverageMap("coverage", 64)
	cov.SetBackend("sancov")
	cov.Buffer()[3] = 1
	cov.Buffer()[9] = 4
	in := feedback.NewInputObserver("input")
	in.RecordInput([]byte("the input"))
	return []feedback.Observer{out, cov, in}
}

func TestAPluginJudgesAnExecutionAcrossTheBoundary(t *testing.T) {
	fb := &counting{}
	h := dial(t, Plugin{
		Name:      "reference",
		Version:   "0.1",
		Feedbacks: map[string]Judger{"custom": fb},
	})

	if got := h.host.Name(); got != "reference" {
		t.Errorf("plugin name = %q, want reference", got)
	}
	if got := h.host.Provides().Feedbacks; len(got) != 1 || got[0] != "custom" {
		t.Errorf("provides = %v, want [custom]", got)
	}

	f, err := h.host.NewFeedback("custom")
	if err != nil {
		t.Fatalf("resolving the feedback: %v", err)
	}
	if got, want := f.Name(), "test:custom"; got != want {
		t.Errorf("feedback name = %q, want %q", got, want)
	}

	interesting, score, err := f.IsInteresting(observers(feedback.ExitCrash), feedback.ExitCrash)
	if err != nil {
		t.Fatalf("judging: %v", err)
	}
	if !interesting {
		t.Error("the plugin found a crash uninteresting; it was told the exit kind")
	}
	if score.NewSignal != 2 {
		t.Errorf("new signal = %d, want 2: the coverage cardinality did not cross the boundary", score.NewSignal)
	}
	if score.Novelty != 0.5 {
		t.Errorf("novelty = %v, want 0.5", score.Novelty)
	}
}

func TestACommitRidesOnTheNextCallRatherThanARoundTripOfItsOwn(t *testing.T) {
	fb := &counting{}
	h := dial(t, Plugin{Feedbacks: map[string]Judger{"custom": fb}})
	f, err := h.host.NewFeedback("custom")
	if err != nil {
		t.Fatal(err)
	}

	obs := observers(feedback.ExitOK)
	if _, _, err := f.IsInteresting(obs, feedback.ExitOK); err != nil {
		t.Fatal(err)
	}
	f.Append()

	// One call so far, and Append must not have cost another. That is the
	// whole point of folding it in: the hot path pays one round trip per
	// execution, not two.
	if got := h.host.Calls(); got != 2 { // hello, judge
		t.Fatalf("calls after one judgement and an Append = %d, want 2 (hello and judge)", got)
	}
	if got := fb.settled(); len(got) != 0 {
		t.Fatalf("the plugin was settled %v before the next call; the commit did not wait", got)
	}

	if _, _, err := f.IsInteresting(obs, feedback.ExitOK); err != nil {
		t.Fatal(err)
	}
	f.Discard()

	if got := fb.settled(); len(got) != 1 || !got[0] {
		t.Fatalf("settled = %v, want [true]: the second judge should have carried the first Append", got)
	}
	if got := h.host.Calls(); got != 3 {
		t.Fatalf("calls = %d, want 3: the commit rode along", got)
	}

	// Closing flushes what is still owed, so a plugin that persists what it
	// learned is not cheated of the last judgement.
	if err := h.host.Close(); err != nil {
		t.Fatalf("closing: %v", err)
	}
	if got := fb.settled(); len(got) != 2 || got[1] {
		t.Fatalf("settled = %v, want [true false]: Close did not flush the Discard", got)
	}
}

func TestAnObjectiveReportsAFinding(t *testing.T) {
	h := dial(t, Plugin{
		Objectives: map[string]Oracle{
			"invariant": OracleFunc(func(batch []Observation) ([]Verdict, error) {
				out := make([]Verdict, len(batch))
				for i, ob := range batch {
					if string(ob.Input) == "the input" {
						out[i].Finding = &Finding{
							Kind: "oracle", Summary: "the input reached the oracle",
							Frames: []string{"check", "main"},
						}
					}
				}
				return out, nil
			}),
		},
	})

	o, err := h.host.NewObjective("invariant")
	if err != nil {
		t.Fatal(err)
	}
	is, found, err := o.IsFinding(observers(feedback.ExitOK), feedback.ExitOK)
	if err != nil {
		t.Fatal(err)
	}
	if !is {
		t.Fatal("the objective saw no finding; the input did not cross the boundary")
	}
	if found.Kind != "oracle" || len(found.Frames) != 2 {
		t.Errorf("finding = %+v, want an oracle finding with two frames", found)
	}
}

func TestAnObservationCarriesWhatAnObserverExposes(t *testing.T) {
	ob := Observe(observers(feedback.ExitTimeout), feedback.ExitTimeout)
	switch {
	case ob.Exit != "timeout":
		t.Errorf("exit = %q, want timeout", ob.Exit)
	case string(ob.Stderr) != "boom":
		t.Errorf("stderr = %q, want boom", ob.Stderr)
	case ob.Signal != 11 || ob.ExitCode != 1:
		t.Errorf("status = %d/%d, want 1/11", ob.ExitCode, ob.Signal)
	case ob.Edges != 2:
		t.Errorf("edges = %d, want 2", ob.Edges)
	case ob.Backend != "sancov":
		t.Errorf("backend = %q, want sancov", ob.Backend)
	case string(ob.Input) != "the input":
		t.Errorf("input = %q, want \"the input\"", ob.Input)
	}

	// An execution with no input observer sends no input, which is the default
	// and the reason the copy is not paid for by every campaign.
	bare := Observe([]feedback.Observer{feedback.NewOutputObserver("o")}, feedback.ExitOK)
	if bare.Input != nil {
		t.Errorf("input = %q with no input observer wired; it should be absent", bare.Input)
	}
}

func TestAPluginSpeakingAnotherProtocolIsRefused(t *testing.T) {
	// A plugin that answers the handshake with the wrong version. Written by
	// hand rather than with the SDK, because the SDK is what makes getting it
	// right easy and the case worth testing is the plugin that does not.
	pluginIn, hostOut := io.Pipe()
	hostIn, pluginOut := io.Pipe()
	go func() {
		conn := NewConn(pluginIn, pluginOut)
		var req Request
		if err := conn.Receive(&req); err != nil {
			return
		}
		conn.Send(&Response{ID: req.ID, Protocol: ProtocolVersion + 7, Name: "from-the-future"})
	}()

	_, err := Dial(Options{
		Label:     "future",
		Transport: Transport{Stdin: hostOut, Stdout: hostIn, Kill: func() error { hostIn.Close(); return hostOut.Close() }},
	})
	if err == nil {
		t.Fatal("a plugin from another protocol version was accepted")
	}
	for _, want := range []string{"future", "protocol", "rebuild"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not mention %q: %v", want, err)
		}
	}
}

func TestAPluginThatDiesFailsItsCampaignAndStaysFailed(t *testing.T) {
	var h *harness
	dying := &dyingFeedback{}
	h = dial(t, Plugin{Feedbacks: map[string]Judger{"custom": dying}})
	dying.kill = func() { h.fromPlugin.Close() }

	f, err := h.host.NewFeedback("custom")
	if err != nil {
		t.Fatal(err)
	}
	obs := observers(feedback.ExitOK)

	if _, _, err := f.IsInteresting(obs, feedback.ExitOK); err != nil {
		t.Fatalf("the first judgement should have succeeded: %v", err)
	}
	_, _, err = f.IsInteresting(obs, feedback.ExitOK)
	if err == nil {
		t.Fatal("a judgement against a dead plugin succeeded")
	}
	if !errors.Is(err, ErrFailed) {
		t.Errorf("error does not wrap ErrFailed: %v", err)
	}
	if !strings.Contains(err.Error(), "test") {
		t.Errorf("the failure does not name the plugin: %v", err)
	}

	// Sticky: the campaign asks once and gets the same answer, and the
	// adapters stop offering themselves.
	if h.host.Err() == nil {
		t.Error("Err() reports nothing after the plugin died")
	}
	if again := h.host.Err().Error(); again != err.Error() {
		t.Errorf("the second reading of the failure differs:\n %s\n %s", err, again)
	}
	if _, _, err := f.IsInteresting(obs, feedback.ExitOK); err == nil {
		t.Error("a third call succeeded against a failed plugin")
	}
}

// dyingFeedback answers once and then makes the process disappear.
type dyingFeedback struct {
	kill  func()
	calls int
}

func (d *dyingFeedback) Judge(batch []Observation) ([]Verdict, error) {
	d.calls++
	if d.calls > 1 {
		d.kill()
		select {} // never answers; the host sees the pipe close
	}
	return make([]Verdict, len(batch)), nil
}

func (d *dyingFeedback) Commit(bool) {}

func TestAPluginThatStopsAnsweringIsKilled(t *testing.T) {
	stuck := make(chan struct{})
	t.Cleanup(func() { close(stuck) })

	h := dial(t, Plugin{
		Objectives: map[string]Oracle{
			"slow": OracleFunc(func(batch []Observation) ([]Verdict, error) {
				<-stuck
				return make([]Verdict, len(batch)), nil
			}),
		},
	}, func(o *Options) { o.CallTimeout = 150 * time.Millisecond })

	o, err := h.host.NewObjective("slow")
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if _, _, err := o.IsFinding(observers(feedback.ExitOK), feedback.ExitOK); err == nil {
		t.Fatal("a plugin that never answered did not fail the call")
	} else if !strings.Contains(err.Error(), "did not answer") {
		t.Errorf("the failure does not say what happened: %v", err)
	}
	if waited := time.Since(start); waited > 2*time.Second {
		t.Errorf("the host waited %s on a plugin with a 150ms timeout", waited)
	}
}

func TestAWrongNumberOfVerdictsIsCaught(t *testing.T) {
	h := dial(t, Plugin{
		Objectives: map[string]Oracle{
			"short": OracleFunc(func([]Observation) ([]Verdict, error) { return nil, nil }),
		},
	})
	o, err := h.host.NewObjective("short")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := o.IsFinding(observers(feedback.ExitOK), feedback.ExitOK); err == nil {
		t.Fatal("a plugin returning no verdicts was believed")
	} else if !strings.Contains(err.Error(), "verdicts") {
		t.Errorf("the failure does not explain the contract: %v", err)
	}
}

func TestAnExtensionThePluginDoesNotProvideIsRefusedAtStartup(t *testing.T) {
	h := dial(t, Plugin{Feedbacks: map[string]Judger{"custom": &counting{}}})

	if _, err := h.host.NewFeedback("costom"); err == nil {
		t.Fatal("a misspelled feedback was accepted")
	} else if !strings.Contains(err.Error(), "custom") {
		t.Errorf("the refusal does not say what is available: %v", err)
	}
	if _, err := h.host.NewMutator("anything"); err == nil {
		t.Fatal("a mutator was resolved against a plugin that provides none")
	} else if !strings.Contains(err.Error(), "no mutators at all") {
		t.Errorf("the refusal should say the plugin provides none: %v", err)
	}
}

func TestAPluginsOwnErrorFailsTheCallButNotTheProcess(t *testing.T) {
	h := dial(t, Plugin{
		Objectives: map[string]Oracle{
			"picky": OracleFunc(func(batch []Observation) ([]Verdict, error) {
				if len(batch) > 0 && batch[0].Exit == "crash" {
					return nil, errors.New("this oracle cannot judge a crash")
				}
				return make([]Verdict, len(batch)), nil
			}),
		},
	})
	o, err := h.host.NewObjective("picky")
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = o.IsFinding(observers(feedback.ExitCrash), feedback.ExitCrash)
	if err == nil {
		t.Fatal("the plugin's refusal was not reported")
	}
	if !strings.Contains(err.Error(), "cannot judge a crash") {
		t.Errorf("the plugin's own words are missing: %v", err)
	}
	if errors.Is(err, ErrFailed) {
		t.Error("a plugin that declined a call was treated as dead")
	}
	if h.host.Err() != nil {
		t.Errorf("the host failed over a call the plugin merely refused: %v", h.host.Err())
	}
	// Still alive, still answering.
	if _, _, err := o.IsFinding(observers(feedback.ExitOK), feedback.ExitOK); err != nil {
		t.Errorf("the plugin stopped working after declining one call: %v", err)
	}
}

func TestNoveltyFromAPluginIsClampedToTheRangeTheSchedulerAssumes(t *testing.T) {
	for _, tc := range []struct{ got, want float64 }{
		{400, 1}, {-3, 0}, {0.25, 0.25},
	} {
		v := Verdict{Novelty: tc.got}
		if got := v.score().Novelty; got != tc.want {
			t.Errorf("a plugin novelty of %v became %v, want %v", tc.got, got, tc.want)
		}
	}
}

func TestAFrameBeyondTheLimitIsRefusedRatherThanAllocated(t *testing.T) {
	var sink strings.Builder
	c := NewConn(strings.NewReader(""), &sink)
	c.SetMaxFrame(64)
	err := c.Send(&Request{Op: OpMutate, Input: make([]byte, 1024)})
	if !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("sending an oversized frame gave %v, want ErrFrameTooLarge", err)
	}

	// And on the way in: a length a hostile plugin announced is never trusted.
	hdr := []byte{0x7f, 0xff, 0xff, 0xff}
	in := NewConn(strings.NewReader(string(hdr)), &sink)
	in.SetMaxFrame(64)
	var req Request
	if err := in.Receive(&req); !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("receiving an announced 2GB frame gave %v, want ErrFrameTooLarge", err)
	}
}

// --- the mutator ------------------------------------------------------------

func payloadNode(a *ir.Arena, b []byte) *ir.Node {
	n := a.Alloc(ir.KindBytes, "payload")
	n.Raw = a.CopyBytes(b)
	return n
}

func mutCtx(a *ir.Arena) *mutate.Ctx {
	c := mutate.NewCtx(7, 0, a)
	return c
}

func TestAPluginMutatorAmortisesTheRoundTripAcrossABatch(t *testing.T) {
	var calls int
	h := dial(t, Plugin{
		Mutators: map[string]Varier{
			"flipper": VaryFunc(func(input []byte, seed uint64, count, _ int) ([][]byte, error) {
				calls++
				r := rng.New(seed)
				out := make([][]byte, count)
				for i := range out {
					v := append([]byte(nil), input...)
					v[r.Intn(len(v))] ^= 0xff
					out[i] = v
				}
				return out, nil
			}),
		},
	})

	m, err := h.host.NewMutator("flipper")
	if err != nil {
		t.Fatal(err)
	}
	m.SetBatch(8)

	// The engine mutates a fresh clone of a corpus entry on every iteration, so
	// successive iterations from the same parent offer the same payload. That
	// is where a batch pays: one round trip covers all of them.
	a := ir.NewArena()
	c := mutCtx(a)
	seed := []byte("aaaaaaaaaaaaaaaa")

	if !m.CanApply(c, payloadNode(a, seed)) {
		t.Fatal("the mutator declined a plain payload node")
	}
	for i := 0; i < 8; i++ {
		if !m.Mutate(c, payloadNode(a, seed)) {
			t.Fatalf("mutation %d produced nothing", i)
		}
	}
	if calls != 1 {
		t.Errorf("the plugin was called %d times for 8 mutations of one parent; the batch is not amortising", calls)
	}
	if !m.Mutate(c, payloadNode(a, seed)) {
		t.Fatal("the ninth mutation produced nothing")
	}
	if calls != 2 {
		t.Errorf("calls = %d after nine mutations, want 2", calls)
	}

	// A different payload must not be served variants of the previous one. A
	// stale batch would not be a mutation of this input, it would be a
	// substitution — and the campaign's provenance would record a lie.
	if !m.Mutate(c, payloadNode(a, []byte("zzzzzzzzzzzzzzzz"))) {
		t.Fatal("a new payload produced nothing")
	}
	if calls != 3 {
		t.Errorf("calls = %d, want 3: the queue was not invalidated by a new payload", calls)
	}
}

func TestAVariantThatBreaksTheSchemaIsDroppedRatherThanTrimmed(t *testing.T) {
	h := dial(t, Plugin{
		Mutators: map[string]Varier{
			"grower": VaryFunc(func(input []byte, _ uint64, count, _ int) ([][]byte, error) {
				// One variant that fits and several that do not, so the host
				// has to be the one enforcing the bound.
				return [][]byte{
					append([]byte(nil), "much too long to fit in four bytes"...),
					append([]byte(nil), "ab"...),
					append([]byte(nil), "IHDR"...),
				}, nil
			}),
		},
	})
	m, err := h.host.NewMutator("grower")
	if err != nil {
		t.Fatal(err)
	}

	a := ir.NewArena()
	n := payloadNode(a, []byte("IEND"))
	n.MinLen, n.MaxLen = 4, 4
	c := mutCtx(a)

	if !m.Mutate(c, n) {
		t.Fatal("nothing was applied although one variant fitted")
	}
	if got := string(n.Raw); got != "IHDR" {
		t.Fatalf("payload = %q, want IHDR: an out-of-bounds variant was used or trimmed", got)
	}
	if len(n.Raw) != 4 {
		t.Fatalf("the node's length bound was broken: %d bytes", len(n.Raw))
	}
}

func TestAFailedPluginStopsOfferingItsMutator(t *testing.T) {
	h := dial(t, Plugin{
		Mutators: map[string]Varier{
			"broken": VaryFunc(func([]byte, uint64, int, int) ([][]byte, error) {
				return nil, errors.New("the model file is missing")
			}),
		},
	})
	m, err := h.host.NewMutator("broken")
	if err != nil {
		t.Fatal(err)
	}

	a := ir.NewArena()
	n := payloadNode(a, []byte("abcd"))
	c := mutCtx(a)

	if m.Mutate(c, n) {
		t.Fatal("a mutator whose plugin refused reported a mutation")
	}
	// Mutate has no error to return, so the failure has to be somewhere the
	// campaign can find it. This is that somewhere.
	if h.host.Err() == nil {
		t.Fatal("the plugin's refusal left no trace; the campaign would run on silently")
	}
	if !strings.Contains(h.host.Err().Error(), "model file is missing") {
		t.Errorf("the recorded failure loses the plugin's words: %v", h.host.Err())
	}
	if m.CanApply(c, n) {
		t.Error("a failed plugin's mutator still offers itself to the scheduler")
	}
}

func TestTheHostReportsWhatItSpentInsideThePlugin(t *testing.T) {
	h := dial(t, Plugin{
		Objectives: map[string]Oracle{
			"slowish": OracleFunc(func(batch []Observation) ([]Verdict, error) {
				time.Sleep(20 * time.Millisecond)
				return make([]Verdict, len(batch)), nil
			}),
		},
	})
	o, err := h.host.NewObjective("slowish")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := o.IsFinding(observers(feedback.ExitOK), feedback.ExitOK); err != nil {
		t.Fatal(err)
	}
	if got := h.host.Inside(); got < 20*time.Millisecond {
		t.Errorf("time inside the plugin = %s, want at least 20ms", got)
	}
	if got := h.host.Calls(); got != 2 {
		t.Errorf("calls = %d, want 2", got)
	}
}

func TestAPluginSeesTheCampaignSeedAndItsSettings(t *testing.T) {
	var gotSeed uint64
	var gotConfig map[string]string
	h := dial(t, Plugin{
		Start: func(seed uint64, config map[string]string) error {
			gotSeed, gotConfig = seed, config
			return nil
		},
	}, func(o *Options) { o.Config = map[string]string{"threshold": "0.9"} })
	_ = h

	if gotSeed != 0x0123456789abcdef {
		t.Errorf("seed = %#x, want 0x0123456789abcdef: a 64-bit seed did not survive the wire", gotSeed)
	}
	if gotConfig["threshold"] != "0.9" {
		t.Errorf("config = %v, want threshold 0.9", gotConfig)
	}
}

func TestAPluginThatRefusesTheCampaignSaysWhy(t *testing.T) {
	pluginIn, hostOut := io.Pipe()
	hostIn, pluginOut := io.Pipe()
	go ServeOn(pluginIn, pluginOut, Plugin{
		Start: func(uint64, map[string]string) error {
			return errors.New("threshold must be between 0 and 1")
		},
	})

	_, err := Dial(Options{
		Label:     "picky",
		Transport: Transport{Stdin: hostOut, Stdout: hostIn, Kill: func() error { hostIn.Close(); return hostOut.Close() }},
	})
	if err == nil {
		t.Fatal("a plugin that refused the campaign was accepted")
	}
	if !strings.Contains(err.Error(), "threshold must be between 0 and 1") {
		t.Errorf("the refusal loses the plugin's explanation: %v", err)
	}
}
