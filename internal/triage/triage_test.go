package triage

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/rom/Xfuzz/pkg/feedback"
)

// fakeRunner decides an outcome from the candidate's content, which is what
// lets these tests exercise the algorithms without a target.
type fakeRunner struct {
	fn   func([]byte) Outcome
	runs int
}

func (f *fakeRunner) Run(_ context.Context, in []byte) (Outcome, error) {
	f.runs++
	return f.fn(in), nil
}

func crash(signal int, output string) Outcome {
	return Outcome{Exit: feedback.ExitCrash, Signal: signal, Output: output}
}

func ok() Outcome { return Outcome{Exit: feedback.ExitOK} }

func TestClassifyKinds(t *testing.T) {
	cases := []struct {
		out  Outcome
		want string
	}{
		{Outcome{Exit: feedback.ExitCrash, Signal: 11}, "crash/sig11"},
		{Outcome{Exit: feedback.ExitTimeout}, "hang"},
		{Outcome{Exit: feedback.ExitOOM}, "oom"},
		{Outcome{Exit: feedback.ExitOK}, "ok"},
		{Outcome{Exit: feedback.ExitCrash, Finding: feedback.Finding{Kind: "address"}}, "address"},
	}
	for _, c := range cases {
		if got := Classify(c.out).String(); got != c.want {
			t.Errorf("Classify(%+v) = %q, want %q", c.out, got, c.want)
		}
	}
}

func TestClassifyExtractsAndNormalisesMarkers(t *testing.T) {
	o := crash(6, "some noise\nAssertion failed: (n > 0), function f, file a.c, line 12.\nmore noise")
	c := Classify(o)
	if !strings.HasPrefix(c.Marker, "Assertion failed:") {
		t.Fatalf("marker = %q", c.Marker)
	}

	// Two runs of one bug that differ only in an address must classify alike:
	// otherwise every execution gets its own bucket.
	a := Classify(crash(6, "panic: runtime error at 0x7ffd1234"))
	b := Classify(crash(6, "panic: runtime error at 0x7ffdabcd"))
	if !a.Equal(b) {
		t.Fatalf("addresses were not normalised: %q vs %q", a.Marker, b.Marker)
	}
	if !strings.Contains(a.Marker, "0xADDR") {
		t.Fatalf("marker = %q", a.Marker)
	}
}

func TestClassifyIgnoresUnknownMarkers(t *testing.T) {
	// A target's own convention is not in the generic set, and inventing a
	// marker from an arbitrary line would split one bug across buckets.
	c := Classify(crash(6, "APPLICATION-SPECIFIC-FAILURE-7\n"))
	if c.Marker != "" {
		t.Fatalf("marker = %q, want none", c.Marker)
	}
}

func TestVerifyDistinguishesAlwaysSometimesNever(t *testing.T) {
	ctx := context.Background()

	always := &fakeRunner{fn: func([]byte) Outcome { return crash(11, "") }}
	rep, err := Verify(ctx, always, []byte("x"), 5)
	if err != nil {
		t.Fatal(err)
	}
	if rep.State() != "verified" || rep.Rate() != 1 {
		t.Fatalf("always: %s", rep)
	}

	n := 0
	sometimes := &fakeRunner{fn: func([]byte) Outcome {
		n++
		if n%2 == 0 {
			return crash(11, "")
		}
		return ok()
	}}
	rep, _ = Verify(ctx, sometimes, []byte("x"), 4)
	if rep.State() != "flaky" || rep.Reproduced != 2 {
		t.Fatalf("sometimes: %s", rep)
	}

	never := &fakeRunner{fn: func([]byte) Outcome { return ok() }}
	rep, _ = Verify(ctx, never, []byte("x"), 3)
	if rep.State() != "unverified" || rep.Reproduced != 0 {
		t.Fatalf("never: %s", rep)
	}
}

func TestVerifyRecordsDivergentClasses(t *testing.T) {
	n := 0
	r := &fakeRunner{fn: func([]byte) Outcome {
		n++
		if n%2 == 0 {
			return crash(6, "")
		}
		return crash(11, "")
	}}
	rep, err := Verify(context.Background(), r, []byte("x"), 6)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Divergent) != 1 {
		t.Fatalf("divergent = %v", rep.Divergent)
	}
	if !strings.Contains(rep.String(), "also seen as") {
		t.Fatalf("the report hides the divergence: %s", rep)
	}
}

func TestMinimizeShrinksToTheTrigger(t *testing.T) {
	// The failure needs "BOOM" anywhere in the input; everything else is
	// padding, which is the shape of nearly every real reproducer.
	input := []byte(strings.Repeat("a", 500) + "BOOM" + strings.Repeat("b", 500))
	r := &fakeRunner{fn: func(in []byte) Outcome {
		if bytes.Contains(in, []byte("BOOM")) {
			return crash(11, "")
		}
		return ok()
	}}
	got, rep, err := Minimize(context.Background(), r, input, MinimizeOptions{})
	if err != nil {
		t.Fatalf("Minimize: %v", err)
	}
	if !bytes.Contains(got, []byte("BOOM")) {
		t.Fatalf("minimisation lost the trigger: %q", got)
	}
	if rep.Reduction() < 0.8 {
		t.Fatalf("reduced only %.0f%%: %s", 100*rep.Reduction(), rep)
	}
	if len(got) != 4 {
		t.Logf("minimised to %d bytes (%q); a block minimiser is not guaranteed a global minimum", len(got), got)
	}
}

func TestMinimizePreservesTheClassNotJustTheCrash(t *testing.T) {
	// Two different bugs. Deleting the first exposes the second, so a minimiser
	// that only asks "does it still crash" would hand back a reproducer for a
	// bug the reporter never saw.
	input := []byte("AAAA-FIRST-BBBB-SECOND-CCCC")
	r := &fakeRunner{fn: func(in []byte) Outcome {
		switch {
		case bytes.Contains(in, []byte("FIRST")):
			return crash(6, "Assertion failed: first")
		case bytes.Contains(in, []byte("SECOND")):
			return crash(11, "Assertion failed: second")
		}
		return ok()
	}}
	got, _, err := Minimize(context.Background(), r, input, MinimizeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(got, []byte("FIRST")) {
		t.Fatalf("minimisation wandered to another bug: %q", got)
	}
}

func TestMinimizeRespectsItsBudget(t *testing.T) {
	input := bytes.Repeat([]byte("x"), 4096)
	r := &fakeRunner{fn: func(in []byte) Outcome {
		if len(in) >= 3 {
			return crash(11, "")
		}
		return ok()
	}}
	_, rep, err := Minimize(context.Background(), r, input, MinimizeOptions{MaxRuns: 10})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Runs > 11 {
		t.Fatalf("spent %d runs against a budget of 10", rep.Runs)
	}
	if !rep.Exhausted {
		t.Fatal("the report does not say the budget ran out")
	}
}

func TestMinimizeNormalizesFiller(t *testing.T) {
	input := []byte("\x01\x02\x03BOOM\x04\x05\x06")
	r := &fakeRunner{fn: func(in []byte) Outcome {
		if bytes.Contains(in, []byte("BOOM")) && len(in) == len(input) {
			return crash(11, "")
		}
		if bytes.Contains(in, []byte("BOOM")) {
			return crash(11, "")
		}
		return ok()
	}}
	got, _, err := Minimize(context.Background(), r, input, MinimizeOptions{Normalize: true})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.ContainsAny(got, "\x01\x02\x03") {
		t.Fatalf("normalisation left non-canonical filler: %q", got)
	}
}

func TestMinimizeRefusesAnInputThatDoesNotFail(t *testing.T) {
	r := &fakeRunner{fn: func([]byte) Outcome { return ok() }}
	if _, _, err := Minimize(context.Background(), r, []byte("harmless"), MinimizeOptions{}); err == nil {
		t.Fatal("minimising a non-failing input reported success")
	}
}

func TestMinimizeSequenceDropsMessages(t *testing.T) {
	session := [][]byte{
		[]byte("HELLO"), []byte("noise"), []byte("AUTH"), []byte("noise"), []byte("TRIGGER"),
	}
	run := func(_ context.Context, msgs [][]byte) (Outcome, error) {
		var seenAuth, seenTrigger bool
		for _, m := range msgs {
			if string(m) == "AUTH" {
				seenAuth = true
			}
			if string(m) == "TRIGGER" && seenAuth {
				seenTrigger = true
			}
		}
		if seenTrigger {
			return crash(11, ""), nil
		}
		return ok(), nil
	}
	got, rep, err := MinimizeSequence(context.Background(), run, session, MinimizeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("minimised to %d messages, want 2: %q", len(got), got)
	}
	if string(got[0]) != "AUTH" || string(got[1]) != "TRIGGER" {
		t.Fatalf("wrong messages kept: %q", got)
	}
	if rep.Reduction() < 0.5 {
		t.Fatalf("reduction = %.2f", rep.Reduction())
	}
}

func TestSignalStrategyMergesUnrelatedCrashes(t *testing.T) {
	s := SignalStrategy{}
	a, _ := s.Signature(crash(11, ""), Classify(crash(11, "")))
	b, _ := s.Signature(crash(11, "elsewhere"), Classify(crash(11, "elsewhere")))
	if a != b {
		t.Fatal("two segfaults produced different signal signatures")
	}
	c, _ := s.Signature(crash(8, ""), Classify(crash(8, "")))
	if a == c {
		t.Fatal("a segfault and an arithmetic fault share a bucket")
	}
}

func TestFrameStrategySkipsNoiseFrames(t *testing.T) {
	o := Outcome{Finding: feedback.Finding{Frames: []string{
		"__asan_memcpy /asan.cc:1",
		"memcpy /interceptors.cc:2",
		"parse_header /parser.c:120:5",
		"main /main.c:9",
	}}}
	sig, ok := FrameStrategy{Depth: 2}.Signature(o, Class{})
	if !ok {
		t.Fatal("no signature from a report with frames")
	}
	if sig != "parse_header;main" {
		t.Fatalf("signature = %q", sig)
	}
}

func TestFrameStrategyIgnoresFileAndLine(t *testing.T) {
	sigOf := func(loc string) string {
		o := Outcome{Finding: feedback.Finding{Frames: []string{"parse " + loc}}}
		s, _ := FrameStrategy{}.Signature(o, Class{})
		return s
	}
	if sigOf("/src/parser.c:120:5") != sigOf("/src/parser.c:340:9") {
		t.Fatal("the bucket moved when an unrelated line was inserted")
	}
}

func TestCoverageStrategySeparatesPaths(t *testing.T) {
	s := CoverageStrategy{}
	mk := func(idx ...int) Outcome {
		m := make([]byte, 64)
		for _, i := range idx {
			m[i] = 1
		}
		return Outcome{Coverage: m}
	}
	a, ok := s.Signature(mk(1, 2, 3), Class{})
	if !ok {
		t.Fatal("no signature from a covered map")
	}
	b, _ := s.Signature(mk(1, 2, 3), Class{})
	if a != b {
		t.Fatal("the same tuple set produced different signatures")
	}
	c, _ := s.Signature(mk(1, 2, 4), Class{})
	if a == c {
		t.Fatal("different tuple sets shared a signature")
	}

	// Hitcounts must not matter: a loop that ran nine times instead of eleven
	// is not a different bug.
	hot := mk(1, 2, 3)
	hot.Coverage[1] = 200
	d, _ := s.Signature(hot, Class{})
	if a != d {
		t.Fatal("the hitcount changed the bucket")
	}
	if _, ok := s.Signature(Outcome{}, Class{}); ok {
		t.Fatal("an uninstrumented outcome produced a coverage signature")
	}
}

func TestChainFallsThroughToWhatHasEvidence(t *testing.T) {
	chain := DefaultChain()

	frames := Outcome{Finding: feedback.Finding{Frames: []string{"parse /p.c:1"}}}
	sig, _ := chain.Signature(frames, Class{Kind: "crash"})
	if !strings.HasPrefix(sig, "frames:") {
		t.Fatalf("frames were available but the chain used %q", sig)
	}

	marker := crash(6, "Assertion failed: n > 0")
	sig, _ = chain.Signature(marker, Classify(marker))
	if !strings.HasPrefix(sig, "marker:") {
		t.Fatalf("a marker was available but the chain used %q", sig)
	}

	cov := Outcome{Exit: feedback.ExitCrash, Signal: 11, Coverage: []byte{0, 1, 0, 1}}
	sig, _ = chain.Signature(cov, Classify(cov))
	if !strings.HasPrefix(sig, "coverage:") {
		t.Fatalf("coverage was available but the chain used %q", sig)
	}

	bare := crash(11, "")
	sig, _ = chain.Signature(bare, Classify(bare))
	if !strings.HasPrefix(sig, "signal:") {
		t.Fatalf("nothing but the signal was available; the chain used %q", sig)
	}
}

func TestBucketNamesTheUnclassifiable(t *testing.T) {
	strategy, sig := Bucket(FrameStrategy{}, Outcome{}, Class{})
	if strategy != "frames" || sig != "unclassified" {
		t.Fatalf("Bucket = %q, %q", strategy, sig)
	}
}

func TestWorkerPipeline(t *testing.T) {
	input := []byte(strings.Repeat("p", 200) + "TRIGGER" + strings.Repeat("q", 200))
	r := &fakeRunner{fn: func(in []byte) Outcome {
		if bytes.Contains(in, []byte("TRIGGER")) {
			return crash(6, "Assertion failed: trigger")
		}
		return ok()
	}}
	w := NewWorker(Config{Runner: r, Trials: 3})
	res := w.Triage(context.Background(), Job{ID: 7, Input: input})

	if res.Err != nil {
		t.Fatalf("Triage: %v", res.Err)
	}
	if res.State != "minimized" {
		t.Fatalf("state = %q", res.State)
	}
	if res.Verify.Reproduced != 3 {
		t.Fatalf("verify = %s", res.Verify)
	}
	if res.Minimize.Reduction() < 0.8 {
		t.Fatalf("minimise = %s", res.Minimize)
	}
	if !strings.HasPrefix(res.Signature, "marker:") {
		t.Fatalf("signature = %q", res.Signature)
	}
}

func TestWorkerReportsUnreproducibleWithoutMinimising(t *testing.T) {
	r := &fakeRunner{fn: func([]byte) Outcome { return ok() }}
	w := NewWorker(Config{Runner: r, Trials: 3})
	res := w.Triage(context.Background(), Job{ID: 1, Input: []byte("was a crash, once")})

	if res.State != "unverified" {
		t.Fatalf("state = %q", res.State)
	}
	if res.Signature != "unreproducible" {
		t.Fatalf("signature = %q", res.Signature)
	}
	if res.Minimize.Runs != 0 {
		t.Fatal("a non-reproducing input was minimised anyway")
	}
	if !bytes.Equal(res.Minimized, []byte("was a crash, once")) {
		t.Fatal("the original reproducer was not preserved")
	}
}

func TestWorkerDropsRatherThanBlocks(t *testing.T) {
	block := make(chan struct{})
	r := &fakeRunner{fn: func([]byte) Outcome {
		<-block
		return ok()
	}}
	w := NewWorker(Config{Runner: r, Queue: 2, Trials: 1, Report: func(Result) {}})
	w.Start(context.Background())

	accepted := 0
	for i := 0; i < 50; i++ {
		if w.Submit(Job{ID: int64(i), Input: []byte("x")}) {
			accepted++
		}
	}
	dropped, _ := w.Stats()
	close(block)
	w.Close()

	if dropped == 0 {
		t.Fatal("a full queue did not drop anything; Submit must never block the fuzz loop")
	}
	if uint64(accepted)+dropped != 50 {
		t.Fatalf("accepted %d + dropped %d != 50", accepted, dropped)
	}
}

func TestWorkerRunsAsynchronously(t *testing.T) {
	r := &fakeRunner{fn: func(in []byte) Outcome {
		if bytes.Contains(in, []byte("!")) {
			return crash(11, "")
		}
		return ok()
	}}
	done := make(chan Result, 4)
	w := NewWorker(Config{
		Runner: r, Trials: 1, SkipMinimize: true,
		Report: func(res Result) { done <- res },
	})
	w.Start(context.Background())
	for i := 0; i < 4; i++ {
		w.Submit(Job{ID: int64(i), Input: []byte("boom!")})
	}
	w.Close()
	close(done)

	n := 0
	for res := range done {
		if res.State != "verified" {
			t.Fatalf("job %d state = %q", res.ID, res.State)
		}
		n++
	}
	if n != 4 {
		t.Fatalf("%d results, want 4", n)
	}
}
