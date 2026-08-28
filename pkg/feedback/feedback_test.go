package feedback

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// stub is a feedback whose answer the test controls, for exercising the algebra.
type stub struct {
	name      string
	answer    bool
	score     Score
	err       error
	appended  int
	discarded int
	asked     int
}

func (s *stub) Name() string { return s.name }
func (s *stub) IsInteresting([]Observer, ExitKind) (bool, Score, error) {
	s.asked++
	return s.answer, s.score, s.err
}
func (s *stub) Append()  { s.appended++ }
func (s *stub) Discard() { s.discarded++ }

func TestExitKind(t *testing.T) {
	for _, tc := range []struct {
		ek    ExitKind
		fault bool
	}{
		{ExitOK, false}, {ExitCrash, true}, {ExitTimeout, true},
		{ExitOOM, true}, {ExitError, false},
	} {
		if got := tc.ek.IsFault(); got != tc.fault {
			t.Errorf("%s.IsFault() = %v, want %v", tc.ek, got, tc.fault)
		}
		if tc.ek.String() == "unknown" {
			t.Errorf("exit kind %d has no name", tc.ek)
		}
	}
	// A harness failure must never count as a fault: reporting infrastructure
	// problems as findings is how a fuzzer loses its credibility.
	if ExitError.IsFault() {
		t.Error("a harness error must not be a fault")
	}
}

func TestAllShortCircuits(t *testing.T) {
	a := &stub{name: "a", answer: false}
	b := &stub{name: "b", answer: true}
	f := All(a, b)

	ok, _, err := f.IsInteresting(nil, ExitOK)
	if err != nil || ok {
		t.Fatalf("All(false, true) = %v, %v", ok, err)
	}
	if b.asked != 0 {
		t.Error("All must not consult later children once one has said no")
	}

	// A child that never saw the execution must not be told to commit anything.
	f.Append()
	if b.appended != 0 {
		t.Error("a short-circuited child was told to append")
	}
	if a.appended != 0 || a.discarded != 1 {
		t.Errorf("the child that said no should be discarded, got %d appends and %d discards",
			a.appended, a.discarded)
	}
}

func TestAnyConsultsEveryChild(t *testing.T) {
	a := &stub{name: "a", answer: false}
	b := &stub{name: "b", answer: true, score: Score{NewSignal: 3}}
	f := Any(a, b)

	ok, s, err := f.IsInteresting(nil, ExitOK)
	if err != nil || !ok {
		t.Fatalf("Any(false, true) = %v, %v", ok, err)
	}
	if s.NewSignal != 3 {
		t.Errorf("score = %+v, want the child's signal to carry through", s)
	}
	// Every child must see the execution, or its novelty state falls behind and
	// it starts reporting inputs as new that it has already seen.
	if a.asked != 1 || b.asked != 1 {
		t.Errorf("children were asked %d and %d times, want 1 each", a.asked, b.asked)
	}

	f.Append()
	if b.appended != 1 {
		t.Error("the child that said yes should have committed")
	}
	if a.discarded != 1 {
		t.Error("the child that said no should have rolled back")
	}
}

func TestCombinatorPropagatesErrors(t *testing.T) {
	boom := errors.New("boom")
	f := Any(&stub{name: "bad", err: boom})
	if _, _, err := f.IsInteresting(nil, ExitOK); !errors.Is(err, boom) {
		t.Errorf("error = %v, want it to carry through", err)
	}
	if _, _, err := All(&stub{name: "bad", err: boom}).IsInteresting(nil, ExitOK); err == nil {
		t.Error("All must propagate a child's error")
	}
}

func TestNotInverts(t *testing.T) {
	inner := &stub{name: "inner", answer: true}
	f := Not(inner)
	ok, _, _ := f.IsInteresting(nil, ExitOK)
	if ok {
		t.Error("Not(true) should be false")
	}
	// The inner novelty state must still advance, or "not covered before" stops
	// meaning anything after the first execution.
	f.Append()
	if inner.appended != 1 {
		t.Error("Not must still commit the inner feedback's state")
	}
	if !strings.Contains(f.Name(), "inner") {
		t.Errorf("name = %q, want it to mention the inner feedback", f.Name())
	}
}

func TestConstantFeedbacks(t *testing.T) {
	if ok, _, _ := Never().IsInteresting(nil, ExitOK); ok {
		t.Error("Never must admit nothing")
	}
	if ok, _, _ := Always().IsInteresting(nil, ExitOK); !ok {
		t.Error("Always must admit everything")
	}
	Never().Append()
	Always().Discard()
}

func TestFastIsAllWithOrdering(t *testing.T) {
	cheap := &stub{name: "cheap", answer: false}
	expensive := &stub{name: "expensive", answer: true}
	if ok, _, _ := Fast(cheap, expensive).IsInteresting(nil, ExitOK); ok {
		t.Error("Fast should be false when the cheap feedback says no")
	}
	if expensive.asked != 0 {
		t.Error("Fast must not evaluate the expensive feedback once the cheap one said no")
	}
}

func TestScoreAdd(t *testing.T) {
	s := Score{NewSignal: 1, Novelty: 0.2, Custom: 1}
	s.Add(Score{NewSignal: 2, Novelty: 0.5, Distance: 3, Custom: 2})
	if s.NewSignal != 3 || s.Novelty != 0.5 || s.Distance != 3 || s.Custom != 3 {
		t.Errorf("Add produced %+v", s)
	}
}

// --- coverage ---------------------------------------------------------------

func TestMapFeedbackAdmitsNewCoverage(t *testing.T) {
	m := NewCoverageMap("cov", 256)
	f := NewMapFeedback("cov", m)

	m.Buffer()[10] = 1
	ok, s, err := f.IsInteresting(nil, ExitOK)
	if err != nil || !ok {
		t.Fatalf("first coverage = %v, %v", ok, err)
	}
	if s.NewSignal != 1 {
		t.Errorf("NewSignal = %d, want 1", s.NewSignal)
	}
	f.Append()
	if f.Covered() != 1 {
		t.Errorf("Covered = %d, want 1", f.Covered())
	}

	// The same coverage again is not new.
	if ok, _, _ := f.IsInteresting(nil, ExitOK); ok {
		t.Error("identical coverage must not be admitted twice")
	}
	f.Discard()

	// A different entry is.
	m.Buffer()[200] = 1
	if ok, _, _ := f.IsInteresting(nil, ExitOK); !ok {
		t.Error("a new entry must be admitted")
	}
	f.Append()
	if f.Covered() != 2 {
		t.Errorf("Covered = %d, want 2", f.Covered())
	}
}

// TestMapFeedbackBucketsHitCounts is what stops a loop counting as new coverage
// on every iteration.
func TestMapFeedbackBucketsHitCounts(t *testing.T) {
	m := NewCoverageMap("cov", 64)
	f := NewMapFeedback("cov", m)

	m.Buffer()[0] = 1
	f.IsInteresting(nil, ExitOK)
	f.Append()

	// Same bucket: 2 and 3 fall in different buckets, but 4 through 7 share one.
	for _, tc := range []struct {
		hits byte
		want bool
	}{
		{1, false}, // already seen
		{2, true},  // bucket 2
		{3, true},  // bucket 4
		{4, true},  // bucket 8
		{5, false}, // still bucket 8
		{7, false}, // still bucket 8
		{8, true},  // bucket 16
		{200, true},
		{255, false}, // still the top bucket
	} {
		m.Buffer()[0] = tc.hits
		ok, _, _ := f.IsInteresting(nil, ExitOK)
		if ok != tc.want {
			t.Errorf("%d hits: interesting = %v, want %v", tc.hits, ok, tc.want)
		}
		f.Append()
	}
}

func TestMapFeedbackDiscardDoesNotCommit(t *testing.T) {
	m := NewCoverageMap("cov", 64)
	f := NewMapFeedback("cov", m)
	m.Buffer()[5] = 1

	f.IsInteresting(nil, ExitOK)
	f.Discard()
	if f.Covered() != 0 {
		t.Error("Discard must not advance the novelty state")
	}
	// So the same input is still interesting: an input rejected by the wider
	// composition must remain discoverable.
	if ok, _, _ := f.IsInteresting(nil, ExitOK); !ok {
		t.Error("after a discard the same coverage must still be new")
	}
}

func TestMapFeedbackDetectsSizeMismatch(t *testing.T) {
	m := NewCoverageMap("cov", 64)
	f := NewMapFeedback("cov", m)
	m.SetBuffer(make([]byte, 128))
	if _, _, err := f.IsInteresting(nil, ExitOK); err == nil {
		t.Error("a map size mismatch must be reported: the executor and the feedback " +
			"would otherwise silently disagree about what they are measuring")
	}
}

func TestMapFeedbackSaveAndRestore(t *testing.T) {
	m := NewCoverageMap("cov", 64)
	f := NewMapFeedback("cov", m)
	for _, i := range []int{1, 7, 33} {
		m.Buffer()[i] = 1
	}
	f.IsInteresting(nil, ExitOK)
	f.Append()
	saved := append([]byte(nil), f.Virgin()...)

	restored := NewMapFeedback("cov", NewCoverageMap("cov", 64))
	if err := restored.LoadVirgin(saved); err != nil {
		t.Fatal(err)
	}
	if restored.Covered() != f.Covered() {
		t.Errorf("restored coverage %d, want %d", restored.Covered(), f.Covered())
	}
	if err := restored.LoadVirgin(make([]byte, 8)); err == nil {
		t.Error("restoring a differently sized map must fail")
	}
}

func TestCoverageMapObserver(t *testing.T) {
	m := NewCoverageMap("cov", 0) // zero means the default size
	if m.Size() != DefaultMapSize {
		t.Errorf("default size = %d, want %d", m.Size(), DefaultMapSize)
	}
	m.SetBackend("sancov")
	if m.Backend() != "sancov" {
		t.Error("the backend must be recorded: coverage is not comparable across backends")
	}
	m.Buffer()[3] = 7
	if m.Hit(3) != 7 || m.Covered() != 1 {
		t.Error("the observer is not reporting its counters")
	}
	m.Pre()
	if m.Covered() != 0 {
		t.Error("Pre must clear the counters before an execution")
	}
	m.Buffer()[3] = 1
	m.Reset()
	if m.Covered() != 0 {
		t.Error("Reset must clear the counters")
	}
	if err := m.Post(ExitOK); err != nil {
		t.Error(err)
	}
}

func TestMapDensity(t *testing.T) {
	m := NewCoverageMap("cov", 100)
	f := NewMapFeedback("cov", m)
	if f.Density() != 0 {
		t.Errorf("density of an empty map = %v", f.Density())
	}
	for i := 0; i < 50; i++ {
		m.Buffer()[i] = 1
	}
	f.IsInteresting(nil, ExitOK)
	f.Append()
	if f.Density() != 0.5 {
		t.Errorf("density = %v, want 0.5", f.Density())
	}
}

// --- observers and objectives ----------------------------------------------

func TestNoveltyFeedback(t *testing.T) {
	obs := NewOutputObserver("out")
	f := NewNoveltyFeedback("novel", obs)

	obs.Record(nil, []byte("hello"), 0, 0)
	if ok, _, _ := f.IsInteresting(nil, ExitOK); !ok {
		t.Error("the first output must be novel")
	}
	f.Append()

	if ok, _, _ := f.IsInteresting(nil, ExitOK); ok {
		t.Error("identical output must not be novel twice")
	}
	f.Discard()

	obs.Record(nil, []byte("different"), 0, 0)
	if ok, _, _ := f.IsInteresting(nil, ExitOK); !ok {
		t.Error("different output must be novel")
	}
	f.Append()
	if f.Distinct() != 2 {
		t.Errorf("distinct outputs = %d, want 2", f.Distinct())
	}

	// The exit kind is part of the identity: the same output from a crash is a
	// different observation.
	obs.Record(nil, []byte("different"), 0, 0)
	if ok, _, _ := f.IsInteresting(nil, ExitCrash); !ok {
		t.Error("the same output with a different exit kind must be novel")
	}
}

func TestNoveltyNormalisation(t *testing.T) {
	obs := NewOutputObserver("out")
	f := NewNoveltyFeedback("novel", obs)
	// A target that prints a changing value looks novel on every execution, and
	// fills the corpus with noise. Normalisation is the answer.
	f.Normalise = func(b []byte) []byte {
		if i := strings.Index(string(b), "pid="); i >= 0 {
			return b[:i]
		}
		return b
	}
	obs.Record(nil, []byte("result ok pid=123"), 0, 0)
	f.IsInteresting(nil, ExitOK)
	f.Append()
	obs.Record(nil, []byte("result ok pid=456"), 0, 0)
	if ok, _, _ := f.IsInteresting(nil, ExitOK); ok {
		t.Error("normalisation should have made these the same observation")
	}
}

func TestOutputObserver(t *testing.T) {
	o := NewOutputObserver("out")
	o.Record([]byte("out"), []byte("err"), 3, 11)
	if string(o.Stdout()) != "out" || string(o.Stderr()) != "err" {
		t.Error("output was not recorded")
	}
	if o.ExitCode() != 3 || o.Signal() != 11 {
		t.Error("exit status was not recorded")
	}
	if o.Combined() != "outerr" {
		t.Errorf("Combined = %q", o.Combined())
	}
	o.Record(nil, []byte("only stderr"), 0, 0)
	if o.Combined() != "only stderr" {
		t.Errorf("Combined with no stdout = %q", o.Combined())
	}
	o.Record([]byte("only stdout"), nil, 0, 0)
	if o.Combined() != "only stdout" {
		t.Errorf("Combined with no stderr = %q", o.Combined())
	}
	o.Pre()
	if o.Combined() != "" || o.ExitCode() != 0 {
		t.Error("Pre must clear the previous execution's output")
	}
}

func TestSlowFeedback(t *testing.T) {
	obs := NewTimingObserver("time")
	f := NewSlowFeedback("slow", obs)
	f.MinSamples = 10
	f.Factor = 4

	// Nothing is judged until there is a baseline to judge against.
	obs.Record(time.Second)
	if ok, _, _ := f.IsInteresting(nil, ExitOK); ok {
		t.Error("a feedback with no baseline must not report an outlier")
	}
	f.Append()

	for i := 0; i < 20; i++ {
		obs.Record(10 * time.Millisecond)
		f.IsInteresting(nil, ExitOK)
		f.Append()
	}
	obs.Record(10 * time.Millisecond)
	if ok, _, _ := f.IsInteresting(nil, ExitOK); ok {
		t.Error("a typical execution must not be an outlier")
	}
	f.Append()

	obs.Record(5 * time.Second)
	if ok, _, _ := f.IsInteresting(nil, ExitOK); !ok {
		t.Errorf("an execution 500x the mean (%v) must be an outlier", f.Mean())
	}
}

func TestTimingObserver(t *testing.T) {
	o := NewTimingObserver("time")
	o.Pre()
	o.Post(ExitOK)
	if o.Elapsed() <= 0 {
		t.Error("the observer recorded no elapsed time")
	}
	o.Record(42 * time.Millisecond)
	if o.Elapsed() != 42*time.Millisecond {
		t.Error("Record must override the measurement")
	}
	o.Reset()
	if o.Elapsed() != 0 {
		t.Error("Reset must clear the measurement")
	}
}

func TestCrashAndHangObjectives(t *testing.T) {
	out := NewOutputObserver("out")
	out.Record(nil, []byte("boom"), 0, 11)

	crash := NewCrashObjective("crash", out)
	hit, f, err := crash.IsFinding(nil, ExitCrash)
	if err != nil || !hit {
		t.Fatalf("a crash was not reported: %v %v", hit, err)
	}
	if f.Signal != 11 || !strings.Contains(f.Summary, "SIGSEGV") {
		t.Errorf("finding = %+v, want it to name the signal", f)
	}
	if hit, _, _ := crash.IsFinding(nil, ExitOK); hit {
		t.Error("a clean exit is not a crash")
	}

	hang := NewHangObjective("hang")
	if hit, _, _ := hang.IsFinding(nil, ExitTimeout); !hit {
		t.Error("a timeout must be reported")
	}
	if hit, _, _ := hang.IsFinding(nil, ExitCrash); hit {
		t.Error("a crash is not a hang")
	}

	oom := NewOOMObjective("oom")
	if hit, _, _ := oom.IsFinding(nil, ExitOOM); !hit {
		t.Error("an out-of-memory must be reported")
	}
	if hit, _, _ := oom.IsFinding(nil, ExitOK); hit {
		t.Error("a clean exit is not an out-of-memory")
	}
}

func TestSanitizerParsing(t *testing.T) {
	const report = `=================================================================
==12345==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000118
READ of size 4 at 0x602000000118 thread T0
    #0 0x4f1234 in parse_chunk /src/parser.c:88:12
    #1 0x4f5678 in main /src/main.c:20:3
    #2 0x7f0000 in __libc_start_main
`
	f := ParseSanitizer(report)
	if f.Kind != "address" {
		t.Errorf("kind = %q, want address", f.Kind)
	}
	if !strings.Contains(f.Summary, "heap-buffer-overflow") {
		t.Errorf("summary = %q", f.Summary)
	}
	// The frames are what let distinct bugs bucket apart; a report reduced to
	// its first line merges every overflow in a program into one finding.
	if len(f.Frames) < 2 {
		t.Fatalf("frames = %v, want at least two", f.Frames)
	}
	if !strings.Contains(f.Frames[0], "parse_chunk") {
		t.Errorf("innermost frame = %q, want parse_chunk", f.Frames[0])
	}

	obs := NewOutputObserver("out")
	obs.Record(nil, []byte(report), 0, 6)
	o := NewSanitizerObjective("san", obs)
	if hit, _, _ := o.IsFinding(nil, ExitCrash); !hit {
		t.Error("a sanitizer report must be a finding")
	}
	// It must fire on a clean exit too: LeakSanitizer and UBSan report without
	// aborting, and requiring a signal would miss whole classes of bug.
	if hit, _, _ := o.IsFinding(nil, ExitOK); !hit {
		t.Error("a sanitizer report on a clean exit must still be a finding")
	}
	obs.Record(nil, []byte("nothing unusual"), 0, 0)
	if hit, _, _ := o.IsFinding(nil, ExitOK); hit {
		t.Error("ordinary output must not be a finding")
	}
	if hit, _, _ := o.IsFinding(nil, ExitError); hit {
		t.Error("a harness error must never be reported as a finding")
	}
}

func TestUBSanParsing(t *testing.T) {
	const report = `/src/x.c:12:5: runtime error: signed integer overflow: 2147483647 + 1 cannot be represented in type 'int'`
	f := ParseSanitizer(report)
	if !strings.Contains(f.Summary, "signed integer overflow") {
		t.Errorf("summary = %q", f.Summary)
	}
}

func TestOracleAndAnyObjective(t *testing.T) {
	oracle := NewOracleObjective("oracle", "logic", func(_ []Observer, ek ExitKind) (bool, string) {
		return ek == ExitOK, "returned success when it should not have"
	})
	hit, f, _ := oracle.IsFinding(nil, ExitOK)
	if !hit || f.Kind != "logic" {
		t.Errorf("oracle finding = %v %+v", hit, f)
	}
	if hit, _, _ := oracle.IsFinding(nil, ExitCrash); hit {
		t.Error("the oracle fired when its predicate was false")
	}

	// More specific objectives first: a sanitizer report says far more than
	// "it crashed".
	any := NewAnyObjective("any", NewHangObjective("hang"), oracle)
	hit, f, _ = any.IsFinding(nil, ExitTimeout)
	if !hit || f.Kind != "hang" {
		t.Errorf("Any returned %v %+v, want the hang", hit, f)
	}
	if hit, _, _ := any.IsFinding(nil, ExitCrash); hit {
		t.Error("Any fired when no child did")
	}
	if any.Name() != "any" {
		t.Errorf("name = %q", any.Name())
	}
}

func TestFindObserver(t *testing.T) {
	a, b := NewOutputObserver("a"), NewTimingObserver("b")
	obs := []Observer{a, b}
	if got, ok := Find(obs, "b"); !ok || got != Observer(b) {
		t.Error("Find did not locate the observer")
	}
	if _, ok := Find(obs, "missing"); ok {
		t.Error("Find located an observer that is not there")
	}
}

func TestFindingString(t *testing.T) {
	f := Finding{Kind: "crash", Summary: "segv", Signal: 11}
	s := f.String()
	for _, want := range []string{"crash", "segv", "11"} {
		if !strings.Contains(s, want) {
			t.Errorf("Finding.String() = %q, want it to contain %q", s, want)
		}
	}
}

func BenchmarkMapFeedbackScan(b *testing.B) {
	m := NewCoverageMap("cov", DefaultMapSize)
	f := NewMapFeedback("cov", m)
	// A realistically sparse map: a few hundred of 65536 entries touched.
	for i := 0; i < 300; i++ {
		m.Buffer()[i*211%DefaultMapSize] = byte(i%7 + 1)
	}
	f.IsInteresting(nil, ExitOK)
	f.Append()
	b.SetBytes(int64(DefaultMapSize))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _, err := f.IsInteresting(nil, ExitOK); err != nil {
			b.Fatal(err)
		}
		f.Discard()
	}
}
