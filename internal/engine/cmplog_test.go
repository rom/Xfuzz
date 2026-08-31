package engine

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/rom/Xfuzz/internal/platform"
	"github.com/rom/Xfuzz/internal/safety"
	"github.com/rom/Xfuzz/pkg/codec"
	"github.com/rom/Xfuzz/pkg/corpus"
	"github.com/rom/Xfuzz/pkg/executor"
	"github.com/rom/Xfuzz/pkg/feedback"
	"github.com/rom/Xfuzz/pkg/mutate"
)

// The comparison table crosses a C-to-Go boundary that no compiler checks. The
// runtime writes a packed struct into shared memory and pkg/feedback reads it
// back by offset; a field added on one side, a padding rule that differs, an
// endianness assumption, and every operand the fuzzer recovers is nonsense —
// while everything still builds and runs and simply finds nothing.
//
// So the layout is not asserted against itself. A real target is built with real
// instrumentation, run with real inputs, and the constants its source compares
// against have to come back out of the table.

// cmpFixture builds the comparison target and returns an executor with a
// comparison region attached.
func cmpFixture(t *testing.T) (*executor.Subprocess, *feedback.CmpObserver, func()) {
	t.Helper()
	target := buildTarget(t, "magic_cmp")

	provider := platform.NewSharedMemoryProvider()
	if !provider.Available() {
		t.Skip("shared memory is unavailable, so the comparison table cannot be attached")
	}
	region, err := provider.Create(feedback.CmpRegionSize)
	if err != nil {
		t.Fatalf("creating the comparison region: %v", err)
	}

	sub := executor.NewSubprocess("cmp", safety.NewSpawner(), executor.ProcSpec{
		Path: target, Args: []string{target}, Timeout: 5 * time.Second,
	})
	sub.CmpShm = region
	obs := feedback.NewCmpObserver("cmp", region.Bytes())

	return sub, obs, func() {
		sub.Close()
		region.Close()
	}
}

// TestTheRuntimeAndTheReaderAgreeAboutTheRecordLayout is the ABI test.
func TestTheRuntimeAndTheReaderAgreeAboutTheRecordLayout(t *testing.T) {
	sub, obs, done := cmpFixture(t)
	defer done()

	// An input long enough for the target to look at, whose first four bytes are
	// nothing in particular. The target compares them against 0xC0FFEE01 and
	// rejects them, and that comparison is what must come back.
	in := padded([]byte{0x11, 0x22, 0x33, 0x44})
	if _, err := sub.Run(t.Context(), executor.Input{Bytes: in},
		[]feedback.Observer{obs}); err != nil {
		t.Fatal(err)
	}

	recs := obs.Records()
	if len(recs) == 0 {
		t.Fatal("the target performed comparisons and the table came back empty. " +
			"Either the instrumentation flag no longer installs the callbacks, or the " +
			"region was not published to the target, or the header layout has drifted")
	}
	t.Logf("%d comparisons recorded", len(recs))

	var sawInput, sawConstant bool
	for _, r := range recs {
		if r.Kind != feedback.CmpInt {
			continue
		}
		a, b := r.AUint(), r.BUint()
		if r.Size == 4 && (a == 0x44332211 || b == 0x44332211) {
			sawInput = true
		}
		if r.Size == 4 && (a == 0xC0FFEE01 || b == 0xC0FFEE01) {
			sawConstant = true
		}
	}
	if !sawConstant {
		t.Errorf("the constant 0xC0FFEE01 the target compares against is not in the "+
			"table; the operands are being decoded from the wrong offsets or the wrong "+
			"width. Recorded: %s", summarise(recs))
	}
	if !sawInput {
		t.Errorf("the value the input supplied (0x44332211) is not in the table, so "+
			"there would be nothing for a substitution to find and replace. Recorded: %s",
			summarise(recs))
	}
}

// TestTheComparisonTableFollowsTheInput is what makes substitution possible: the
// operands have to change when the input changes, or the table describes the
// program rather than this execution of it.
func TestTheComparisonTableFollowsTheInput(t *testing.T) {
	sub, obs, done := cmpFixture(t)
	defer done()

	found := func(in []byte, want uint64, size uint8) bool {
		t.Helper()
		if _, err := sub.Run(t.Context(), executor.Input{Bytes: in},
			[]feedback.Observer{obs}); err != nil {
			t.Fatal(err)
		}
		for _, r := range obs.Records() {
			if r.Kind == feedback.CmpInt && r.Size == size &&
				(r.AUint() == want || r.BUint() == want) {
				return true
			}
		}
		return false
	}

	if !found(padded([]byte{0xAA, 0xBB, 0xCC, 0xDD}), 0xDDCCBBAA, 4) {
		t.Error("the first input's value is not in the table")
	}
	if found(padded([]byte{0x11, 0x22, 0x33, 0x44}), 0xDDCCBBAA, 4) {
		t.Error("the previous input's value is still in the table; the count is not " +
			"being reset between executions, so every stage downstream sees a mixture " +
			"of this execution's comparisons and the last one's")
	}
}

// TestTheComparisonTableReachesPastTheFirstGate proves the table is what makes
// a magic-number ladder climbable: satisfying the first comparison exposes the
// second one's constant, which was never reached before.
func TestTheComparisonTableReachesPastTheFirstGate(t *testing.T) {
	sub, obs, done := cmpFixture(t)
	defer done()

	has := func(want uint64, size uint8) bool {
		for _, r := range obs.Records() {
			if r.Kind == feedback.CmpInt && r.Size == size &&
				(r.AUint() == want || r.BUint() == want) {
				return true
			}
		}
		return false
	}

	// Before the first gate is satisfied, the second constant is unreachable and
	// so is its comparison.
	if _, err := sub.Run(t.Context(), executor.Input{Bytes: make([]byte, 16)},
		[]feedback.Observer{obs}); err != nil {
		t.Fatal(err)
	}
	if has(0x0123456789ABCDEF, 8) {
		t.Fatal("the second gate's constant appeared before the first gate was passed")
	}

	// Satisfy it, and the next one's constant is now in the table — which is
	// exactly the step a campaign takes when it substitutes.
	in := make([]byte, 16)
	binary.LittleEndian.PutUint32(in, 0xC0FFEE01)
	if _, err := sub.Run(t.Context(), executor.Input{Bytes: in},
		[]feedback.Observer{obs}); err != nil {
		t.Fatal(err)
	}
	if !has(0x0123456789ABCDEF, 8) {
		t.Errorf("passing the first gate did not put the second gate's 64-bit constant "+
			"in the table, so a campaign has nothing to substitute for its next step. "+
			"Recorded: %s", summarise(obs.Records()))
	}
}

// TestValueProfileRewardsGettingCloser is the second use of the same data: a
// comparison that nearly passed has to look different from one that did not.
func TestValueProfileRewardsGettingCloser(t *testing.T) {
	sub, obs, done := cmpFixture(t)
	defer done()

	vp := feedback.NewValueProfile("value-profile", obs, 0)

	run := func(in []byte) (bool, feedback.Score) {
		t.Helper()
		ek, err := sub.Run(t.Context(), executor.Input{Bytes: in}, []feedback.Observer{obs})
		if err != nil {
			t.Fatal(err)
		}
		ok, score, err := vp.IsInteresting(nil, ek)
		if err != nil {
			t.Fatal(err)
		}
		if ok {
			vp.Append()
		} else {
			vp.Discard()
		}
		return ok, score
	}

	// The first input establishes a baseline; the second differs from the gate
	// in fewer bits, so it lands in a different value-profile bucket for the
	// same comparison site and must count as new.
	first := padded(nil)
	closer := padded([]byte{0x01, 0xEE, 0xFF, 0xC0}) // the gate exactly, little-endian

	if ok, _ := run(first); !ok {
		t.Fatal("the first input produced no value-profile signal at all")
	}
	before := vp.Covered()
	if ok, score := run(closer); !ok {
		t.Errorf("an input that matches the gate exactly produced no new value-profile "+
			"signal, so the campaign has no reason to keep it (covered %d, score %+v)",
			before, score)
	}
	if after := vp.Covered(); after <= before {
		t.Errorf("value-profile coverage did not grow: %d then %d", before, after)
	}
}

// padded returns an input long enough for the target to inspect at all.
//
// The target checks its length once, up front, for all three of its gates. An
// input shorter than that is rejected before any comparison happens, and a test
// that used one would be measuring the length check rather than the table.
func padded(prefix []byte) []byte {
	in := make([]byte, 16)
	copy(in, prefix)
	return in
}

// summarise renders a comparison table for a failure message.
func summarise(recs []feedback.CmpRecord) string {
	const show = 12
	out := ""
	for i, r := range recs {
		if i >= show {
			out += " ..."
			break
		}
		if r.Kind == feedback.CmpInt {
			out += formatCmp(r)
			continue
		}
		out += " mem"
	}
	return out
}

func formatCmp(r feedback.CmpRecord) string {
	return " " + hex(r.AUint()) + "!=" + hex(r.BUint())
}

func hex(v uint64) string {
	const digits = "0123456789abcdef"
	if v == 0 {
		return "0x0"
	}
	var buf [16]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = digits[v&0xF]
		v >>= 4
	}
	return "0x" + string(buf[i:])
}

// TestCmpLogGetsPastAMagicNumberThatMutationCannot is the claim ADR-0007 makes
// for this stage, tested as a comparison rather than as an assertion about one
// run.
//
// The target's first gate is a 32-bit equality against a constant. Mutation
// reaches it once in four billion attempts, which over a campaign of this length
// means never; substitution reaches it in one, because the constant is in the
// comparison table waiting to be written into the input. So the same campaign is
// run twice from the same seed with the same budget, once with the stage and
// once without, and the gate has to be the difference.
func TestCmpLogGetsPastAMagicNumberThatMutationCannot(t *testing.T) {
	if testing.Short() {
		t.Skip("this runs two campaigns")
	}
	withStage := runMagicCampaign(t, true)
	without := runMagicCampaign(t, false)

	t.Logf("with cmplog:    %d execs, %d coverage, %d corpus, %d findings (%d cmp execs, %d admitted)",
		withStage.Execs, withStage.Coverage, withStage.CorpusSize, withStage.Findings,
		withStage.CmpExecs, withStage.CmpAdmitted)
	t.Logf("without cmplog: %d execs, %d coverage, %d corpus, %d findings",
		without.Execs, without.Coverage, without.CorpusSize, without.Findings)

	if withStage.CmpExecs == 0 {
		t.Fatal("the comparison stage spent no executions, so it did not run at all")
	}
	if withStage.CmpAdmitted == 0 {
		t.Errorf("the comparison stage admitted nothing in %d executions. The target's "+
			"first gate is a 32-bit constant that is in the table on every run, so a "+
			"substitution that found nothing means either the operands are not reaching "+
			"the input or the encodings tried do not include the one the target reads",
			withStage.CmpExecs)
	}
	if withStage.Coverage <= without.Coverage {
		t.Errorf("the campaign with comparison substitution covered %d entries and the "+
			"one without covered %d. Getting past a four-byte magic number by mutation "+
			"takes four billion attempts and this campaign ran %d, so the stage is what "+
			"has to make the difference",
			withStage.Coverage, without.Coverage, withStage.Execs)
	}

	// The whole ladder, not just the first rung. The three gates are 32, 64 and
	// 16 bits wide, so reaching the bug means every width was logged, decoded
	// and substituted — and the 16-bit one only works because C promoted it to a
	// 32-bit comparison and the narrower widths are tried as well.
	if withStage.Findings == 0 {
		t.Errorf("the bug behind the three gates was not reached in %d executions. "+
			"Each gate is an equality against a constant that is in the comparison "+
			"table, so each is one substitution away once the one before it is passed",
			withStage.Execs)
	}
	if without.Findings != 0 {
		t.Errorf("the campaign without substitution found the bug in %d executions, "+
			"which cannot happen by mutation — the first gate alone is one chance in "+
			"four billion per attempt. The stage is not the thing being measured",
			without.Execs)
	}
}

// runMagicCampaign fuzzes magic_cmp for a fixed number of executions, with or
// without the comparison stage.
func runMagicCampaign(t *testing.T, cmplog bool) Stats {
	return runMagicCampaignN(t, cmplog, 20000)
}

func runMagicCampaignN(t *testing.T, cmplog bool, budget uint64) Stats {
	t.Helper()
	target := buildTarget(t, "magic_cmp")

	provider := platform.NewSharedMemoryProvider()
	if !provider.Available() {
		t.Skip("shared memory is unavailable; this needs the fork server")
	}
	shm, err := provider.Create(feedback.DefaultMapSize)
	if err != nil {
		t.Fatalf("creating the coverage region: %v", err)
	}
	defer shm.Close()

	cov := feedback.NewCoverageMap("coverage", feedback.DefaultMapSize)
	cov.SetBuffer(shm.Bytes())
	cov.SetBackend("sancov")
	out := feedback.NewOutputObserver("output")

	fs := executor.NewForkServer("forkserver", safety.NewSpawner(), executor.ProcSpec{
		Path: target, Args: []string{target},
	})
	fs.Coverage, fs.Shm, fs.Output = cov, shm, out
	fs.Timeout = time.Second

	observers := []feedback.Observer{cov, out}
	var cmp *feedback.CmpObserver
	if cmplog {
		cmpShm, cerr := provider.Create(feedback.CmpRegionSize)
		if cerr != nil {
			t.Fatalf("creating the comparison region: %v", cerr)
		}
		defer cmpShm.Close()
		fs.CmpShm = cmpShm
		cmp = feedback.NewCmpObserver("cmp", cmpShm.Bytes())
		observers = append(observers, cmp)
	}

	if err := fs.Start(t.Context()); err != nil {
		t.Skipf("the fork server would not start: %v", err)
	}
	defer fs.Close()

	e, err := New(Config{
		CampaignSeed:  0x5EED,
		Executor:      fs,
		Observers:     observers,
		Feedback:      feedback.NewMapFeedback("coverage", cov),
		Objective:     feedback.NewCrashObjective("crash", out),
		Corpus:        corpus.New(),
		Schedule:      corpus.NewFastScheduler(),
		Mutators:      mutate.Default(),
		Codec:         codec.Raw{},
		Cmp:           cmp,
		MaxInputBytes: 4096,
		MaxChildren:   64,
	})
	if err != nil {
		t.Fatal(err)
	}
	// A seed long enough to hold every gate, with none of them satisfied. There
	// is nothing here for mutation to climb: until the first four bytes are
	// exactly right, every input covers the same code.
	if err := e.AddSeed(t.Context(), make([]byte, 16), "seed"); err != nil {
		t.Fatal(err)
	}

	stats, err := e.Run(t.Context(), Budget{MaxExecs: budget})
	if err != nil {
		t.Fatalf("running the campaign: %v", err)
	}
	return stats
}
