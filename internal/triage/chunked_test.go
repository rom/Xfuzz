//go:build integration

// The M4 exit criterion for triage: chunked_format's five planted bugs must
// produce approximately the right number of buckets, and minimisation must
// shrink a reproducer by at least 80% without moving it to another bucket.
//
// It sits behind the integration tag because it builds and runs an instrumented
// target thousands of times (docs/TESTS.md section 4).

package triage

import (
	"context"
	"encoding/binary"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/rom/Xfuzz/internal/platform"
	"github.com/rom/Xfuzz/internal/safety"
	"github.com/rom/Xfuzz/pkg/executor"
	"github.com/rom/Xfuzz/pkg/feedback"
	"github.com/rom/Xfuzz/pkg/ir"
)

// forkRunner runs candidates against an instrumented target and reports the
// coverage each one reached, which is what coverage bucketing needs.
type forkRunner struct {
	fs  *executor.ForkServer
	cov *feedback.CoverageMap
	out *feedback.OutputObserver
	obs []feedback.Observer
}

func newForkRunner(t testing.TB, target string) *forkRunner {
	t.Helper()

	provider := platform.NewSharedMemoryProvider()
	if !provider.Available() {
		t.Skip("shared memory is unavailable; coverage bucketing needs it")
	}
	shm, err := provider.Create(feedback.DefaultMapSize)
	if err != nil {
		t.Fatalf("creating the coverage region: %v", err)
	}
	cov := feedback.NewCoverageMap("coverage", feedback.DefaultMapSize)
	cov.SetBuffer(shm.Bytes())
	cov.SetBackend("sancov")
	out := feedback.NewOutputObserver("output")

	fs := executor.NewForkServer("forkserver", safety.NewSpawner(), executor.ProcSpec{
		Path: target, Args: []string{target},
	})
	fs.Coverage, fs.Shm, fs.Output = cov, shm, out
	fs.Timeout = time.Second
	if err := fs.Start(context.Background()); err != nil {
		shm.Close()
		t.Fatalf("starting the fork server: %v", err)
	}
	t.Cleanup(func() { fs.Close(); shm.Close() })

	return &forkRunner{fs: fs, cov: cov, out: out, obs: []feedback.Observer{cov, out}}
}

// Run implements Runner.
func (r *forkRunner) Run(ctx context.Context, input []byte) (Outcome, error) {
	ek, err := r.fs.Run(ctx, executor.Input{Bytes: input}, r.obs)
	if err != nil {
		return Outcome{}, err
	}
	snapshot := append([]byte(nil), r.cov.Buffer()...)
	return Outcome{
		Exit:     ek,
		Signal:   r.out.Signal(),
		Output:   r.out.Combined(),
		Coverage: snapshot,
	}, nil
}

// --- input construction -----------------------------------------------------
//
// Reproducers are built as IR trees, not as byte strings, because that is how a
// campaign driven by chunked_format.xfg would hold them — and because the whole
// question this file settles is whether having the tree makes minimisation
// possible on a checksum-gated format.

// chunkNode builds one chunk: a tag, a derived length, a payload, and a CRC-32
// over the three. The derived fields are what make the tree reducible: dropping
// a chunk or shortening a payload leaves every length and checksum wrong, and
// the fixup pass puts them right before the candidate is ever run.
func chunkNode(tag string, payload []byte) *ir.Node {
	return ir.Struct("chunk",
		ir.Magic("tag", []byte(tag)),
		ir.LenOf("length", 4, ir.BigEndian, ir.Sibling("payload")),
		ir.Blob("payload", payload),
		ir.CRC("crc", "crc32", 4, ir.BigEndian, ir.Sibling("tag"), ir.Sibling("payload")),
	)
}

func fileNode(chunks ...*ir.Node) *ir.Node {
	return ir.Struct("chunked",
		ir.Magic("magic", []byte("XCHK")),
		ir.Magic("version", []byte{1}),
		ir.Repeat("chunks", chunks...),
	)
}

func encodeNode(t testing.TB, n *ir.Node) []byte {
	t.Helper()
	b, err := ir.NewFixer().Fix(n, ir.Suppress{})
	if err != nil {
		t.Fatalf("encoding the reproducer: %v", err)
	}
	return append([]byte(nil), b...)
}

func u32(v uint32) []byte {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	return b[:]
}

// padding is an inert chunk. Every reproducer carries several, so minimisation
// has something real to remove — a reproducer that is already minimal proves
// nothing about a minimiser.
func padding(n int) *ir.Node { return chunkNode("PADX", make([]byte, n)) }

// reproducers are one input per planted bug, each an order of magnitude larger
// than the chunk that actually triggers it.
func reproducers() map[int]*ir.Node {
	pad := func(trigger *ir.Node) *ir.Node {
		return fileNode(padding(64), padding(64), padding(64), trigger,
			padding(64), padding(64), padding(64))
	}
	sizePayload := make([]byte, 64)
	sizePayload[0] = 0xFF

	return map[int]*ir.Node{
		1: pad(chunkNode("SIZE", sizePayload)),
		2: pad(chunkNode("IDXT", []byte{0x00, 0xC0, 0x41})),
		3: fileNode(padding(64), padding(64), padding(64), padding(64), padding(64),
			chunkNode("DPTH", []byte{0}), chunkNode("DPTH", []byte{0}),
			chunkNode("DPTH", []byte{0}), chunkNode("DPTH", []byte{0}),
			padding(64), padding(64)),
		4: pad(chunkNode("MATH", append(u32(0x2000), u32(0)...))),
		5: pad(chunkNode("PTRV", []byte{0x2A, 0x2B})),
	}
}

func TestChunkedFormatReproducersAllCrash(t *testing.T) {
	r := newForkRunner(t, buildTarget(t, "chunked_format"))
	for bug, node := range reproducers() {
		o, err := r.Run(context.Background(), encodeNode(t, node))
		if err != nil {
			t.Fatalf("bug %d: %v", bug, err)
		}
		if !o.Crashed() {
			t.Fatalf("bug %d did not crash: exit=%v output=%q", bug, o.Exit, o.Output)
		}
		if !strings.Contains(o.Output, fmt.Sprintf("XFUZZ-BUG-%d", bug)) {
			t.Fatalf("bug %d reported %q", bug, o.Output)
		}
	}
}

// TestChunkedFormatBucketCounts is the exit criterion's bucketing half.
//
// The five bugs end in three distinct signals, so signal bucketing must find
// three and coverage bucketing must find five. Asserting both is what makes the
// difference between the strategies a measurement rather than a claim.
func TestChunkedFormatBucketCounts(t *testing.T) {
	r := newForkRunner(t, buildTarget(t, "chunked_format"))
	ctx := context.Background()

	outcomes := map[int]Outcome{}
	for bug, node := range reproducers() {
		o, err := r.Run(ctx, encodeNode(t, node))
		if err != nil {
			t.Fatal(err)
		}
		outcomes[bug] = o
	}

	count := func(s Strategy) map[string][]int {
		buckets := map[string][]int{}
		for bug, o := range outcomes {
			_, sig := Bucket(s, o, Classify(o))
			buckets[sig] = append(buckets[sig], bug)
		}
		return buckets
	}

	signal := count(SignalStrategy{})
	if len(signal) != 3 {
		t.Errorf("signal bucketing produced %d buckets, want 3: %v", len(signal), signal)
	}

	coverage := count(CoverageStrategy{})
	if len(coverage) != 5 {
		t.Errorf("coverage bucketing produced %d buckets for 5 bugs: %v", len(coverage), coverage)
	}
	for sig, bugs := range coverage {
		if len(bugs) != 1 {
			t.Errorf("coverage bucket %s holds bugs %v; distinct bugs must not share one", sig, bugs)
		}
	}
}

// TestChunkedFormatCoverageBucketsAreStable checks the property the whole
// strategy rests on: the same bug reached twice must land in the same bucket.
func TestChunkedFormatCoverageBucketsAreStable(t *testing.T) {
	r := newForkRunner(t, buildTarget(t, "chunked_format"))
	ctx := context.Background()

	for bug, node := range reproducers() {
		input := encodeNode(t, node)
		var first string
		for i := 0; i < 3; i++ {
			o, err := r.Run(ctx, input)
			if err != nil {
				t.Fatal(err)
			}
			_, sig := Bucket(CoverageStrategy{}, o, Classify(o))
			if i == 0 {
				first = sig
				continue
			}
			if sig != first {
				t.Fatalf("bug %d bucketed as %s then %s; coverage bucketing is not deterministic",
					bug, first, sig)
			}
		}
	}
}

// TestChunkedFormatMinimization is the exit criterion's minimisation half: at
// least 80% reduction, with the bucket preserved.
//
// "Preserved" needs saying precisely, because the obvious reading is wrong.
// Comparing the bloated reproducer's coverage bucket with the minimised one's
// and demanding they match would demand that minimisation change nothing: the
// bloated input walks six padding chunks the minimised one does not, so its
// tuple set necessarily differs. Removing that path is the job, not a defect.
//
// What must hold is that the bucket still identifies the bug. Two things are
// checked, and together they are the property anybody actually depends on: the
// minimised reproducer still triggers the same planted bug, and two independent
// bloated reproducers of one bug minimise into the same bucket while different
// bugs stay in different ones.
func TestChunkedFormatMinimization(t *testing.T) {
	r := newForkRunner(t, buildTarget(t, "chunked_format"))
	ctx := context.Background()
	w := NewWorker(Config{
		Runner:       r,
		Strategy:     CoverageStrategy{},
		Trials:       3,
		MinimizeOpts: MinimizeOptions{MaxRuns: 2000},
	})

	buckets := map[string][]int{}
	for bug, node := range reproducers() {
		input := encodeNode(t, node)
		res := w.Triage(ctx, Job{ID: int64(bug), Input: input, Node: node})
		if res.Err != nil {
			t.Fatalf("bug %d: %v", bug, res.Err)
		}
		if res.Verify.State() != "verified" {
			t.Errorf("bug %d verified as %s; a deterministic planted bug must reproduce every time",
				bug, res.Verify)
		}
		if got := res.Minimize.Reduction(); got < 0.80 {
			t.Errorf("bug %d reduced %.0f%% (%s); the criterion is 80%%",
				bug, 100*got, res.Minimize)
		}
		// The minimised reproducer must still name the same bug. A reduction
		// that lands on a different bug is worse than no reduction: it sends
		// whoever reads the report to the wrong place.
		after, err := r.Run(ctx, res.Minimized)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(after.Output, fmt.Sprintf("XFUZZ-BUG-%d", bug)) {
			t.Errorf("bug %d minimised into %q", bug, after.Output)
		}
		buckets[res.Signature] = append(buckets[res.Signature], bug)
		t.Logf("bug %d: %s, bucket %s", bug, res.Minimize, res.Signature)
	}

	if len(buckets) != 5 {
		t.Errorf("five minimised reproducers occupy %d buckets: %v", len(buckets), buckets)
	}
	for sig, bugs := range buckets {
		if len(bugs) != 1 {
			t.Errorf("bucket %s holds bugs %v; distinct bugs must not merge", sig, bugs)
		}
	}
}

// TestChunkedFormatMinimizationConverges is the other half of "preserving the
// bucket": two differently bloated reproducers of one bug must minimise into
// the same bucket.
//
// This is what makes coverage bucketing usable at all. Without it, every input
// that reaches a bug by a slightly different route is its own finding, and the
// bucket count measures how varied the corpus was rather than how many bugs
// there are.
func TestChunkedFormatMinimizationConverges(t *testing.T) {
	r := newForkRunner(t, buildTarget(t, "chunked_format"))
	ctx := context.Background()
	w := NewWorker(Config{
		Runner:       r,
		Strategy:     CoverageStrategy{},
		Trials:       1,
		MinimizeOpts: MinimizeOptions{MaxRuns: 2000},
	})

	trigger := func() *ir.Node { return chunkNode("PTRV", []byte{0x2A, 0x2B}) }
	variants := []*ir.Node{
		fileNode(padding(64), trigger(), padding(64)),
		fileNode(padding(8), padding(200), padding(16), trigger()),
		fileNode(trigger(), padding(120), padding(120), padding(120), padding(120)),
	}

	var first string
	for i, node := range variants {
		res := w.Triage(ctx, Job{ID: int64(i), Input: encodeNode(t, node), Node: node})
		if res.Err != nil {
			t.Fatalf("variant %d: %v", i, res.Err)
		}
		if i == 0 {
			first = res.Signature
			t.Logf("variant %d: %s, bucket %s", i, res.Minimize, res.Signature)
			continue
		}
		if res.Signature != first {
			t.Errorf("variant %d minimised into bucket %s, variant 0 into %s; "+
				"two reproducers of one bug did not converge",
				i, res.Signature, first)
		}
		t.Logf("variant %d: %s, bucket %s", i, res.Minimize, res.Signature)
	}
}
