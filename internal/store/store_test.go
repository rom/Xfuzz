package store

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rom/Xfuzz/pkg/corpus"
	"github.com/rom/Xfuzz/pkg/feedback"
)

func open(t *testing.T) *Store {
	t.Helper()
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestOpenMigratesAndIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	v, err := s.Version(context.Background())
	if err != nil {
		t.Fatalf("Version: %v", err)
	}
	if v != SchemaVersion {
		t.Fatalf("version = %d, want %d", v, SchemaVersion)
	}
	s.Close()

	// Re-opening must not re-run migrations. If it did, the CREATE TABLE
	// statements would fail, which is the point of the check.
	s2, err := Open(dir)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer s2.Close()
	if v2, _ := s2.Version(context.Background()); v2 != SchemaVersion {
		t.Fatalf("version after reopen = %d", v2)
	}
}

func TestOpenRefusesNewerSchema(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if _, err := s.DB().Exec(
		`INSERT INTO meta (key, value) VALUES ('schema_version', ?)
		 ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
		"99"); err != nil {
		t.Fatal(err)
	}
	s.Close()

	if _, err := Open(dir); !errors.Is(err, ErrNewerSchema) {
		t.Fatalf("reopening a version-99 store: err = %v, want ErrNewerSchema", err)
	}
}

func TestBlobRoundTripAndDedup(t *testing.T) {
	s := open(t)
	b := s.Blobs()

	payload := []byte("the quick brown fox")
	d, err := b.Put(payload)
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	if d != corpus.DigestOf(payload) {
		t.Fatal("Put returned the wrong digest")
	}
	got, err := b.Get(d)
	if err != nil || string(got) != string(payload) {
		t.Fatalf("Get = %q, %v", got, err)
	}

	count, bytes := b.Usage()
	if _, err := b.Put(payload); err != nil {
		t.Fatal(err)
	}
	count2, bytes2 := b.Usage()
	if count2 != count || bytes2 != bytes {
		t.Fatalf("re-storing identical content changed usage: %d/%d -> %d/%d",
			count, bytes, count2, bytes2)
	}
}

func TestBlobUsageSurvivesReopen(t *testing.T) {
	dir := t.TempDir()
	b, err := OpenBlobStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		if _, err := b.Put([]byte{byte(i), byte(i), byte(i)}); err != nil {
			t.Fatal(err)
		}
	}
	wantCount, wantBytes := b.Usage()

	b2, err := OpenBlobStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	gotCount, gotBytes := b2.Usage()
	if gotCount != wantCount || gotBytes != wantBytes {
		t.Fatalf("usage after reopen = %d/%d, want %d/%d", gotCount, gotBytes, wantCount, wantBytes)
	}
}

func TestBlobDetectsCorruption(t *testing.T) {
	dir := t.TempDir()
	b, err := OpenBlobStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	d, err := b.Put([]byte("original content"))
	if err != nil {
		t.Fatal(err)
	}
	p := b.path(d)
	if err := os.Chmod(p, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("tampered content"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Get(d); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("Get on a tampered blob: err = %v, want ErrCorrupt", err)
	}
}

func TestBlobMissingIsNotFound(t *testing.T) {
	s := open(t)
	if _, err := s.Blobs().Get(corpus.DigestOf([]byte("never stored"))); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestBlobSweepRemovesTempFiles(t *testing.T) {
	dir := t.TempDir()
	b, err := OpenBlobStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Put([]byte("keep me")); err != nil {
		t.Fatal(err)
	}
	stray := filepath.Join(dir, "ab", ".tmp-interrupted")
	if err := os.MkdirAll(filepath.Dir(stray), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stray, []byte("half a blob"), 0o600); err != nil {
		t.Fatal(err)
	}
	n, err := b.Sweep()
	if err != nil || n != 1 {
		t.Fatalf("Sweep = %d, %v; want 1, nil", n, err)
	}
	if _, err := os.Stat(stray); !os.IsNotExist(err) {
		t.Fatal("the temporary file survived the sweep")
	}
}

func TestCampaignLifecycle(t *testing.T) {
	s := open(t)
	ctx := context.Background()

	c, err := s.CreateCampaign(ctx, "png", "cfg-digest", 0xdeadbeef)
	if err != nil {
		t.Fatalf("CreateCampaign: %v", err)
	}
	if c.Status != StatusCreated {
		t.Fatalf("status = %q", c.Status)
	}
	if err := s.SetCampaignStatus(ctx, c.ID, StatusRunning); err != nil {
		t.Fatal(err)
	}
	got, err := s.Campaign(ctx, "png")
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != StatusRunning || got.Seed != 0xdeadbeef || got.ConfigDigest != "cfg-digest" {
		t.Fatalf("round trip lost data: %+v", got)
	}
	if _, err := s.Campaign(ctx, "absent"); !errors.Is(err, ErrNoCampaign) {
		t.Fatalf("err = %v, want ErrNoCampaign", err)
	}
	if _, err := s.CreateCampaign(ctx, "png", "", 1); err == nil {
		t.Fatal("a duplicate campaign name was accepted")
	}
}

func testcase(payload string, cov int, favoured bool) *corpus.Testcase {
	tc := corpus.NewTestcase(nil, []byte(payload))
	tc.Meta.Coverage = cov
	tc.Meta.Favoured = favoured
	tc.Meta.Score = feedback.Score{NewSignal: cov}
	tc.Meta.ExecTime = 3 * time.Millisecond
	tc.Meta.Depth = 2
	return tc
}

func TestTestcaseRoundTrip(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	c, _ := s.CreateCampaign(ctx, "c", "", 1)

	tc := testcase("hello world", 17, true)
	tc.Prov = corpus.Provenance{
		Parent: corpus.DigestOf([]byte("parent")),
		Worker: 3,
		Origin: "seed",
		Ops:    []corpus.Op{{Mutator: "bit-flip", Path: []int{0, 2}, RandPos: 99}},
	}
	if err := s.SaveTestcase(ctx, c.ID, tc); err != nil {
		t.Fatalf("SaveTestcase: %v", err)
	}

	got, err := s.Testcase(ctx, c.ID, tc.ID)
	if err != nil {
		t.Fatalf("Testcase: %v", err)
	}
	if string(got.Bytes) != "hello world" {
		t.Fatalf("payload = %q", got.Bytes)
	}
	if got.Meta.Coverage != 17 || !got.Meta.Favoured || got.Meta.Depth != 2 {
		t.Fatalf("metadata lost: %+v", got.Meta)
	}
	if got.Meta.ExecTime != 3*time.Millisecond {
		t.Fatalf("exec time = %v", got.Meta.ExecTime)
	}
	if got.Prov.Parent != tc.Prov.Parent || got.Prov.Worker != 3 || got.Prov.Origin != "seed" {
		t.Fatalf("provenance lost: %+v", got.Prov)
	}
	if len(got.Prov.Ops) != 1 || got.Prov.Ops[0].Mutator != "bit-flip" ||
		got.Prov.Ops[0].RandPos != 99 || len(got.Prov.Ops[0].Path) != 2 {
		t.Fatalf("ops lost: %+v", got.Prov.Ops)
	}
}

func TestSaveTestcaseIsIdempotent(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	c, _ := s.CreateCampaign(ctx, "c", "", 1)

	tc := testcase("payload", 5, false)
	for i := 0; i < 3; i++ {
		tc.Meta.Fuzzed = uint64(i)
		if err := s.SaveTestcase(ctx, c.ID, tc); err != nil {
			t.Fatalf("save %d: %v", i, err)
		}
	}
	n, _, err := s.CountTestcases(ctx, c.ID)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("count = %d, want 1", n)
	}
	got, _ := s.Testcase(ctx, c.ID, tc.ID)
	if got.Meta.Fuzzed != 2 {
		t.Fatalf("fuzzed = %d, want the latest value 2", got.Meta.Fuzzed)
	}
}

func TestTestcaseBatchAndQuery(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	c, _ := s.CreateCampaign(ctx, "c", "", 1)

	batch := []*corpus.Testcase{
		testcase("aaaa", 10, false),
		testcase("bb", 40, true),
		testcase("cccccc", 25, false),
	}
	if err := s.SaveTestcases(ctx, c.ID, batch); err != nil {
		t.Fatalf("SaveTestcases: %v", err)
	}

	byCov, err := s.Testcases(ctx, c.ID, TestcaseQuery{Order: "coverage"})
	if err != nil {
		t.Fatal(err)
	}
	if len(byCov) != 3 || byCov[0].Meta.Coverage != 40 || byCov[2].Meta.Coverage != 10 {
		t.Fatalf("coverage order wrong: %v", coverages(byCov))
	}
	bySize, _ := s.Testcases(ctx, c.ID, TestcaseQuery{Order: "size"})
	if bySize[0].Meta.Size != 2 || bySize[2].Meta.Size != 6 {
		t.Fatalf("size order wrong: %v", sizes(bySize))
	}
	fav, _ := s.Testcases(ctx, c.ID, TestcaseQuery{FavouredOnly: true, WithPayload: true})
	if len(fav) != 1 || string(fav[0].Bytes) != "bb" {
		t.Fatalf("favoured query wrong: %d entries", len(fav))
	}
	if lim, _ := s.Testcases(ctx, c.ID, TestcaseQuery{Limit: 2}); len(lim) != 2 {
		t.Fatal("limit ignored")
	}
}

func coverages(tcs []*corpus.Testcase) []int {
	out := make([]int, len(tcs))
	for i, tc := range tcs {
		out[i] = tc.Meta.Coverage
	}
	return out
}

func sizes(tcs []*corpus.Testcase) []int {
	out := make([]int, len(tcs))
	for i, tc := range tcs {
		out[i] = tc.Meta.Size
	}
	return out
}

func TestFindingBucketing(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	c, _ := s.CreateCampaign(ctx, "c", "", 1)

	mk := func(payload, sig string) *Finding {
		f := &Finding{
			CampaignID:  c.ID,
			Digest:      corpus.DigestOf([]byte(payload)),
			Finding:     feedback.Finding{Kind: "crash", Summary: "SIGSEGV", Signal: 11},
			FoundAtExec: 4242,
		}
		f.SetBucket("frames", sig)
		return f
	}
	for _, tcase := range []struct{ payload, sig string }{
		{"input-a", "parse+0x10"},
		{"input-b", "parse+0x10"},
		{"input-c", "verify+0x40"},
	} {
		if err := s.SaveFinding(ctx, mk(tcase.payload, tcase.sig), []byte(tcase.payload)); err != nil {
			t.Fatalf("SaveFinding: %v", err)
		}
	}

	n, err := s.CountBuckets(ctx, c.ID, "frames")
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("buckets = %d, want 2", n)
	}
	buckets, _ := s.Buckets(ctx, c.ID, "frames")
	if buckets[0].Count != 2 || buckets[0].Signature != "parse+0x10" {
		t.Fatalf("top bucket = %+v", buckets[0])
	}
}

func TestDuplicateFindingDoesNotInflateBucket(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	c, _ := s.CreateCampaign(ctx, "c", "", 1)

	for i := 0; i < 3; i++ {
		f := &Finding{
			CampaignID: c.ID,
			Digest:     corpus.DigestOf([]byte("same input")),
			Finding:    feedback.Finding{Kind: "crash", Summary: "SIGSEGV"},
		}
		f.SetBucket("frames", "sig")
		if err := s.SaveFinding(ctx, f, []byte("same input")); err != nil {
			t.Fatalf("save %d: %v", i, err)
		}
	}
	buckets, _ := s.Buckets(ctx, c.ID, "frames")
	if len(buckets) != 1 || buckets[0].Count != 1 {
		t.Fatalf("re-reporting one reproducer three times gave count %v", buckets)
	}
	fs, _ := s.Findings(ctx, c.ID)
	if len(fs) != 1 {
		t.Fatalf("findings = %d, want 1", len(fs))
	}
}

func TestTriageUpdate(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	c, _ := s.CreateCampaign(ctx, "c", "", 1)

	f := &Finding{
		CampaignID:   c.ID,
		Digest:       corpus.DigestOf([]byte("big input")),
		OriginalSize: 1000,
		Finding:      feedback.Finding{Kind: "crash", Frames: []string{"a", "b"}},
	}
	f.SetBucket("frames", "sig")
	if err := s.SaveFinding(ctx, f, []byte("big input")); err != nil {
		t.Fatal(err)
	}

	loaded, err := s.Finding(ctx, f.ID)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.ReproTrials != 0 {
		t.Fatal("a fresh finding must record zero verification trials")
	}
	if len(loaded.Frames) != 2 || loaded.Frames[0] != "a" {
		t.Fatalf("frames lost: %v", loaded.Frames)
	}

	small := corpus.DigestOf([]byte("small"))
	if err := s.UpdateTriage(ctx, f.ID, TriageMinimized, 10, 1.0, small, 120, "reduced"); err != nil {
		t.Fatal(err)
	}
	loaded, _ = s.Finding(ctx, f.ID)
	if loaded.TriageState != TriageMinimized || loaded.ReproTrials != 10 || loaded.ReproRate != 1.0 {
		t.Fatalf("triage not recorded: %+v", loaded)
	}
	if got := loaded.Reduction(); got < 0.87 || got > 0.89 {
		t.Fatalf("reduction = %.3f, want 0.88", got)
	}
	pending, _ := s.FindingsInState(ctx, c.ID, TriageNew)
	if len(pending) != 0 {
		t.Fatal("the finding is still listed as untriaged")
	}
}

func TestCheckpointRoundTrip(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	c, _ := s.CreateCampaign(ctx, "c", "", 1)

	if _, err := s.Checkpoint(ctx, c.ID); !errors.Is(err, ErrNoCheckpoint) {
		t.Fatalf("err = %v, want ErrNoCheckpoint", err)
	}

	cov := make([]byte, 65536)
	for i := 0; i < 400; i++ {
		cov[i*97%len(cov)] = byte(i)
	}
	cp := &Checkpoint{
		Coverage:     cov,
		Execs:        1234567,
		CorpusSize:   42,
		RNGPositions: map[string]uint64{"0:mutation": 900, "1:mutation": 950},
	}
	if err := s.SaveCheckpoint(ctx, c.ID, cp); err != nil {
		t.Fatalf("SaveCheckpoint: %v", err)
	}
	got, err := s.Checkpoint(ctx, c.ID)
	if err != nil {
		t.Fatalf("Checkpoint: %v", err)
	}
	if len(got.Coverage) != len(cov) {
		t.Fatalf("coverage length = %d, want %d", len(got.Coverage), len(cov))
	}
	for i := range cov {
		if got.Coverage[i] != cov[i] {
			t.Fatalf("coverage differs at %d", i)
		}
	}
	if got.Execs != 1234567 || got.CorpusSize != 42 {
		t.Fatalf("counters lost: %+v", got)
	}
	if got.RNGPositions["1:mutation"] != 950 {
		t.Fatalf("RNG positions lost: %v", got.RNGPositions)
	}

	// A second save replaces the first wholesale.
	cp.Execs = 2000000
	if err := s.SaveCheckpoint(ctx, c.ID, cp); err != nil {
		t.Fatal(err)
	}
	got, _ = s.Checkpoint(ctx, c.ID)
	if got.Execs != 2000000 {
		t.Fatalf("execs = %d after overwrite", got.Execs)
	}
}

func TestCheckpointCompressesSparseMaps(t *testing.T) {
	cov := make([]byte, 1<<20)
	for i := 0; i < 5000; i++ {
		cov[i*211%len(cov)] = 1
	}
	packed, err := packCoverage(cov)
	if err != nil {
		t.Fatal(err)
	}
	if len(packed) >= len(cov)/4 {
		t.Fatalf("packed a sparse 1 MiB map into %d bytes; compression is not working", len(packed))
	}
	back, err := unpackCoverage(packed)
	if err != nil {
		t.Fatal(err)
	}
	if len(back) != len(cov) {
		t.Fatalf("unpacked length = %d, want %d", len(back), len(cov))
	}
	for i := range cov {
		if back[i] != cov[i] {
			t.Fatalf("differs at %d", i)
		}
	}
}

func TestAuditChainVerifies(t *testing.T) {
	s := open(t)
	ctx := context.Background()

	for i, action := range []string{AuditCampaignStart, AuditTargetSpawn, AuditScopeDeny} {
		if _, err := s.Audit(ctx, "operator", action, "detail"); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	n, err := s.VerifyAudit(ctx)
	if err != nil {
		t.Fatalf("VerifyAudit: %v", err)
	}
	if n != 3 {
		t.Fatalf("verified %d entries, want 3", n)
	}

	entries, _ := s.AuditLog(ctx)
	if entries[0].PrevHash != "" {
		t.Fatal("the first entry must chain to nothing")
	}
	for i := 1; i < len(entries); i++ {
		if entries[i].PrevHash != entries[i-1].Hash {
			t.Fatalf("entry %d does not chain to its predecessor", i+1)
		}
	}
}

func TestAuditDetectsModification(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		if _, err := s.Audit(ctx, "operator", AuditScopeAllow, "host=example.test"); err != nil {
			t.Fatal(err)
		}
	}
	// Rewrite the third entry's detail, exactly as someone hiding a connection
	// would.
	if _, err := s.DB().Exec(`UPDATE audit SET detail = 'host=innocent.test' WHERE id = 3`); err != nil {
		t.Fatal(err)
	}
	n, err := s.VerifyAudit(ctx)
	if !errors.Is(err, ErrAuditTampered) {
		t.Fatalf("err = %v, want ErrAuditTampered", err)
	}
	if n != 2 {
		t.Fatalf("verified %d entries before the divergence, want 2", n)
	}
	if !strings.Contains(err.Error(), "entry 3") {
		t.Fatalf("the error does not name the entry: %v", err)
	}
}

func TestAuditDetectsTruncation(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	for i := 0; i < 4; i++ {
		if _, err := s.Audit(ctx, "operator", AuditTargetSpawn, "t"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.DB().Exec(`DELETE FROM audit WHERE id = 4`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.VerifyAudit(ctx); !errors.Is(err, ErrAuditTampered) {
		t.Fatalf("truncating the log went undetected: err = %v", err)
	}
}

func TestAuditDetectsDeletionFromTheMiddle(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	for i := 0; i < 4; i++ {
		if _, err := s.Audit(ctx, "operator", AuditTargetSpawn, "t"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.DB().Exec(`DELETE FROM audit WHERE id = 2`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.VerifyAudit(ctx); !errors.Is(err, ErrAuditTampered) {
		t.Fatal("removing an entry from the middle went undetected")
	}
}

func TestBudgetCullsCheapestFirstAndProtects(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	c, _ := s.CreateCampaign(ctx, "c", "", 1)

	// Coverage per byte: cheap 1/64, mid 20/64, rich 60/64. favoured is cheap
	// but in the minimal covering set; repro is cheap but a finding needs it.
	entries := map[string]*corpus.Testcase{
		"cheap":    testcase(strings.Repeat("a", 64), 1, false),
		"mid":      testcase(strings.Repeat("b", 64), 20, false),
		"rich":     testcase(strings.Repeat("c", 64), 60, false),
		"favoured": testcase(strings.Repeat("d", 64), 1, true),
		"repro":    testcase(strings.Repeat("e", 64), 1, false),
	}
	var batch []*corpus.Testcase
	for _, tc := range entries {
		batch = append(batch, tc)
	}
	if err := s.SaveTestcases(ctx, c.ID, batch); err != nil {
		t.Fatal(err)
	}
	f := &Finding{CampaignID: c.ID, Digest: entries["repro"].ID,
		Finding: feedback.Finding{Kind: "crash"}}
	f.SetBucket("frames", "sig")
	if err := s.SaveFinding(ctx, f, entries["repro"].Bytes); err != nil {
		t.Fatal(err)
	}

	// 5 entries of 64 bytes = 320. Cap at 200 so two must go.
	rep, err := s.Enforce(ctx, c.ID, Budget{MaxBytes: 200})
	if err != nil {
		t.Fatalf("Enforce: %v", err)
	}
	if rep.Removed != 2 || rep.BytesFreed != 128 {
		t.Fatalf("removed %d entries / %d bytes, want 2 / 128", rep.Removed, rep.BytesFreed)
	}
	for _, name := range []string{"favoured", "repro", "rich"} {
		if _, err := s.Testcase(ctx, c.ID, entries[name].ID); err != nil {
			t.Fatalf("%s was culled but must be kept: %v", name, err)
		}
	}
	if _, err := s.Testcase(ctx, c.ID, entries["cheap"].ID); err == nil {
		t.Fatal("the cheapest entry survived")
	}
}

func TestBudgetReportsWhenItCannotBeMet(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	c, _ := s.CreateCampaign(ctx, "c", "", 1)

	var batch []*corpus.Testcase
	for i := 0; i < 4; i++ {
		batch = append(batch, testcase(strings.Repeat(string(rune('a'+i)), 100), 1, true))
	}
	if err := s.SaveTestcases(ctx, c.ID, batch); err != nil {
		t.Fatal(err)
	}
	rep, err := s.Enforce(ctx, c.ID, Budget{MaxBytes: 100})
	if err == nil {
		t.Fatal("enforcing an unmeetable budget reported success")
	}
	if rep.Removed != 0 || rep.Protected != 4 {
		t.Fatalf("report = %+v", rep)
	}
	if !strings.Contains(err.Error(), "protected") {
		t.Fatalf("the error does not explain why: %v", err)
	}
}

func TestBudgetIsDeterministic(t *testing.T) {
	run := func() []string {
		s := open(t)
		ctx := context.Background()
		c, _ := s.CreateCampaign(ctx, "c", "", 1)
		var batch []*corpus.Testcase
		for i := 0; i < 20; i++ {
			// Identical value density, so only the tie-break distinguishes them.
			batch = append(batch, testcase(strings.Repeat(string(rune('a'+i)), 32), 5, false))
		}
		if err := s.SaveTestcases(ctx, c.ID, batch); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Enforce(ctx, c.ID, Budget{MaxEntries: 5}); err != nil {
			t.Fatal(err)
		}
		left, _ := s.Testcases(ctx, c.ID, TestcaseQuery{Order: "size"})
		var out []string
		for _, tc := range left {
			out = append(out, tc.ID.String())
		}
		return out
	}
	a, b := run(), run()
	if len(a) != 5 || len(b) != 5 {
		t.Fatalf("kept %d and %d entries, want 5", len(a), len(b))
	}
	for i := range a {
		if a[i] != b[i] {
			t.Fatalf("two identical campaigns culled differently at %d: %s vs %s", i, a[i], b[i])
		}
	}
}

func TestCollectBlobsRespectsReachabilityAndGrace(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	c, _ := s.CreateCampaign(ctx, "c", "", 1)

	live := testcase("referenced payload", 9, false)
	if err := s.SaveTestcase(ctx, c.ID, live); err != nil {
		t.Fatal(err)
	}
	orphan, err := s.Blobs().Put([]byte("nobody points at me"))
	if err != nil {
		t.Fatal(err)
	}

	// With a grace window, a freshly written orphan is exactly the blob whose
	// row has not been committed yet, and must survive.
	rep, err := s.CollectBlobs(ctx, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Removed != 0 {
		t.Fatalf("collection inside the grace window removed %d blobs", rep.Removed)
	}
	if !s.Blobs().Has(orphan) {
		t.Fatal("the young orphan was collected")
	}

	rep, err = s.CollectBlobs(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Removed != 1 {
		t.Fatalf("removed %d blobs, want 1", rep.Removed)
	}
	if s.Blobs().Has(orphan) {
		t.Fatal("the orphan survived collection")
	}
	if _, err := s.Testcase(ctx, c.ID, live.ID); err != nil {
		t.Fatalf("a referenced payload was collected: %v", err)
	}
}

func TestCollectBlobsKeepsFindingReproducers(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	c, _ := s.CreateCampaign(ctx, "c", "", 1)

	payload := []byte("crashing input")
	minimized := []byte("crash")
	f := &Finding{CampaignID: c.ID, Digest: corpus.DigestOf(payload),
		Finding: feedback.Finding{Kind: "crash"}}
	f.SetBucket("frames", "sig")
	if err := s.SaveFinding(ctx, f, payload); err != nil {
		t.Fatal(err)
	}
	md, _ := s.Blobs().Put(minimized)
	if err := s.UpdateTriage(ctx, f.ID, TriageMinimized, 5, 1.0, md, len(minimized), ""); err != nil {
		t.Fatal(err)
	}

	if _, err := s.CollectBlobs(ctx, 0); err != nil {
		t.Fatal(err)
	}
	if !s.Blobs().Has(corpus.DigestOf(payload)) {
		t.Fatal("a finding's reproducer was collected")
	}
	if !s.Blobs().Has(md) {
		t.Fatal("a finding's minimised reproducer was collected")
	}
}
