package daemon

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rom/Xfuzz/internal/metrics"
	"github.com/rom/Xfuzz/internal/store"
	"github.com/rom/Xfuzz/internal/testenv"
	"github.com/rom/Xfuzz/pkg/campaign"
	"github.com/rom/Xfuzz/pkg/corpus"
	"github.com/rom/Xfuzz/pkg/executor"
)

// fixture builds a campaign whose workers are fake handles, so lifecycle,
// corpus sync, findings and termination can be exercised without spawning a
// single process.
type fixture struct {
	t        *testing.T
	campaign *Campaign
	store    *store.Store
	handles  []*fakeHandle
	spawner  *fakeSpawner
	bus      *Bus
	cmds     []chan *Message
}

func newFixture(t *testing.T, yaml string, workers int) *fixture {
	t.Helper()

	dir := testenv.ReachableDir(t)
	testenv.StubTarget(t, dir)
	path := filepath.Join(dir, "c.yaml")
	if err := os.WriteFile(path, []byte(testenv.ForThisPlatform(yaml)), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := campaign.Load(path)
	if err != nil {
		t.Fatalf("loading the campaign: %v", err)
	}

	st, err := store.Open(filepath.Join(dir, "store"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })

	handles := make([]*fakeHandle, workers)
	sp := &fakeSpawner{}
	for i := range handles {
		handles[i] = newFakeHandle(t, 1000+i, executor.ProcResult{})
		sp.handles = append(sp.handles, handles[i])
	}

	// The fake workers behave like real ones in the one respect that matters
	// for lifecycle tests: they read their control pipe and exit when asked to
	// stop. A fake that ignored its commands would make every test wait out the
	// supervisor's grace period, and would hide the difference between "asked
	// politely" and "killed".
	cmds := make([]chan *Message, len(handles))
	for i, h := range handles {
		cmds[i] = make(chan *Message, 32)
		go func(h *fakeHandle, out chan *Message) {
			dec := NewDecoder(h.workerIn)
			for {
				m, err := dec.Decode()
				if err != nil {
					return
				}
				select {
				case out <- m:
				default:
				}
				if m.Type == CmdStop {
					h.exit()
					return
				}
			}
		}(h, cmds[i])
	}

	bus := NewBus(0)
	c, err := NewCampaign(context.Background(), cfg, CampaignOptions{
		Store: st, Bus: bus, Spawner: sp, WorkerBinary: trueBin, WorkDir: dir,
		Seed: 0x5EED,
	})
	if err != nil {
		t.Fatalf("NewCampaign: %v", err)
	}
	return &fixture{t: t, campaign: c, store: st, handles: handles, spawner: sp, bus: bus, cmds: cmds}
}

// worker returns an encoder that speaks as worker i.
func (f *fixture) worker(i int) *Encoder { return NewEncoder(f.handles[i].workerOut) }

// commands returns the stream of commands the daemon sent to worker i,
// intercepted from the fixture's reader.
func (f *fixture) commands(i int) <-chan *Message { return f.cmds[i] }

const baseYAML = `
name: fixture
target:
  path: ./target
seeds:
  inline: ["alpha", "beta"]
workers:
  count: 2
  sync_interval: 20ms
storage:
  checkpoint_interval: 50ms
`

func TestCampaignStartsWorkersAndImportsSeeds(t *testing.T) {
	f := newFixture(t, baseYAML, 2)
	ctx := context.Background()

	if err := f.campaign.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer f.campaign.Stop(ctx, "test over")

	waitFor(t, func() bool { return len(f.campaign.Workers()) == 2 }, "the workers never started")
	if got := f.campaign.State(); got != StateRunning {
		t.Fatalf("state = %v", got)
	}

	// Seeds are imported by the daemon rather than by each worker, so N workers
	// do not race to insert the same entries.
	n, _, err := f.store.CountTestcases(ctx, f.campaign.ID())
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("the store holds %d seeds, want the 2 the file declared", n)
	}
}

func TestCampaignRecordsCorpusAndSyncsToSiblings(t *testing.T) {
	f := newFixture(t, baseYAML, 2)
	ctx := context.Background()
	if err := f.campaign.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer f.campaign.Stop(ctx, "test over")
	waitFor(t, func() bool { return f.campaign.Workers() != nil && len(f.campaign.Workers()) == 2 },
		"the workers never started")

	payload := []byte("a discovery")
	digest := corpus.DigestOf(payload).String()
	if err := f.worker(0).Encode(&Message{
		Type: MsgCorpus,
		Entries: []CorpusEntry{{
			Digest: digest, Payload: payload, Coverage: 42, NewSignal: 3, Favoured: true,
		}},
	}); err != nil {
		t.Fatal(err)
	}

	// Stored.
	waitFor(t, func() bool {
		n, _, _ := f.store.CountTestcases(ctx, f.campaign.ID())
		return n == 3
	}, "the discovery was never stored")

	// And handed to the sibling that did not find it, not back to the finder.
	select {
	case m := <-f.commands(1):
		if m.Type != CmdSync || len(m.Entries) != 1 {
			t.Fatalf("worker 1 received %+v", m)
		}
		if m.Entries[0].Digest != digest {
			t.Errorf("the wrong entry was synced")
		}
		// Marked, so provenance does not claim the receiver discovered it.
		if m.Entries[0].Origin != "sync:worker-0" {
			t.Errorf("origin = %q, want sync:worker-0", m.Entries[0].Origin)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the discovery was never synced to the sibling")
	}
}

func TestCampaignDeduplicatesDiscoveries(t *testing.T) {
	// Two workers finding the same input is normal, and it must not become two
	// corpus entries or two sync broadcasts.
	f := newFixture(t, baseYAML, 2)
	ctx := context.Background()
	if err := f.campaign.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer f.campaign.Stop(ctx, "test over")
	waitFor(t, func() bool { return len(f.campaign.Workers()) == 2 }, "the workers never started")

	payload := []byte("found twice")
	entry := CorpusEntry{Digest: corpus.DigestOf(payload).String(), Payload: payload, Coverage: 5}
	if err := f.worker(0).Encode(&Message{Type: MsgCorpus, Entries: []CorpusEntry{entry}}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool {
		n, _, _ := f.store.CountTestcases(ctx, f.campaign.ID())
		return n == 3
	}, "the first discovery was never stored")

	if err := f.worker(1).Encode(&Message{Type: MsgCorpus, Entries: []CorpusEntry{entry}}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)

	n, _, _ := f.store.CountTestcases(ctx, f.campaign.ID())
	if n != 3 {
		t.Fatalf("the corpus holds %d entries; the duplicate was stored again", n)
	}
}

func TestCampaignRecordsFindingsAndCountsBuckets(t *testing.T) {
	f := newFixture(t, baseYAML, 2)
	ctx := context.Background()
	if err := f.campaign.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer f.campaign.Stop(ctx, "test over")
	waitFor(t, func() bool { return len(f.campaign.Workers()) == 2 }, "the workers never started")

	sub := f.bus.Subscribe(16, EventFinding)
	defer sub.Close()

	for i, sig := range []string{"parse+0x10", "parse+0x10", "verify+0x40"} {
		payload := []byte{byte(i)}
		if err := f.worker(0).Encode(&Message{
			Type: MsgFinding,
			Finding: &FindingReport{
				Digest: corpus.DigestOf(payload).String(), Payload: payload,
				Kind: "crash", Signal: 11, Strategy: "frames", Signature: sig,
				FoundAtExec: uint64(1000 * (i + 1)),
			},
		}); err != nil {
			t.Fatal(err)
		}
	}

	waitFor(t, func() bool {
		fs, _ := f.store.Findings(ctx, f.campaign.ID())
		return len(fs) == 3
	}, "the findings were never stored")

	n, err := f.store.CountBuckets(ctx, f.campaign.ID(), "frames")
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("buckets = %d, want 2: three crashes on two signatures", n)
	}

	// The stream says which findings opened a new bucket, which is the number
	// a person watching actually cares about.
	events := drain(sub.Events(), 3, 2*time.Second)
	if len(events) != 3 {
		t.Fatalf("received %d finding events, want 3", len(events))
	}
	newBuckets := 0
	for _, e := range events {
		if d, ok := e.Data.(map[string]any); ok && d["new_bucket"] == true {
			newBuckets++
		}
	}
	if newBuckets != 2 {
		t.Errorf("%d events marked a new bucket, want 2", newBuckets)
	}
}

func TestCampaignStoresCheckpointsFromWorkerZeroOnly(t *testing.T) {
	// Every worker's map is a union of what it has seen and the corpus is
	// shared, so one worker's state is enough to resume from — and storing all
	// of them would make the checkpoint N times larger for nothing.
	f := newFixture(t, baseYAML, 2)
	ctx := context.Background()
	if err := f.campaign.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer f.campaign.Stop(ctx, "test over")
	waitFor(t, func() bool { return len(f.campaign.Workers()) == 2 }, "the workers never started")

	if err := f.worker(1).Encode(&Message{Type: MsgCheckpoint,
		Checkpoint: &CheckpointState{Execs: 999, Coverage: []byte{1, 2, 3}}}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(150 * time.Millisecond)
	if _, err := f.store.Checkpoint(ctx, f.campaign.ID()); err == nil {
		t.Fatal("worker 1's checkpoint was stored as the campaign's")
	}

	if err := f.worker(0).Encode(&Message{Type: MsgCheckpoint,
		Checkpoint: &CheckpointState{Execs: 4242, Coverage: []byte{9, 9},
			RNG: map[string]uint64{"0:seed-select": 17}}}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool {
		cp, err := f.store.Checkpoint(ctx, f.campaign.ID())
		return err == nil && cp.Execs == 4242
	}, "worker 0's checkpoint was never stored")

	cp, _ := f.store.Checkpoint(ctx, f.campaign.ID())
	if cp.RNGPositions["0:seed-select"] != 17 {
		t.Errorf("the RNG positions did not survive: %v", cp.RNGPositions)
	}
}

func TestCampaignStopsOnItsExecutionBudget(t *testing.T) {
	// A budget is the campaign's, not each worker's: "stop after a million
	// executions" must not mean a million per worker.
	f := newFixture(t, baseYAML+"stop:\n  execs: 1000\n", 2)
	ctx := context.Background()
	if err := f.campaign.Start(ctx); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return len(f.campaign.Workers()) == 2 }, "the workers never started")

	for i := 0; i < 2; i++ {
		if err := f.worker(i).Encode(&Message{Type: MsgMetrics,
			Metrics: &metrics.Snapshot{Execs: 600}}); err != nil {
			t.Fatal(err)
		}
	}
	// 600 + 600 = 1200, over the campaign's 1000.
	waitFor(t, func() bool { return f.campaign.State() == StateFinished }, "the campaign never stopped")
	if got := f.campaign.Status().Reason; got == "" {
		t.Error("the campaign stopped without recording why")
	}
}

func TestCampaignStopsOnItsFindingBudget(t *testing.T) {
	f := newFixture(t, baseYAML+"stop:\n  findings: 2\n", 2)
	ctx := context.Background()
	if err := f.campaign.Start(ctx); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return len(f.campaign.Workers()) == 2 }, "the workers never started")

	for i, sig := range []string{"a", "a", "b"} {
		payload := []byte{byte(i)}
		f.worker(0).Encode(&Message{Type: MsgFinding, Finding: &FindingReport{
			Digest: corpus.DigestOf(payload).String(), Payload: payload,
			Kind: "crash", Strategy: "frames", Signature: sig,
		}})
	}
	// Distinct buckets, not raw findings: stopping after ten thousand reports
	// of one bug is not stopping after ten thousand bugs.
	waitFor(t, func() bool { return f.campaign.State() == StateFinished }, "the campaign never stopped")
}

func TestCampaignPauseAndResume(t *testing.T) {
	f := newFixture(t, baseYAML, 2)
	ctx := context.Background()
	if err := f.campaign.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer f.campaign.Stop(ctx, "test over")
	waitFor(t, func() bool { return len(f.campaign.Workers()) == 2 }, "the workers never started")

	cmds := f.commands(0)

	if err := f.campaign.Pause(ctx); err != nil {
		t.Fatalf("Pause: %v", err)
	}
	if f.campaign.State() != StatePaused {
		t.Fatalf("state = %v", f.campaign.State())
	}
	if err := f.campaign.Resume(ctx); err != nil {
		t.Fatalf("Resume: %v", err)
	}
	if f.campaign.State() != StateRunning {
		t.Fatalf("state = %v", f.campaign.State())
	}

	// Pause and resume rather than stop and restart, so the worker keeps its
	// in-memory state.
	want := []MessageType{CmdPause, CmdResume}
	for _, w := range want {
		select {
		case m := <-cmds:
			if m.Type != w {
				t.Fatalf("worker received %v, want %v", m.Type, w)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("the worker never received %v", w)
		}
	}
}

func TestCampaignRefusesARemoteRunWithoutAuthorization(t *testing.T) {
	// Caught before anything starts, not after the first packet.
	dir := testenv.ReachableDir(t)
	testenv.StubTarget(t, dir)
	path := filepath.Join(dir, "c.yaml")
	os.WriteFile(path, []byte(testenv.ForThisPlatform(`
name: remote
target:
  path: ./target
seeds:
  inline: ["s"]
safety:
  network: true
  scope:
    allow: ["10.0.0.0/8:80"]
`)), 0o644)

	if _, err := campaign.Load(path); err == nil {
		t.Fatal("a remote campaign with no authorization record was accepted by validation")
	}
}

func TestCampaignReportsHealth(t *testing.T) {
	f := newFixture(t, baseYAML, 2)
	ctx := context.Background()
	if err := f.campaign.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer f.campaign.Stop(ctx, "test over")
	waitFor(t, func() bool { return len(f.campaign.Workers()) == 2 }, "the workers never started")

	st := f.campaign.Status()
	if st.Name != "fixture" || st.Seed == 0 {
		t.Fatalf("status = %+v", st)
	}
	if st.Isolation == "" {
		t.Error("the status does not report the isolation in force")
	}
	if len(st.Workers) != 2 {
		t.Errorf("status lists %d workers", len(st.Workers))
	}
}

func TestDaemonRefusesDuplicateAndOverLimitCampaigns(t *testing.T) {
	dir := testenv.ReachableDir(t)
	d, err := New(Options{DataDir: dir, MaxCampaigns: 1, Spawner: &fakeSpawner{}})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close(context.Background())

	cfgDir := testenv.ReachableDir(t)
	testenv.StubTarget(t, cfgDir)
	mk := func(name string) *campaign.Resolved {
		p := filepath.Join(cfgDir, name+".yaml")
		os.WriteFile(p, []byte(testenv.ForThisPlatform("name: "+name+"\ntarget:\n  path: ./target\nseeds:\n  inline: [\"s\"]\n")), 0o644)
		r, err := campaign.Load(p)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}

	if _, err := d.Create(context.Background(), mk("one")); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := d.Create(context.Background(), mk("one")); err == nil {
		t.Error("a duplicate campaign name was accepted")
	}
	if _, err := d.Create(context.Background(), mk("two")); err == nil {
		t.Error("a campaign over the limit was accepted")
	}
	if got := d.Info().Campaigns; got != 1 {
		t.Errorf("Info reports %d campaigns", got)
	}
}

func TestDaemonSharesOneStorePerDirectory(t *testing.T) {
	// Two campaigns pointed at one directory are pointed at one SQLite
	// database, and opening it twice in one process is how a daemon deadlocks
	// against itself.
	dir := testenv.ReachableDir(t)
	d, err := New(Options{DataDir: dir, Spawner: &fakeSpawner{}})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close(context.Background())

	cfgDir := testenv.ReachableDir(t)
	testenv.StubTarget(t, cfgDir)
	var stores []*store.Store
	for _, name := range []string{"a", "b"} {
		p := filepath.Join(cfgDir, name+".yaml")
		os.WriteFile(p, []byte(testenv.ForThisPlatform("name: "+name+"\ntarget:\n  path: ./target\nseeds:\n  inline: [\"s\"]\n")), 0o644)
		r, err := campaign.Load(p)
		if err != nil {
			t.Fatal(err)
		}
		st, err := d.storeAt(r.Storage.Dir)
		if err != nil {
			t.Fatal(err)
		}
		stores = append(stores, st)
	}
	if stores[0] != stores[1] {
		t.Fatal("two campaigns in one directory got two stores")
	}
}

// A finished campaign is reachable from its store alone, with the file that
// produced it gone.
//
// This is the half of ADR-0003's "triage tomorrow" that a digest cannot serve:
// the store knew which configuration ran, but not what it was, so reading last
// week's findings meant first finding last week's file.
func TestFinishedCampaignsLoadWithoutTheirFile(t *testing.T) {
	dir := testenv.ReachableDir(t)
	d, err := New(Options{DataDir: dir, Spawner: &fakeSpawner{}})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close(context.Background())

	cfgDir := testenv.ReachableDir(t)
	target := testenv.StubTarget(t, cfgDir)
	path := filepath.Join(cfgDir, "c.yaml")
	doc := "name: kept\ntarget:\n  path: " + target + "\nseeds:\n  inline: [\"s\"]\n"
	if err := os.WriteFile(path, []byte(doc), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := campaign.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.Create(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}

	// The campaign leaves the daemon, and its file leaves the disk. All that is
	// left is the store, which is the situation this is about.
	if err := d.Forget("kept"); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}

	loaded, err := d.Load(context.Background(), "", "kept")
	if err != nil {
		t.Fatalf("loading a finished campaign from its store: %v", err)
	}
	if got := loaded.Status().Name; got != "kept" {
		t.Errorf("loaded campaign is named %q", got)
	}
	if got := loaded.Config.Target.Path; got != target {
		t.Errorf("the loaded configuration points at %q, not the target that ran (%q); "+
			"what was loaded is not what ran", got, target)
	}

	// Loading twice is what a console does when somebody opens the same
	// campaign in two tabs, and the useful answer is the campaign.
	again, err := d.Load(context.Background(), "", "kept")
	if err != nil {
		t.Fatalf("loading an already-loaded campaign: %v", err)
	}
	if again != loaded {
		t.Error("loading twice produced two campaigns over one store")
	}

	if _, err := d.Load(context.Background(), "", "never-ran"); err == nil {
		t.Error("loading a campaign the store has never held succeeded")
	}
}

// A campaign with a grammar and no seed files writes its own starting corpus.
//
// The configuration for this validated all along and did nothing: seeds.generate
// was accepted, no seeds were imported, and the engine started with an empty
// corpus and no account of why. An empty corpus is the hardest kind of failure
// to read, because everything else about the campaign looks correct.
func TestCampaignGeneratesSeedsFromItsGrammar(t *testing.T) {
	dir := testenv.ReachableDir(t)
	d, err := New(Options{DataDir: dir, Spawner: &fakeSpawner{}})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close(context.Background())

	cfgDir := testenv.ReachableDir(t)
	testenv.StubTarget(t, cfgDir)
	grammar := filepath.Join(cfgDir, "g.xfg")
	if err := os.WriteFile(grammar, []byte(
		"format message {\n  tag:  magic \"MSG\"\n  body: bytes<1..16>\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(cfgDir, "g.yaml")
	doc := testenv.ForThisPlatform(
		"name: grown\ntarget:\n  path: ./target\nformat:\n  grammar: ./g.xfg\nseeds:\n  generate: 12\n")
	if err := os.WriteFile(path, []byte(doc), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := campaign.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	c, err := d.Create(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.importSeeds(context.Background()); err != nil {
		t.Fatalf("importing seeds: %v", err)
	}

	entries, err := c.store.Testcases(context.Background(), c.id, store.TestcaseQuery{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 {
		t.Fatal("a campaign with a grammar and no seed files started with an empty corpus")
	}
	for _, e := range entries {
		if e.Prov.Origin != "generated" {
			t.Errorf("entry %s came from %q, not from the grammar", e.ID, e.Prov.Origin)
		}
	}
}
