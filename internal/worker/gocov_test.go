//go:build integration

// Coverage from a Go target, which until this backend had none.
//
// ADR-0026 records that Go's coverage format has no public reader, so a Go
// program fell back to black box. Go's *compiler* carries instrumentation
// already — an inline counter per basic block — and the only thing missing was
// somewhere for it to land. What this test asserts is that it lands: a campaign
// against a Go binary sees coverage grow and keeps seeds for it, where a
// black-box campaign over the same target and budget cannot.

package worker

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rom/Xfuzz/internal/testenv"
	"github.com/rom/Xfuzz/pkg/campaign"
)

func goCampaign(t *testing.T, target, coverage, seeds string) *campaign.Resolved {
	t.Helper()
	body := "name: gotest\n" +
		"target:\n  path: " + target + "\n  input: stdin\n  timeout: 2s\n" +
		"seeds:\n  inline: " + seeds + "\n" +
		"feedback:\n  coverage: " + coverage + "\n"
	if coverage == "blackbox" || coverage == "none" {
		body += "  novelty: true\n"
	}
	path := filepath.Join(t.TempDir(), "c.yaml")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := campaign.Load(path)
	if err != nil {
		t.Fatalf("loading the campaign: %v\n%s", err, body)
	}
	return cfg
}

// TestGocovSeesMoreThanBlackbox is the measurement, not the mechanism: the same
// target, the same seeds, the same budget, and the only difference is whether
// the campaign can see where an input went.
func TestGocovSeesMoreThanBlackbox(t *testing.T) {
	target := testenv.BuildGoTarget(t, "magic_go")
	const seeds = `["GOFZ xyz", "GOFZ ab"]`

	run := func(coverage string) *observer {
		cfg := goCampaign(t, target, coverage, seeds)
		return runWorker(t, cfg, func(o *observer) bool { return o.execs > 20000 },
			"the "+coverage+" campaign made no progress", 120*time.Second)
	}

	guided := run("gocov")
	guided.mu.Lock()
	gExecs, gCorpus, gFindings := guided.execs, len(guided.corpus), guided.findings
	ready := guided.ready.Executor
	guided.mu.Unlock()
	t.Logf("gocov: %d execs, %d corpus, %d findings (%s)", gExecs, gCorpus, gFindings, ready)

	if gCorpus == 0 {
		t.Fatal("the gocov campaign admitted nothing to its corpus, so it saw no coverage " +
			"at all — which is exactly what a Go target looked like before this backend")
	}

	black := run("blackbox")
	black.mu.Lock()
	bCorpus, bFindings := len(black.corpus), black.findings
	black.mu.Unlock()
	t.Logf("blackbox: %d corpus, %d findings", bCorpus, bFindings)

	// The claim is about coverage, so the corpus is what to compare: a
	// coverage-guided campaign keeps an input because it went somewhere new,
	// and a black-box one has no way to know that.
	if gCorpus <= bCorpus {
		t.Errorf("gocov kept %d corpus entries and blackbox kept %d; the coverage signal "+
			"is not distinguishing anything", gCorpus, bCorpus)
	}
}

// TestGocovSurvivesACrash is the property the design turns on. The counters are
// the shared region rather than a copy of it, so an execution that dies still
// reports where it got to — which for a fuzzer is the one execution whose
// coverage matters most. A design that folded at exit would report nothing here,
// because a Go program leaves through the kernel and never runs a C exit
// handler, and a crashing one never reaches an exit handler at all.
func TestGocovSurvivesACrash(t *testing.T) {
	target := testenv.BuildGoTarget(t, "magic_go")
	// A header claiming three bytes with none behind it: the planted bounds
	// mistake, and a panic on every execution that keeps it.
	cfg := goCampaign(t, target, "gocov", `["GOFZ "]`)

	obs := runWorker(t, cfg, func(o *observer) bool { return o.findings > 0 },
		"the crashing seed produced no finding", 90*time.Second)
	obs.mu.Lock()
	defer obs.mu.Unlock()
	if len(obs.corpus) == 0 {
		t.Error("nothing was admitted to the corpus from a campaign whose seed crashes, " +
			"so a crashing execution reported no coverage")
	}
	t.Logf("%d findings, %d corpus entries, kinds %v", obs.findings, len(obs.corpus), obs.kinds)
}
