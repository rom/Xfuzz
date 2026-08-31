//go:build integration

// docs/TESTS.md lists `magic_parser` against "CmpLog, dictionary, value
// profile". The dictionary half has been checked since M3, by a campaign that
// finds all four bugs with `magic_parser.dict` supplying the constants and seeds
// that are already valid files of the format.
//
// That campaign cannot say anything about comparison substitution, because it
// was given the answers. This one takes them away: no dictionary, and seeds that
// are not valid files. Everything the campaign learns about the format it has to
// read out of the comparisons the target performed.

package engine

import (
	"testing"
	"time"

	"github.com/rom/Xfuzz/pkg/feedback"
)

func TestCmpLogFindsMagicParserWithoutADictionary(t *testing.T) {
	// One seed, and not a valid file. A campaign given "XFZ!\x02..." has been
	// told the header; the point here is that it works it out.
	seeds := [][]byte{[]byte("....\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")}
	budget := Budget{MaxExecs: 400_000, MaxTime: 90 * time.Second}

	obj := func(out *feedback.OutputObserver) feedback.Objective {
		return plantedBugObjective(out)
	}

	with := runCmpCampaign(t, cmpCampaign{
		target: "magic_parser", cmplog: true, seeds: seeds, budget: budget, objective: obj,
	})
	without := runCmpCampaign(t, cmpCampaign{
		target: "magic_parser", cmplog: false, seeds: seeds, budget: budget, objective: obj,
	})

	t.Logf("with cmplog:    %d execs, %d coverage, %d corpus, %d buckets (%d cmp execs, %d admitted)",
		with.Execs, with.Coverage, with.CorpusSize, with.Buckets, with.CmpExecs, with.CmpAdmitted)
	t.Logf("without cmplog: %d execs, %d coverage, %d corpus, %d buckets",
		without.Execs, without.Coverage, without.CorpusSize, without.Buckets)

	// Buckets rather than findings: the targets announce which bug they reached,
	// and "found one bug four hundred times" and "found four bugs" are the same
	// number of findings and very different campaigns (ASR-0011).
	if with.Buckets == 0 {
		t.Errorf("no bug reached in %d executions. Everything in this target sits behind "+
			"the four-byte header, which is one chance in four billion by mutation and "+
			"one substitution away from the comparison table", with.Execs)
	}
	if with.Buckets <= without.Buckets {
		t.Errorf("comparison substitution reached %d distinct bug(s) and mutation alone "+
			"reached %d, with the same seed and the same budget. docs/TESTS.md lists this "+
			"target against CmpLog, so either the claim or the implementation is wrong",
			with.Buckets, without.Buckets)
	}
}
