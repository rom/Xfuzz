package metrics

import (
	"strings"
	"sync"
	"testing"
	"time"
)

func TestCollectorSumsRatesAndTakesTheMaximumOfSharedFacts(t *testing.T) {
	c := NewCollector(time.Hour)

	// Coverage, corpus and findings are campaign-wide facts that every worker
	// observes through the shared store. Summing them would report four times
	// the coverage a four-worker campaign actually has.
	c.Report(0, Snapshot{Execs: 100, ExecsPerS: 50, Coverage: 30, CorpusSize: 9, Buckets: 2})
	c.Report(1, Snapshot{Execs: 200, ExecsPerS: 60, Coverage: 31, CorpusSize: 9, Buckets: 2})

	s := c.Snapshot()
	if s.Execs != 300 {
		t.Errorf("execs = %d, want the sum 300", s.Execs)
	}
	if s.ExecsPerS != 110 {
		t.Errorf("execs/s = %v, want the sum 110", s.ExecsPerS)
	}
	if s.Coverage != 31 {
		t.Errorf("coverage = %d, want the maximum 31", s.Coverage)
	}
	if s.CorpusSize != 9 {
		t.Errorf("corpus = %d, want the maximum 9", s.CorpusSize)
	}
	if s.Buckets != 2 {
		t.Errorf("buckets = %d, want the maximum 2", s.Buckets)
	}
	if s.Workers != 2 {
		t.Errorf("workers = %d", s.Workers)
	}
}

func TestCollectorHandlesAWorkerRestart(t *testing.T) {
	c := NewCollector(time.Hour)
	c.Report(0, Snapshot{Execs: 1000})
	c.Report(1, Snapshot{Execs: 1000})
	if got := c.Snapshot().Execs; got != 2000 {
		t.Fatalf("execs = %d", got)
	}

	// Worker 1 dies and comes back. Its own counters reset, and the campaign
	// total must follow rather than double-count or freeze.
	c.Report(1, Snapshot{Execs: 5})
	if got := c.Snapshot().Execs; got != 1005 {
		t.Fatalf("after a restart execs = %d, want 1005", got)
	}

	c.Forget(1)
	if got := c.Snapshot().Execs; got != 1000 {
		t.Fatalf("after forgetting a worker execs = %d, want 1000", got)
	}
	if got := c.Snapshot().Workers; got != 1 {
		t.Fatalf("workers = %d, want 1", got)
	}
}

func TestCollectorIsSafeUnderConcurrentReports(t *testing.T) {
	c := NewCollector(time.Hour)
	var wg sync.WaitGroup
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				c.Report(w, Snapshot{Execs: uint64(i), Coverage: i})
				_ = c.Snapshot()
				_ = c.History()
			}
		}(w)
	}
	wg.Wait()
	if got := c.Snapshot().Workers; got != 8 {
		t.Fatalf("workers = %d, want 8", got)
	}
}

func TestSeriesKeepsRecentResolutionAndThinsHistory(t *testing.T) {
	s := NewSeries(0)
	base := time.Unix(0, 0)

	// Four hours of per-second reports. Keeping them all would be 14,400
	// points; keeping only the last N would lose the shape of the run.
	for i := 0; i < 4*60*60; i++ {
		s.Add(Snapshot{At: base.Add(time.Duration(i) * time.Second), Execs: uint64(i)})
	}
	pts := s.Points()

	if len(pts) > 4*perLevel {
		t.Fatalf("series holds %d points after four hours; the levels cap it at %d",
			len(pts), 4*perLevel)
	}
	if len(pts) < 100 {
		t.Fatalf("series holds only %d points; the shape of a four-hour run is lost", len(pts))
	}

	// Ordered, and no instant repeated across levels — a duplicate would put a
	// visible step in every chart at a level boundary.
	seen := map[time.Time]bool{}
	for i, p := range pts {
		if seen[p.At] {
			t.Fatalf("point %d repeats the instant %v", i, p.At)
		}
		seen[p.At] = true
		if i > 0 && p.At.Before(pts[i-1].At) {
			t.Fatalf("points are not ordered at %d", i)
		}
	}

	// The last two minutes are still per-second, which is what somebody
	// watching a live campaign is reading.
	last := pts[len(pts)-1].At
	fine := 0
	for _, p := range pts {
		if last.Sub(p.At) <= 2*time.Minute {
			fine++
		}
	}
	if fine < 60 {
		t.Errorf("only %d points in the last two minutes; recent history is not full resolution", fine)
	}

	// The oldest point is genuinely old: history was thinned, not dropped.
	if span := last.Sub(pts[0].At); span < 3*time.Hour {
		t.Errorf("the series spans %v of a four-hour run", span)
	}
}

func TestSeriesRetentionDropsOldPoints(t *testing.T) {
	s := NewSeries(10 * time.Minute)
	base := time.Unix(0, 0)
	for i := 0; i < 3600; i++ {
		s.Add(Snapshot{At: base.Add(time.Duration(i) * time.Second)})
	}
	pts := s.Points()
	if len(pts) == 0 {
		t.Fatal("retention dropped everything")
	}
	oldest := pts[0].At
	newest := pts[len(pts)-1].At
	if newest.Sub(oldest) > 11*time.Minute {
		t.Fatalf("series spans %v against a 10-minute retention", newest.Sub(oldest))
	}
}

func TestSeriesRetainsRealPointsNotAverages(t *testing.T) {
	// A coverage curve is monotonic and an execution count is cumulative, so a
	// retained point is a true statement about the campaign. An averaged one
	// would be a number that never happened.
	s := NewSeries(0)
	base := time.Unix(0, 0)
	for i := 0; i < 1000; i++ {
		s.Add(Snapshot{At: base.Add(time.Duration(i) * time.Second), Execs: uint64(i * 10)})
	}
	for _, p := range s.Points() {
		if p.Execs%10 != 0 {
			t.Fatalf("point at %v has execs %d, which no report ever contained", p.At, p.Execs)
		}
	}
}

func healthy() Snapshot {
	now := time.Unix(1_000_000, 0)
	return Snapshot{
		At: now, Execs: 500_000, ExecsPerS: 2500, Coverage: 4000, MapDensity: 0.06,
		CorpusSize: 300, Buckets: 2, Stability: 1, Overhead: 0.04,
		LastNewCoverage: now.Add(-time.Minute), Workers: 4, WorkersHealthy: 4,
	}
}

func TestHealthySnapshotHasNothingToSay(t *testing.T) {
	ds := Health(healthy(), time.Hour, DefaultThresholds(), PhaseRunning)
	if len(ds) != 0 {
		t.Fatalf("a healthy campaign produced diagnostics: %v", ds)
	}
}

func TestHealthIsSilentDuringTheGracePeriod(t *testing.T) {
	// Every check is meaningless in the first seconds of a run, and a
	// diagnostic that fires on every campaign start teaches people to ignore
	// diagnostics.
	if ds := Health(Snapshot{}, time.Second, DefaultThresholds(), PhaseRunning); len(ds) != 0 {
		t.Fatalf("a three-second-old campaign was judged: %v", ds)
	}
}

func TestHealthNamesEachSilentFailure(t *testing.T) {
	th := DefaultThresholds()
	cases := []struct {
		name string
		snap func(Snapshot) Snapshot
		want string
		sev  Severity
	}{
		{
			name: "target never starts",
			snap: func(s Snapshot) Snapshot { s.Execs = 0; return s },
			want: "no-executions", sev: SeverityBroken,
		},
		{
			name: "target is not instrumented",
			snap: func(s Snapshot) Snapshot { s.Coverage = 0; return s },
			want: "no-coverage", sev: SeverityBroken,
		},
		{
			name: "input never reaches the target",
			snap: func(s Snapshot) Snapshot { s.HarnessError = s.Execs; return s },
			want: "harness-failing", sev: SeverityBroken,
		},
		{
			name: "nothing is ever admitted",
			snap: func(s Snapshot) Snapshot { s.CorpusSize = 0; return s },
			want: "empty-corpus", sev: SeverityBroken,
		},
		{
			name: "target is non-deterministic",
			snap: func(s Snapshot) Snapshot { s.Stability = 0.4; return s },
			want: "unstable", sev: SeverityWarn,
		},
		{
			name: "the fuzzer costs more than the target",
			snap: func(s Snapshot) Snapshot { s.Overhead = 0.35; return s },
			want: "overhead", sev: SeverityWarn,
		},
		{
			name: "the map is saturating",
			snap: func(s Snapshot) Snapshot { s.MapDensity = 0.8; return s },
			want: "map-saturated", sev: SeverityWarn,
		},
		{
			name: "a worker keeps dying",
			snap: func(s Snapshot) Snapshot { s.WorkersHealthy = 2; return s },
			want: "workers-down", sev: SeverityWarn,
		},
		{
			name: "the campaign has stopped learning",
			snap: func(s Snapshot) Snapshot { s.LastNewCoverage = s.At.Add(-2 * time.Hour); return s },
			want: "coverage-stalled", sev: SeverityInfo,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ds := Health(tc.snap(healthy()), time.Hour, th, PhaseRunning)
			var found *Diagnostic
			for i := range ds {
				if ds[i].Name == tc.want {
					found = &ds[i]
				}
			}
			if found == nil {
				t.Fatalf("no %q diagnostic: %v", tc.want, ds)
			}
			if found.Severity != tc.sev {
				t.Errorf("%s severity = %v, want %v", tc.want, found.Severity, tc.sev)
			}
			// A diagnostic with no remedy is a complaint.
			if found.Remedy == "" {
				t.Errorf("%s has no remedy", tc.want)
			}
			// And it has to be quantified: "your campaign is unhealthy" is not
			// actionable. A digit, or an explicit "no" where the quantity is
			// zero and a digit would only read worse.
			quantified := strings.ContainsAny(found.Summary, "0123456789") ||
				strings.HasPrefix(found.Summary, "no ")
			if !quantified {
				t.Errorf("%s summary is not quantified: %q", tc.want, found.Summary)
			}
		})
	}
}

func TestHealthOrdersBySeverity(t *testing.T) {
	s := healthy()
	s.Coverage = 0
	s.Stability = 0.3
	s.LastNewCoverage = s.At.Add(-2 * time.Hour)

	ds := Health(s, time.Hour, DefaultThresholds(), PhaseRunning)
	if len(ds) < 3 {
		t.Fatalf("expected several diagnostics, got %v", ds)
	}
	for i := 1; i < len(ds); i++ {
		if ds[i].Severity > ds[i-1].Severity {
			t.Fatalf("diagnostics are not ordered worst first: %v", ds)
		}
	}
	if Worst(ds) != SeverityBroken {
		t.Errorf("Worst = %v", Worst(ds))
	}
}

func TestHealthStopsAtNoExecutions(t *testing.T) {
	// With no executions every other check is derived from a zero and would
	// produce a page of noise. One accurate diagnostic beats nine derived ones.
	s := healthy()
	s.Execs = 0
	ds := Health(s, time.Hour, DefaultThresholds(), PhaseRunning)
	if len(ds) != 1 || ds[0].Name != "no-executions" {
		t.Fatalf("diagnostics = %v, want only no-executions", ds)
	}
}

func TestExecsPhraseReadsLikeAPersonWroteIt(t *testing.T) {
	for execs, want := range map[uint64]string{
		1: "1 execution", 999: "999 executions", 12_000: "12k executions",
		4_500_000: "4.5M executions",
	} {
		if got := (Snapshot{Execs: execs}).execsPhrase(); got != want {
			t.Errorf("%d -> %q, want %q", execs, got, want)
		}
	}
}
