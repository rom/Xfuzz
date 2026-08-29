package metrics

import (
	"strings"
	"testing"
	"time"
)

// A campaign that executed nothing has two possible causes, and naming the
// wrong one sends the reader to the wrong place: a target that will not start,
// or a budget shorter than the campaign's own startup.
func TestZeroExecutionsNamesTheLikelyCause(t *testing.T) {
	th := DefaultThresholds()
	var s Snapshot

	short := Health(s, th.Grace+time.Second, th, PhaseStopped)
	if len(short) == 0 {
		t.Fatal("a campaign that executed nothing was reported as healthy")
	}
	if !strings.Contains(short[0].Remedy, "budget") {
		t.Errorf("a campaign shorter than its own startup was told its target is broken: %q",
			short[0].Remedy)
	}

	long := Health(s, th.StartupGrace+time.Minute, th, PhaseStopped)
	if len(long) == 0 {
		t.Fatal("a long campaign that executed nothing was reported as healthy")
	}
	if !strings.Contains(long[0].Remedy, "failing to start") {
		t.Errorf("a campaign with time to spare was not told its target is at fault: %q",
			long[0].Remedy)
	}
}
