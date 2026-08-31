package feedback_test

import (
	"encoding/binary"
	"strings"
	"testing"

	"github.com/rom/Xfuzz/pkg/feedback"
)

// The counter region is what a compiler that does not call back leaves behind.
// What has to be right is the reading of it: the header describes where the
// counters are, and getting that wrong reads the target's other data as
// coverage — which looks like a working campaign and is noise.

// region builds a counter region the way the runtime writes one.
func region(t *testing.T, size int, offset, count, failed uint32, set map[int]byte) []byte {
	t.Helper()
	r := make([]byte, size)
	binary.LittleEndian.PutUint32(r[0:4], feedback.CounterMagic)
	binary.LittleEndian.PutUint32(r[4:8], offset)
	binary.LittleEndian.PutUint32(r[8:12], count)
	binary.LittleEndian.PutUint32(r[12:16], failed)
	for i, v := range set {
		r[int(offset)+i] = v
	}
	return r
}

func TestCounterObserverFoldsIntoTheMap(t *testing.T) {
	m := feedback.NewCoverageMap("coverage", 1<<12)
	r := region(t, 1<<16, 4096, 64, 0, map[int]byte{0: 1, 7: 3, 63: 200})
	o := feedback.NewCounterObserver("counters", r, m)

	if err := o.Post(feedback.ExitOK); err != nil {
		t.Fatal(err)
	}
	if o.Count() != 64 {
		t.Errorf("Count() = %d, want 64", o.Count())
	}
	if o.Covered() != 3 {
		t.Errorf("Covered() = %d, want the 3 counters that were touched", o.Covered())
	}
	if got := m.Covered(); got != 3 {
		t.Errorf("the map holds %d entries for 3 touched counters", got)
	}
}

// TestCounterObserverSpreadsAcrossTheMap is the difference between a coverage
// map and a coverage prefix. A counter index is a dense small integer, so
// without spreading the first few hundred blocks land in the first few hundred
// slots and the rest of the map stays empty for ever.
func TestCounterObserverSpreadsAcrossTheMap(t *testing.T) {
	const n = 512
	m := feedback.NewCoverageMap("coverage", 1<<12)
	set := map[int]byte{}
	for i := 0; i < n; i++ {
		set[i] = 1
	}
	r := region(t, 1<<16, 4096, n, 0, set)
	o := feedback.NewCounterObserver("counters", r, m)
	if err := o.Post(feedback.ExitOK); err != nil {
		t.Fatal(err)
	}

	// Where they landed, by quarter of the map.
	buf := m.Buffer()
	quarters := make([]int, 4)
	for i, c := range buf {
		if c != 0 {
			quarters[i*4/len(buf)]++
		}
	}
	for i, q := range quarters {
		if q == 0 {
			t.Errorf("quarter %d of the map is empty: %v", i, quarters)
		}
	}
}

// TestCounterObserverClearsBetweenExecutions. The counters *are* the shared
// region, so without this an execution's coverage is the accumulation of every
// execution before it and nothing is ever new.
func TestCounterObserverClearsBetweenExecutions(t *testing.T) {
	m := feedback.NewCoverageMap("coverage", 1<<12)
	r := region(t, 1<<16, 4096, 8, 0, map[int]byte{0: 1, 1: 1})
	o := feedback.NewCounterObserver("counters", r, m)

	if err := o.Pre(); err != nil {
		t.Fatal(err)
	}
	if err := o.Post(feedback.ExitOK); err != nil {
		t.Fatal(err)
	}
	if o.Covered() != 0 {
		t.Errorf("%d counters survived Pre", o.Covered())
	}
	// And the header survives, or the next read finds no counters at all.
	if binary.LittleEndian.Uint32(r[0:4]) != feedback.CounterMagic {
		t.Error("Pre cleared the header the target wrote")
	}
}

func TestCounterObserverSaysNothingAboutATargetThatNeverRan(t *testing.T) {
	m := feedback.NewCoverageMap("coverage", 1<<12)
	o := feedback.NewCounterObserver("counters", make([]byte, 1<<16), m)
	if err := o.Post(feedback.ExitOK); err != nil {
		t.Errorf("an empty region was an error: %v", err)
	}
	if m.Covered() != 0 {
		t.Error("an empty region produced coverage")
	}
}

// TestCounterObserverReportsAHeaderItCannotUse. A target whose counters do not
// fit, or whose remapping failed, has no coverage — and that is indistinguishable
// from a target with no reachable code unless it is said out loud.
func TestCounterObserverReportsAHeaderItCannotUse(t *testing.T) {
	m := feedback.NewCoverageMap("coverage", 1<<12)

	failed := region(t, 1<<16, 4096, 64, 3, nil)
	o := feedback.NewCounterObserver("counters", failed, m)
	err := o.Post(feedback.ExitOK)
	if err == nil {
		t.Fatal("a target that could not map its counters was reported as fine")
	}
	if !strings.Contains(err.Error(), "counter array") {
		t.Errorf("the error does not say what happened: %v", err)
	}

	past := region(t, 1<<16, 60000, 20000, 0, nil)
	o = feedback.NewCounterObserver("counters", past, m)
	if err := o.Post(feedback.ExitOK); err == nil {
		t.Fatal("counters past the end of the region were read anyway")
	}
}
