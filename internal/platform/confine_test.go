package platform

import (
	"os"
	"strings"
	"testing"
)

// TestConfinementKeepsTheCoverageMapWritable is the check that would have
// caught a whole platform reporting no coverage.
//
// A confinement policy has two halves, and only one of them fails loudly. Deny
// something a target needs to *start* and the campaign says so at once; deny
// something it needs to *record* and the campaign runs, finds nothing, and
// looks like a target with no branches — which is exactly what happened when a
// Seatbelt profile denied the temporary directory the shared maps live in, and
// what the macOS job then reported as an uninstrumented target.
func TestConfinementKeepsTheCoverageMapWritable(t *testing.T) {
	w := ConfineWritable(ConfineRequest{Path: "/bin/true", Writable: []string{"/campaign/work"}})

	shm, err := NewSharedMemoryProvider().Create(4096)
	if err == nil {
		defer shm.Close()
		var covered bool
		for _, dir := range w {
			if dir != "" && strings.HasPrefix(shm.ID(), dir) {
				covered = true
			}
		}
		if !covered {
			t.Errorf("a shared map at %s is not under any writable path: %v", shm.ID(), w)
		}
	}

	// And the caller's own directories survive: a target that cannot write its
	// working directory is indistinguishable from a broken one.
	if len(w) == 0 || w[len(w)-1] != "/campaign/work" {
		t.Errorf("the caller's writable directories did not survive: %v", w)
	}
	if w[0] != os.TempDir() && w[0] != "/dev/shm" && w[0] != "/run/shm" {
		t.Errorf("the shared memory directory is not first in %v", w)
	}
}
