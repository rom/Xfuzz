//go:build windows

package platform

import (
	"math"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The job object is asked what it holds rather than trusted to hold what it
// was given: SetInformationJobObject accepts a struct, and a flag left out of
// LimitFlags leaves its field ignored without an error.
func TestTheJobObjectCarriesEveryCapItCan(t *testing.T) {
	j, err := NewCgroup("caps", Limits{
		AddressSpaceBytes: 512 << 20,
		Processes:         7,
		CPUSeconds:        3,
	})
	if err != nil {
		t.Skipf("no job object here: %v", err)
	}
	defer j.Close()

	var info windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	var n uint32
	if err := windows.QueryInformationJobObject(j.h, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info)), &n); err != nil {
		t.Fatal(err)
	}
	basic := info.BasicLimitInformation

	for _, want := range []struct {
		name string
		flag uint32
	}{
		{"kill on close", windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE},
		{"memory", windows.JOB_OBJECT_LIMIT_PROCESS_MEMORY},
		{"process count", windows.JOB_OBJECT_LIMIT_ACTIVE_PROCESS},
		{"CPU time", windows.JOB_OBJECT_LIMIT_PROCESS_TIME},
	} {
		if basic.LimitFlags&want.flag == 0 {
			t.Errorf("the job does not carry the %s limit (flags %#x)", want.name, basic.LimitFlags)
		}
	}
	if info.ProcessMemoryLimit != 512<<20 {
		t.Errorf("memory cap = %d, want %d", info.ProcessMemoryLimit, 512<<20)
	}
	if basic.ActiveProcessLimit != 7 {
		t.Errorf("process cap = %d, want 7", basic.ActiveProcessLimit)
	}
	// Three seconds, in 100-nanosecond units.
	if basic.PerProcessUserTimeLimit != 3*10_000_000 {
		t.Errorf("CPU cap = %d hundred-nanoseconds, want %d", basic.PerProcessUserTimeLimit, 3*10_000_000)
	}
}

func TestTheCPUCapSaturatesRatherThanWrapping(t *testing.T) {
	if got := hundredsOfNanoseconds(math.MaxUint64); got != math.MaxInt64 {
		t.Errorf("an absurd budget became %d; a wrapped cap would kill every target at once", got)
	}
	if got := hundredsOfNanoseconds(2); got != 20_000_000 {
		t.Errorf("two seconds became %d", got)
	}
}

func TestWindowsSaysWhichLimitItCannotEnforce(t *testing.T) {
	// The file-size cap has no mechanism here. Everything else the job
	// carries, so setting them earns no note — a report that warned about
	// enforced limits would teach people to skip the warnings.
	if notes := UnenforceableLimits(Limits{AddressSpaceBytes: 1, Processes: 1, CPUSeconds: 1}); len(notes) != 0 {
		t.Errorf("enforced limits were reported as unenforceable: %q", notes)
	}
	notes := UnenforceableLimits(Limits{FileSizeBytes: 1 << 20})
	if len(notes) != 1 || !strings.Contains(notes[0], "file_size_limit") {
		t.Errorf("a file-size cap on Windows was not reported: %q", notes)
	}
	if !strings.Contains(LimitsDetail(), "no file-size cap") {
		t.Errorf("the doctor's detail does not say what is missing: %q", LimitsDetail())
	}
}
