package tracer

import (
	"strings"
	"testing"
)

// TestParseExecLogReadsEveryFormatQEMUHasUsed matters because a fuzzer cannot
// require a particular version of a tool it did not build. All three shapes have
// been in circulation across supported distributions.
func TestParseExecLogReadsEveryFormatQEMUHasUsed(t *testing.T) {
	cases := []struct {
		name string
		log  string
		want []uint64
	}{
		{
			"one bracketed field",
			"Trace 0x7f3a4c000100 [0000000000401136]\n" +
				"Trace 0x7f3a4c000180 [0000000000401150]\n",
			[]uint64{0x401136, 0x401150},
		},
		{
			"code segment, counter, flags",
			"Trace 0x7f3a4c000100 [00000000/0000000000401136/00000033]\n",
			[]uint64{0x401136},
		},
		{
			"cpu index and a symbol",
			"Trace 0: 0x7f3a4c000100 [00000000/0000000000401136/00000033/ff020000] main+0x0\n" +
				"Trace 0: 0x7f3a4c000180 [00000000/000000000040115a/00000033/ff020000] main+0x24\n",
			[]uint64{0x401136, 0x40115a},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := parseExecLog(strings.NewReader(c.log), 0)
			if len(got) != len(c.want) {
				t.Fatalf("got %d addresses, want %d: %#x", len(got), len(c.want), got)
			}
			for i := range got {
				if got[i] != c.want[i] {
					t.Errorf("address %d is %#x, want %#x", i, got[i], c.want[i])
				}
			}
		})
	}
}

// TestParseExecLogIgnoresEverythingElse keeps the backend from failing on the
// emulator's own diagnostics. -d exec is a debugging stream, and it carries
// chain-linking notices and whatever else the build prints.
func TestParseExecLogIgnoresEverythingElse(t *testing.T) {
	log := `Linking TBs 0x7f3a4c000100 [0000000000401136] index 0 -> 0x7f3a4c000180
Trace 0x7f3a4c000100 [0000000000401136]
Stopped execution of TB chain before 0x7f3a4c000180 [0000000000401150]
Trace 0x7f3a4c000180 [0000000000401150]
Trace 0x7f3a4c000200 [not a number]
Trace with no brackets at all
`
	got := parseExecLog(strings.NewReader(log), 0)
	want := []uint64{0x401136, 0x401150}
	if len(got) != len(want) {
		t.Fatalf("got %#x, want %#x", got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("address %d is %#x, want %#x", i, got[i], want[i])
		}
	}
}

// TestParseExecLogStopsAtItsLimit bounds what one execution can cost. A target
// that loops under emulation prints millions of lines, and the beginning of the
// trace has already said what the input reached.
func TestParseExecLogStopsAtItsLimit(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 10000; i++ {
		b.WriteString("Trace 0x1 [0000000000401136]\n")
	}
	if got := parseExecLog(strings.NewReader(b.String()), 100); len(got) != 100 {
		t.Errorf("read %d addresses under a limit of 100", len(got))
	}
}

// TestResolveBaseRecoversWhereTheGuestWasLoaded is the arithmetic the qemu
// backend depends on: the emulator does not say where it put a
// position-independent guest, and the guest has exited by the time its log is
// read.
func TestResolveBaseRecoversWhereTheGuestWasLoaded(t *testing.T) {
	known := []uint64{0x1136, 0x1150, 0x1162, 0x1190, 0x11c4, 0x2000, 0x2044}
	const base = 0x4000000000

	observed := make([]uint64, 0, len(known))
	for _, k := range known {
		observed = append(observed, base+k)
	}
	got, ok := resolveBase(known, observed)
	if !ok {
		t.Fatal("the base could not be resolved from a trace that was entirely this image")
	}
	if got != base {
		t.Errorf("resolved base %#x, want %#x", got, base)
	}
}

// TestResolveBaseSurvivesForeignAddresses is the realistic case: a trace holds
// the dynamic linker and the C library as well as the program, and only the
// program's blocks were analysed.
func TestResolveBaseSurvivesForeignAddresses(t *testing.T) {
	known := []uint64{0x1136, 0x1150, 0x1162, 0x1190, 0x11c4, 0x2000, 0x2044}
	const base = 0x5555_5555_4000

	var observed []uint64
	for i := 0; i < 200; i++ {
		// The dynamic linker, at an unrelated base, doing far more work than
		// the program itself.
		observed = append(observed, 0x7ffff7fc0000+uint64(i*16))
	}
	for _, k := range known {
		observed = append(observed, base+k)
	}
	got, ok := resolveBase(known, observed)
	if !ok {
		t.Fatal("the base could not be resolved with the linker's blocks in the trace")
	}
	if got != base {
		t.Errorf("resolved base %#x, want %#x", got, base)
	}
}

// TestResolveBaseRefusesWhenItCannotTell is the half that keeps the backend
// honest. Coverage against a wrong base is coverage against noise, and it would
// look exactly like a campaign that was working.
func TestResolveBaseRefusesWhenItCannotTell(t *testing.T) {
	known := []uint64{0x1136, 0x1150, 0x1162, 0x1190}
	if _, ok := resolveBase(known, nil); ok {
		t.Error("an empty trace resolved a base")
	}
	if _, ok := resolveBase(nil, []uint64{0x401136}); ok {
		t.Error("a trace with no analysis to compare against resolved a base")
	}
	// A trace of some entirely different program: the low bits will match by
	// coincidence now and then, and one or two coincidences must not win.
	foreign := []uint64{0x7ffff7fc1136, 0x7ffff7fc2150, 0x7ffff7fc3000}
	if base, ok := resolveBase(known, foreign); ok && base != 0x7ffff7fc0000 {
		t.Errorf("a trace of another image resolved base %#x", base)
	}
}
