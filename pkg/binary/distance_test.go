package binary_test

import (
	"os/exec"
	"testing"

	"github.com/rom/Xfuzz/pkg/binary"
)

// The distance map is what a directed campaign is steered by, so a wrong one
// does not fail: it steers the campaign somewhere else and reports progress the
// whole way. These tests check the property that makes it usable — a block
// further from the target along the program's own control flow must have a
// larger distance — rather than any particular number.

const layeredSrc = `
#include <stdio.h>
#include <string.h>

__attribute__((noinline)) void deepest(const char *s) { printf("deepest %s\n", s); }
__attribute__((noinline)) void middle(const char *s)  { deepest(s); }
__attribute__((noinline)) void shallow(const char *s) { middle(s); }
__attribute__((noinline)) void elsewhere(const char *s) { printf("elsewhere %s\n", s); }

int main(void) {
	char b[64];
	if (!fgets(b, sizeof b, stdin)) return 0;
	if (b[0] == 'A') { shallow(b); return 0; }
	if (b[0] == 'B') { middle(b); return 0; }
	if (b[0] == 'C') { deepest(b); return 0; }
	elsewhere(b);
	return 0;
}
`

func layeredImage(t *testing.T) (*binary.Image, *binary.Analysis) {
	t.Helper()
	target := buildC(t, layeredSrc)
	im, err := binary.Open(target)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { im.Close() })
	if im.Arch != binary.ArchAMD64 {
		t.Skipf("this host is %v; block recovery is amd64 only", im.Arch)
	}
	a, err := binary.Analyze(im)
	if err != nil {
		t.Fatal(err)
	}
	return im, a
}

// TestDistanceGrowsWithCallDepth is the property the whole feature rests on.
func TestDistanceGrowsWithCallDepth(t *testing.T) {
	im, a := layeredImage(t)

	addr, ok := im.Lookup("deepest")
	if !ok {
		t.Skip("this toolchain emitted no symbol for the target function")
	}
	d, err := binary.BuildDistanceMap(a, []uint64{addr})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%d of %d blocks reach the target (%.0f%%), longest distance %d",
		d.Reachable, len(a.Blocks), 100*d.Coverage(a), d.Max)

	distOf := func(fn string) uint32 {
		t.Helper()
		at, ok := im.Lookup(fn)
		if !ok {
			t.Skipf("no symbol for %s", fn)
		}
		b, ok := a.Containing(at)
		if !ok {
			t.Fatalf("%s at %#x is in no recovered block", fn, at)
		}
		v, ok := d.Of(b.Addr)
		if !ok {
			t.Fatalf("%s has no distance to the target, so a campaign could not tell "+
				"an input that reached it from one that did not", fn)
		}
		return v
	}

	deepest := distOf("deepest")
	middle := distOf("middle")
	shallow := distOf("shallow")
	t.Logf("deepest=%d middle=%d shallow=%d", deepest, middle, shallow)

	if deepest != 0 {
		t.Errorf("the target function's own block has distance %d, not 0", deepest)
	}
	if !(middle > deepest) {
		t.Errorf("middle (%d) is not further from the target than the target itself (%d)",
			middle, deepest)
	}
	if !(shallow > middle) {
		t.Errorf("shallow calls middle which calls the target, so shallow (%d) must be "+
			"further than middle (%d); a distance that does not grow with call depth "+
			"gives a directed campaign nothing to descend", shallow, middle)
	}
}

// TestABlockThatCannotReachTheTargetHasNoDistance keeps the map from claiming
// direction it does not have. Scoring an unrelated function as merely "far"
// would make every input look like partial progress.
func TestABlockThatCannotReachTheTargetHasNoDistance(t *testing.T) {
	im, a := layeredImage(t)
	addr, ok := im.Lookup("deepest")
	if !ok {
		t.Skip("no symbol for the target function")
	}
	d, err := binary.BuildDistanceMap(a, []uint64{addr})
	if err != nil {
		t.Fatal(err)
	}

	// elsewhere() calls printf and returns; nothing in it leads to the target.
	at, ok := im.Lookup("elsewhere")
	if !ok {
		t.Skip("no symbol for elsewhere")
	}
	b, ok := a.Containing(at)
	if !ok {
		t.Fatal("elsewhere is in no recovered block")
	}
	if v, ok := d.Of(b.Addr); ok {
		t.Errorf("a function with no route to the target was given distance %d", v)
	}
}

// TestBuildDistanceMapRefusesTargetsItCannotUse is the staleness rule ADR-0007
// asks for, in the form that actually catches the mistake: an address from a
// different build lands in no block, and a campaign told to aim at it would
// otherwise run happily and steer nowhere.
func TestBuildDistanceMapRefusesTargetsItCannotUse(t *testing.T) {
	_, a := layeredImage(t)

	if _, err := binary.BuildDistanceMap(a, nil); err == nil {
		t.Error("a distance map with no targets was built")
	}
	_, err := binary.BuildDistanceMap(a, []uint64{0xDEAD0000})
	if err == nil {
		t.Fatal("an address in no recovered block was accepted as a target")
	}
	t.Logf("refused with: %v", err)
}

// TestResolveAcceptsTheThreeFormsPeopleActuallyHave checks the input side: an
// address from a crash report, a function name from a discussion, a file and
// line from a patch.
func TestResolveAcceptsTheThreeFormsPeopleActuallyHave(t *testing.T) {
	target := buildC(t, layeredSrc, "-g", "-O0")
	im, err := binary.Open(target)
	if err != nil {
		t.Fatal(err)
	}
	defer im.Close()

	addr, ok := im.Lookup("deepest")
	if !ok {
		t.Skip("no symbol for the target function")
	}

	t.Run("function name", func(t *testing.T) {
		got, err := binary.Resolve(im, []binary.TargetSpec{"deepest"})
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 || got[0] != addr {
			t.Errorf("resolved %#x, want %#x", got, addr)
		}
	})

	t.Run("address", func(t *testing.T) {
		got, err := binary.Resolve(im, []binary.TargetSpec{binary.TargetSpec(hexOf(addr))})
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 || got[0] != addr {
			t.Errorf("resolved %#x, want %#x", got, addr)
		}
	})

	t.Run("file and line", func(t *testing.T) {
		// The line deepest() is defined on in the fixture.
		got, err := binary.Resolve(im, []binary.TargetSpec{"t.c:5"})
		if err != nil {
			t.Skipf("this build carries no usable line table: %v", err)
		}
		if len(got) == 0 {
			t.Error("a file and line resolved to no addresses")
		}
	})

	t.Run("names what it cannot resolve", func(t *testing.T) {
		_, err := binary.Resolve(im, []binary.TargetSpec{"no_such_function"})
		if err == nil {
			t.Fatal("a function that does not exist resolved")
		}
		t.Logf("refused with: %v", err)
	})
}

func hexOf(v uint64) string {
	const digits = "0123456789abcdef"
	var buf [16]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = digits[v&0xF]
		v >>= 4
	}
	return "0x" + string(buf[i:])
}

var _ = exec.LookPath
