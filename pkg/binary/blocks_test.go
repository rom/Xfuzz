package binary_test

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"testing"

	"github.com/rom/Xfuzz/pkg/binary"
)

// buildC compiles a C source string and returns the executable. It is the
// binary-only path's only fixture: everything here has to work on a program
// whose source the fuzzer never sees, and building one is how that is arranged.
func buildC(t *testing.T, src string, extra ...string) string {
	t.Helper()
	cc, err := exec.LookPath("clang")
	if err != nil {
		cc, err = exec.LookPath("gcc")
		if err != nil {
			t.Skip("no C compiler; the binary-only path needs a native target to analyse")
		}
	}
	dir := t.TempDir()
	in := filepath.Join(dir, "t.c")
	if err := os.WriteFile(in, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "t")
	args := append([]string{"-O0", "-o", out, in}, extra...)
	cmd := exec.Command(cc, args...)
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("compiling the fixture failed (%v): %s", err, b)
	}
	return out
}

const ladderSrc = `
#include <stdio.h>
#include <string.h>
__attribute__((noinline)) int level3(const char *s) { return s[3] == 'D' ? 30 : 3; }
__attribute__((noinline)) int level2(const char *s) { if (s[2] == 'C') return level3(s); return 2; }
__attribute__((noinline)) int level1(const char *s) { if (s[1] == 'B') return level2(s); return 1; }
int main(void) {
	char b[64];
	if (!fgets(b, sizeof b, stdin)) return 0;
	if (b[0] != 'A') { printf("no\n"); return 0; }
	printf("%d\n", level1(b));
	return 0;
}
`

func TestAnalyzeFindsTheFunctionsAndTheirBlocks(t *testing.T) {
	target := buildC(t, ladderSrc)
	im, err := binary.Open(target)
	if err != nil {
		t.Fatal(err)
	}
	defer im.Close()
	if im.Arch != binary.ArchAMD64 {
		t.Skipf("this host is %v; block recovery is amd64 only", im.Arch)
	}
	if im.Stripped {
		t.Fatal("the unstripped fixture reports itself stripped")
	}

	a, err := binary.Analyze(im)
	if err != nil {
		t.Fatal(err)
	}

	byName := map[string]binary.Function{}
	for _, f := range a.Functions {
		byName[f.Name] = f
	}
	for _, want := range []string{"main", "level1", "level2", "level3"} {
		f, ok := byName[want]
		if !ok {
			t.Errorf("no function %q among %d recovered", want, len(a.Functions))
			continue
		}
		if len(f.Blocks) == 0 {
			t.Errorf("%s has no blocks", want)
		}
	}
	// Each of the three ladder rungs branches, so each must have more than one
	// block. A recovery that returned one block per function would look
	// plausible and would give the fuzzer no signal at all.
	for _, name := range []string{"level1", "level2"} {
		if n := len(byName[name].Blocks); n < 2 {
			t.Errorf("%s recovered as %d block(s); it contains a branch", name, n)
		}
	}
	t.Logf("%d blocks, %d functions, %d indirect, %.0f%% of text",
		len(a.Blocks), len(a.Functions), a.Indirect, 100*a.Coverage)
}

// TestBlocksDoNotOverlap is the invariant every consumer depends on. A
// breakpoint set per block must be set once, and a distance map keyed by block
// address must have one entry per address.
func TestBlocksDoNotOverlap(t *testing.T) {
	target := buildC(t, ladderSrc)
	im, err := binary.Open(target)
	if err != nil {
		t.Fatal(err)
	}
	defer im.Close()
	if im.Arch != binary.ArchAMD64 {
		t.Skip("amd64 only")
	}
	a, err := binary.Analyze(im)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i+1 < len(a.Blocks); i++ {
		x, y := a.Blocks[i], a.Blocks[i+1]
		if x.Addr >= y.Addr {
			t.Fatalf("blocks are not sorted: %#x then %#x", x.Addr, y.Addr)
		}
		if x.End > y.Addr {
			t.Errorf("block %#x..%#x overlaps the one at %#x", x.Addr, x.End, y.Addr)
		}
		if x.End <= x.Addr {
			t.Errorf("block %#x is empty", x.Addr)
		}
	}
}

// TestAnalyzeWorksOnAStrippedBinary is the whole point of the package, so it is
// asserted against the unstripped analysis of the very same program rather than
// against a number someone chose.
//
// Stripping removes sections from the end of the file and moves nothing, so the
// two analyses are directly comparable address for address. The claim is that
// the code the fuzzer needs to see — the functions the campaign will actually
// exercise — is still found without a symbol table.
func TestAnalyzeWorksOnAStrippedBinary(t *testing.T) {
	strip, err := exec.LookPath("strip")
	if err != nil {
		t.Skip("strip is not installed, so a stripped fixture cannot be made")
	}
	target := buildC(t, ladderSrc)

	im, err := binary.Open(target)
	if err != nil {
		t.Fatal(err)
	}
	if im.Arch != binary.ArchAMD64 {
		im.Close()
		t.Skip("amd64 only")
	}
	full, err := binary.Analyze(im)
	if err != nil {
		t.Fatal(err)
	}
	// The blocks belonging to the program's own functions, as opposed to the C
	// runtime's. Those are what a campaign against this target explores, and the
	// runtime's startup code is reached identically either way.
	want := map[uint64]string{}
	for _, f := range full.Functions {
		switch f.Name {
		case "main", "level1", "level2", "level3":
			for _, addr := range f.Blocks {
				want[addr] = f.Name
			}
		}
	}
	im.Close()
	if len(want) < 8 {
		t.Fatalf("the unstripped analysis found only %d blocks in the program's own "+
			"functions; the fixture cannot measure anything", len(want))
	}

	stripped := target + ".stripped"
	if b, err := exec.Command("cp", target, stripped).CombinedOutput(); err != nil {
		t.Fatalf("copying the fixture: %v: %s", err, b)
	}
	if b, err := exec.Command(strip, stripped).CombinedOutput(); err != nil {
		t.Skipf("strip failed (%v): %s", err, b)
	}

	sim, err := binary.Open(stripped)
	if err != nil {
		t.Fatal(err)
	}
	defer sim.Close()
	if !sim.Stripped {
		t.Fatal("the stripped fixture still has a symbol table")
	}
	bare, err := binary.Analyze(sim)
	if err != nil {
		t.Fatal(err)
	}

	found := map[uint64]bool{}
	for _, b := range bare.Blocks {
		found[b.Addr] = true
	}
	var missing []string
	for addr, fn := range want {
		if !found[addr] {
			missing = append(missing, fmt.Sprintf("%s+%#x", fn, addr))
		}
	}
	t.Logf("stripped: %d blocks, %d functions, %d from unwind tables, %d address-taken, %.0f%% of text",
		len(bare.Blocks), len(bare.Functions), bare.UnwindEntries, bare.AddressTaken, 100*bare.Coverage)

	if len(missing) > 0 {
		sort.Strings(missing)
		t.Errorf("%d of %d blocks in the program's own functions were lost with the "+
			"symbol table: %v\nwithout a symbol table, recovery has only the unwind "+
			"tables and address-taken references to start from, and losing these means "+
			"a campaign against a stripped build would be blind where an unstripped one "+
			"sees", len(missing), len(want), missing)
	}
}

// TestAnalyzeRefusesArchitecturesItCannotDecode keeps the failure honest. There
// is no partial answer for arm64 here, and returning an empty block list would
// look like a target with no branches.
func TestAnalyzeRefusesArchitecturesItCannotDecode(t *testing.T) {
	cc, err := exec.LookPath("clang")
	if err != nil {
		t.Skip("clang is needed to produce a foreign-architecture object")
	}
	dir := t.TempDir()
	src := filepath.Join(dir, "a.c")
	if err := os.WriteFile(src, []byte("int f(int x){return x+1;}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	obj := filepath.Join(dir, "a.o")
	cmd := exec.Command(cc, "--target=aarch64-linux-gnu", "-c", "-o", obj, src)
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("no aarch64 target support in this clang (%v): %s", err, b)
	}
	im, err := binary.Open(obj)
	if err != nil {
		t.Fatal(err)
	}
	defer im.Close()
	if _, err := binary.Analyze(im); err == nil {
		t.Fatal("analysing an arm64 image succeeded; it cannot have")
	}
}

// TestAnalyzeFollowsAnAddressTakenFunction covers the fallback the unwind tables
// usually make unnecessary.
//
// Built without unwind information, the program's own functions have no frame
// description entry, so the only remaining evidence that main exists at all is
// the instruction in the C runtime's startup code that loads its address. A
// binary in this shape is not exotic — it is what -fno-asynchronous-unwind-
// tables produces, and what a good deal of embedded and hand-written assembly
// looks like — and without this path a campaign against one would see the
// runtime and nothing else.
func TestAnalyzeFollowsAnAddressTakenFunction(t *testing.T) {
	strip, err := exec.LookPath("strip")
	if err != nil {
		t.Skip("strip is not installed")
	}
	target := buildC(t, ladderSrc, "-fno-asynchronous-unwind-tables", "-fno-unwind-tables")

	im, err := binary.Open(target)
	if err != nil {
		t.Fatal(err)
	}
	if im.Arch != binary.ArchAMD64 {
		im.Close()
		t.Skip("amd64 only")
	}
	mainAddr, ok := im.Lookup("main")
	if !ok {
		im.Close()
		t.Skip("this toolchain did not emit a main symbol to compare against")
	}
	im.Close()

	if b, err := exec.Command(strip, target).CombinedOutput(); err != nil {
		t.Skipf("strip failed (%v): %s", err, b)
	}
	sim, err := binary.Open(target)
	if err != nil {
		t.Fatal(err)
	}
	defer sim.Close()
	a, err := binary.Analyze(sim)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := a.Block(mainAddr); !ok {
		t.Errorf("main is at %#x and no block starts there; with no unwind entry for it, "+
			"the lea in the startup code is the only thing that names it, and following "+
			"that reference is what this test covers (%d blocks, %d address-taken)",
			mainAddr, len(a.Blocks), a.AddressTaken)
	}
	if a.AddressTaken == 0 {
		t.Errorf("no entry point came from an address-taken reference, so this test " +
			"passed without exercising the path it exists for")
	}
	t.Logf("no unwind tables: %d blocks, %d functions, %d address-taken, %.0f%% of text",
		len(a.Blocks), len(a.Functions), a.AddressTaken, 100*a.Coverage)
}
