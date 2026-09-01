package binary_test

import (
	"debug/pe"
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	xbin "github.com/rom/Xfuzz/pkg/binary"
)

// A Windows executable built by the Microsoft toolchain has no symbol table at
// all: link.exe writes names to a separate PDB file, so an ordinary build — not
// a stripped one, not a hardened one — reaches this package in the same shape a
// stripped ELF does. The exception directory is what is left, and unlike DWARF
// call-frame information it is mandatory for x64 code and states where each
// function ends as well as where it begins.
//
// Nothing here needs Windows to run. The fixture is a freestanding program with
// no includes, so any clang can compile it for the Microsoft target and any COFF
// linker can link it without a Windows SDK, which is what lets the symbol-less
// path be tested on every host rather than only on the one where it matters.
const peLadderSrc = `
// orphan is called by nothing and its address is taken by nothing. The only
// thing in the whole image that says it exists is its exception-directory
// entry, so a block at its first instruction can have come from nowhere else.
__attribute__((noinline)) int orphan(const char *s) {
	if (s[0] == 'A') return 1;
	if (s[1] == 'B') return 2;
	return 3;
}
__attribute__((noinline)) int level3(const char *s) { return s[3] == 'D' ? 30 : 3; }
__attribute__((noinline)) int level2(const char *s) { if (s[2] == 'C') return level3(s); return 2; }
__attribute__((noinline)) int level1(const char *s) { if (s[1] == 'B') return level2(s); return 1; }
int mainCRTStartup(void) {
	const char *b = "ABCD";
	if (b[0] != 'A') return 0;
	return level1(b);
}
`

// buildPE compiles and links the ladder fixture as an executable.
func buildPE(t *testing.T, linkExtra ...string) string {
	t.Helper()
	link := []string{
		"/entry:mainCRTStartup",
		"/subsystem:console",
		// Keep the unreferenced function. Reference-based section stripping is
		// on by default, and it would remove the one piece of the fixture that
		// only the exception directory can find.
		"/opt:noref",
	}
	return buildPEFrom(t, peLadderSrc, append(link, linkExtra...))
}

// buildPEFrom compiles and links a source for x86_64 Windows and returns the
// image, or skips when the host cannot produce one.
func buildPEFrom(t *testing.T, src string, link []string) string {
	t.Helper()
	cc, err := exec.LookPath("clang")
	if err != nil {
		t.Skip("clang is needed to compile for the Microsoft target")
	}
	// lld-link ships with LLVM everywhere; link.exe is the Microsoft one, and is
	// only ever on the path on Windows.
	var linker string
	for _, name := range []string{"lld-link", "link.exe", "lld-link.exe"} {
		if p, err := exec.LookPath(name); err == nil {
			linker = p
			break
		}
	}
	if linker == "" {
		t.Skip("no COFF linker on this host, so a PE cannot be produced")
	}

	dir := t.TempDir()
	csrc := filepath.Join(dir, "pe.c")
	if err := os.WriteFile(csrc, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	obj := filepath.Join(dir, "pe.obj")
	cmd := exec.Command(cc, "--target=x86_64-pc-windows-msvc", "-O0", "-c", "-o", obj, csrc)
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("this clang cannot target Windows (%v): %s", err, b)
	}

	out := filepath.Join(dir, "pe.bin")
	args := append([]string{"/out:" + out, "/nodefaultlib"}, link...)
	args = append(args, obj)
	if b, err := exec.Command(linker, args...).CombinedOutput(); err != nil {
		t.Skipf("linking the fixture failed (%v): %s", err, b)
	}
	return out
}

// TestAnalyzeRecoversASymbolLessPE is the Windows counterpart of the stripped
// ELF test, and the case that matters more there: on Windows this is not the
// stripped build, it is every build.
//
// The two link layouts differ in one thing. A PE records every address in its
// exception directory relative to the image base, and the base is in the
// optional header — but an image whose first section starts within the first
// 64K of it can also be made to look right by rounding that section's address
// down, which is what this package used to do. The second layout moves the code
// past that point, where the rounding lands a whole section short and every
// function start it produces is an address with no code at it.
func TestAnalyzeRecoversASymbolLessPE(t *testing.T) {
	layouts := []struct {
		name string
		link []string
	}{
		{"default layout", nil},
		// /align sets the section alignment in memory, which pushes .text to an
		// address the image base cannot be guessed back out of. The linker warns
		// that the result may not run; nothing here runs it.
		{"code past the first 64K", []string{"/align:65536", "/filealign:512"}},
	}
	for _, layout := range layouts {
		t.Run(layout.name, func(t *testing.T) {
			target := buildPE(t, layout.link...)
			im, err := xbin.Open(target)
			if err != nil {
				t.Fatal(err)
			}
			defer im.Close()
			if im.Format != xbin.FormatPE {
				t.Fatalf("built a %v, not a PE", im.Format)
			}
			if im.Arch != xbin.ArchAMD64 {
				t.Skipf("this clang produced %v", im.Arch)
			}
			if !im.Stripped {
				t.Skipf("this linker wrote a symbol table into the image (%d symbols), "+
					"so the fixture is not the symbol-less one this test is about",
					len(im.Symbols()))
			}

			a, err := xbin.Analyze(im)
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("%d blocks, %d functions, %d from the exception directory, "+
				"%d address-taken, %.0f%% of text",
				len(a.Blocks), len(a.Functions), a.UnwindEntries, a.AddressTaken, 100*a.Coverage)

			// Five functions are compiled and none is discarded, so the
			// exception directory has to name all five. Fewer means the
			// directory was misread; none at all means it was not found.
			if a.UnwindEntries < 5 {
				t.Fatalf("the exception directory yielded %d functions; the fixture has five",
					a.UnwindEntries)
			}

			// Every function the image declares must have a block at its first
			// instruction. This is what the image base buys: an address computed
			// against the wrong one is not merely off, it is outside the code,
			// and recovery silently finds nothing there.
			declared := peFunctions(t, target)
			var missing int
			for _, f := range declared {
				if _, ok := a.Block(f.start); !ok {
					missing++
					if missing <= 5 {
						t.Errorf("the exception directory declares a function at %#x "+
							"and no block starts there", f.start)
					}
				}
			}
			if missing > 0 {
				t.Errorf("%d declared functions have no recovered block; a campaign "+
					"against this image would be blind in all of them", missing)
			}

			// The unreferenced function is the whole point: nothing calls it and
			// nothing loads its address, so descent from the entry point cannot
			// reach it, and it is only present because the exception directory
			// named it. It branches twice, so it is more than one block.
			orphan := peOrphan(t, declared, a, im.Entry)
			blocks := 0
			for _, b := range a.Blocks {
				if b.Addr >= orphan.start && b.Addr < orphan.end {
					blocks++
				}
			}
			if blocks < 3 {
				t.Errorf("the function at %#x..%#x recovered as %d block(s); it contains "+
					"two branches, and nothing but the exception directory could have "+
					"found it at all", orphan.start, orphan.end, blocks)
			}
		})
	}
}

// peFunc is one entry of the exception directory, read here rather than taken
// from the package under test: the addresses this test checks have to come from
// somewhere independent, or it would only be checking that the reader agrees
// with itself.
type peFunc struct{ start, end uint64 }

// peFunctions reads the exception directory straight out of the file.
func peFunctions(t *testing.T, path string) []peFunc {
	t.Helper()
	f, err := pe.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	var base uint64
	switch oh := f.OptionalHeader.(type) {
	case *pe.OptionalHeader64:
		base = oh.ImageBase
	case *pe.OptionalHeader32:
		base = uint64(oh.ImageBase)
	default:
		t.Fatal("the fixture has no optional header, so it has no image base")
	}

	var pdata []byte
	for _, s := range f.Sections {
		if s.Name == ".pdata" {
			b, err := s.Data()
			if err != nil {
				t.Fatal(err)
			}
			if s.VirtualSize > 0 && uint32(len(b)) > s.VirtualSize {
				b = b[:s.VirtualSize]
			}
			pdata = b
		}
	}
	if len(pdata) == 0 {
		t.Fatal("the fixture has no .pdata section, so it declares no functions")
	}

	var out []peFunc
	for i := 0; i+12 <= len(pdata); i += 12 {
		begin := uint64(binary.LittleEndian.Uint32(pdata[i:]))
		end := uint64(binary.LittleEndian.Uint32(pdata[i+4:]))
		if begin == 0 || end <= begin {
			continue
		}
		out = append(out, peFunc{start: base + begin, end: base + end})
	}
	return out
}

// peOrphan returns the declared function that nothing calls and that is not the
// entry point, which in this fixture is exactly one.
func peOrphan(t *testing.T, declared []peFunc, a *xbin.Analysis, entry uint64) peFunc {
	t.Helper()
	called := map[uint64]bool{}
	for _, b := range a.Blocks {
		for _, c := range b.Calls {
			called[c] = true
		}
	}
	var found []peFunc
	for _, f := range declared {
		if f.start != entry && !called[f.start] {
			found = append(found, f)
		}
	}
	if len(found) != 1 {
		t.Fatalf("%d of the %d declared functions are neither the entry point nor "+
			"called from anywhere; the fixture has exactly one", len(found), len(declared))
	}
	return found[0]
}

// A library exports its interface by name whether or not it carries a symbol
// table, exactly as an ELF shared object does through its dynamic symbols. The
// static function is the control: it is in the same image, it is named nowhere,
// and only the exception directory says it is there.
const peDLLSrc = `
__declspec(dllexport) int exported_branch(const char *s) {
	if (s[0] == 'A') return 1;
	return 2;
}
__declspec(dllexport) int exported_add(int a, int b) { return a + b; }
static int hidden(int x) { return x * 3; }
__declspec(dllexport) int exported_uses_hidden(int x) { return hidden(x) + 1; }
`

// TestPEExportsAreNamesWhenThereAreNoSymbols covers the second half of what a
// symbol-less PE still tells an analyser.
//
// For an executable the export table is empty and the exception directory is
// everything. For a library it is the other way round: the exports name the
// functions an operator would actually think to fuzz, and they survive whatever
// the build did to the symbol table because the loader itself needs them.
func TestPEExportsAreNamesWhenThereAreNoSymbols(t *testing.T) {
	target := buildPEFrom(t, peDLLSrc, []string{"/dll", "/noentry"})
	im, err := xbin.Open(target)
	if err != nil {
		t.Fatal(err)
	}
	defer im.Close()
	if im.Arch != xbin.ArchAMD64 {
		t.Skipf("this clang produced %v", im.Arch)
	}
	if !im.Stripped {
		t.Skipf("this linker wrote a symbol table into the image, so the export "+
			"table is not the only source of names (%d symbols)", len(im.Symbols()))
	}

	for _, want := range []string{"exported_branch", "exported_add", "exported_uses_hidden"} {
		addr, ok := im.Lookup(want)
		if !ok {
			t.Errorf("the library exports %q and no symbol of that name was read; "+
				"the image has %d", want, len(im.Symbols()))
			continue
		}
		if _, inCode := im.At(addr, 1); !inCode {
			t.Errorf("%s resolved to %#x, which is not inside the image at all", want, addr)
		}
	}
	if t.Failed() {
		return
	}

	a, err := xbin.Analyze(im)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%d blocks, %d functions, %d exported names, %d from the exception directory",
		len(a.Blocks), len(a.Functions), len(im.Symbols()), a.UnwindEntries)

	// A library has no entry point to descend from, so every block here was
	// reached from a name or from the exception directory.
	branch, _ := im.Lookup("exported_branch")
	if _, ok := a.Block(branch); !ok {
		t.Errorf("no block at exported_branch (%#x)", branch)
	}
	blocks := 0
	for _, f := range a.Functions {
		if f.Name == "exported_branch" {
			blocks = len(f.Blocks)
		}
	}
	if blocks < 2 {
		t.Errorf("exported_branch recovered as %d block(s); it contains a branch", blocks)
	}

	// The static function is declared by the exception directory and by nothing
	// else, and dropping it would leave a campaign against this library blind in
	// code its own exports call.
	for _, f := range peFunctions(t, target) {
		if _, ok := a.Block(f.start); !ok {
			t.Errorf("the exception directory declares a function at %#x and no "+
				"block starts there", f.start)
		}
	}
}
