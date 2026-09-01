package tracer

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
	"testing"
)

// writeDRcov builds a coverage file the way the tools that produce them do, so
// the reader is tested against the format rather than against itself.
func writeDRcov(version int, modules []drcovModule, blocks []drcovBlock) []byte {
	var b bytes.Buffer
	b.WriteString("DRCOV VERSION: 2\n")
	b.WriteString("DRCOV FLAVOR: drcov\n")
	if version == 1 {
		fmt.Fprintf(&b, "Module Table: %d\n", len(modules))
		for _, m := range modules {
			fmt.Fprintf(&b, "%d, %d, %d, %s\n", m.ID, m.Base, m.End, m.Path)
		}
	} else {
		fmt.Fprintf(&b, "Module Table: version 2, count %d\n", len(modules))
		b.WriteString("Columns: id, base, end, entry, checksum, timestamp, path\n")
		for _, m := range modules {
			fmt.Fprintf(&b, "  %d, 0x%016x, 0x%016x, 0x0, 0x0, 0x0, %s\n", m.ID, m.Base, m.End, m.Path)
		}
	}
	fmt.Fprintf(&b, "BB Table: %d bbs\n", len(blocks))
	for _, blk := range blocks {
		_ = binary.Write(&b, binary.LittleEndian, blk)
	}
	return b.Bytes()
}

func TestReadDRcovAcceptsBothModuleTableVersions(t *testing.T) {
	modules := []drcovModule{
		{ID: 0, Base: 0x400000, End: 0x452000, Path: "/tmp/xfuzz/target"},
		{ID: 1, Base: 0x7ffff7dd7000, End: 0x7ffff7ff4000, Path: "/lib/ld-linux.so.2"},
	}
	blocks := []drcovBlock{
		{Offset: 0x1136, Size: 20, Module: 0},
		{Offset: 0x1150, Size: 12, Module: 0},
		{Offset: 0x0900, Size: 8, Module: 1},
	}
	for _, version := range []int{1, 2} {
		t.Run(fmt.Sprintf("version %d", version), func(t *testing.T) {
			f, err := readDRcov(bytes.NewReader(writeDRcov(version, modules, blocks)))
			if err != nil {
				t.Fatal(err)
			}
			if len(f.Modules) != 2 {
				t.Fatalf("read %d modules, want 2", len(f.Modules))
			}
			if got := f.Modules[0].Path; got != "/tmp/xfuzz/target" {
				t.Errorf("module 0 path %q", got)
			}
			if got := f.Modules[0].Base; got != 0x400000 {
				t.Errorf("module 0 base %#x", got)
			}
			if len(f.Blocks) != 3 {
				t.Fatalf("read %d blocks, want 3", len(f.Blocks))
			}
		})
	}
}

// TestDRcovBlocksAreAttributedToOneModule is the property the frida backend
// depends on: a trace holds the program, the dynamic linker and every library,
// and only the program's blocks belong in its coverage map.
func TestDRcovBlocksAreAttributedToOneModule(t *testing.T) {
	modules := []drcovModule{
		{ID: 0, Base: 0x400000, End: 0x452000, Path: "/tmp/xfuzz/target"},
		{ID: 1, Base: 0x7ffff7dd7000, End: 0x7ffff7ff4000, Path: "/lib/libc.so.6"},
	}
	blocks := []drcovBlock{
		{Offset: 0x1136, Module: 0},
		{Offset: 0x0900, Module: 1},
		{Offset: 0x1150, Module: 0},
		{Offset: 0x0a00, Module: 1},
	}
	f, err := readDRcov(bytes.NewReader(writeDRcov(2, modules, blocks)))
	if err != nil {
		t.Fatal(err)
	}

	// An image linked at zero — a position-independent ELF: the offsets are
	// already link-time addresses.
	got := f.blocksFor("target", 0)
	want := []uint64{0x1136, 0x1150}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("linked at zero: got %#x, want %#x", got, want)
	}

	// A fixed-address ELF, whose link base is where the loader must put it.
	got = f.blocksFor("target", 0x400000)
	want = []uint64{0x401136, 0x401150}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("fixed address: got %#x, want %#x", got, want)
	}

	// A relocatable image that is nonetheless not linked at zero: a PE at its
	// ImageBase, and a Mach-O at 4GB. Reading "may move" as "linked at zero" —
	// which is only true of an ELF — puts every one of these blocks at an
	// address the image has no code at, and a campaign then collects coverage
	// that matches nothing it analysed.
	got = f.blocksFor("target", 0x140000000)
	want = []uint64{0x140001136, 0x140001150}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("relocatable but based: got %#x, want %#x", got, want)
	}

	if got := f.blocksFor("no-such-module", 0); got != nil {
		t.Errorf("a module that is not in the file returned %#x", got)
	}
}

// TestReadDRcovDistinguishesNotCoverageFromBadCoverage matters because the two
// mean different things to an operator: the first is a tool that did not run,
// the second is a tool that ran and something went wrong.
func TestReadDRcovDistinguishesNotCoverageFromBadCoverage(t *testing.T) {
	if _, err := readDRcov(strings.NewReader("this is not a coverage file\n")); err != ErrNotDRcov {
		t.Errorf("a file that is not coverage reported %v, want %v", err, ErrNotDRcov)
	}
	if _, err := readDRcov(strings.NewReader("")); err != ErrNotDRcov {
		t.Errorf("an empty file reported %v, want %v", err, ErrNotDRcov)
	}

	truncated := "DRCOV VERSION: 2\nModule Table: version 2, count 0\nBB Table: 4 bbs\n"
	_, err := readDRcov(strings.NewReader(truncated))
	if err == nil {
		t.Error("a file claiming four blocks and holding none was read without complaint")
	}
	if err == ErrNotDRcov {
		t.Error("a truncated coverage file was reported as not being coverage at all")
	}
}

// TestReadDRcovRefusesAnImplausibleBlockCount bounds what a file the fuzzer did
// not write can cost. The tool that produced it was running against a hostile
// target.
func TestReadDRcovRefusesAnImplausibleBlockCount(t *testing.T) {
	huge := "DRCOV VERSION: 2\nModule Table: version 2, count 0\nBB Table: 4000000000 bbs\n"
	if _, err := readDRcov(strings.NewReader(huge)); err == nil {
		t.Error("a file claiming four billion blocks was accepted")
	}
}

// TestParseModuleKeepsAPathWithACommaInIt is a small thing that would corrupt
// module attribution silently: the path is the last column and everything after
// the last comma, not the fourth field.
func TestParseModuleKeepsAPathWithACommaInIt(t *testing.T) {
	m, err := parseModule("  0, 0x400000, 0x452000, 0x0, 0x0, 0x0, /tmp/some,dir/target")
	if err != nil {
		t.Fatal(err)
	}
	if m.Path != "/tmp/some,dir/target" {
		t.Errorf("path %q", m.Path)
	}
}
