package tracer

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// Reading DRcov files.
//
// DRcov is DynamoRIO's coverage format and the closest thing binary-only tooling
// has to a common currency: DynamoRIO writes it, Intel Pin plugins write it,
// Frida's Stalker-based coverage tools write it, and every reverse-engineering
// tool that draws coverage on a disassembly reads it. Reading it here means the
// frida backend needs no protocol of its own, and that coverage collected by
// some other tool entirely can be brought into a campaign.
//
// The file is a text header followed by a binary block table:
//
//	DRCOV VERSION: 2
//	DRCOV FLAVOR: drcov
//	Module Table: version 2, count 2
//	Columns: id, base, end, entry, checksum, timestamp, path
//	  0, 0x0000000000400000, 0x0000000000452000, ..., /path/to/target
//	  1, 0x00007ffff7dd7000, 0x00007ffff7ff4000, ..., /lib/ld.so
//	BB Table: 41 bbs
//	<41 × { uint32 offset; uint16 size; uint16 module }>
//
// A block's address is its module's base plus the offset, and the offset is
// what makes the format position-independent: it is already relative to wherever
// the module was loaded, so nothing has to be un-randomised afterwards.

// drcovBlock is one entry of the block table.
type drcovBlock struct {
	Offset uint32
	Size   uint16
	Module uint16
}

// drcovModule is one row of the module table.
type drcovModule struct {
	ID   int
	Base uint64
	End  uint64
	Path string
}

// drcovFile is a parsed coverage file.
type drcovFile struct {
	Modules map[int]drcovModule
	Blocks  []drcovBlock
}

// ErrNotDRcov reports a file that is not coverage at all, as opposed to one that
// is malformed. The distinction matters: the first means the tool did not run,
// the second means it ran and something went wrong.
var ErrNotDRcov = errors.New("tracer: not a DRcov coverage file")

// maxDRcovBlocks bounds what will be read from a file the fuzzer did not write.
// A coverage file comes from an external tool running against a hostile target,
// so its length is not something to trust.
const maxDRcovBlocks = 1 << 22

// readDRcov parses a DRcov file.
func readDRcov(r io.Reader) (*drcovFile, error) {
	br := bufio.NewReader(r)

	line, err := readLine(br)
	if err != nil {
		return nil, ErrNotDRcov
	}
	if !strings.HasPrefix(line, "DRCOV VERSION:") {
		return nil, ErrNotDRcov
	}

	f := &drcovFile{Modules: map[int]drcovModule{}}
	var pending int
	for {
		line, err = readLine(br)
		if err != nil {
			return nil, fmt.Errorf("tracer: reading the coverage header: %w", err)
		}
		switch {
		case strings.HasPrefix(line, "Module Table:"):
			pending, err = moduleCount(line)
			if err != nil {
				return nil, err
			}
		case strings.HasPrefix(line, "Columns:"):
			// A version 2 header naming its own columns. The layout it
			// describes always ends in the path and always begins with the
			// identifier, base and end, which is all that is read.
		case strings.HasPrefix(line, "BB Table:"):
			n, err := bbCount(line)
			if err != nil {
				return nil, err
			}
			if n > maxDRcovBlocks {
				return nil, fmt.Errorf("tracer: the coverage file claims %d blocks, "+
					"past the %d this will read", n, maxDRcovBlocks)
			}
			f.Blocks = make([]drcovBlock, n)
			if err := binary.Read(br, binary.LittleEndian, f.Blocks); err != nil {
				return nil, fmt.Errorf("tracer: reading %d coverage blocks: %w", n, err)
			}
			return f, nil
		case line == "" || strings.HasPrefix(line, "DRCOV FLAVOR:"):
		default:
			if pending > 0 {
				m, err := parseModule(line)
				if err == nil {
					f.Modules[m.ID] = m
				}
				pending--
			}
		}
	}
}

func readLine(br *bufio.Reader) (string, error) {
	s, err := br.ReadString('\n')
	if err != nil && s == "" {
		return "", err
	}
	return strings.TrimRight(s, "\r\n"), nil
}

func moduleCount(line string) (int, error) {
	// "Module Table: version 2, count 3" or the version 1 "Module Table: 3".
	rest := strings.TrimSpace(strings.TrimPrefix(line, "Module Table:"))
	if i := strings.LastIndex(rest, "count"); i >= 0 {
		rest = strings.TrimSpace(rest[i+len("count"):])
	}
	n, err := strconv.Atoi(strings.TrimSpace(rest))
	if err != nil {
		return 0, fmt.Errorf("tracer: unreadable module table header %q", line)
	}
	return n, nil
}

func bbCount(line string) (int, error) {
	rest := strings.TrimSpace(strings.TrimPrefix(line, "BB Table:"))
	rest = strings.TrimSpace(strings.TrimSuffix(rest, "bbs"))
	n, err := strconv.Atoi(rest)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("tracer: unreadable block table header %q", line)
	}
	return n, nil
}

// parseModule reads one module row.
//
// The two format versions differ in how many columns come before the path:
// three in version 1, six in version 2, and a version 3 could add more. They
// agree that every column before the path is a number and that the first three
// are the identifier, the base and the end.
//
// So the path is everything from the first column that is not a number, rejoined
// with the commas that separated it. Taking the last comma instead — which is
// the obvious reading, and was the first one written here — silently truncates
// any path with a comma in it, and a truncated path means the module is not
// recognised and its blocks are dropped from coverage without a word.
func parseModule(line string) (drcovModule, error) {
	var m drcovModule
	fields := strings.Split(line, ",")
	if len(fields) < 4 {
		return m, fmt.Errorf("tracer: module row %q has too few columns", line)
	}

	nums := make([]uint64, 0, 8)
	i := 0
	for ; i < len(fields); i++ {
		v, err := parseNum(fields[i])
		if err != nil {
			break
		}
		nums = append(nums, v)
	}
	if len(nums) < 3 || i >= len(fields) {
		return m, fmt.Errorf("tracer: module row %q does not begin with an id, a base and an end", line)
	}
	m.ID = int(nums[0])
	m.Base, m.End = nums[1], nums[2]
	m.Path = strings.TrimSpace(strings.Join(fields[i:], ","))
	if m.Path == "" {
		return m, fmt.Errorf("tracer: module row %q names no path", line)
	}
	return m, nil
}

// parseNum reads a column that may be hexadecimal with a prefix or plain
// decimal. Version 1 files write decimal and version 2 files write hexadecimal,
// and both are in circulation.
func parseNum(s string) (uint64, error) {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		return strconv.ParseUint(s[2:], 16, 64)
	}
	return strconv.ParseUint(s, 10, 64)
}

// blocksFor returns the link-time addresses of the blocks recorded against one
// module, identified by a suffix of its path.
//
// The offsets in the file are relative to where the module was loaded, so the
// link-time address is the image's own link base plus the offset. Nothing has
// to be inferred, which is the advantage this format has over reading an
// emulator's log — but the base has to come from the image rather than from
// whether it is relocatable. Those coincide only for an ELF: one that can move
// is linked at zero, so an offset is already a link-time address. A Mach-O that
// can move is linked at 4GB and a PE at its ImageBase, and taking either for
// zero yields addresses that fall in no recovered block at all.
func (f *drcovFile) blocksFor(pathSuffix string, linkBase uint64) []uint64 {
	want := -1
	for id, m := range f.Modules {
		if strings.HasSuffix(m.Path, pathSuffix) {
			want = id
			break
		}
	}
	if want < 0 {
		return nil
	}
	out := make([]uint64, 0, len(f.Blocks))
	for _, b := range f.Blocks {
		if int(b.Module) == want {
			out = append(out, linkBase+uint64(b.Offset))
		}
	}
	return out
}
