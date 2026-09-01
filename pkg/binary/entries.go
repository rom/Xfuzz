package binary

import "encoding/binary"

// Recovering entry points from a stripped image.
//
// Recursive descent needs somewhere to start, and on a stripped binary the
// symbol table is gone. Descent from the ELF entry point alone finds almost
// nothing: _start does not call main, it passes its address to
// __libc_start_main through a register, and it reaches that function through the
// procedure linkage table, whose stub is an indirect jump. Two hops in, the walk
// is out of statically known addresses. Measured on a stripped C program: one
// block, six per cent of the text section.
//
// Two sources close most of that gap, and neither depends on symbols.
//
// The unwind tables are the principled one. Every function compiled with unwind
// information — the default on Linux and macOS, and required by the ABI for
// anything a C++ exception can pass through — has an entry naming its start
// address and its length. That table is needed at run time, so stripping cannot
// remove it. Windows keeps the equivalent in .pdata, where it is mandatory
// rather than merely usual, and where it is very often the only thing left: the
// Microsoft toolchain writes names to a PDB and not into the image, so an
// ordinary Windows build arrives here in the same shape a stripped ELF does.
//
// Address-taken code is the other. A pointer to a function that nothing calls
// directly is loaded with a RIP-relative lea, and its target is computable from
// the encoding. That is exactly how _start names main, and it is how callback
// tables, vtables and jump-table entries name their contents.
//
// Both over-approximate: an unwind entry can describe a fragment, and a lea can
// point at data that happens to be in an executable section. The walker checks
// that what it is given decodes as code before it trusts it, so a wrong root
// costs a failed decode rather than a corrupted analysis.

// funcRange is a function's extent as an unwind table declares it. End is zero
// when the table names only where the function starts, which is all that is read
// out of DWARF call-frame information here.
type funcRange struct {
	Start uint64
	End   uint64
}

// unwindRanges returns the functions named by the image's unwind tables.
func unwindRanges(im *Image) []funcRange {
	switch im.Format {
	case FormatELF, FormatMachO:
		for _, s := range im.sections {
			if s.Name == ".eh_frame" || s.Name == "__TEXT,__eh_frame" {
				starts := ehFrameStarts(s.Data, s.Addr)
				out := make([]funcRange, 0, len(starts))
				for _, a := range starts {
					out = append(out, funcRange{Start: a})
				}
				return out
			}
		}
	case FormatPE:
		// An entry is three 32-bit fields on x64 and two on ARM64, so reading
		// the wrong architecture's table would not misread a field, it would
		// misread every field after the first.
		if im.Arch != ArchAMD64 {
			return nil
		}
		for _, s := range im.sections {
			if s.Name == ".pdata" {
				return pdataRanges(s.Data, im.base)
			}
		}
	}
	return nil
}

// pdataRanges reads Windows' exception directory: three addresses per function,
// each relative to the image base, of which the first two are where the function
// begins and ends.
//
// It is the best source of function boundaries any of these formats offers.
// Unwinding an x64 stack is table-driven with no frame-pointer fallback, so the
// ABI requires an entry for every non-leaf function; the table is needed at run
// time, so stripping cannot remove it; and unlike a call-frame description
// entry, it states where the function ends as well as where it starts.
func pdataRanges(data []byte, base uint64) []funcRange {
	var out []funcRange
	for i := 0; i+12 <= len(data); i += 12 {
		begin := uint64(binary.LittleEndian.Uint32(data[i:]))
		end := uint64(binary.LittleEndian.Uint32(data[i+4:]))
		if begin == 0 || end <= begin {
			// A zeroed entry is table padding, and one that does not run
			// forwards is not describing anything this can use.
			continue
		}
		out = append(out, funcRange{Start: base + begin, End: base + end})
	}
	return out
}

// DWARF pointer encodings, as used in the CIE augmentation data.
const (
	dwEhPeAbsptr = 0x00
	dwEhPeUleb   = 0x01
	dwEhPeUdata2 = 0x02
	dwEhPeUdata4 = 0x03
	dwEhPeUdata8 = 0x04
	dwEhPeSleb   = 0x09
	dwEhPeSdata2 = 0x0A
	dwEhPeSdata4 = 0x0B
	dwEhPeSdata8 = 0x0C
	dwEhPeOmit   = 0xFF

	dwEhPePcrel   = 0x10
	dwEhPeDatarel = 0x30
)

// ehFrameStarts walks the call-frame information and returns each frame
// description entry's initial location.
//
// The section is a sequence of length-prefixed records. A record whose second
// word is zero describes a common information entry, which is where the pointer
// encoding for the entries that reference it is declared; anything else is a
// frame description entry, and its first field is the address of the function it
// describes. Only that first field is read: everything after it is unwind
// instructions, which say nothing about where the code is.
func ehFrameStarts(data []byte, secAddr uint64) []uint64 {
	var out []uint64
	// The pointer encoding, keyed by the offset of the entry that declared it,
	// because a frame description entry names its own by a backwards offset.
	encAt := map[uint64]byte{}

	for off := 0; off+4 <= len(data); {
		start := off
		length := uint64(binary.LittleEndian.Uint32(data[off:]))
		off += 4
		if length == 0 {
			break // terminator
		}
		if length == 0xFFFFFFFF {
			if off+8 > len(data) {
				break
			}
			length = binary.LittleEndian.Uint64(data[off:])
			off += 8
		}
		end := off + int(length)
		if end > len(data) || end < off {
			break
		}
		body := data[off:end]
		if len(body) < 4 {
			off = end
			continue
		}
		id := binary.LittleEndian.Uint32(body)
		if id == 0 {
			if enc, ok := cieEncoding(body[4:]); ok {
				encAt[uint64(start)] = enc
			}
			off = end
			continue
		}

		// A frame description entry. The identifier is the distance back to its
		// common information entry, measured from the identifier's own offset.
		ciePos := uint64(off) - uint64(id)
		enc, ok := encAt[ciePos]
		if !ok {
			enc = dwEhPePcrel | dwEhPeSdata4 // the near-universal default
		}
		// The pointer is applied relative to its own address in the loaded
		// image, which is the section's address plus the pointer's offset.
		ptrOff := off + 4
		addr, _, ok := readEncoded(data, ptrOff, enc, secAddr)
		off = end
		if ok && addr != 0 {
			out = append(out, addr)
		}
	}
	return out
}

// cieEncoding pulls the frame-description pointer encoding out of a common
// information entry's augmentation data.
func cieEncoding(b []byte) (byte, bool) {
	if len(b) == 0 {
		return 0, false
	}
	i := 1 // version
	augStart := i
	for i < len(b) && b[i] != 0 {
		i++
	}
	if i >= len(b) {
		return 0, false
	}
	aug := string(b[augStart:i])
	i++ // the terminator
	if len(aug) == 0 || aug[0] != 'z' {
		// Without the length-prefixed augmentation block there is no declared
		// encoding, and the default applies.
		return 0, false
	}
	if _, n := uleb(b[i:]); n > 0 {
		i += n // code alignment factor
	} else {
		return 0, false
	}
	if _, n := sleb(b[i:]); n > 0 {
		i += n // data alignment factor
	} else {
		return 0, false
	}
	if _, n := uleb(b[i:]); n > 0 {
		i += n // return address register
	} else {
		return 0, false
	}
	if _, n := uleb(b[i:]); n > 0 {
		i += n // augmentation data length
	} else {
		return 0, false
	}
	// Walk the augmentation string past 'z', consuming what each letter says.
	for _, c := range aug[1:] {
		switch c {
		case 'R':
			if i >= len(b) {
				return 0, false
			}
			return b[i], true
		case 'L':
			i++
		case 'P':
			if i >= len(b) {
				return 0, false
			}
			enc := b[i]
			i++
			_, n, ok := readEncoded(b, i, enc, 0)
			if !ok {
				return 0, false
			}
			i += n
		case 'S', 'B', 'G':
			// Signal frame, and the two AArch64 pointer-authentication markers:
			// flags, carrying no data.
		default:
			return 0, false
		}
	}
	return 0, false
}

// readEncoded decodes one DWARF-encoded pointer at off, where base is the
// virtual address the buffer starts at, and returns the address, the number of
// bytes consumed, and whether it could be read at all.
func readEncoded(b []byte, off int, enc byte, base uint64) (uint64, int, bool) {
	if enc == dwEhPeOmit || off >= len(b) {
		return 0, 0, false
	}
	var v uint64
	var n int
	switch enc & 0x0F {
	case dwEhPeAbsptr, dwEhPeUdata8:
		if off+8 > len(b) {
			return 0, 0, false
		}
		v, n = binary.LittleEndian.Uint64(b[off:]), 8
	case dwEhPeUdata2:
		if off+2 > len(b) {
			return 0, 0, false
		}
		v, n = uint64(binary.LittleEndian.Uint16(b[off:])), 2
	case dwEhPeUdata4:
		if off+4 > len(b) {
			return 0, 0, false
		}
		v, n = uint64(binary.LittleEndian.Uint32(b[off:])), 4
	case dwEhPeSdata2:
		if off+2 > len(b) {
			return 0, 0, false
		}
		v, n = uint64(int64(int16(binary.LittleEndian.Uint16(b[off:])))), 2
	case dwEhPeSdata4:
		if off+4 > len(b) {
			return 0, 0, false
		}
		v, n = uint64(int64(int32(binary.LittleEndian.Uint32(b[off:])))), 4
	case dwEhPeSdata8:
		if off+8 > len(b) {
			return 0, 0, false
		}
		v, n = binary.LittleEndian.Uint64(b[off:]), 8
	case dwEhPeUleb:
		var m int
		v, m = uleb(b[off:])
		if m == 0 {
			return 0, 0, false
		}
		n = m
	case dwEhPeSleb:
		var sv int64
		var m int
		sv, m = sleb(b[off:])
		if m == 0 {
			return 0, 0, false
		}
		v, n = uint64(sv), m
	default:
		return 0, 0, false
	}

	switch enc & 0x70 {
	case dwEhPePcrel:
		v += base + uint64(off)
	case dwEhPeDatarel:
		v += base
	}
	return v, n, true
}

func uleb(b []byte) (uint64, int) {
	var v uint64
	var shift uint
	for i := 0; i < len(b) && i < 10; i++ {
		v |= uint64(b[i]&0x7F) << shift
		if b[i]&0x80 == 0 {
			return v, i + 1
		}
		shift += 7
	}
	return 0, 0
}

func sleb(b []byte) (int64, int) {
	var v int64
	var shift uint
	for i := 0; i < len(b) && i < 10; i++ {
		v |= int64(b[i]&0x7F) << shift
		shift += 7
		if b[i]&0x80 == 0 {
			if shift < 64 && b[i]&0x40 != 0 {
				v -= 1 << shift
			}
			return v, i + 1
		}
	}
	return 0, 0
}
