package binary

import (
	"debug/dwarf"
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
)

// Arch is the instruction set an image was built for.
type Arch uint8

// The architectures. Only AMD64 can be decoded; the rest are recognised so that
// a campaign against them fails with the reason rather than with nonsense.
const (
	ArchUnknown Arch = iota
	ArchAMD64
	ArchARM64
	Arch386
	ArchOther
)

var archNames = [...]string{
	ArchUnknown: "unknown", ArchAMD64: "amd64", ArchARM64: "arm64",
	Arch386: "386", ArchOther: "another architecture",
}

func (a Arch) String() string {
	if int(a) < len(archNames) {
		return archNames[a]
	}
	return "unknown"
}

// Format is the container the code came in.
type Format uint8

// The container formats.
const (
	FormatUnknown Format = iota
	FormatELF
	FormatPE
	FormatMachO
)

var formatNames = [...]string{
	FormatUnknown: "unknown", FormatELF: "ELF", FormatPE: "PE", FormatMachO: "Mach-O",
}

func (f Format) String() string {
	if int(f) < len(formatNames) {
		return formatNames[f]
	}
	return "unknown"
}

// Section is one span of the image, at the address it will be loaded at when the
// image is not relocated.
type Section struct {
	Name       string
	Addr       uint64
	Data       []byte
	Executable bool
}

// Sym is a named address.
type Sym struct {
	Name string
	Addr uint64
	Size uint64
}

// Image is an executable opened for analysis.
//
// Addresses throughout are *link-time* addresses — what the file says, not what
// the loader chose. A position-independent executable is loaded at a base the
// kernel picks per run, and converting between the two is the caller's job
// because only the caller knows which process it is talking about. Getting that
// backwards is the single most common way a binary-only tool ends up putting
// breakpoints in unmapped memory, so the two are kept in different units here
// and never silently mixed.
type Image struct {
	Path   string
	Format Format
	Arch   Arch

	// Entry is the link-time entry point.
	Entry uint64

	// PIE reports whether the image is position-independent and will therefore
	// be loaded at a base other than the one in the file.
	PIE bool

	// Stripped reports that the image carries no symbol table beyond whatever
	// dynamic linking requires. It is the condition the whole binary-only path
	// exists for, so it is reported rather than inferred by the caller.
	Stripped bool

	// base is the address the image is linked at. See LinkBase.
	base uint64

	sections []Section
	symbols  []Sym
	dwarf    *dwarf.Data
	closer   io.Closer
}

// Open reads an executable. The file is kept open only for as long as reading
// its sections requires; Close releases whatever remains.
func Open(path string) (*Image, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	var magic [4]byte
	if _, err := io.ReadFull(f, magic[:]); err != nil {
		f.Close()
		return nil, fmt.Errorf("binary: %s: reading the header: %w", path, err)
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		f.Close()
		return nil, err
	}

	switch {
	case magic == [4]byte{0x7f, 'E', 'L', 'F'}:
		return openELF(path, f)
	case magic[0] == 'M' && magic[1] == 'Z':
		return openPE(path, f)
	case magic == [4]byte{0xFE, 0xED, 0xFA, 0xCF} || magic == [4]byte{0xCF, 0xFA, 0xED, 0xFE},
		magic == [4]byte{0xFE, 0xED, 0xFA, 0xCE} || magic == [4]byte{0xCE, 0xFA, 0xED, 0xFE}:
		return openMachO(path, f)
	}
	f.Close()
	return nil, fmt.Errorf("binary: %s: not an ELF, PE or Mach-O executable", path)
}

// Close releases the image.
func (im *Image) Close() error {
	if im.closer != nil {
		err := im.closer.Close()
		im.closer = nil
		return err
	}
	return nil
}

// LinkBase is the address the beginning of the image is linked at, and so what
// an offset into the module is measured from.
//
// Zero for a position-independent ELF, whose addresses are already offsets from
// wherever the loader put it. The __TEXT segment's address for a Mach-O, which
// is position-independent and still linked at 4GB. The optional header's
// ImageBase for a PE, which keeps its base whether or not it may be relocated —
// "may move" and "is linked at zero" are the same thing for an ELF and two
// different things for the other two, which is the trap.
//
// It is what turns a module-relative offset back into an address the analysis
// can be compared against. A coverage tool reports offsets because an offset is
// the only thing that survives relocation, and adding the wrong base produces
// addresses that are not wrong by a little: they are in no block at all, and the
// campaign records coverage nothing can be matched to.
func (im *Image) LinkBase() uint64 { return im.base }

// Sections returns the loadable sections, executable ones included.
func (im *Image) Sections() []Section { return im.sections }

// Symbols returns the named addresses, sorted by address. Empty for a stripped
// image, which is the case the binary-only path is built for.
func (im *Image) Symbols() []Sym { return im.symbols }

// Text returns the executable sections.
func (im *Image) Text() []Section {
	var out []Section
	for _, s := range im.sections {
		if s.Executable {
			out = append(out, s)
		}
	}
	return out
}

// At returns up to n bytes of image content starting at the link-time address
// addr, and reports whether the address is inside a section at all.
//
// Fewer than n bytes come back at the end of a section: that is not an error,
// because an instruction at the last address of a section is a real instruction
// and truncating the read is how the decoder learns the section ended.
func (im *Image) At(addr uint64, n int) ([]byte, bool) {
	for i := range im.sections {
		s := &im.sections[i]
		if addr < s.Addr || addr >= s.Addr+uint64(len(s.Data)) {
			continue
		}
		off := addr - s.Addr
		end := off + uint64(n)
		if end > uint64(len(s.Data)) {
			end = uint64(len(s.Data))
		}
		return s.Data[off:end], true
	}
	return nil, false
}

// SymbolAt returns the symbol containing an address.
func (im *Image) SymbolAt(addr uint64) (Sym, bool) {
	i := sort.Search(len(im.symbols), func(i int) bool { return im.symbols[i].Addr > addr })
	if i == 0 {
		return Sym{}, false
	}
	s := im.symbols[i-1]
	if s.Size > 0 && addr >= s.Addr+s.Size {
		return Sym{}, false
	}
	return s, true
}

// Lookup returns the address of a named symbol.
func (im *Image) Lookup(name string) (uint64, bool) {
	for _, s := range im.symbols {
		if s.Name == name {
			return s.Addr, true
		}
	}
	return 0, false
}

// ErrNoDebugInfo means the image has no DWARF, so source locations cannot be
// resolved. It is a normal state for a stripped binary, not a failure.
var ErrNoDebugInfo = errors.New("binary: the image carries no debug information")

// LineAddrs returns the addresses that map to a source file and line.
//
// Directed fuzzing is configured in the terms a person has — a file and a line
// in a patch — and this is the only thing that can turn those into the addresses
// a distance map is computed over. A stripped binary has none, which is why
// directed campaigns against one must be given addresses or symbol names
// instead.
func (im *Image) LineAddrs(file string, line int) ([]uint64, error) {
	if im.dwarf == nil {
		return nil, ErrNoDebugInfo
	}
	var out []uint64
	r := im.dwarf.Reader()
	for {
		ent, err := r.Next()
		if err != nil {
			return nil, fmt.Errorf("binary: reading debug information: %w", err)
		}
		if ent == nil {
			break
		}
		if ent.Tag != dwarf.TagCompileUnit {
			continue
		}
		lr, err := im.dwarf.LineReader(ent)
		if err != nil || lr == nil {
			r.SkipChildren()
			continue
		}
		var le dwarf.LineEntry
		for {
			if err := lr.Next(&le); err != nil {
				break
			}
			if le.EndSequence || !le.IsStmt || le.Line != line || le.File == nil {
				continue
			}
			if matchFile(le.File.Name, file) {
				out = append(out, le.Address)
			}
		}
		r.SkipChildren()
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out, nil
}

// matchFile compares a DWARF file name against what an operator typed. A person
// writes "parse.c"; the compiler recorded "/home/build/src/parse.c". Matching on
// the suffix at a path boundary accepts the short form without accepting
// "reparse.c".
func matchFile(recorded, want string) bool {
	if recorded == want {
		return true
	}
	if len(recorded) <= len(want) {
		return false
	}
	if recorded[len(recorded)-len(want):] != want {
		return false
	}
	c := recorded[len(recorded)-len(want)-1]
	return c == '/' || c == '\\'
}

func sortSymbols(syms []Sym) []Sym {
	out := syms[:0]
	for _, s := range syms {
		if s.Name == "" || s.Addr == 0 {
			continue
		}
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Addr != out[j].Addr {
			return out[i].Addr < out[j].Addr
		}
		return out[i].Name < out[j].Name
	})
	return out
}

func openELF(path string, f *os.File) (*Image, error) {
	e, err := elf.NewFile(f)
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("binary: %s: %w", path, err)
	}
	im := &Image{Path: path, Format: FormatELF, Entry: e.Entry, closer: f}
	switch e.Machine {
	case elf.EM_X86_64:
		im.Arch = ArchAMD64
	case elf.EM_AARCH64:
		im.Arch = ArchARM64
	case elf.EM_386:
		im.Arch = Arch386
	default:
		im.Arch = ArchOther
	}
	im.PIE = e.Type == elf.ET_DYN
	// The address the beginning of the file is mapped at, which is what an
	// offset into the module is measured from. Taking the lowest segment's own
	// address instead would be wrong by however far into the file that segment
	// starts — 0x1000 on anything a current linker produces, which is small
	// enough to look like a rounding question and large enough to put every
	// address in the wrong block.
	first := true
	for _, p := range e.Progs {
		if p.Type != elf.PT_LOAD {
			continue
		}
		if b := p.Vaddr - p.Off; first || b < im.base {
			im.base, first = b, false
		}
	}

	for _, s := range e.Sections {
		if s.Type == elf.SHT_NOBITS || s.Flags&elf.SHF_ALLOC == 0 || s.Size == 0 {
			continue
		}
		data, err := s.Data()
		if err != nil {
			continue
		}
		im.sections = append(im.sections, Section{
			Name: s.Name, Addr: s.Addr, Data: data,
			Executable: s.Flags&elf.SHF_EXECINSTR != 0,
		})
	}

	var syms []Sym
	if ss, err := e.Symbols(); err == nil {
		for _, s := range ss {
			if elf.ST_TYPE(s.Info) == elf.STT_FUNC {
				syms = append(syms, Sym{Name: s.Name, Addr: s.Value, Size: s.Size})
			}
		}
	}
	im.Stripped = len(syms) == 0
	// The dynamic symbol table survives stripping and names every exported
	// function, which for a shared library is most of them. It is worth much
	// less than a full table and is still far better than nothing.
	if ds, err := e.DynamicSymbols(); err == nil {
		for _, s := range ds {
			if elf.ST_TYPE(s.Info) == elf.STT_FUNC && s.Value != 0 {
				syms = append(syms, Sym{Name: s.Name, Addr: s.Value, Size: s.Size})
			}
		}
	}
	im.symbols = sortSymbols(syms)
	if d, err := e.DWARF(); err == nil {
		im.dwarf = d
	}
	return im, nil
}

// PE section characteristics, as the header records them.
const (
	scnCntCode = 0x00000020
	scnMemExec = 0x20000000
	scnMemRead = 0x40000000
)

// dataDirectory is one entry of the optional header's directory table: an
// address relative to the image base, and how far it runs.
type dataDirectory struct {
	VirtualAddress uint32
	Size           uint32
}

func openPE(path string, f *os.File) (*Image, error) {
	p, err := pe.NewFile(f)
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("binary: %s: %w", path, err)
	}
	im := &Image{Path: path, Format: FormatPE, closer: f}
	switch p.Machine {
	case pe.IMAGE_FILE_MACHINE_AMD64:
		im.Arch = ArchAMD64
	case pe.IMAGE_FILE_MACHINE_ARM64:
		im.Arch = ArchARM64
	case pe.IMAGE_FILE_MACHINE_I386:
		im.Arch = Arch386
	default:
		im.Arch = ArchOther
	}

	var base uint64
	var exportDir dataDirectory
	switch oh := p.OptionalHeader.(type) {
	case *pe.OptionalHeader64:
		base = oh.ImageBase
		im.Entry = base + uint64(oh.AddressOfEntryPoint)
		im.PIE = oh.DllCharacteristics&0x0040 != 0 // DYNAMIC_BASE
		if len(oh.DataDirectory) > 0 {
			exportDir = dataDirectory{oh.DataDirectory[0].VirtualAddress, oh.DataDirectory[0].Size}
		}
	case *pe.OptionalHeader32:
		base = uint64(oh.ImageBase)
		im.Entry = base + uint64(oh.AddressOfEntryPoint)
		im.PIE = oh.DllCharacteristics&0x0040 != 0
		if len(oh.DataDirectory) > 0 {
			exportDir = dataDirectory{oh.DataDirectory[0].VirtualAddress, oh.DataDirectory[0].Size}
		}
	}
	im.base = base

	for _, s := range p.Sections {
		if s.Characteristics&scnMemRead == 0 {
			continue
		}
		data, err := s.Data()
		if err != nil {
			continue
		}
		// VirtualSize can be smaller than the file-aligned size, and the tail is
		// padding that is not part of the image.
		if s.VirtualSize > 0 && uint32(len(data)) > s.VirtualSize {
			data = data[:s.VirtualSize]
		}
		im.sections = append(im.sections, Section{
			Name: s.Name, Addr: base + uint64(s.VirtualAddress), Data: data,
			Executable: s.Characteristics&(scnMemExec|scnCntCode) != 0,
		})
	}

	// The COFF symbol table, which a MinGW or Cygwin toolchain writes into the
	// image and which the Microsoft one does not: link.exe puts names in a
	// separate PDB, so a perfectly ordinary release build arrives here with no
	// symbol table at all. That is the case the rest of this package exists for
	// and it is reported, not worked around.
	var syms []Sym
	for _, s := range p.Symbols {
		if s.SectionNumber <= 0 || int(s.SectionNumber) > len(p.Sections) {
			continue
		}
		sec := p.Sections[s.SectionNumber-1]
		if sec.Characteristics&(scnMemExec|scnCntCode) == 0 {
			// Only code is named here. A data symbol is never an entry point,
			// and letting one through would put a name on whatever function
			// happens to precede its address.
			continue
		}
		syms = append(syms, Sym{Name: s.Name, Addr: base + uint64(sec.VirtualAddress) + uint64(s.Value)})
	}
	im.Stripped = len(syms) == 0
	// The export table survives stripping and names every exported function,
	// which for a DLL is the whole of its interface. It is the PE counterpart of
	// the ELF dynamic symbol table, and worth the same: little for an
	// executable, a great deal for a library.
	syms = append(syms, peExports(im, exportDir)...)
	im.symbols = sortSymbols(syms)
	if d, err := p.DWARF(); err == nil {
		im.dwarf = d
	}
	return im, nil
}

func openMachO(path string, f *os.File) (*Image, error) {
	m, err := macho.NewFile(f)
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("binary: %s: %w", path, err)
	}
	im := &Image{Path: path, Format: FormatMachO, closer: f}
	switch m.Cpu {
	case macho.CpuAmd64:
		im.Arch = ArchAMD64
	case macho.CpuArm64:
		im.Arch = ArchARM64
	case macho.Cpu386:
		im.Arch = Arch386
	default:
		im.Arch = ArchOther
	}
	// MH_PIE. Mach-O executables have been position-independent by default for
	// long enough that the flag is effectively always set — which does not make
	// them linked at zero: __TEXT is at 4GB, and that is the base every address
	// here is measured from.
	im.PIE = m.Flags&0x00200000 != 0
	if seg := m.Segment("__TEXT"); seg != nil {
		im.base = seg.Addr
	}

	for _, s := range m.Sections {
		data, err := s.Data()
		if err != nil {
			continue
		}
		im.sections = append(im.sections, Section{
			Name: s.Seg + "," + s.Name, Addr: s.Addr, Data: data,
			Executable: s.Seg == "__TEXT" && s.Name == "__text",
		})
	}

	var syms []Sym
	if m.Symtab != nil {
		for _, s := range m.Symtab.Syms {
			// N_SECT: defined in a section of this file.
			if s.Type&0x0e == 0x0e && s.Value != 0 {
				syms = append(syms, Sym{Name: s.Name, Addr: s.Value})
			}
		}
	}
	im.Stripped = len(syms) == 0
	im.symbols = sortSymbols(syms)
	if d, err := m.DWARF(); err == nil {
		im.dwarf = d
	}
	// The entry point lives in an LC_MAIN command, which debug/macho does not
	// surface. The first executable section start is a serviceable stand-in for
	// recursive descent, which reaches main through the runtime's own calls.
	if im.Entry == 0 {
		for _, s := range im.sections {
			if s.Executable {
				im.Entry = s.Addr
				break
			}
		}
	}
	return im, nil
}

// maxExports bounds what an export table is believed to declare. A count is a
// field in the file, so a corrupt or hostile image can name four billion
// exports; nothing legitimate names more than a few tens of thousands.
const maxExports = 1 << 16

// peExports reads the export directory and returns the exported code addresses.
//
// The directory holds three parallel arrays: the addresses of every export by
// ordinal, the names, and for each name the ordinal it refers to. Only the named
// ones are useful here — an export by ordinal alone has no name to report — and
// an address that lands back inside the directory is a forwarder, a string
// naming another library's export rather than code in this image.
func peExports(im *Image, dir dataDirectory) []Sym {
	if dir.VirtualAddress == 0 || dir.Size < 0x28 {
		return nil
	}
	hdr, ok := im.At(im.base+uint64(dir.VirtualAddress), 0x28)
	if !ok || len(hdr) < 0x28 {
		return nil
	}
	var (
		nFuncs    = binary.LittleEndian.Uint32(hdr[0x14:])
		nNames    = binary.LittleEndian.Uint32(hdr[0x18:])
		funcsRVA  = binary.LittleEndian.Uint32(hdr[0x1C:])
		namesRVA  = binary.LittleEndian.Uint32(hdr[0x20:])
		ordsRVA   = binary.LittleEndian.Uint32(hdr[0x24:])
		dirStart  = uint64(dir.VirtualAddress)
		dirEnd    = dirStart + uint64(dir.Size)
		out       []Sym
		haveNames = nNames > 0 && namesRVA != 0 && ordsRVA != 0
	)
	if !haveNames || funcsRVA == 0 || nFuncs == 0 {
		return nil
	}
	if nNames > maxExports {
		nNames = maxExports
	}
	names, ok := im.At(im.base+uint64(namesRVA), int(nNames)*4)
	if !ok || len(names) < int(nNames)*4 {
		return nil
	}
	ords, ok := im.At(im.base+uint64(ordsRVA), int(nNames)*2)
	if !ok || len(ords) < int(nNames)*2 {
		return nil
	}
	for i := 0; i < int(nNames); i++ {
		ord := uint32(binary.LittleEndian.Uint16(ords[i*2:]))
		if ord >= nFuncs {
			continue
		}
		fn, ok := im.At(im.base+uint64(funcsRVA)+uint64(ord)*4, 4)
		if !ok || len(fn) < 4 {
			continue
		}
		rva := uint64(binary.LittleEndian.Uint32(fn))
		if rva == 0 || (rva >= dirStart && rva < dirEnd) {
			continue // unused ordinal, or a forwarder to another library
		}
		name := peString(im, uint64(binary.LittleEndian.Uint32(names[i*4:])))
		if name == "" {
			continue
		}
		out = append(out, Sym{Name: name, Addr: im.base + rva})
	}
	return out
}

// maxSymbolName bounds a name read out of the image, which is terminated by a
// byte the image itself supplies.
const maxSymbolName = 4096

// peString reads a NUL-terminated name at an address relative to the image base.
func peString(im *Image, rva uint64) string {
	if rva == 0 {
		return ""
	}
	b, ok := im.At(im.base+rva, maxSymbolName)
	if !ok {
		return ""
	}
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return ""
}
