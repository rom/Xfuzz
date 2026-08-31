package binary

import (
	"errors"
	"fmt"
	"sort"
)

// Block is a basic block: a run of instructions entered only at its first
// address and left only at its last.
type Block struct {
	// Addr is the link-time address of the first instruction.
	Addr uint64

	// End is one past the last byte, so End-Addr is the block's size.
	End uint64

	// Kind is how the block ends. A block that ends in KindOther was cut short
	// because the next address is the start of another block, which happens when
	// something jumps into the middle of a straight-line run.
	Kind Kind

	// Succ are the successors that could be determined statically. An indirect
	// branch contributes none, which is the honest answer and the reason
	// Confidence exists.
	Succ []uint64

	// Calls are the targets of the direct calls this block makes.
	//
	// A list, not one address. A call does not end a basic block — control comes
	// back to it — so one block routinely makes several, and on an instrumented
	// binary the first is always the coverage callback. Keeping only the last
	// would give almost every block an edge to a sanitizer helper and lose every
	// real call edge in the program, which does not fail: it produces a call
	// graph that looks complete and in which nothing reaches anything.
	Calls []uint64
}

// Function is a run of blocks reached from one entry point.
type Function struct {
	Name   string
	Entry  uint64
	Blocks []uint64
}

// Analysis is what recovery found, along with what it could not.
type Analysis struct {
	// Blocks are the recovered basic blocks, sorted by address.
	Blocks []Block

	// Functions are the entry points recursive descent started from and the
	// blocks reached from each.
	Functions []Function

	// Indirect counts branches whose targets could not be determined. It is the
	// single most useful number for judging whether recovery is trustworthy on
	// this binary: a switch-heavy interpreter has hundreds and its coverage will
	// be full of holes, and a straight-line parser has none.
	Indirect int

	// Undecodable counts addresses the sweep gave up on.
	Undecodable int

	// UnwindEntries and AddressTaken count how many entry points came from
	// somewhere other than a symbol table. On a stripped image they are the
	// whole of the analysis, and reporting them is how an operator can tell
	// whether the recovery had anything to work with.
	UnwindEntries int
	AddressTaken  int

	// Coverage is the fraction of executable bytes that recovery accounted for.
	// Anything much below one means large regions were never reached from a
	// known entry point, so a campaign relying on block breakpoints will be
	// blind in them.
	Coverage float64

	byAddr map[uint64]int
}

// Block returns the block starting at an address.
func (a *Analysis) Block(addr uint64) (Block, bool) {
	i, ok := a.byAddr[addr]
	if !ok {
		return Block{}, false
	}
	return a.Blocks[i], true
}

// Containing returns the block an address falls inside.
func (a *Analysis) Containing(addr uint64) (Block, bool) {
	i := sort.Search(len(a.Blocks), func(i int) bool { return a.Blocks[i].Addr > addr })
	if i == 0 {
		return Block{}, false
	}
	b := a.Blocks[i-1]
	if addr >= b.End {
		return Block{}, false
	}
	return b, true
}

// Addrs returns every block's start address, sorted.
func (a *Analysis) Addrs() []uint64 {
	out := make([]uint64, len(a.Blocks))
	for i, b := range a.Blocks {
		out[i] = b.Addr
	}
	return out
}

// ErrUnsupportedArch reports an image this package cannot analyse.
var ErrUnsupportedArch = errors.New("binary: only amd64 images can be analysed")

// MaxBlocks bounds recovery, so a pathological or hostile image cannot exhaust
// memory before it is rejected. Sixty-four thousand blocks is well past any
// target worth fuzzing one block at a time.
const MaxBlocks = 1 << 16

// Analyze recovers basic blocks by recursive descent from every entry point the
// image names.
//
// Recursive descent rather than a linear sweep, because a linear sweep over a
// text section decodes its jump tables, its string literals and its alignment
// padding as though they were instructions, and cannot tell that it did. Descent
// follows only addresses something actually branches to, so what it finds is
// code. What it pays for that is completeness: a function reached only through a
// computed pointer is never visited, and the Coverage field is what says so.
//
// Both are reported rather than reconciled. A caller putting breakpoints on
// blocks wants only the reliable ones; a caller estimating how much of the
// binary it can see wants to know how much it cannot.
func Analyze(im *Image) (*Analysis, error) {
	if im.Arch != ArchAMD64 {
		return nil, fmt.Errorf("%w: this one is %v", ErrUnsupportedArch, im.Arch)
	}

	a := &Analysis{byAddr: make(map[uint64]int)}
	w := &walker{im: im, an: a, seen: make(map[uint64]bool), leaders: make(map[uint64]bool)}

	// Every address worth starting from. On an unstripped image the symbol table
	// supplies almost all of them; on a stripped one it supplies none, and the
	// unwind tables and address-taken references in entries.go are what stand in
	// for it.
	roots := []uint64{}
	if im.Entry != 0 {
		roots = append(roots, im.Entry)
	}
	for _, s := range im.symbols {
		roots = append(roots, s.Addr)
	}
	roots = append(roots, unwindStarts(im)...)
	a.UnwindEntries = len(roots)

	// Descend from what is known first, then again from every address the code
	// just walked was seen taking. The order matters: an address-taken candidate
	// is only trusted if it decodes, and after the first pass most of the text
	// has been proven to be code, so a candidate landing inside a known block is
	// recognisably not a function start.
	for _, root := range roots {
		w.root(root)
	}
	// w.taken grows while this loop runs, because descending into a newly found
	// function finds the addresses it in turn takes. Indexing rather than
	// ranging is what lets the walk reach a callback registered by a callback.
	for i := 0; i < len(w.taken); i++ {
		cand := w.taken[i]
		if w.seen[cand] {
			continue
		}
		w.root(cand)
		a.AddressTaken++
	}

	w.finish()
	return a, nil
}

// root descends from one candidate entry point and records what it reached as a
// function.
func (w *walker) root(root uint64) {
	{
		if !w.executable(root) || w.seen[root] {
			return
		}
		before := len(w.blocks)
		w.descend(root)
		if len(w.blocks) == before {
			return
		}
		fn := Function{Entry: root, Blocks: w.since(before)}
		if s, ok := w.im.SymbolAt(root); ok && s.Addr == root {
			fn.Name = s.Name
		}
		w.an.Functions = append(w.an.Functions, fn)
	}
}

// walker holds recursive-descent state.
type walker struct {
	im   *Image
	an   *Analysis
	seen map[uint64]bool // addresses already descended from

	// leaders are block start addresses. A block found later that jumps into the
	// middle of one found earlier splits it, which is why the starts are
	// collected first and the blocks cut afterwards.
	leaders map[uint64]bool

	blocks []Block
	order  []uint64

	// taken collects the addresses code was seen loading with a lea, which is
	// how a function that nothing calls directly is named.
	taken []uint64
}

func (w *walker) executable(addr uint64) bool {
	for _, s := range w.im.sections {
		if s.Executable && addr >= s.Addr && addr < s.Addr+uint64(len(s.Data)) {
			return true
		}
	}
	return false
}

func (w *walker) since(n int) []uint64 {
	out := make([]uint64, 0, len(w.blocks)-n)
	for _, b := range w.blocks[n:] {
		out = append(out, b.Addr)
	}
	return out
}

// descend walks one block and queues its successors.
//
// Iterative rather than recursive: a deeply chained function would otherwise put
// its call depth on the goroutine stack, and a hostile binary could choose that
// depth.
func (w *walker) descend(start uint64) {
	work := []uint64{start}
	for len(work) > 0 && len(w.blocks) < MaxBlocks {
		addr := work[len(work)-1]
		work = work[:len(work)-1]
		if w.seen[addr] || !w.executable(addr) {
			continue
		}
		w.seen[addr] = true
		w.leaders[addr] = true

		b, next := w.block(addr)
		w.blocks = append(w.blocks, b)
		w.order = append(w.order, addr)
		work = append(work, next...)
	}
}

// block decodes forward from addr until control leaves, and returns the block
// and the addresses to visit next.
func (w *walker) block(addr uint64) (Block, []uint64) {
	b := Block{Addr: addr, End: addr}
	var next []uint64

	pc := addr
	for {
		code, ok := w.im.At(pc, maxInstBytes)
		if !ok || len(code) == 0 {
			break
		}
		in, err := Decode(code, pc)
		if err != nil {
			w.an.Undecodable++
			break
		}
		pc += uint64(in.Len)
		b.End = pc
		b.Kind = in.Kind

		if in.RefIsAddress && w.executable(in.Ref) {
			w.taken = append(w.taken, in.Ref)
		}

		switch {
		case in.Kind == KindCall:
			// A call does not end a block, but its target begins one — that is
			// how descent reaches a function nothing else names.
			if in.HasTarget {
				b.Calls = append(b.Calls, in.Target)
				next = append(next, in.Target)
			}
			continue

		case in.Kind == KindIndirectCall:
			continue

		case in.Kind == KindCondJump:
			if in.HasTarget {
				b.Succ = append(b.Succ, in.Target)
				next = append(next, in.Target)
			}
			b.Succ = append(b.Succ, pc)
			next = append(next, pc)

		case in.Kind == KindJump:
			if in.HasTarget {
				b.Succ = append(b.Succ, in.Target)
				next = append(next, in.Target)
			}

		case in.Kind == KindIndirectJump:
			// The successors are exactly what static analysis cannot supply.
			// Counted rather than guessed: a guess here invents edges, and an
			// invented edge in a distance map moves every score that depends on
			// it.
			w.an.Indirect++

		case in.Kind == KindReturn, in.Kind == KindTrap:
			// Control does not continue.

		default:
			// Falls through. Stop anyway if the next address already starts a
			// block, so blocks never overlap.
			if w.leaders[pc] && pc != addr {
				b.Succ = append(b.Succ, pc)
				return b, next
			}
			continue
		}
		return b, next
	}
	return b, next
}

// maxInstBytes is how much is handed to the decoder at a time: the longest
// possible instruction, plus a byte so that a truncated read at a section
// boundary is distinguishable from a decode that simply needs no more.
const maxInstBytes = maxInstLen + 1

// finish sorts the recovered blocks, splits any that a later discovery cut into,
// and measures how much of the executable image was accounted for.
func (w *walker) finish() {
	blocks := w.blocks
	sort.Slice(blocks, func(i, j int) bool { return blocks[i].Addr < blocks[j].Addr })

	// A block found by falling forward may span the start of a block found
	// later, when something branched into the middle of it. Truncate the earlier
	// one at the later one's start and give it a fall-through successor: the two
	// halves are then a correct pair, and every address is in exactly one block.
	for i := 0; i+1 < len(blocks); i++ {
		if blocks[i].End > blocks[i+1].Addr {
			blocks[i].End = blocks[i+1].Addr
			if !containsAddr(blocks[i].Succ, blocks[i+1].Addr) {
				blocks[i].Succ = append(blocks[i].Succ, blocks[i+1].Addr)
			}
			blocks[i].Kind = KindOther
		}
	}

	w.an.Blocks = blocks
	for i, b := range blocks {
		w.an.byAddr[b.Addr] = i
	}

	var covered, total uint64
	for _, b := range blocks {
		covered += b.End - b.Addr
	}
	for _, s := range w.im.sections {
		if s.Executable {
			total += uint64(len(s.Data))
		}
	}
	if total > 0 {
		w.an.Coverage = float64(covered) / float64(total)
	}
}

func containsAddr(s []uint64, v uint64) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
