package binary

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Distance to a target: the artifact a directed campaign is steered by.
//
// Coverage-guided fuzzing asks "did this input go somewhere new". Directed
// fuzzing asks "did this input go somewhere *closer*", and the difference is the
// whole of what makes it useful for a patch, a sanitizer report, or a line in a
// diff: an input that reached no new code but got two calls nearer the function
// under investigation is progress, and coverage cannot see it (ADR-0007).
//
// Closer is measured in basic blocks. Every block gets its shortest distance to
// a target block along the interprocedural control-flow graph — intra-procedural
// successors, plus an edge from a block that calls a function to that function's
// entry. Searching backwards from the targets means one traversal answers the
// question for every block at once, rather than a search per execution.
//
// The graph is recovered from a binary, so it is partial in exactly the ways
// recovery is: an indirect branch contributes no edges, and code the analysis
// never reached has no blocks. That makes the distance an upper bound on the
// true one and, for a block whose only route to the target is through a computed
// call, no distance at all. Both are reported rather than smoothed over —
// Reachable says how much of the program can see the target, and a campaign
// where that is a handful of blocks is one whose direction is an illusion.

// DistanceMap gives each recovered basic block its distance to the nearest
// target, in blocks.
type DistanceMap struct {
	dist map[uint64]uint32

	// ranges are the blocks that have a distance, sorted by address, so that an
	// address anywhere inside one can be resolved to it.
	//
	// Necessary because almost nothing reports a block by its first address. The
	// instrumented runtime reports the return address of its own callback, which
	// is a few bytes in; a tracer reports wherever its breakpoint or its
	// translation unit began. Requiring an exact match would mean every lookup
	// missing and a directed campaign scoring every input identically — which
	// looks exactly like a campaign that has not found the target's
	// neighbourhood yet.
	ranges []blockRange

	// Targets are the block addresses direction is measured towards.
	Targets []uint64

	// Max is the largest finite distance, which is what a normalised score is
	// divided by.
	Max uint32

	// Reachable is how many blocks have any route to a target at all. Compared
	// against the analysis's block count, it is the single number that says
	// whether a directed campaign can work on this binary.
	Reachable int
}

// blockRange is one block's extent and its distance.
type blockRange struct {
	addr, end uint64
	dist      uint32
}

// Of returns the distance of the block containing an address, and whether that
// block has one.
func (d *DistanceMap) Of(addr uint64) (uint32, bool) {
	if v, ok := d.dist[addr]; ok {
		return v, true
	}
	i := sort.Search(len(d.ranges), func(i int) bool { return d.ranges[i].addr > addr })
	if i == 0 {
		return 0, false
	}
	r := d.ranges[i-1]
	if addr >= r.end {
		return 0, false
	}
	return r.dist, true
}

// Len returns how many blocks have a distance.
func (d *DistanceMap) Len() int { return len(d.dist) }

// MaxDistance returns the largest finite distance, which normalises a score. It
// is a method as well as a field so that this map satisfies the small interface
// pkg/feedback declares, without pkg/feedback having to know this package
// exists.
func (d *DistanceMap) MaxDistance() uint32 { return d.Max }

// ErrNoTargets reports a directed campaign with nowhere to go.
var ErrNoTargets = errors.New("binary: no target locations were resolved")

// ErrUnreachable reports targets that no recovered block can reach.
var ErrUnreachable = errors.New("binary: no recovered block reaches any target")

// BuildDistanceMap computes the distance from every block to the nearest target.
//
// Targets are given as addresses; each is mapped to the block containing it,
// because an address in the middle of a block is reached exactly when the block
// is. A target address in no recovered block is reported rather than dropped: it
// is usually a sign that the address came from a different build of the binary,
// which is the failure mode a staleness rule exists to catch.
func BuildDistanceMap(a *Analysis, targets []uint64) (*DistanceMap, error) {
	if len(targets) == 0 {
		return nil, ErrNoTargets
	}

	d := &DistanceMap{dist: make(map[uint64]uint32, len(a.Blocks))}

	// Map each target address onto the block that contains it.
	seen := map[uint64]bool{}
	var frontier []uint64
	var missing []uint64
	for _, t := range targets {
		b, ok := a.Containing(t)
		if !ok {
			missing = append(missing, t)
			continue
		}
		if seen[b.Addr] {
			continue
		}
		seen[b.Addr] = true
		d.dist[b.Addr] = 0
		d.Targets = append(d.Targets, b.Addr)
		frontier = append(frontier, b.Addr)
	}
	if len(frontier) == 0 {
		return nil, fmt.Errorf("%w: %d target address(es), none inside a recovered block "+
			"(%s) — check that the addresses came from this build", ErrNoTargets,
			len(targets), hexList(missing))
	}

	// The reverse graph: for every edge x -> y, an entry y -> x. Built once and
	// walked once, so the whole map costs a single breadth-first pass rather
	// than a search per block.
	rev := make(map[uint64][]uint64, len(a.Blocks))
	for i := range a.Blocks {
		b := &a.Blocks[i]
		for _, s := range b.Succ {
			rev[s] = append(rev[s], b.Addr)
		}
		for _, callee := range b.Calls {
			// A block that calls a function reaches everything that function
			// reaches. The call does not end the block — control comes back to
			// it — so this one edge covers both the call and the return.
			rev[callee] = append(rev[callee], b.Addr)
		}
	}

	for len(frontier) > 0 {
		var next []uint64
		for _, cur := range frontier {
			nd := d.dist[cur] + 1
			for _, p := range rev[cur] {
				if _, done := d.dist[p]; done {
					continue
				}
				d.dist[p] = nd
				if nd > d.Max {
					d.Max = nd
				}
				next = append(next, p)
			}
		}
		frontier = next
	}

	// The extents, so an address inside a block resolves to it.
	d.ranges = make([]blockRange, 0, len(d.dist))
	for i := range a.Blocks {
		b := &a.Blocks[i]
		if v, ok := d.dist[b.Addr]; ok {
			d.ranges = append(d.ranges, blockRange{addr: b.Addr, end: b.End, dist: v})
		}
	}
	sort.Slice(d.ranges, func(i, j int) bool { return d.ranges[i].addr < d.ranges[j].addr })

	d.Reachable = len(d.dist)
	if d.Reachable <= len(d.Targets) {
		return nil, fmt.Errorf("%w: the %d target block(s) have no predecessors in the "+
			"recovered graph, so nothing can be measured as getting closer to them",
			ErrUnreachable, len(d.Targets))
	}
	return d, nil
}

// Coverage returns the fraction of recovered blocks that can reach a target.
//
// It is the honest measure of whether direction is meaningful on this binary. A
// campaign directed at a function reachable only through a virtual call will see
// a handful of blocks with distances and every input scoring the same, which
// looks exactly like a directed campaign that is not making progress.
func (d *DistanceMap) Coverage(a *Analysis) float64 {
	if len(a.Blocks) == 0 {
		return 0
	}
	return float64(d.Reachable) / float64(len(a.Blocks))
}

// TargetSpec is a place a directed campaign is aimed at, as an operator writes
// it.
//
// Three forms, because three kinds of evidence send people here. A crash report
// gives an address. A patch gives a file and a line. A design discussion gives a
// function name. Requiring the address form would mean an operator disassembling
// their own binary before they could start.
type TargetSpec string

// Resolve turns target specifications into link-time addresses.
//
// Each form fails differently and the failures are reported rather than
// summarised: a file and line that resolves to nothing usually means the binary
// carries no debug information, a function name that resolves to nothing usually
// means it was stripped or inlined, and an address that resolves to nothing
// usually means it came from a different build. Those are three different things
// to do next.
func Resolve(im *Image, specs []TargetSpec) ([]uint64, error) {
	var out []uint64
	var problems []string

	for _, spec := range specs {
		s := strings.TrimSpace(string(spec))
		if s == "" {
			continue
		}
		switch {
		case strings.HasPrefix(s, "0x"), strings.HasPrefix(s, "0X"):
			v, err := strconv.ParseUint(s[2:], 16, 64)
			if err != nil {
				problems = append(problems, fmt.Sprintf("%q is not an address", s))
				continue
			}
			out = append(out, v)

		case strings.Contains(s, ":"):
			file, lineStr, _ := strings.Cut(s, ":")
			line, err := strconv.Atoi(lineStr)
			if err != nil {
				problems = append(problems, fmt.Sprintf("%q: %q is not a line number", s, lineStr))
				continue
			}
			addrs, err := im.LineAddrs(file, line)
			if err != nil {
				problems = append(problems, fmt.Sprintf("%q: %v", s, err))
				continue
			}
			if len(addrs) == 0 {
				problems = append(problems, fmt.Sprintf("%q matches no code; the line may be "+
					"blank, optimised away, or in a file this binary was not built from", s))
				continue
			}
			out = append(out, addrs...)

		default:
			addr, ok := im.Lookup(s)
			if !ok {
				problems = append(problems, fmt.Sprintf("%q: no such function; it may have been "+
					"stripped or inlined, in which case name a line inside it or an address", s))
				continue
			}
			out = append(out, addr)
		}
	}

	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	if len(out) == 0 {
		return nil, fmt.Errorf("%w: %s", ErrNoTargets, strings.Join(problems, "; "))
	}
	if len(problems) > 0 {
		// Some resolved and some did not. The campaign can run, and running it
		// without saying which targets were dropped would let it report progress
		// towards a place nobody asked about.
		return out, fmt.Errorf("some targets did not resolve: %s", strings.Join(problems, "; "))
	}
	return out, nil
}

func hexList(v []uint64) string {
	if len(v) == 0 {
		return "none"
	}
	parts := make([]string, 0, len(v))
	for i, a := range v {
		if i >= 4 {
			parts = append(parts, "...")
			break
		}
		parts = append(parts, "0x"+strconv.FormatUint(a, 16))
	}
	return strings.Join(parts, ", ")
}
