package tracer

import (
	"bufio"
	"io"
	"strconv"
	"strings"
)

// Reading QEMU's execution log.
//
// qemu-user with -d exec prints one line for every translation block it enters.
// That is block tracing, in order, from a stock unpatched emulator — no build of
// QEMU with a coverage patch, no matching versions between the fuzzer and the
// emulator, nothing to install beyond the distribution's own package. It is slow,
// because the line is formatted and written to a file per block, and slow is what
// the tier is for.
//
// The line has had three shapes across QEMU's history, and a fuzzer cannot
// require a particular version of a tool it did not build:
//
//	Trace 0x7f3a4c000100 [0000000000401136]
//	Trace 0x7f3a4c000100 [00000000/0000000000401136/00000033]
//	Trace 0: 0x7f3a4c000100 [00000000/0000000000401136/00000033/ff020000] main+0x0
//
// The bracketed group is the interesting part. Where it has one field, that is
// the guest program counter; where it has several, the counter is the second,
// after the code segment base. Everything else on the line — the host address of
// the translated block, the CPU index, the symbol — varies with the build and
// says nothing about the guest.

// parseExecLog extracts guest program counters from a QEMU execution log, in
// order.
//
// Malformed lines are skipped rather than reported: the log is a debugging
// stream that also carries linking notices, chain-break notices and whatever
// else the emulator was asked to print, and refusing to read a trace because it
// contained a line about something else would make the backend fail on the
// emulator's own diagnostics.
func parseExecLog(r io.Reader, limit int) []uint64 {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)

	var out []uint64
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "Trace") {
			continue
		}
		open := strings.IndexByte(line, '[')
		if open < 0 {
			continue
		}
		close := strings.IndexByte(line[open:], ']')
		if close < 0 {
			continue
		}
		fields := strings.Split(line[open+1:open+close], "/")
		var raw string
		switch len(fields) {
		case 0:
			continue
		case 1:
			raw = fields[0]
		default:
			raw = fields[1]
		}
		pc, err := strconv.ParseUint(strings.TrimSpace(raw), 16, 64)
		if err != nil {
			continue
		}
		out = append(out, pc)
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out
}

// resolveBase works out where a guest image was loaded, from the addresses that
// were traced and the addresses static analysis expects.
//
// QEMU does not say where it put a position-independent guest, and the guest
// process has exited by the time its log is read, so there is nothing to ask.
// What is known is that loading is page-aligned: whatever the base, an address's
// low twelve bits survive it. So each traced address is paired with every
// analysed block whose low bits match, each pairing implies a base, and the base
// that explains the most traced addresses is the one. A wrong answer needs a
// coincidence to beat the truth across hundreds of addresses.
//
// Reported as unresolved rather than guessed when nothing wins clearly. Coverage
// against a wrong base is coverage against noise: it would look like a working
// campaign and mean nothing.
func resolveBase(known, observed []uint64) (uint64, bool) {
	if len(known) == 0 || len(observed) == 0 {
		return 0, false
	}
	// Group the analysed blocks by their offset within a page, so a traced
	// address only has to be compared against the ones it could possibly be.
	const pageMask = 0xFFF
	byPage := make(map[uint64][]uint64, len(known))
	for _, k := range known {
		p := k & pageMask
		byPage[p] = append(byPage[p], k)
	}

	votes := make(map[uint64]int)
	for _, o := range observed {
		for _, k := range byPage[o&pageMask] {
			if o < k {
				continue
			}
			votes[o-k]++
		}
	}

	var best uint64
	var bestN, secondN int
	for base, n := range votes {
		switch {
		case n > bestN:
			best, bestN, secondN = base, n, bestN
		case n > secondN:
			secondN = n
		}
	}
	// A base is accepted only if it explains a real share of what was traced and
	// beats its nearest rival. Both conditions matter: the first rules out a
	// trace that has nothing to do with this image, the second rules out a tie
	// between two equally unsupported answers.
	if bestN < 4 || bestN*2 <= secondN*3 {
		return 0, false
	}
	return best, true
}
