package engine

import (
	"bytes"
	"context"
	"encoding/binary"
	"strconv"

	"github.com/rom/Xfuzz/pkg/executor"
	"github.com/rom/Xfuzz/pkg/feedback"
)

// Input-to-state substitution: getting past a comparison by reading it.
//
// A four-byte magic number is a one-in-four-billion guess, and a checksum is
// worse. No mutation schedule solves that, because there is nothing to climb:
// every wrong value is equally wrong, coverage is flat until the exact value
// appears, and the campaign has no gradient to follow.
//
// The way through is not to guess. The target compared something against
// something, and the comparison log says what both were. If the value the input
// supplied appears in the input — and for a field the program read out of the
// input, it does — then replacing it with the value the program wanted turns
// four billion guesses into one edit. That is Redqueen's insight and the reason
// ADR-0007 calls this stage native and cheap.
//
// Cheap matters. Each substitution is one execution, and the number of them is
// bounded by the number of distinct comparisons that failed, not by an energy
// budget. A stage that spent a seed's whole budget here would starve the
// mutation it exists to unblock.

// cmpLogStage derives inputs by writing what the target wanted into the places
// where the input said something else.
type cmpLogStage struct {
	// buf is reused across candidates so the stage does not allocate a copy of
	// the input per substitution.
	buf []byte

	// tried is the set of (needle, replacement) pairs already attempted for the
	// current parent, so that a comparison inside a loop does not produce the
	// same edit a thousand times.
	tried map[cmpPair]bool

	// records is this stage's own copy of the parent's comparison table, held
	// across candidates because the observer's copy does not survive one.
	records []feedback.CmpRecord
}

type cmpPair struct{ a, b string }

// Bounds. Each is there because the comparison table is written by a program
// that is being fuzzed, so its length is a function of the target's behaviour
// rather than of anything the fuzzer chose.
const (
	// maxCmpRecords is how many comparisons one parent's substitutions are drawn
	// from. A target that compares in a loop fills the table with the same site
	// over and over; the first entries are the ones nearest the input's entry to
	// the program, which is where a substitution is most likely to matter.
	maxCmpRecords = 512

	// maxCmpCandidates bounds the executions this stage may spend on one parent.
	// It is small on purpose: the stage exists to unblock mutation, and mutation
	// is what finds bugs.
	maxCmpCandidates = 96

	// minCmpWidth is the narrowest operand worth substituting. A one-byte
	// comparison is something mutation solves in 256 attempts, and substituting
	// for it would fill the corpus with edits that a single havoc round would
	// have found anyway.
	minCmpWidth = 2
)

func (s *cmpLogStage) name() string { return "cmplog" }

func (s *cmpLogStage) run(ctx context.Context, e *Engine, in stageInput) (stageResult, error) {
	var res stageResult
	obs := e.cfg.Cmp
	if obs == nil {
		return res, nil
	}

	// Execute the parent, so the table describes the comparisons this input
	// reached rather than whatever the last candidate happened to reach. The
	// execution is counted like any other: it is real work the campaign did.
	parentBytes := in.parent.Bytes
	if len(parentBytes) == 0 {
		return res, nil
	}
	ek, err := e.cfg.Executor.Run(ctx, executor.Input{
		Bytes: parentBytes, Node: in.parent.Input,
	}, e.cfg.Observers)
	e.stats.Execs++
	e.stats.CmpExecs++
	if err != nil {
		// A harness failure here is the same harness failure it would be
		// anywhere, and the stage has nothing to contribute without a table.
		e.stats.HarnessError++
		return res, nil
	}

	// The feedback saw this execution and may have found it interesting. It was
	// not a new input, so nothing should be admitted for it — but the feedback's
	// pending state has to be resolved either way, or the next candidate's
	// judgement is made against state left over from this one.
	if interesting, _, jerr := e.cfg.Feedback.IsInteresting(e.cfg.Observers, ek); jerr == nil && interesting {
		e.cfg.Feedback.Discard()
	}

	// Copied, not borrowed. The observer hands back the slice it fills, and the
	// very next execution — the first candidate this stage produces — clears it
	// and refills it with that candidate's comparisons. Iterating the borrowed
	// slice means every substitution after the first is derived from an input
	// that is not the parent, which does not fail: it produces plausible edits
	// aimed at the wrong bytes, so the stage keeps costing executions and stops
	// making progress. Measured: one admission, then a hard plateau that a
	// budget of a hundred and fifty thousand executions did not move.
	s.records = append(s.records[:0], obs.Records()...)
	records := s.records
	if len(records) > maxCmpRecords {
		records = records[:maxCmpRecords]
	}
	if s.tried == nil {
		s.tried = make(map[cmpPair]bool, 64)
	}
	clear(s.tried)

	spent := 0
	for _, r := range records {
		if ctx.Err() != nil {
			return res, nil
		}
		if spent >= maxCmpCandidates {
			break
		}
		if in.budget.MaxExecs > 0 && e.stats.Execs >= in.budget.MaxExecs {
			return res, nil
		}

		for _, sub := range substitutions(r) {
			if spent >= maxCmpCandidates {
				break
			}
			if len(sub.needle) < minCmpWidth || bytes.Equal(sub.needle, sub.want) {
				continue
			}
			key := cmpPair{string(sub.needle), string(sub.want)}
			if s.tried[key] {
				continue
			}
			s.tried[key] = true

			idx := bytes.Index(parentBytes, sub.needle)
			if idx < 0 {
				// The value the target compared is not in the input. That is the
				// common case — a length, a loop counter, a hash of something —
				// and it is why this stage is cheap: there is nothing to do.
				continue
			}

			s.buf = append(s.buf[:0], parentBytes...)
			copy(s.buf[idx:], sub.want)

			tree, ok := decodeCandidate(e, s.buf)
			if !ok {
				continue
			}
			spent++
			e.stats.CmpExecs++
			v, verr := e.evaluate(ctx, in.parent, candidate{
				tree:    tree,
				encoded: append([]byte(nil), s.buf...),
				ops:     substitutionOps("cmplog:" + sub.how),
			})
			if verr != nil {
				return res, verr
			}
			if v.admitted {
				res.admitted++
				e.stats.CmpAdmitted++
			}
			if v.interesting && v.score.NewSignal > res.best.NewSignal {
				res.best = v.score
			}
			if v.finding && in.budget.StopOnFirstFinding {
				res.stop = true
				return res, nil
			}
		}
	}
	return res, nil
}

// substitution is one edit to try: find needle, write want.
type substitution struct {
	needle []byte
	want   []byte
	how    string
}

// substitutions enumerates the edits one comparison suggests.
//
// Both directions, because the compiler decides which operand is which and a
// campaign cannot: for a constant comparison clang puts the constant second, but
// for `if (a == b)` between two computed values either could be the one that came
// from the input.
//
// And several encodings, because a program that compares an integer did not
// necessarily read it from the input as one. A length field is little-endian
// bytes, a protocol header is big-endian, a text format spells the same number
// in decimal, and a hex dump spells it in hex. Substituting only the native
// encoding solves binary formats and no others, and the extra encodings cost
// one execution each on a stage already bounded to a hundred.
func substitutions(r feedback.CmpRecord) []substitution {
	if r.Kind == feedback.CmpMem {
		n := int(r.Size)
		a := append([]byte(nil), r.A[:n]...)
		b := append([]byte(nil), r.B[:n]...)
		return []substitution{
			{needle: a, want: b, how: "mem"},
			{needle: b, want: a, how: "mem"},
		}
	}

	n := int(r.Size)
	if n < minCmpWidth || n > 8 {
		return nil
	}
	a, b := r.AUint(), r.BUint()

	var out []substitution
	add := func(na, nb []byte, how string) {
		out = append(out,
			substitution{needle: na, want: nb, how: how},
			substitution{needle: nb, want: na, how: how})
	}
	add(leBytes(a, n), leBytes(b, n), "le")
	add(beBytes(a, n), beBytes(b, n), "be")
	add([]byte(strconv.FormatUint(a, 10)), []byte(strconv.FormatUint(b, 10)), "dec")
	add([]byte(strconv.FormatUint(a, 16)), []byte(strconv.FormatUint(b, 16)), "hex")

	// Narrower widths, when both operands fit in them.
	//
	// C promotes anything narrower than an int before comparing it, so
	// `uint16_t tail; if (tail != 0xBEEF)` compiles to a *four*-byte comparison
	// of 0x0000BEEF against a value whose top half is always zero. The field in
	// the input is two bytes; the needle built at the logged width is four, and
	// four zero bytes are not where the two-byte field is. Every comparison on a
	// char or a short is in this shape, which is most of the comparisons a
	// parser makes — so without this the stage substitutes for the wide gates
	// and silently does nothing for the narrow ones. Measured on a three-gate
	// ladder: the campaign passed the 32-bit and 64-bit gates and then stopped
	// dead at the 16-bit one, for a hundred and fifty thousand executions.
	for w := minCmpWidth; w < n; w *= 2 {
		if !fitsIn(a, w) || !fitsIn(b, w) {
			continue
		}
		add(leBytes(a, w), leBytes(b, w), "le"+strconv.Itoa(w*8))
		add(beBytes(a, w), beBytes(b, w), "be"+strconv.Itoa(w*8))
	}

	// Off-by-one neighbours, for the comparisons that are not equalities. A
	// bounds check the input failed by one is passed by the value next to the
	// one that was compared, and an exact substitution would leave it failing.
	add(leBytes(a, n), leBytes(b+1, n), "le+1")
	add(leBytes(a, n), leBytes(b-1, n), "le-1")
	return out
}

// fitsIn reports whether a value is representable in w bytes.
func fitsIn(v uint64, w int) bool {
	if w >= 8 {
		return true
	}
	return v>>(8*uint(w)) == 0
}

func leBytes(v uint64, n int) []byte {
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], v)
	return append([]byte(nil), b[:n]...)
}

func beBytes(v uint64, n int) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	return append([]byte(nil), b[8-n:]...)
}
