package corpus

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"time"

	"github.com/rom/Xfuzz/pkg/feedback"
	"github.com/rom/Xfuzz/pkg/ir"
)

// Digest is a testcase's content address.
//
// Content addressing gives de-duplication, integrity checking, and a stable
// identity for provenance in one mechanism (ADR-0008). SHA-256 rather than a
// fast non-cryptographic hash because a corpus is long-lived and shared, and a
// collision would silently merge two distinct inputs.
type Digest [sha256.Size]byte

// DigestOf returns the content address of an encoded input.
func DigestOf(b []byte) Digest { return sha256.Sum256(b) }

// String renders the digest as hex.
func (d Digest) String() string { return hex.EncodeToString(d[:]) }

// Short renders the first eight hex characters, for logs and tables.
func (d Digest) Short() string { return hex.EncodeToString(d[:4]) }

// IsZero reports whether the digest is unset.
func (d Digest) IsZero() bool { return d == Digest{} }

// Op is one applied mutation, recorded so an input can be reconstructed from
// its parent.
//
// It mirrors the mutation layer's own record rather than importing it: the
// corpus stores history, and coupling it to one mutation engine's types would
// stop a plugin mutator from participating in provenance at all.
type Op struct {
	// Mutator is the operator's name.
	Mutator string
	// Path is the child-index route to the node it changed.
	Path []int
	// RandPos is the parameter stream's position before it ran.
	RandPos uint64
}

// Provenance is how a testcase came to exist (ASR-0008).
type Provenance struct {
	// Parent is the entry this was derived from, zero for a seed.
	Parent Digest

	// Ops are the operators applied to the parent, in order.
	Ops []Op

	// Worker and Stream identify the RNG stream that produced it.
	Worker uint32

	// Origin records where a seed came from when there is no parent: a corpus
	// import, the grammar, or a captured session.
	Origin string

	// State is the protocol state the scheduler was aiming for when this entry
	// was produced, or empty.
	//
	// Recorded because it is the only place the reason for a mutation survives.
	// "This session was kept because we were trying to get past auth-ok" is
	// what makes a stateful campaign's choices reviewable afterwards, and
	// without it a corpus of sessions is a heap of byte sequences that happen
	// to have been interesting once.
	State string
}

// Metadata is what the scheduler and the reports need to know about an entry.
type Metadata struct {
	// Score is what the feedback stack reported when the entry was admitted.
	Score feedback.Score

	// ExecTime is how long the input took, used to prefer fast seeds: at equal
	// value, an input that runs twice as fast is worth twice as much.
	ExecTime time.Duration

	// Size is the encoded byte length. Smaller seeds mutate faster and minimise
	// better.
	Size int

	// Coverage is how many map entries the input reached.
	Coverage int

	// Fuzzed counts how many times the entry has been selected. The schedule
	// uses it to spread attention rather than re-fuzzing the same few seeds.
	Fuzzed uint64

	// Children counts entries derived from this one, which is the clearest
	// measure of whether attention paid to it was repaid.
	Children uint64

	// Depth is how many mutation generations separate it from a seed. It stands
	// in for age in scheduling, because wall-clock time must not influence a
	// fuzzing decision (ASR-0008).
	Depth int

	// Discovered is when it was found. Reporting only; never a scheduling input.
	Discovered time.Time

	// Favoured marks an entry in the minimal set that covers everything known.
	Favoured bool
}

// Testcase is one corpus entry.
type Testcase struct {
	ID    Digest
	Input *ir.Node
	Bytes []byte
	Meta  Metadata
	Prov  Provenance
}

// NewTestcase builds an entry from an input and its encoding.
func NewTestcase(input *ir.Node, encoded []byte) *Testcase {
	b := append([]byte(nil), encoded...)
	return &Testcase{
		ID:    DigestOf(b),
		Input: input,
		Bytes: b,
		Meta:  Metadata{Size: len(b), Discovered: time.Now()},
	}
}

func (t *Testcase) String() string {
	return fmt.Sprintf("%s (%d bytes, cov %d, depth %d, fuzzed %d)",
		t.ID.Short(), t.Meta.Size, t.Meta.Coverage, t.Meta.Depth, t.Meta.Fuzzed)
}

// Corpus is the set of inputs worth mutating further.
//
// It is in-memory and holds no persistence of its own; the store behind the
// daemon owns durability (ADR-0008). Keeping them separate is what lets the
// hot loop touch the corpus on every execution while writes are batched and
// asynchronous.
type Corpus struct {
	entries []*Testcase
	byID    map[Digest]int

	totalBytes int64
	totalTime  time.Duration
	totalCov   int64
}

// New returns an empty corpus.
func New() *Corpus { return &Corpus{byID: map[Digest]int{}} }

// Len returns the number of entries.
func (c *Corpus) Len() int { return len(c.entries) }

// At returns the entry at an index.
func (c *Corpus) At(i int) *Testcase { return c.entries[i] }

// Entries returns the backing slice. Callers must not reorder it; indices are
// used as identities by the schedulers.
func (c *Corpus) Entries() []*Testcase { return c.entries }

// Lookup finds an entry by content address.
func (c *Corpus) Lookup(d Digest) (*Testcase, bool) {
	i, ok := c.byID[d]
	if !ok {
		return nil, false
	}
	return c.entries[i], true
}

// Contains reports whether an input is already present.
func (c *Corpus) Contains(d Digest) bool {
	_, ok := c.byID[d]
	return ok
}

// Add admits an entry, reporting false if an identical input is already
// present.
//
// De-duplication by content is not an optimisation: without it, a mutation that
// happens to reproduce an existing entry is admitted again, and the corpus fills
// with copies that each consume scheduling attention.
func (c *Corpus) Add(tc *Testcase) bool {
	if _, dup := c.byID[tc.ID]; dup {
		return false
	}
	c.byID[tc.ID] = len(c.entries)
	c.entries = append(c.entries, tc)
	c.totalBytes += int64(tc.Meta.Size)
	c.totalTime += tc.Meta.ExecTime
	c.totalCov += int64(tc.Meta.Coverage)
	return true
}

// Remove deletes an entry by index.
func (c *Corpus) Remove(i int) {
	tc := c.entries[i]
	c.totalBytes -= int64(tc.Meta.Size)
	c.totalTime -= tc.Meta.ExecTime
	c.totalCov -= int64(tc.Meta.Coverage)

	delete(c.byID, tc.ID)
	last := len(c.entries) - 1
	c.entries[i] = c.entries[last]
	c.entries[last] = nil
	c.entries = c.entries[:last]
	if i < last {
		c.byID[c.entries[i].ID] = i
	}
}

// Averages summarises the corpus, which is what a power schedule compares an
// individual entry against.
type Averages struct {
	Size     float64
	ExecTime float64
	Coverage float64
	Depth    float64
}

// Averages returns the current means.
func (c *Corpus) Averages() Averages {
	n := float64(len(c.entries))
	if n == 0 {
		return Averages{}
	}
	depth := 0
	for _, e := range c.entries {
		depth += e.Meta.Depth
	}
	return Averages{
		Size:     float64(c.totalBytes) / n,
		ExecTime: float64(c.totalTime) / n,
		Coverage: float64(c.totalCov) / n,
		Depth:    float64(depth) / n,
	}
}

// Stats summarises a corpus for reporting.
type Stats struct {
	Entries    int
	TotalBytes int64
	MaxDepth   int
	Favoured   int
}

// Stats returns a summary.
func (c *Corpus) Stats() Stats {
	s := Stats{Entries: len(c.entries), TotalBytes: c.totalBytes}
	for _, e := range c.entries {
		if e.Meta.Depth > s.MaxDepth {
			s.MaxDepth = e.Meta.Depth
		}
		if e.Meta.Favoured {
			s.Favoured++
		}
	}
	return s
}

// SortedByCoverage returns indices ordered by descending coverage, for reports
// and for the minimal-set computation that marks favoured entries.
func (c *Corpus) SortedByCoverage() []int {
	idx := make([]int, len(c.entries))
	for i := range idx {
		idx[i] = i
	}
	sort.SliceStable(idx, func(a, b int) bool {
		return c.entries[idx[a]].Meta.Coverage > c.entries[idx[b]].Meta.Coverage
	})
	return idx
}
