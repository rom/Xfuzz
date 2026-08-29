package api

import (
	"encoding/hex"
	"fmt"
	"time"

	"github.com/rom/Xfuzz/internal/daemon"
	"github.com/rom/Xfuzz/internal/store"
	"github.com/rom/Xfuzz/pkg/corpus"
)

// The wire shapes.
//
// Deliberately separate from the store's types. The store's structs change with
// the schema, and an API that serialised them directly would make every schema
// change a breaking API change — and would leak fields nobody outside the daemon
// should depend on.

// corpusEntryView is one corpus entry as the API returns it.
type corpusEntryView struct {
	Digest    string    `json:"digest"`
	Size      int       `json:"size"`
	Coverage  int       `json:"coverage"`
	NewSignal int       `json:"new_signal"`
	ExecTime  string    `json:"exec_time"`
	Depth     int       `json:"depth"`
	Fuzzed    uint64    `json:"fuzzed"`
	Children  uint64    `json:"children"`
	Favoured  bool      `json:"favoured"`
	Origin    string    `json:"origin,omitempty"`
	Parent    string    `json:"parent,omitempty"`
	Worker    uint32    `json:"worker"`
	Found     time.Time `json:"discovered"`

	// Ops is the provenance chain: how this input came to exist. It is what
	// answers "why does the fuzzer think this matters" months later.
	Ops []string `json:"ops,omitempty"`

	// Payload is present only when one entry was asked for, never in a listing:
	// a listing of ten thousand entries with payloads is a response nobody
	// wanted and a browser cannot render.
	Payload []byte `json:"payload,omitempty"`
}

func viewOf(tc *corpus.Testcase) corpusEntryView {
	v := corpusEntryView{
		Digest:    tc.ID.String(),
		Size:      tc.Meta.Size,
		Coverage:  tc.Meta.Coverage,
		NewSignal: tc.Meta.Score.NewSignal,
		ExecTime:  tc.Meta.ExecTime.String(),
		Depth:     tc.Meta.Depth,
		Fuzzed:    tc.Meta.Fuzzed,
		Children:  tc.Meta.Children,
		Favoured:  tc.Meta.Favoured,
		Origin:    tc.Prov.Origin,
		Worker:    tc.Prov.Worker,
		Found:     tc.Meta.Discovered,
	}
	if !tc.Prov.Parent.IsZero() {
		v.Parent = tc.Prov.Parent.String()
	}
	for _, op := range tc.Prov.Ops {
		v.Ops = append(v.Ops, fmt.Sprintf("%s@%v", op.Mutator, op.Path))
	}
	return v
}

// findingView is one finding as the API returns it.
type findingView struct {
	ID      int64    `json:"id"`
	Digest  string   `json:"digest"`
	Kind    string   `json:"kind"`
	Signal  int      `json:"signal,omitempty"`
	Summary string   `json:"summary,omitempty"`
	Detail  string   `json:"detail,omitempty"`
	Frames  []string `json:"frames,omitempty"`
	Bucket  int64    `json:"bucket_id"`

	// TriageState, ReproTrials and ReproRate are reported together on purpose:
	// a rate without a trial count cannot distinguish "never reproduces" from
	// "nobody looked".
	TriageState string  `json:"triage_state"`
	ReproTrials int     `json:"repro_trials"`
	ReproRate   float64 `json:"repro_rate"`

	OriginalSize  int       `json:"original_size"`
	MinimizedSize int       `json:"minimized_size,omitempty"`
	Reduction     float64   `json:"reduction,omitempty"`
	Notes         string    `json:"notes,omitempty"`
	FoundAtExec   uint64    `json:"found_at_exec"`
	Created       time.Time `json:"created"`

	// Reproducer is present only when one finding was asked for.
	Reproducer []byte `json:"reproducer,omitempty"`
}

func findingViewOf(f *store.Finding) findingView {
	return findingView{
		ID: f.ID, Digest: f.Digest.String(), Kind: f.Kind, Signal: f.Signal,
		Summary: f.Summary, Detail: f.Detail, Frames: f.Frames, Bucket: f.BucketID,
		TriageState: f.TriageState, ReproTrials: f.ReproTrials, ReproRate: f.ReproRate,
		OriginalSize: f.OriginalSize, MinimizedSize: f.MinimizedSize,
		Reduction: f.Reduction(), Notes: f.Notes, FoundAtExec: f.FoundAtExec,
		Created: f.CreatedAt,
	}
}

// bucketView is a bucket as the API reports it.
//
// A view rather than the store's own record, for the same reason findings have
// one: the store's field names are Go's, and an API that answered in Go field
// names for one resource and snake_case for the rest would be answering in two
// languages.
type bucketView struct {
	ID        int64     `json:"id"`
	Strategy  string    `json:"strategy"`
	Signature string    `json:"signature"`
	Kind      string    `json:"kind,omitempty"`
	Summary   string    `json:"summary,omitempty"`
	Count     int64     `json:"count"`
	FirstSeen time.Time `json:"first_seen"`
}

func bucketViewOf(b *store.Bucket) bucketView {
	return bucketView{
		ID: b.ID, Strategy: b.Strategy, Signature: b.Signature,
		Kind: b.Kind, Summary: b.Summary, Count: b.Count, FirstSeen: b.FirstSeenAt,
	}
}

func bucketViewsOf(bs []*store.Bucket) []bucketView {
	out := make([]bucketView, 0, len(bs))
	for _, b := range bs {
		out = append(out, bucketViewOf(b))
	}
	return out
}

// storeOf returns the store a campaign writes to.
func (s *Server) storeOf(c *daemon.Campaign) (*store.Store, error) {
	st := c.Store()
	if st == nil {
		return nil, fmt.Errorf("campaign %q has no store", c.Config.Name)
	}
	return st, nil
}

func parseDigest(s string) (corpus.Digest, error) {
	var d corpus.Digest
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != len(d) {
		return d, fmt.Errorf("%q is not a digest", s)
	}
	copy(d[:], b)
	return d, nil
}
