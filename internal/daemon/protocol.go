package daemon

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/rom/Xfuzz/internal/metrics"
)

// The worker protocol.
//
// A worker is a separate process (ADR-0015) and writes nothing to the store
// itself: every corpus entry, finding and counter goes to the daemon, which owns
// the store and the audit log (ADR-0003, ADR-0008). That is what makes the
// daemon the single chokepoint it is supposed to be, and it is also what makes
// corpus sync free — the daemon already sees every admission.
//
// The encoding is newline-delimited JSON over a pipe pair. It carries control
// traffic and admissions, not executions: a campaign at 3,000 exec/s admits a
// handful of entries a second, so the cost of JSON here is invisible, and being
// able to read the stream with `cat` when a worker misbehaves is worth more than
// the bytes.

// MessageType identifies a protocol message.
type MessageType string

// Worker-to-daemon messages.
const (
	// MsgReady is sent once, when the worker has built its engine and is about
	// to start. It carries what the worker resolved, so the daemon can report a
	// worker that disagrees with the campaign rather than discovering it later.
	MsgReady MessageType = "ready"

	// MsgMetrics reports the worker's counters. Sent on a timer.
	MsgMetrics MessageType = "metrics"

	// MsgCorpus reports a newly admitted corpus entry, with its payload.
	MsgCorpus MessageType = "corpus"

	// MsgFinding reports a crash, hang, or oracle violation, with the input.
	MsgFinding MessageType = "finding"

	// MsgCheckpoint carries the worker's resume state.
	MsgCheckpoint MessageType = "checkpoint"

	// MsgStates carries the protocol state machine a worker has inferred.
	//
	// Its own message rather than a field on the metrics one: metrics are sent
	// several times a second and coalesced, and a state graph is neither small
	// nor changing that fast. Sent on the checkpoint cadence instead, which is
	// the rate at which it actually changes once a campaign has been running
	// for a minute.
	MsgStates MessageType = "states"

	// MsgStopped is sent when the worker's own budget ended, with the reason.
	MsgStopped MessageType = "stopped"

	// MsgLog carries a diagnostic line.
	MsgLog MessageType = "log"
)

// Daemon-to-worker messages.
const (
	// CmdSync delivers corpus entries discovered by siblings.
	CmdSync MessageType = "sync"

	// CmdPause and CmdResume suspend and resume fuzzing without losing the
	// worker's in-memory state, which a stop-and-restart would.
	CmdPause  MessageType = "pause"
	CmdResume MessageType = "resume"

	// CmdCheckpoint asks for resume state now.
	CmdCheckpoint MessageType = "checkpoint"

	// CmdStop asks the worker to finish and exit.
	CmdStop MessageType = "stop"
)

// Message is one protocol frame.
type Message struct {
	Type   MessageType `json:"type"`
	Worker int         `json:"worker"`
	At     time.Time   `json:"at,omitempty"`

	// Ready
	Ready *ReadyInfo `json:"ready,omitempty"`

	// Metrics
	Metrics *metrics.Snapshot `json:"metrics,omitempty"`

	// Corpus and Sync
	Entries []CorpusEntry `json:"entries,omitempty"`

	// Finding
	Finding *FindingReport `json:"finding,omitempty"`

	// Checkpoint
	Checkpoint *CheckpointState `json:"checkpoint,omitempty"`

	// States
	States *StateReport `json:"states,omitempty"`

	// Stopped
	Reason string `json:"reason,omitempty"`

	// Log
	Level string `json:"level,omitempty"`
	Text  string `json:"text,omitempty"`
}

// ReadyInfo is what a worker reports about itself at startup.
type ReadyInfo struct {
	Pid int `json:"pid"`

	// Strategy is which ensemble strategy this worker was assigned.
	Strategy string `json:"strategy,omitempty"`

	// Executor and Isolation are what the worker actually got, which may be
	// weaker than what was asked for. Reporting it here means a campaign that
	// silently fell back to a slower tier or a weaker sandbox is visible in the
	// first second rather than in a post-mortem.
	Executor  string `json:"executor"`
	Isolation string `json:"isolation"`

	// Seeds is how many the worker loaded, and CoverageMapSize what it is using.
	Seeds           int `json:"seeds"`
	CoverageMapSize int `json:"coverage_map_size"`
}

// CorpusEntry is an admitted input crossing the wire.
type CorpusEntry struct {
	// Digest is the content address, hex.
	Digest string `json:"digest"`

	// Payload is the input. Base64 through JSON, which the encoder does for a
	// []byte without being asked.
	Payload []byte `json:"payload"`

	Coverage  int   `json:"coverage,omitempty"`
	NewSignal int   `json:"new_signal,omitempty"`
	ExecTime  int64 `json:"exec_time_ns,omitempty"`
	Depth     int   `json:"depth,omitempty"`
	Favoured  bool  `json:"favoured,omitempty"`

	// Origin says where it came from: a seed import, a mutation, or a sibling.
	// An entry synced from a sibling is marked so that provenance does not claim
	// this worker discovered it.
	Origin string `json:"origin,omitempty"`
}

// FindingReport is a crash crossing the wire.
type FindingReport struct {
	Digest  string   `json:"digest"`
	Payload []byte   `json:"payload"`
	Kind    string   `json:"kind"`
	Signal  int      `json:"signal,omitempty"`
	Summary string   `json:"summary,omitempty"`
	Detail  string   `json:"detail,omitempty"`
	Frames  []string `json:"frames,omitempty"`

	// Bucket is the worker's provisional classification. Triage recomputes it
	// from the minimised reproducer, where the evidence is better.
	Strategy  string `json:"strategy,omitempty"`
	Signature string `json:"signature,omitempty"`

	// FoundAtExec is the campaign's own clock, which unlike wall time is the
	// same on a replay.
	FoundAtExec uint64 `json:"found_at_exec"`

	// Coverage is the map the crashing execution produced, for coverage
	// bucketing. Omitted when the target is not instrumented.
	Coverage []byte `json:"coverage,omitempty"`
}

// CheckpointState is a worker's resume state crossing the wire.
type CheckpointState struct {
	Coverage   []byte            `json:"coverage,omitempty"`
	Execs      uint64            `json:"execs"`
	CorpusSize int               `json:"corpus_size"`
	RNG        map[string]uint64 `json:"rng,omitempty"`
}

// MaxMessageBytes bounds one frame.
//
// A worker is a process running code the campaign supplies, and a length the
// sender chooses is a length the sender can make enormous. The cap is generous
// enough for any corpus entry a campaign should be keeping and small enough that
// a runaway worker cannot exhaust the daemon.
const MaxMessageBytes = 64 << 20

// Encoder writes protocol messages.
type Encoder struct {
	w   *bufio.Writer
	enc *json.Encoder
}

// NewEncoder returns an encoder over w.
func NewEncoder(w io.Writer) *Encoder {
	bw := bufio.NewWriterSize(w, 1<<16)
	return &Encoder{w: bw, enc: json.NewEncoder(bw)}
}

// Encode writes one message and flushes.
//
// Flushing every message is deliberate: an unflushed report from a worker that
// then crashes is a report that never happened, and the crash is exactly when
// the report matters most.
func (e *Encoder) Encode(m *Message) error {
	if m.At.IsZero() {
		m.At = time.Now()
	}
	if err := e.enc.Encode(m); err != nil {
		return err
	}
	return e.w.Flush()
}

// Decoder reads protocol messages.
type Decoder struct {
	sc *bufio.Scanner
}

// NewDecoder returns a decoder over r.
func NewDecoder(r io.Reader) *Decoder {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 1<<16), MaxMessageBytes)
	return &Decoder{sc: sc}
}

// Decode reads the next message. It returns io.EOF at the end of the stream.
func (d *Decoder) Decode() (*Message, error) {
	for d.sc.Scan() {
		line := d.sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var m Message
		if err := json.Unmarshal(line, &m); err != nil {
			// A worker's stdout also carries whatever the Go runtime writes on
			// a panic. Skipping unparseable lines rather than failing means a
			// panicking worker produces a readable log instead of an
			// unreadable protocol error on top of it.
			return nil, fmt.Errorf("daemon: unreadable worker message: %w\n%s", err, truncate(line, 512))
		}
		return &m, nil
	}
	if err := d.sc.Err(); err != nil {
		return nil, err
	}
	return nil, io.EOF
}

func truncate(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return string(b[:n]) + "…"
}

// StateReport is the protocol state machine one worker has inferred.
//
// Exemplars are carried with it because a state label is a hash and a hash
// explains nothing: seeing what the target actually said is how somebody
// decides whether the clustering is right, which is what ADR-0006 means by
// inference being inspectable. Without it a campaign reporting four hundred
// states is a number nobody can act on.
type StateReport struct {
	States      []StateCount      `json:"states"`
	Transitions []TransitionCount `json:"transitions"`

	// Illegal lists moves outside a declared model: the target accepting a
	// transition its own protocol forbids.
	Illegal []TransitionCount `json:"illegal,omitempty"`

	// Fn names the state function that produced the labels.
	Fn string `json:"fn,omitempty"`
}

// StateCount is one state and how often it was reached.
type StateCount struct {
	Label string `json:"label"`
	Count int    `json:"count"`

	// Exemplar is the first response that produced this label, truncated.
	Exemplar string `json:"exemplar,omitempty"`

	// Variants is how many distinct responses produced this label, capped.
	// More than one means the state function merged responses, which is how a
	// campaign aiming at a state can keep landing somewhere it has been.
	Variants int `json:"variants,omitempty"`
}

// TransitionCount is one move and how often it was made.
type TransitionCount struct {
	From  string `json:"from"`
	To    string `json:"to"`
	Count int    `json:"count"`
}
