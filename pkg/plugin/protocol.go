package plugin

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
)

// ProtocolVersion is the wire contract this build speaks.
//
// A plugin is a separate program, often built at a different time by someone
// else, so the version is checked in the handshake and a mismatch is refused
// outright. The alternative — proceeding and discovering the disagreement in a
// field that silently changed meaning — produces a campaign whose results are
// wrong rather than absent, which is worse (ASR-0008).
const ProtocolVersion = 1

// Op names a request. Every exchange is one request and one response, in order,
// on a single connection: the host never has two calls in flight, so there is
// no multiplexing to get wrong and no dispatcher for a plugin author to write.
// The ID exists to catch a plugin that answers the wrong question, not to allow
// concurrency.
type Op string

// The operations.
const (
	// OpHello is the handshake. It must be the first frame.
	OpHello Op = "hello"

	// OpJudge asks a feedback whether a batch of executions is interesting.
	OpJudge Op = "judge"

	// OpFinding asks an objective whether a batch of executions are bugs.
	OpFinding Op = "finding"

	// OpMutate asks a mutator for a batch of variants of one input.
	OpMutate Op = "mutate"

	// OpCommit settles the most recent judgement without judging anything new.
	// The hot path folds the commit into the next OpJudge instead; this is the
	// flush at the end of a campaign.
	OpCommit Op = "commit"

	// OpBye asks the plugin to exit. A plugin that ignores it is killed.
	OpBye Op = "bye"
)

// Request is a frame from the host to the plugin.
//
// One flat struct rather than a tagged union of payloads: a plugin may be
// written in a language with no sum types and no code generator, and the whole
// point of this tier is that writing one should not require either (ADR-0010).
// Unused fields are omitted, so a judge frame does not carry a mutator's.
type Request struct {
	ID uint64 `json:"id"`
	Op Op     `json:"op"`

	// Name selects which of the plugin's extensions the call is for. A plugin
	// may provide several.
	Name string `json:"name,omitempty"`

	// Protocol, Engine, Seed and Config belong to OpHello.
	//
	// Seed is a string because a campaign seed is a full 64-bit value and JSON
	// numbers are doubles in most languages: a plugin in JavaScript or Python
	// that parsed it as a number would derive a different sequence from the one
	// the engine derived, and the campaign would not replay (ASR-0008).
	Protocol int               `json:"protocol,omitempty"`
	Engine   string            `json:"engine,omitempty"`
	Seed     uint64            `json:"seed,string,omitempty"`
	Config   map[string]string `json:"config,omitempty"`

	// Batch carries the executions to judge, for OpJudge and OpFinding.
	Batch []Observation `json:"batch,omitempty"`

	// Keep settles the judgement the plugin returned last time: true commits
	// the novelty state it accumulated, false rolls it back.
	//
	// It rides along on the next call rather than costing a round trip of its
	// own. The engine's Append/Discard always follows a judgement and always
	// precedes the next one, so "settle the last, then answer this" loses
	// nothing and halves the IPC on the hot path.
	Keep *bool `json:"keep,omitempty"`

	// Input, Count and MaxBytes belong to OpMutate. Count variants are asked
	// for at once because a round trip costs more than a mutation does
	// (ADR-0010), and MaxBytes is the length the schema and the campaign allow,
	// so a plugin can respect a bound rather than have its work discarded for
	// breaking one it was never told about.
	//
	// Seed carries the draw for the batch on this call. A plugin that makes
	// random choices must derive them from it, or the campaign stops replaying.
	Input    []byte `json:"input,omitempty"`
	Count    int    `json:"count,omitempty"`
	MaxBytes int    `json:"max_bytes,omitempty"`
}

// Response is a frame from the plugin to the host.
type Response struct {
	ID uint64 `json:"id"`

	// Error is the plugin's own failure. It is not an infrastructure fault: the
	// call was delivered and understood, and the plugin declined it. The
	// campaign fails with this text, which is why a plugin should make it say
	// what a person could act on.
	Error string `json:"error,omitempty"`

	// Protocol, Name, Version and Provides answer OpHello.
	Protocol int      `json:"protocol,omitempty"`
	Name     string   `json:"name,omitempty"`
	Version  string   `json:"version,omitempty"`
	Provides Provides `json:"provides,omitzero"`

	// Verdicts answers OpJudge and OpFinding, one per observation, in order.
	Verdicts []Verdict `json:"verdicts,omitempty"`

	// Outputs answers OpMutate. Fewer than Count is allowed and normal: a
	// mutator with nothing useful to say should say nothing.
	Outputs [][]byte `json:"outputs,omitempty"`
}

// Provides is what a plugin declares it can do, by extension point.
//
// The host resolves the names a campaign asked for against this list at
// startup, so a typo in a campaign file is a refusal before the first execution
// rather than a feedback that silently never fires.
type Provides struct {
	Feedbacks  []string `json:"feedbacks,omitempty"`
	Mutators   []string `json:"mutators,omitempty"`
	Objectives []string `json:"objectives,omitempty"`
}

// Observation is what an out-of-process extension can see of one execution.
//
// It is deliberately a copy rather than a window. An in-process observer reads
// a shared coverage map with no copying at all; a plugin cannot, so what
// crosses the boundary is what is worth the bytes. Coverage arrives as a
// cardinality and a signature rather than the whole map: a 64 KiB map per
// execution would make the transport the campaign's dominant cost, and no
// plugin feedback yet proposed needs more.
type Observation struct {
	// Input is the bytes that were executed. Omitted when the caller judges an
	// input the plugin has already seen, or when it is too large to be worth
	// sending.
	Input []byte `json:"input,omitempty"`

	// Exit is how the execution ended: ok, crash, timeout, oom or error.
	//
	// A name rather than a number, because the plugin author reads it, and
	// because a renumbering must not silently change what a plugin decides.
	Exit string `json:"exit"`

	// ExitCode and Signal are the process's status, when there was a process.
	ExitCode int `json:"exit_code,omitempty"`
	Signal   int `json:"signal,omitempty"`

	// Stdout and Stderr are what the target wrote, already truncated to
	// whatever the executor retained.
	Stdout []byte `json:"stdout,omitempty"`
	Stderr []byte `json:"stderr,omitempty"`

	// DurationNS is how long the execution took.
	DurationNS int64 `json:"duration_ns,omitempty"`

	// Edges counts the coverage entries this execution touched, and Signature
	// fingerprints them. Backend names the instrumentation, because coverage is
	// not comparable across backends (ADR-0002).
	Edges     int    `json:"edges,omitempty"`
	Signature uint64 `json:"signature,string,omitempty"`
	Backend   string `json:"backend,omitempty"`

	// States is the protocol state trace, oldest first, for a stateful
	// campaign (ADR-0006). Empty for a stateless one.
	States []string `json:"states,omitempty"`
}

// Verdict is what a plugin says about one observation.
//
// One type serves both feedbacks and objectives because the two answer the same
// observation, differently (ADR-0007): a feedback fills in Interesting and the
// score, an objective fills in Finding. A frame that sets neither means "no".
type Verdict struct {
	Interesting bool `json:"interesting,omitempty"`

	NewSignal int     `json:"new_signal,omitempty"`
	Novelty   float64 `json:"novelty,omitempty"`
	Distance  float64 `json:"distance,omitempty"`
	Custom    float64 `json:"custom,omitempty"`

	// Finding is set when the execution is a bug. Nil is the common answer and
	// costs nothing on the wire.
	Finding *Finding `json:"finding,omitempty"`
}

// Finding is a bug an objective reports. It mirrors feedback.Finding; the host
// converts, so pkg/feedback stays free of any wire concern.
type Finding struct {
	Kind    string   `json:"kind"`
	Signal  int      `json:"signal,omitempty"`
	Summary string   `json:"summary,omitempty"`
	Detail  string   `json:"detail,omitempty"`
	Frames  []string `json:"frames,omitempty"`
}

// --- framing ----------------------------------------------------------------

// MaxFrameBytes bounds one frame. A plugin is untrusted by construction — that
// is the reason it is out of process — so a length it supplies must never be
// allocated on trust.
const MaxFrameBytes = 32 << 20

// headerBytes is the length prefix: four bytes, big-endian.
//
// Length-prefixed rather than newline-delimited, because a frame carries base64
// of arbitrary target output and a delimiter that can appear in the payload is
// a parser bug waiting for the input that contains it. Four bytes rather than a
// varint, because every language can read a fixed-width big-endian integer
// without a library.
const headerBytes = 4

// ErrFrameTooLarge is returned for a frame beyond MaxFrameBytes.
var ErrFrameTooLarge = errors.New("plugin: frame too large")

// Conn is a framed connection to the other end of the protocol.
//
// Reads are single-threaded by the protocol's own shape and writes are guarded,
// so a plugin that logs from a goroutine cannot interleave a half-written frame
// with a reply.
type Conn struct {
	r   *bufio.Reader
	w   io.Writer
	max int

	mu  sync.Mutex
	hdr [headerBytes]byte
	buf []byte
}

// NewConn returns a connection reading from r and writing to w.
func NewConn(r io.Reader, w io.Writer) *Conn {
	return &Conn{r: bufio.NewReaderSize(r, 64<<10), w: w, max: MaxFrameBytes}
}

// SetMaxFrame lowers the frame ceiling. Zero restores the default.
func (c *Conn) SetMaxFrame(n int) {
	if n <= 0 || n > MaxFrameBytes {
		n = MaxFrameBytes
	}
	c.max = n
}

// Send writes one frame.
func (c *Conn) Send(v any) error {
	body, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("plugin: encoding a frame: %w", err)
	}
	if len(body) > c.max {
		return fmt.Errorf("%w: %d bytes to send, limit %d", ErrFrameTooLarge, len(body), c.max)
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	var hdr [headerBytes]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(body)))
	if _, err := c.w.Write(hdr[:]); err != nil {
		return err
	}
	if _, err := c.w.Write(body); err != nil {
		return err
	}
	if f, ok := c.w.(interface{ Flush() error }); ok {
		return f.Flush()
	}
	return nil
}

// Receive reads one frame into v.
//
// The read buffer is reused across frames. That is safe because every byte
// field decodes through encoding/json, which allocates its own storage; nothing
// v holds afterwards points into the buffer.
func (c *Conn) Receive(v any) error {
	if _, err := io.ReadFull(c.r, c.hdr[:]); err != nil {
		return err
	}
	n := int(binary.BigEndian.Uint32(c.hdr[:]))
	if n > c.max {
		return fmt.Errorf("%w: %d bytes announced, limit %d", ErrFrameTooLarge, n, c.max)
	}
	if cap(c.buf) < n {
		c.buf = make([]byte, n)
	}
	c.buf = c.buf[:n]
	if _, err := io.ReadFull(c.r, c.buf); err != nil {
		return err
	}
	if err := json.Unmarshal(c.buf, v); err != nil {
		return fmt.Errorf("plugin: unreadable frame: %w", err)
	}
	return nil
}
