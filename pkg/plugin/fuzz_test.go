package plugin

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

// FuzzReceive fuzzes the protocol frame decoder from the host's side.
//
// A plugin is untrusted by construction — that is the reason it runs out of
// process (ADR-0010) — so everything it writes back is attacker-controlled from
// the host's point of view. The length prefix in particular is a number a
// hostile plugin chooses and the host must never allocate on trust.
//
// The whole frame is fuzzed rather than just the JSON, because the framing and
// the decoding are separate parsers that meet: the length says how much to
// read, the body says what it means, and a disagreement between them is exactly
// what a malicious plugin would construct.
func FuzzReceive(f *testing.F) {
	f.Add(frame(`{"id":1,"protocol":1,"name":"p"}`))
	f.Add(frame(`{"id":1,"verdicts":[{"interesting":true,"novelty":0.5}]}`))
	f.Add(frame(`{"id":1,"outputs":["aGVsbG8="]}`))
	f.Add(frame(`{"id":1,"error":"no"}`))
	f.Add(frame(``))
	f.Add([]byte{0xff, 0xff, 0xff, 0xff})
	f.Add([]byte{0x00, 0x00, 0x00, 0x04})
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, raw []byte) {
		c := NewConn(bytes.NewReader(raw), &strings.Builder{})
		c.SetMaxFrame(1 << 20)

		var resp Response
		if err := c.Receive(&resp); err != nil {
			return
		}
		// A frame that decoded must be usable without further checking. The
		// host reads these fields straight into the engine's types, so a value
		// that arrives out of range has to be caught by the conversion rather
		// than by the caller remembering to.
		for _, v := range resp.Verdicts {
			n := v.score().Novelty
			if n < 0 || n > 1 || n != n {
				t.Fatalf("a decoded verdict produced novelty %v, outside the range the scheduler assumes", n)
			}
		}
		for _, v := range resp.Verdicts {
			// The conversion must be total: a finding that decoded is one the
			// store will be asked to write.
			_ = v.Finding.finding()
		}
	})
}

// FuzzServe fuzzes the plugin's side: a request stream from a hostile host.
//
// The mirror image, and it matters for the same reason in reverse. A plugin
// written against this SDK inherits whatever robustness the SDK has, and a
// plugin that can be crashed by its host is a plugin that fails its campaign
// for a reason nobody can find.
func FuzzServe(f *testing.F) {
	f.Add(frame(`{"id":1,"op":"hello","protocol":1,"seed":"7"}`))
	f.Add(frame(`{"id":2,"op":"judge","name":"f","batch":[{"exit":"crash"}]}`))
	f.Add(frame(`{"id":3,"op":"mutate","name":"m","input":"aGk=","count":4}`))
	f.Add(frame(`{"id":4,"op":"finding","name":"o","batch":[{"exit":"ok"}]}`))
	f.Add(frame(`{"id":5,"op":"bye"}`))
	f.Add(frame(`{"id":6,"op":"judge","name":"f","batch":null,"keep":true}`))
	f.Add(append(frame(`{"id":1,"op":"hello","protocol":1}`), frame(`{"id":2,"op":"unknown"}`)...))

	p := Plugin{
		Name:      "fuzz",
		Feedbacks: map[string]Judger{"f": constantJudger{}},
		Objectives: map[string]Oracle{"o": OracleFunc(func(b []Observation) ([]Verdict, error) {
			return make([]Verdict, len(b)), nil
		})},
		Mutators: map[string]Varier{"m": VaryFunc(func(in []byte, _ uint64, count, _ int) ([][]byte, error) {
			out := make([][]byte, count)
			for i := range out {
				out[i] = append(append([]byte(nil), in...), byte(i))
			}
			return out, nil
		})},
	}

	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 1<<20 {
			return
		}
		var sink bytes.Buffer
		// Serve must always return rather than panic, whatever it is fed. A
		// truncated stream ends it; a malformed frame is answered with an
		// error and the loop continues, because a plugin that dies on a bad
		// request takes its campaign with it.
		_ = ServeOn(bytes.NewReader(raw), &sink, p)
	})
}

type constantJudger struct{}

func (constantJudger) Judge(b []Observation) ([]Verdict, error) { return make([]Verdict, len(b)), nil }
func (constantJudger) Commit(bool)                              {}

// frame wraps a JSON body in the protocol's length prefix.
func frame(body string) []byte {
	out := make([]byte, headerBytes+len(body))
	binary.BigEndian.PutUint32(out, uint32(len(body)))
	copy(out[headerBytes:], body)
	return out
}
