package plugin

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
)

// A plugin's side of the protocol.
//
// This exists so that the reference implementation of the wire format is the
// one the tests exercise, and so that writing a plugin in Go is a matter of
// filling in a function rather than reimplementing framing. A plugin in another
// language reimplements this file; it is fifty lines of length-prefixed JSON,
// which is the whole reason the protocol looks the way it does (ADR-0010).

// Judger is a feedback running inside a plugin.
//
// Judge answers one verdict per observation, in order. Commit settles the
// judgements from the previous Judge: true means the engine kept the input and
// the novelty state should stand, false means it did not and the state must be
// rolled back. A feedback that keeps no state may ignore it entirely.
type Judger interface {
	Judge(batch []Observation) ([]Verdict, error)
	Commit(keep bool)
}

// Oracle is an objective running inside a plugin. It holds no state across
// executions, so there is nothing to settle.
type Oracle interface {
	Judge(batch []Observation) ([]Verdict, error)
}

// Varier is a mutator running inside a plugin.
//
// It is asked for up to count variants of one input at a time. Returning fewer
// is fine and returning none is fine; what is not fine is deriving them from
// anything but the seed, because a campaign that cannot be replayed is not a
// finding anyone can act on (ASR-0008).
type Varier interface {
	Vary(input []byte, seed uint64, count, maxBytes int) ([][]byte, error)
}

// OracleFunc adapts a function to Oracle.
type OracleFunc func(batch []Observation) ([]Verdict, error)

// Judge implements Oracle.
func (f OracleFunc) Judge(batch []Observation) ([]Verdict, error) { return f(batch) }

// VaryFunc adapts a function to Varier.
type VaryFunc func(input []byte, seed uint64, count, maxBytes int) ([][]byte, error)

// Vary implements Varier.
func (f VaryFunc) Vary(input []byte, seed uint64, count, maxBytes int) ([][]byte, error) {
	return f(input, seed, count, maxBytes)
}

// Plugin is what a plugin program declares about itself.
type Plugin struct {
	// Name and Version identify the plugin in the handshake, and are what a
	// campaign's provenance records. They are the plugin's own names for
	// itself; the label it runs under comes from the campaign file.
	Name    string
	Version string

	Feedbacks  map[string]Judger
	Objectives map[string]Oracle
	Mutators   map[string]Varier

	// Start runs once, on the handshake, with the campaign seed and the
	// plugin's settings from the campaign file. Returning an error refuses the
	// campaign, which is the right answer to a setting a plugin cannot honour:
	// better than running and quietly ignoring it.
	Start func(seed uint64, config map[string]string) error
}

// Serve runs the plugin loop on standard input and output until the host says
// goodbye or closes the pipe.
//
// Standard error is left alone deliberately. A plugin author will print while
// debugging, and a protocol that shares a stream with those prints turns a
// debugging aid into a corrupted frame.
func Serve(p Plugin) error { return ServeOn(os.Stdin, os.Stdout, p) }

// ServeOn is Serve over an explicit pair of streams, which is what a test uses.
func ServeOn(r io.Reader, w io.Writer, p Plugin) error {
	bw := bufio.NewWriterSize(w, 64<<10)
	conn := NewConn(r, bw)

	for {
		var req Request
		if err := conn.Receive(&req); err != nil {
			if errors.Is(err, io.EOF) {
				// The host is gone. That is how a campaign ends when it ends
				// abruptly, and it is not this plugin's failure to report.
				return nil
			}
			return err
		}
		if req.Op == OpBye {
			return conn.Send(&Response{ID: req.ID})
		}
		resp := p.handle(&req)
		resp.ID = req.ID
		if err := conn.Send(resp); err != nil {
			return err
		}
	}
}

// handle answers one request.
//
// Every failure becomes a Response.Error rather than an exit. A plugin that
// dies on a bad request takes the campaign with it; one that answers "I cannot
// do that" leaves the host holding a message it can put in front of a person.
func (p *Plugin) handle(req *Request) *Response {
	switch req.Op {
	case OpHello:
		if req.Protocol != ProtocolVersion {
			return failure(fmt.Sprintf("this plugin speaks protocol %d, the host speaks %d",
				ProtocolVersion, req.Protocol))
		}
		if p.Start != nil {
			if err := p.Start(req.Seed, req.Config); err != nil {
				return failure(err.Error())
			}
		}
		return &Response{
			Protocol: ProtocolVersion,
			Name:     p.Name,
			Version:  p.Version,
			Provides: Provides{
				Feedbacks:  keysOf(p.Feedbacks),
				Objectives: keysOf(p.Objectives),
				Mutators:   keysOf(p.Mutators),
			},
		}

	case OpJudge:
		f, ok := p.Feedbacks[req.Name]
		if !ok {
			return failure("no feedback named " + req.Name)
		}
		p.settle(req)
		vs, err := f.Judge(req.Batch)
		return verdicts(vs, err, len(req.Batch))

	case OpCommit:
		p.settle(req)
		return &Response{}

	case OpFinding:
		o, ok := p.Objectives[req.Name]
		if !ok {
			return failure("no objective named " + req.Name)
		}
		vs, err := o.Judge(req.Batch)
		return verdicts(vs, err, len(req.Batch))

	case OpMutate:
		m, ok := p.Mutators[req.Name]
		if !ok {
			return failure("no mutator named " + req.Name)
		}
		out, err := m.Vary(req.Input, req.Seed, req.Count, req.MaxBytes)
		if err != nil {
			return failure(err.Error())
		}
		if len(out) > req.Count && req.Count > 0 {
			out = out[:req.Count]
		}
		return &Response{Outputs: out}

	default:
		return failure("unknown operation " + string(req.Op))
	}
}

// settle applies a commit that rode along on this request.
func (p *Plugin) settle(req *Request) {
	if req.Keep == nil {
		return
	}
	if f, ok := p.Feedbacks[req.Name]; ok {
		f.Commit(*req.Keep)
	}
}

// verdicts checks the shape of an answer before it goes on the wire.
//
// The host enforces this too, and deliberately: a plugin that returns the wrong
// number of verdicts has a bug, and catching it on the side that has the source
// code is the difference between a clear message and a mysterious one.
func verdicts(vs []Verdict, err error, want int) *Response {
	if err != nil {
		return failure(err.Error())
	}
	if len(vs) != want {
		return failure(fmt.Sprintf("returned %d verdicts for %d observations", len(vs), want))
	}
	return &Response{Verdicts: vs}
}

func failure(msg string) *Response { return &Response{Error: msg} }

// keysOf lists a map's keys in a stable order, so a handshake is the same on
// every run and a campaign's provenance does not change between them.
func keysOf[V any](m map[string]V) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
