package script

import (
	"fmt"

	"go.starlark.net/starlark"

	"github.com/rom/Xfuzz/pkg/feedback"
	"github.com/rom/Xfuzz/pkg/plugin"
)

// observation is one execution, seen from Starlark.
//
// The same fields a plugin sees (ADR-0010: the tiers must not drift), presented
// as attributes rather than as a dict so that a misspelled field is an error
// naming the ones that exist, instead of None quietly flowing through a
// comparison and making the oracle always say no.
type observation struct{ ob plugin.Observation }

var observationFields = []string{
	"backend", "duration_ms", "edges", "exit", "exit_code",
	"input", "signal", "states", "stderr", "stdout",
}

func (o observation) String() string {
	return fmt.Sprintf("observation(exit=%q, edges=%d)", o.ob.Exit, o.ob.Edges)
}
func (o observation) Type() string          { return "observation" }
func (o observation) Freeze()               {}
func (o observation) Truth() starlark.Bool  { return starlark.True }
func (o observation) Hash() (uint32, error) { return 0, fmt.Errorf("observation is unhashable") }

func (o observation) AttrNames() []string { return observationFields }

func (o observation) Attr(name string) (starlark.Value, error) {
	switch name {
	case "exit":
		return starlark.String(o.ob.Exit), nil
	case "exit_code":
		return starlark.MakeInt(o.ob.ExitCode), nil
	case "signal":
		return starlark.MakeInt(o.ob.Signal), nil
	case "edges":
		return starlark.MakeInt(o.ob.Edges), nil
	case "backend":
		return starlark.String(o.ob.Backend), nil
	case "duration_ms":
		return starlark.MakeInt64(o.ob.DurationNS / 1e6), nil
	case "stdout":
		// Text, not bytes. An oracle is almost always looking for a phrase a
		// target printed, and `"assertion failed" in x.stderr` is the line
		// someone writes first. Starlark's bytes type would make that a type
		// error and send them looking for an encode call.
		return starlark.String(o.ob.Stdout), nil
	case "stderr":
		return starlark.String(o.ob.Stderr), nil
	case "input":
		// Bytes, unlike the output, because an input is arbitrary and a script
		// that indexes it wants byte values rather than runes.
		return starlark.Bytes(o.ob.Input), nil
	case "states":
		return stringList(o.ob.States), nil
	}
	return nil, nil // starlark reports the miss, naming AttrNames
}

func stringList(xs []string) *starlark.List {
	vs := make([]starlark.Value, len(xs))
	for i, x := range xs {
		vs[i] = starlark.String(x)
	}
	l := starlark.NewList(vs)
	l.Freeze()
	return l
}

// makeFinding is the `finding()` builtin: the way a script says "this is a bug".
//
// A constructor rather than a bare dict, so that a typo in a key is caught when
// it is written rather than becoming a finding with no summary. Everything but
// the kind is optional, and the kind defaults to oracle, because that is what a
// script-reported finding is.
func makeFinding(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var (
		kind    = starlark.String("oracle")
		summary starlark.String
		detail  starlark.String
		frames  *starlark.List
	)
	if err := starlark.UnpackArgs(b.Name(), args, kwargs,
		"summary?", &summary, "kind?", &kind, "detail?", &detail, "frames?", &frames); err != nil {
		return nil, err
	}

	d := starlark.NewDict(4)
	d.SetKey(starlark.String("kind"), kind)
	d.SetKey(starlark.String("summary"), summary)
	d.SetKey(starlark.String("detail"), detail)
	if frames != nil {
		d.SetKey(starlark.String("frames"), frames)
	}
	return d, nil
}

// --- reading answers back ---------------------------------------------------

// asFinding interprets what an oracle returned.
//
// Three shapes are accepted because three shapes are natural to write: None or
// False for "no", a bare string for the common case where the summary is the
// whole answer, and the finding() dict when there is more to say. Anything else
// is an error rather than a guess — an oracle that returns a number has a bug,
// and treating 0 as "no" would hide it.
func (s *Script) asFinding(v starlark.Value) (bool, feedback.Finding, error) {
	switch t := v.(type) {
	case starlark.NoneType:
		return false, feedback.Finding{}, nil
	case starlark.Bool:
		if !bool(t) {
			return false, feedback.Finding{}, nil
		}
		return true, feedback.Finding{Kind: "oracle", Summary: "the oracle returned True"}, nil
	case starlark.String:
		if t == "" {
			return false, feedback.Finding{}, nil
		}
		return true, feedback.Finding{Kind: "oracle", Summary: s.text(string(t))}, nil
	case *starlark.Dict:
		f, err := s.findingFromDict(t)
		return err == nil, f, err
	}
	return false, feedback.Finding{}, fmt.Errorf(
		"script %s: an oracle returned %s; return None, a summary string, or finding(...)",
		s.name, v.Type())
}

func (s *Script) findingFromDict(d *starlark.Dict) (feedback.Finding, error) {
	f := feedback.Finding{Kind: "oracle"}
	str := func(key string) (string, error) {
		v, found, err := d.Get(starlark.String(key))
		if err != nil || !found {
			return "", err
		}
		sv, ok := starlark.AsString(v)
		if !ok {
			return "", fmt.Errorf("script %s: finding %s is %s, want a string", s.name, key, v.Type())
		}
		return s.text(sv), nil
	}

	var err error
	if f.Kind, err = str("kind"); err != nil {
		return f, err
	}
	if f.Kind == "" {
		f.Kind = "oracle"
	}
	if f.Summary, err = str("summary"); err != nil {
		return f, err
	}
	if f.Detail, err = str("detail"); err != nil {
		return f, err
	}
	if v, found, _ := d.Get(starlark.String("frames")); found {
		iter, ok := v.(starlark.Iterable)
		if !ok {
			return f, fmt.Errorf("script %s: finding frames is %s, want a list", s.name, v.Type())
		}
		it := iter.Iterate()
		defer it.Done()
		var x starlark.Value
		for it.Next(&x) && len(f.Frames) < maxFrames {
			sv, _ := starlark.AsString(x)
			f.Frames = append(f.Frames, s.text(sv))
		}
	}
	return f, nil
}

// maxFrames bounds a stack a script invents. Bucketing reads the top few
// frames; a thousand of them is not more information, it is a bigger row.
const maxFrames = 64

// text bounds a string a script produced, so a finding cannot become the
// campaign's memory profile.
func (s *Script) text(v string) string { return truncate(v, s.opts.MaxOutputBytes) }

// asByteList interprets what a mutator returned: a list of bytes or strings.
func (s *Script) asByteList(v starlark.Value, limit int) ([][]byte, error) {
	if _, ok := v.(starlark.NoneType); ok {
		return nil, nil
	}
	iter, ok := v.(starlark.Iterable)
	if !ok {
		return nil, fmt.Errorf("script %s: a mutator returned %s; return a list of bytes", s.name, v.Type())
	}

	it := iter.Iterate()
	defer it.Done()

	var out [][]byte
	var x starlark.Value
	for it.Next(&x) {
		if limit > 0 && len(out) >= limit {
			break
		}
		b, ok := asBytes(x)
		if !ok {
			return nil, fmt.Errorf("script %s: a mutator returned a %s among its variants; "+
				"each must be bytes or a string", s.name, x.Type())
		}
		if len(b) > s.opts.MaxOutputBytes {
			// Dropped rather than truncated: a variant cut in half is not what
			// the script proposed, and filing it under the script's name would
			// attribute something it did not write.
			continue
		}
		out = append(out, b)
	}
	return out, nil
}

// asBytes reads a Starlark value as bytes.
//
// Both types, because both are natural to write and neither is wrong. A script
// that builds a variant with bytes([...]) has bytes; one that slices a literal
// has a string; and a mutator that rejected either would be rejecting a correct
// program on a technicality.
func asBytes(v starlark.Value) ([]byte, bool) {
	switch t := v.(type) {
	case starlark.Bytes:
		return []byte(t), true
	case starlark.String:
		return []byte(t), true
	}
	return nil, false
}
