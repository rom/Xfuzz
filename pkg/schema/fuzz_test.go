package schema

import (
	"strings"
	"testing"
)

// FuzzParse fuzzes the .xfg grammar parser.
//
// Untrusted because grammars are meant to be shared: the point of a format
// description is that someone else wrote it. A parser that can be crashed by a
// grammar is a parser that can be crashed by a file downloaded from a wiki
// (ADR-0021, SECURITY.md section 3.5).
//
// The property is not "it parses" — most inputs are not grammars — but that it
// terminates and returns, either a schema or an error. A panic here is a bug in
// Xfuzz, and so is a parse that succeeds and leaves a schema the rest of the
// engine cannot use.
func FuzzParse(f *testing.F) {
	f.Add([]byte("format m { tag: magic \"MSG\"  body: bytes<1..16> }"))
	f.Add([]byte("format m {\n  n: u16le\n  body: bytes<0..n>\n}"))
	f.Add([]byte("format m { c: choice { a: u8  b: u16be } }"))
	f.Add([]byte("format m { xs: repeat<1..4> { x: u8 } }"))
	f.Add([]byte("format m { len: u32le = len(body)  body: bytes<0..64> }"))
	f.Add([]byte(""))
	f.Add([]byte("format"))
	f.Add([]byte("format m {"))
	f.Add([]byte("format m { a: bytes<9999999999999999999..1> }"))

	f.Fuzz(func(t *testing.T, src []byte) {
		s, err := Parse(src, "fuzz.xfg")
		if err != nil {
			// An error must say where. A grammar author with "syntax error"
			// and no line number has been given a puzzle rather than a
			// diagnosis, and an empty message is worse than no check.
			if strings.TrimSpace(err.Error()) == "" {
				t.Fatal("the parser refused the input with an empty message")
			}
			return
		}
		if s == nil {
			t.Fatal("the parser returned neither a schema nor an error")
		}
		// A schema that parsed must be usable. Validate is what the engine
		// calls before it builds anything; a parse that succeeds and leaves a
		// schema that cannot be validated has moved the failure somewhere with
		// no source line to point at.
		if err := s.Validate(); err != nil {
			t.Fatalf("a schema parsed but does not validate: %v", err)
		}
		if _, ok := s.Lookup(s.Root); !ok {
			t.Fatalf("a schema parsed with root %q, which it does not declare", s.Root)
		}
	})
}
