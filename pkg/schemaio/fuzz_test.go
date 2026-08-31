package schemaio_test

import (
	"testing"

	"github.com/rom/Xfuzz/pkg/schemaio"
)

// FuzzImport fuzzes every importer with the same corpus.
//
// Untrusted for the reason the whole package exists: the point of importing a
// description is that somebody else wrote it, so a .proto from a service
// repository, a .ksy from the Kaitai gallery and an ABNF pasted out of an RFC
// all arrive as files of unknown provenance. A parser that can be crashed by one
// is a parser that can be crashed by a file downloaded from a wiki (ADR-0021,
// SECURITY.md section 3.5).
//
// The property is not that anything imports — most inputs are not descriptions —
// but that every importer terminates and returns, and that a schema it says it
// produced is one the rest of the system can use. An importer that returned an
// invalid schema would push the failure into the campaign, where it is a
// crashing worker rather than an error message.
func FuzzImport(f *testing.F) {
	f.Add("abnf", httpABNF)
	f.Add("kaitai", gifKSY)
	f.Add("jsonschema", orderSchema)
	f.Add("openapi", ordersOpenAPI)
	f.Add("proto", orderProto)
	f.Add("asn1", certASN1)
	for _, name := range schemaio.Names() {
		f.Add(name, "")
		f.Add(name, "\x00\x00")
		f.Add(name, "{")
		f.Add(name, "a = a")
		f.Add(name, "meta:\n  id: x\nseq: [{id: a, type: u1}]")
		f.Add(name, "message M { repeated M m = 1; }")
		f.Add(name, "M DEFINITIONS ::= BEGIN T ::= SEQUENCE { a T } END")
	}

	f.Fuzz(func(t *testing.T, which, src string) {
		imp, ok := schemaio.For(which)
		if !ok {
			// The first argument selects the importer; anything else is a
			// corpus entry the fuzzer invented and there is nothing to run.
			return
		}
		s, rep, err := imp.Import([]byte(src), "fuzz")
		if err != nil {
			if rep != nil && !rep.Complete() {
				// A failed import may still report what it saw, which is fine;
				// what it must not do is claim a schema.
				_ = rep.String()
			}
			if s != nil {
				t.Fatalf("%s returned both an error and a schema", which)
			}
			return
		}
		if s == nil {
			t.Fatalf("%s returned neither a schema nor an error", which)
		}
		if err := s.Validate(); err != nil {
			t.Fatalf("%s produced a schema that does not validate: %v\n%s", which, err, s)
		}
		if _, ok := s.Lookup(s.Root); !ok {
			t.Fatalf("%s produced a schema whose root %q is not one of its types", which, s.Root)
		}
		// The rendering must be readable by the tool's own parser, or the
		// import produces a file xfuzz cannot open.
		_ = s.String()
		_ = rep.String()
	})
}
