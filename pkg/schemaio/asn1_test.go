package schemaio_test

import (
	"strings"
	"testing"

	"github.com/rom/Xfuzz/pkg/schema"
	"github.com/rom/Xfuzz/pkg/schemaio"
)

// An ASN.1 module of the shape a standard carries: a SEQUENCE with optional
// members, a SEQUENCE OF, a CHOICE, context tags, a SIZE constraint this
// language can use and a value constraint it cannot.
const certASN1 = `
Demo DEFINITIONS ::= BEGIN

Certificate ::= SEQUENCE {
    version        [0] INTEGER,
    serialNumber   INTEGER (1..1000),
    issuer         Name,
    subject        Name,
    validity       Validity,
    extensions     Extensions OPTIONAL
}

Name ::= SEQUENCE {
    common      UTF8String (SIZE(1..16)),
    country     PrintableString OPTIONAL
}

Validity ::= SEQUENCE {
    notBefore   UTCTime,
    notAfter    UTCTime
}

Extensions ::= SEQUENCE OF Extension

Extension ::= SEQUENCE {
    extnID      OBJECT IDENTIFIER,
    critical    BOOLEAN DEFAULT FALSE,
    extnValue   OCTET STRING
}

GeneralName ::= CHOICE {
    dNSName     IA5String,
    ipAddress   OCTET STRING,
    other       NULL
}

END
`

func TestASN1GeneratesWellFormedDER(t *testing.T) {
	s, rep := mustImport(t, schemaio.ASN1{}, certASN1, "cert.asn1")
	t.Logf("%s", rep)

	for i := 0; i < 16; i++ {
		out := generates(t, s)
		if i == 0 {
			t.Logf("generated %d bytes: %x", len(out), out)
		}
		// Read it the way a DER decoder does: tag, length, content, repeat. A
		// frame that does not walk is one every decoder rejects at the first
		// element.
		rest, err := walkDER(out)
		if err != nil {
			t.Fatalf("sample %d is not well-formed DER: %v\n%x", i, err, out)
		}
		if len(rest) != 0 {
			t.Fatalf("sample %d has %d bytes after the outermost element\n%x", i, len(rest), out)
		}
	}
}

// walkDER reads one tag-length-value and returns what follows it.
func walkDER(b []byte) ([]byte, error) {
	if len(b) < 2 {
		return nil, protoErr{"truncated element"}
	}
	tag := b[0]
	length := int(b[1])
	if length&0x80 != 0 {
		return nil, protoErr{"long-form length, which this grammar does not generate"}
	}
	b = b[2:]
	if len(b) < length {
		return nil, protoErr{"length " + itoa(length) + " past the end of the element"}
	}
	content, rest := b[:length], b[length:]
	if tag&0x20 != 0 {
		// Constructed: the content is a sequence of elements of its own.
		for len(content) > 0 {
			var err error
			content, err = walkDER(content)
			if err != nil {
				return nil, err
			}
		}
	}
	return rest, nil
}

func TestASN1TagsAreExact(t *testing.T) {
	s, _ := mustImport(t, schemaio.ASN1{}, certASN1, "cert.asn1")
	validity, ok := s.Lookup("Validity")
	if !ok {
		t.Fatal("Validity is missing")
	}
	if got := validity.Fields[0].Type; !got.Immutable || len(got.Literal) != 1 ||
		got.Literal[0] != 0x30 {
		t.Errorf("a SEQUENCE's tag is %v, want an immutable 0x30", got)
	}

	// A context tag replaces the universal one and keeps its constructed bit:
	// [0] on an INTEGER is primitive, and forcing it constructed produces a
	// message no decoder reads.
	cert, _ := s.Lookup("Certificate")
	body, ok := s.Lookup(refTargetOf(t, cert, "v"))
	if !ok {
		t.Fatalf("the sequence body of Certificate is missing:\n%s", cert)
	}
	version := body.Fields[0].Type
	if version.Kind != schema.KindStruct {
		// It has been extracted into a named type by the renderer.
		if version.Kind == schema.KindRef {
			version, _ = s.Lookup(version.Target)
		}
	}
	if got := version.Fields[0].Type.Literal; len(got) != 1 || got[0] != 0x80 {
		t.Errorf("[0] INTEGER got tag %x, want 80", got)
	}
}

// refTargetOf returns the type a named field of t refers to.
func refTargetOf(t *testing.T, owner *schema.Type, name string) string {
	t.Helper()
	for _, f := range owner.Fields {
		if f.Name == name {
			return f.Type.Target
		}
	}
	return ""
}

func TestASN1OptionalIsAnOpt(t *testing.T) {
	s, _ := mustImport(t, schemaio.ASN1{}, certASN1, "cert.asn1")
	name, _ := s.Lookup("Name")
	body, _ := s.Lookup(refTargetOf(t, name, "v"))
	if body == nil {
		t.Fatalf("the sequence body of Name is missing:\n%s", name)
	}
	var found bool
	for _, f := range body.Fields {
		if f.Name != "country" {
			continue
		}
		found = true
		if f.Type.Kind != schema.KindOpt {
			t.Errorf("an OPTIONAL member became %s", f.Type.Kind)
		}
	}
	if !found {
		t.Errorf("the optional member is missing:\n%s", body)
	}
}

// TestASN1SizeConstraintIsUsedAndValueConstraintIsReported is the line between
// the two languages: a SIZE is a bound this language has, and a value range is a
// predicate it does not.
func TestASN1SizeConstraintIsUsedAndValueConstraintIsReported(t *testing.T) {
	s, rep := mustImport(t, schemaio.ASN1{}, certASN1, "cert.asn1")
	text := s.String()
	if !strings.Contains(text, "bytes<1..16>") {
		t.Errorf("SIZE(1..16) was not used as a bound:\n%s", text)
	}
	joined := strings.Join(rep.Summarise(), "\n")
	if !strings.Contains(joined, "value constraint") {
		t.Errorf("INTEGER (1..1000) was not reported:\n%s", joined)
	}
}

func TestASN1ChoiceHasNoTagOfItsOwn(t *testing.T) {
	s, _ := mustImport(t, schemaio.ASN1{}, certASN1, "cert.asn1")
	gn, ok := s.Lookup("GeneralName")
	if !ok {
		t.Fatal("GeneralName is missing")
	}
	// What appears on the wire is whichever alternative was selected, tag and
	// all, so the CHOICE itself contributes nothing.
	alt := gn.Fields[0].Type
	if alt.Kind != schema.KindChoice || len(alt.Fields) != 3 {
		t.Fatalf("a CHOICE became %s with %d alternatives", alt.Kind, len(alt.Fields))
	}
}

func TestASN1SequenceOf(t *testing.T) {
	s, _ := mustImport(t, schemaio.ASN1{}, certASN1, "cert.asn1")
	ext, ok := s.Lookup("Extensions")
	if !ok {
		t.Fatal("Extensions is missing")
	}
	items, _ := s.Lookup(refTargetOf(t, ext, "v"))
	if items == nil || items.Fields[0].Type.Kind != schema.KindRepeat {
		t.Errorf("SEQUENCE OF did not become a repeat:\n%s", ext)
	}
}

func TestASN1Comments(t *testing.T) {
	src := "M DEFINITIONS ::= BEGIN\n-- a comment\nT ::= INTEGER -- trailing\nEND\n"
	s, _, err := schemaio.ASN1{}.Import([]byte(src), "m.asn1")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Lookup("T"); !ok {
		t.Errorf("a comment swallowed the assignment:\n%s", s)
	}
}

func TestASN1RefusesAModuleWithNoAssignments(t *testing.T) {
	if _, _, err := (schemaio.ASN1{}).Import(
		[]byte("M DEFINITIONS ::= BEGIN\nEND\n"), "m.asn1"); err == nil {
		t.Error("an empty module imported successfully")
	}
}

func TestASN1IsDeterministic(t *testing.T) {
	first, _, err := schemaio.ASN1{}.Import([]byte(certASN1), "c.asn1")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 8; i++ {
		got, _, err := schemaio.ASN1{}.Import([]byte(certASN1), "c.asn1")
		if err != nil {
			t.Fatal(err)
		}
		if got.String() != first.String() {
			t.Fatalf("import %d differed:\n%s\n---\n%s", i+1, first, got)
		}
	}
}
