package schemaio_test

import (
	"strings"
	"testing"

	"github.com/rom/Xfuzz/pkg/schema"
	"github.com/rom/Xfuzz/pkg/schemaio"
)

// The ABNF an RFC actually contains, folded across lines, with comments, core
// rules it never defines, and one piece of prose where the authors gave up.
const httpABNF = `
; a request, roughly as RFC 9112 states it
request-line   = method SP request-target SP HTTP-version CRLF
method         = %s"GET" / %s"POST" / %s"HEAD" / token
request-target = "/" *( pchar / "/" )
pchar          = unreserved / pct-encoded
unreserved     = ALPHA / DIGIT / "-" / "." / "_" / "~"
pct-encoded    = "%" HEXDIG HEXDIG
HTTP-version   = %s"HTTP/" DIGIT "." DIGIT
token          = 1*tchar
tchar          = "!" / "#" / "$" / ALPHA / DIGIT
field-line     = field-name ":" OWS field-value OWS
field-name     = token
field-value    = *( field-content )
field-content  = VCHAR / SP / HTAB
OWS            = *( SP / HTAB )
message-body   = <the payload, whose length is given by Content-Length>
`

func TestABNFImportsAnRFCGrammar(t *testing.T) {
	s, rep := mustImport(t, schemaio.ABNF{}, httpABNF, "http.abnf")

	if s.Root != "request_line" {
		t.Errorf("the root is %q; the first rule in the file is the conventional one", s.Root)
	}
	// The core rules the grammar uses and never defines have to come from
	// somewhere, or half the references resolve to nothing.
	for _, n := range []string{"ALPHA", "DIGIT", "SP", "CRLF", "HEXDIG", "HTAB", "VCHAR"} {
		if _, ok := s.Lookup(n); !ok {
			t.Errorf("the core rule %s was not supplied", n)
		}
	}
	// And a core rule nothing referenced is not left in: a grammar that reports
	// sixteen types when the format has nine is a grammar nobody can size.
	if _, ok := s.Lookup("LWSP"); ok {
		t.Error("an unreferenced core rule survived")
	}
	t.Logf("%s", rep)
	generates(t, s)
}

func TestABNFReportsWhatItCannotTranslate(t *testing.T) {
	_, rep := mustImport(t, schemaio.ABNF{}, httpABNF, "http.abnf")
	if rep.Complete() {
		t.Fatal("a grammar containing a prose-val reported a complete translation")
	}
	joined := strings.Join(rep.Summarise(), "\n")
	if !strings.Contains(joined, "prose-val") {
		t.Errorf("the prose-val was not reported:\n%s", joined)
	}
	// And the note has to say *why*, because somebody is deciding whether to
	// write the missing part by hand.
	if !strings.Contains(joined, "English") {
		t.Errorf("the note does not explain the limitation:\n%s", joined)
	}
}

// TestABNFRepetitionForms is the part where a plausible misreading changes the
// grammar completely: "3" is exactly three, "*" is any number including none,
// and "1*" is at least one.
func TestABNFRepetitionForms(t *testing.T) {
	for _, tc := range []struct {
		rule     string
		min, max int
	}{
		{"r = 3a", 3, 3},
		{"r = *a", 0, 0},
		{"r = 1*a", 1, schemaio.UnboundedRepeatMax},
		{"r = 2*5a", 2, 5},
		{"r = *5a", 0, 5},
	} {
		src := tc.rule + "\na = \"x\"\n"
		s, _, err := schemaio.ABNF{}.Import([]byte(src), "t.abnf")
		if err != nil {
			t.Fatalf("%s: %v", tc.rule, err)
		}
		root, _ := s.Lookup(s.Root)
		if len(root.Fields) != 1 {
			t.Fatalf("%s produced %d fields", tc.rule, len(root.Fields))
		}
		got := root.Fields[0].Type
		if got.Kind != schema.KindRepeat {
			t.Errorf("%s produced %s, want a repeat", tc.rule, got.Kind)
			continue
		}
		if got.Min != tc.min || got.Max != tc.max {
			t.Errorf("%s produced repeat<%d..%d>, want <%d..%d>",
				tc.rule, got.Min, got.Max, tc.min, tc.max)
		}
	}
	// An option is a repeat of nought or one, and is written as one.
	s, _, err := schemaio.ABNF{}.Import([]byte("r = [a]\na = \"x\"\n"), "t.abnf")
	if err != nil {
		t.Fatal(err)
	}
	root, _ := s.Lookup(s.Root)
	if root.Fields[0].Type.Kind != schema.KindOpt {
		t.Errorf("[a] produced %s, want an opt", root.Fields[0].Type.Kind)
	}
}

// TestABNFNumericValues covers the three bases and the two shapes, because
// %x0D.0A is a two-byte literal and %x0D-0A is a range, and one character
// between them is the whole difference.
func TestABNFNumericValues(t *testing.T) {
	s, _, err := schemaio.ABNF{}.Import([]byte(
		"r = crlf sp digit\ncrlf = %x0D.0A\nsp = %d32\ndigit = %x30-39\n"), "t.abnf")
	if err != nil {
		t.Fatal(err)
	}
	crlf, _ := s.Lookup("crlf")
	if got := string(crlf.Fields[0].Type.Literal); got != "\r\n" {
		t.Errorf("%%x0D.0A became %q", got)
	}
	sp, _ := s.Lookup("sp")
	if got := string(sp.Fields[0].Type.Literal); got != " " {
		t.Errorf("%%d32 became %q", got)
	}
	digit, _ := s.Lookup("digit")
	alts := digit.Fields[0].Type
	if alts.Kind != schema.KindChoice || len(alts.Fields) != 10 {
		t.Errorf("%%x30-39 became %s with %d alternatives, want a choice of 10",
			alts.Kind, len(alts.Fields))
	}
}

// TestABNFWideRangeIsReportedRatherThanEnumerated. A value range is a constraint
// the grammar language cannot state, and the only exact translation is a choice
// over every byte in it — which is right for the digits and absurd for OCTET.
func TestABNFWideRangeIsReportedRatherThanEnumerated(t *testing.T) {
	s, rep, err := schemaio.ABNF{}.Import([]byte("r = any\nany = %x00-FF\n"), "t.abnf")
	if err != nil {
		t.Fatal(err)
	}
	any, _ := s.Lookup("any")
	if any.Fields[0].Type.Kind != schema.KindBytes {
		t.Errorf("a 256-value range became %s", any.Fields[0].Type.Kind)
	}
	if rep.Complete() {
		t.Error("dropping a value constraint was not reported")
	}
}

// TestABNFFoldsContinuationLines. An RFC folds a long rule across lines by
// indenting the continuation; a reader without this splits half the rules in
// every document it meets.
func TestABNFFoldsContinuationLines(t *testing.T) {
	src := "r = a\n      b\n      c\na = \"1\"\nb = \"2\"\nc = \"3\"\n"
	s, _, err := schemaio.ABNF{}.Import([]byte(src), "t.abnf")
	if err != nil {
		t.Fatal(err)
	}
	root, _ := s.Lookup(s.Root)
	if len(root.Fields) != 3 {
		t.Errorf("a rule folded across three lines produced %d fields:\n%s",
			len(root.Fields), s)
	}
}

func TestABNFIncrementalAlternation(t *testing.T) {
	src := "r = a\na = \"1\"\na =/ \"2\"\na =/ \"3\"\n"
	s, _, err := schemaio.ABNF{}.Import([]byte(src), "t.abnf")
	if err != nil {
		t.Fatal(err)
	}
	a, _ := s.Lookup("a")
	alts := a.Fields[0].Type
	if alts.Kind != schema.KindChoice || len(alts.Fields) != 3 {
		t.Errorf("=/ produced %s with %d alternatives, want a choice of 3",
			alts.Kind, len(alts.Fields))
	}
}

func TestABNFComments(t *testing.T) {
	src := "; a comment\nr = a  ; and a trailing one\na = \";\" ; a semicolon in a string\n"
	s, _, err := schemaio.ABNF{}.Import([]byte(src), "t.abnf")
	if err != nil {
		t.Fatal(err)
	}
	a, _ := s.Lookup("a")
	if got := string(a.Fields[0].Type.Literal); got != ";" {
		t.Errorf("a semicolon inside a string was taken for a comment: %q", got)
	}
}

// TestABNFGroupIsNotAnAlternative: "a / (b / c)" is three alternatives, and a
// nested choice picks the group half the time and then b or c a quarter each,
// which is not what the grammar says.
func TestABNFGroupIsNotAnAlternative(t *testing.T) {
	s, _, err := schemaio.ABNF{}.Import([]byte(
		"r = a / (b / c)\na = \"1\"\nb = \"2\"\nc = \"3\"\n"), "t.abnf")
	if err != nil {
		t.Fatal(err)
	}
	root, _ := s.Lookup(s.Root)
	alts := root.Fields[0].Type
	if alts.Kind != schema.KindChoice || len(alts.Fields) != 3 {
		t.Errorf("a / (b / c) produced %s with %d alternatives, want 3",
			alts.Kind, len(alts.Fields))
	}
}

func TestABNFRefusesAFileWithNoRules(t *testing.T) {
	if _, _, err := (schemaio.ABNF{}).Import([]byte("; only a comment\n"), "t.abnf"); err == nil {
		t.Error("a file with no rules imported successfully")
	}
}

func TestABNFIsDeterministic(t *testing.T) {
	first, _, err := schemaio.ABNF{}.Import([]byte(httpABNF), "http.abnf")
	if err != nil {
		t.Fatal(err)
	}
	want := first.String()
	for i := 0; i < 8; i++ {
		got, _, err := schemaio.ABNF{}.Import([]byte(httpABNF), "http.abnf")
		if err != nil {
			t.Fatal(err)
		}
		if got.String() != want {
			t.Fatalf("import %d differed:\n%s\n---\n%s", i+1, want, got)
		}
	}
}
