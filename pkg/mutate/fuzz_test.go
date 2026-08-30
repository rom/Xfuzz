package mutate

import (
	"bytes"
	"strings"
	"testing"
)

// FuzzParseDictionary fuzzes the AFL-format dictionary parser.
//
// Untrusted because dictionaries are the most-shared artefact in fuzzing:
// every format that has been fuzzed has a dictionary somewhere, and people
// copy them between projects without reading them.
func FuzzParseDictionary(f *testing.F) {
	f.Add([]byte("kw_a=\"IHDR\"\nkw_b=\"IEND\"\n"))
	f.Add([]byte("\"\\x89PNG\"\n"))
	f.Add([]byte("# a comment\nname@1=\"value\"\n"))
	f.Add([]byte("a=\"\\xzz\"\n"))
	f.Add([]byte("a=\"unterminated\n"))
	f.Add([]byte("=\"\"\n"))
	f.Add([]byte(""))

	f.Fuzz(func(t *testing.T, src []byte) {
		d, err := ParseDictionary(bytes.NewReader(src))
		if err != nil {
			if strings.TrimSpace(err.Error()) == "" {
				t.Fatal("the parser refused the dictionary with an empty message")
			}
			return
		}
		if d == nil {
			t.Fatal("the parser returned neither a dictionary nor an error")
		}
		// Every token must be usable by the operator that inserts it. An empty
		// token would be inserted on every mutation and change nothing, which
		// is a silent waste of a campaign's budget rather than a crash.
		for i := 0; i < d.Len(); i++ {
			name, tok := d.At(i)
			if len(tok) == 0 {
				t.Fatalf("token %q is empty; it would be inserted forever and change nothing", name)
			}
		}
	})
}
