package mutate

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rom/Xfuzz/pkg/rng"
)

func TestParseDictionary(t *testing.T) {
	const src = `
# a comment, and a blank line follows

keyword_a="hello"
keyword_b@3="level three"
"unnamed token"
esc="tab\there"
hex="\x00\xff\x41"
quote="say \"hi\""
back="a\\b"
newline="line\nbreak"
nul="\0end"
`
	d, err := ParseDictionary(strings.NewReader(src))
	if err != nil {
		t.Fatal(err)
	}
	if d.Len() != 9 {
		t.Fatalf("parsed %d tokens, want 9", d.Len())
	}

	want := map[string]string{
		"keyword_a": "hello",
		"keyword_b": "level three",
		"":          "unnamed token",
		"esc":       "tab\there",
		"hex":       "\x00\xff\x41",
		"quote":     `say "hi"`,
		"back":      `a\b`,
		"newline":   "line\nbreak",
		"nul":       "\x00end",
	}
	for i := 0; i < d.Len(); i++ {
		name, tok := d.At(i)
		w, ok := want[name]
		if !ok {
			t.Errorf("unexpected token name %q", name)
			continue
		}
		if string(tok) != w {
			t.Errorf("%s = %q, want %q", name, tok, w)
		}
	}
}

// TestParseDictionaryRejectsMalformedLines matters more than it looks: a
// dictionary that silently drops half its tokens produces a campaign that looks
// healthy and explores far less than it should.
func TestParseDictionaryRejectsMalformedLines(t *testing.T) {
	cases := map[string]string{
		"no equals":       `keyword "value"`,
		"unquoted value":  `keyword=value`,
		"unterminated":    `keyword="value`,
		"trailing escape": `keyword="value\"`,
		"bad hex":         `keyword="\xZZ"`,
		"short hex":       `keyword="\x4"`,
		"unknown escape":  `keyword="\q"`,
		"bad level":       `keyword@x="value"`,
	}
	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseDictionary(strings.NewReader(src)); err == nil {
				t.Errorf("expected an error for %q", src)
			}
		})
	}
}

func TestLoadDictionary(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.dict")
	if err := os.WriteFile(path, []byte("a=\"one\"\nb=\"two\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	d, err := LoadDictionary(path)
	if err != nil {
		t.Fatal(err)
	}
	if d.Len() != 2 {
		t.Errorf("loaded %d tokens, want 2", d.Len())
	}
	if _, err := LoadDictionary(filepath.Join(dir, "missing.dict")); err == nil {
		t.Error("loading a missing file must fail")
	}
	bad := filepath.Join(dir, "bad.dict")
	os.WriteFile(bad, []byte("garbage\n"), 0o644)
	if _, err := LoadDictionary(bad); err == nil || !strings.Contains(err.Error(), "bad.dict") {
		t.Errorf("a parse error should name the file, got %v", err)
	}
}

func TestDictionaryTokenSelection(t *testing.T) {
	var nilDict *Dictionary
	if nilDict.Len() != 0 {
		t.Error("a nil dictionary must report zero tokens")
	}
	if nilDict.Token(rng.New(1)) != nil {
		t.Error("a nil dictionary must yield no token")
	}

	d := NewDictionary()
	d.Add("empty", nil, 0)
	if d.Len() != 0 {
		t.Error("an empty token must be ignored")
	}

	d.Add("a", []byte("aaa"), 0)
	d.Add("b", []byte("bbb"), 0)
	r := rng.New(7)
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		seen[string(d.Token(r))] = true
	}
	if len(seen) != 2 {
		t.Errorf("selection covered %d of 2 tokens", len(seen))
	}
}

func TestDictionaryRoundTripsAFLFormat(t *testing.T) {
	// The published AFL dictionaries are the point of supporting this format at
	// all (ASR-0013), so a realistic sample must parse.
	const aflStyle = `#
# PNG dictionary
#
header_png="\x89PNG\x0d\x0a\x1a\x0a"
section_IDAT="IDAT"
section_IEND="IEND"
section_IHDR="IHDR"
section_PLTE="PLTE"
section_bKGD="bKGD"
`
	d, err := ParseDictionary(strings.NewReader(aflStyle))
	if err != nil {
		t.Fatal(err)
	}
	if d.Len() != 6 {
		t.Fatalf("parsed %d tokens, want 6", d.Len())
	}
	_, sig := d.At(0)
	if !bytes.Equal(sig, []byte{0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a}) {
		t.Errorf("PNG signature parsed as %x", sig)
	}
}
