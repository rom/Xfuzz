package mutate

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/rom/Xfuzz/pkg/ir"
	"github.com/rom/Xfuzz/pkg/rng"
)

// Dictionary holds the format tokens a target's parser compares against:
// magic values, keywords, tag names, delimiters.
//
// Random mutation essentially never produces a four-byte magic value, so a
// dictionary is the cheapest way to reach code behind one. Xfuzz reads the AFL
// dictionary format so the existing published dictionaries work unchanged
// (ASR-0013).
type Dictionary struct {
	tokens [][]byte
	names  []string
	levels []int
}

// NewDictionary returns an empty dictionary.
func NewDictionary() *Dictionary { return &Dictionary{} }

// Add records a token. Empty tokens are ignored.
func (d *Dictionary) Add(name string, token []byte, level int) {
	if len(token) == 0 {
		return
	}
	d.tokens = append(d.tokens, token)
	d.names = append(d.names, name)
	d.levels = append(d.levels, level)
}

// Len returns the token count.
func (d *Dictionary) Len() int {
	if d == nil {
		return 0
	}
	return len(d.tokens)
}

// Token returns a random token, or nil when the dictionary is empty. The
// returned slice must not be modified.
func (d *Dictionary) Token(r *rng.Rand) []byte {
	if d.Len() == 0 {
		return nil
	}
	return d.tokens[r.Intn(len(d.tokens))]
}

// At returns the name and token at an index.
func (d *Dictionary) At(i int) (string, []byte) { return d.names[i], d.tokens[i] }

// LoadDictionary reads an AFL-format dictionary file.
func LoadDictionary(path string) (*Dictionary, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("mutate: opening dictionary: %w", err)
	}
	defer f.Close()
	d, err := ParseDictionary(f)
	if err != nil {
		return nil, fmt.Errorf("mutate: %s: %w", path, err)
	}
	return d, nil
}

// ParseDictionary reads the AFL dictionary format:
//
//	# a comment
//	keyword="value"
//	keyword@3="only at level 3 and above"
//	"an unnamed token"
//
// Values use C-style escapes: \\, \", and \xNN.
//
// A malformed line is an error rather than a silent skip. A dictionary that
// quietly loses half its tokens produces a campaign that looks healthy and
// explores far less than it should.
func ParseDictionary(r io.Reader) (*Dictionary, error) {
	d := NewDictionary()
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)

	for line := 1; sc.Scan(); line++ {
		text := strings.TrimSpace(sc.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}

		name, rest, level := "", text, 0
		if !strings.HasPrefix(text, `"`) {
			eq := strings.Index(text, "=")
			if eq < 0 {
				return nil, fmt.Errorf("line %d: expected name=\"value\" or \"value\", got %q", line, text)
			}
			name, rest = strings.TrimSpace(text[:eq]), strings.TrimSpace(text[eq+1:])
			if at := strings.Index(name, "@"); at >= 0 {
				lv, err := strconv.Atoi(name[at+1:])
				if err != nil {
					return nil, fmt.Errorf("line %d: bad level in %q: %w", line, name, err)
				}
				name, level = name[:at], lv
			}
		}

		tok, err := unquoteToken(rest)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", line, err)
		}
		d.Add(name, tok, level)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return d, nil
}

func unquoteToken(s string) ([]byte, error) {
	if len(s) < 2 || s[0] != '"' || s[len(s)-1] != '"' {
		return nil, fmt.Errorf("token %q is not enclosed in double quotes", s)
	}
	body := s[1 : len(s)-1]
	out := make([]byte, 0, len(body))
	for i := 0; i < len(body); i++ {
		if body[i] != '\\' {
			out = append(out, body[i])
			continue
		}
		i++
		if i >= len(body) {
			return nil, fmt.Errorf("token ends with a trailing backslash")
		}
		switch body[i] {
		case '\\':
			out = append(out, '\\')
		case '"':
			out = append(out, '"')
		case 'n':
			out = append(out, '\n')
		case 'r':
			out = append(out, '\r')
		case 't':
			out = append(out, '\t')
		case '0':
			out = append(out, 0)
		case 'x':
			if i+2 >= len(body) {
				return nil, fmt.Errorf(`\x escape needs two hex digits`)
			}
			v, err := strconv.ParseUint(body[i+1:i+3], 16, 8)
			if err != nil {
				return nil, fmt.Errorf(`bad \x escape %q: %w`, body[i+1:i+3], err)
			}
			out = append(out, byte(v))
			i += 2
		default:
			return nil, fmt.Errorf("unknown escape \\%c", body[i])
		}
	}
	return out, nil
}

// DictOverwrite writes a dictionary token over part of a payload.
type DictOverwrite struct{}

func (DictOverwrite) Name() string { return "dict-overwrite" }
func (DictOverwrite) Kind() Kind   { return KindDictionary }
func (DictOverwrite) CanApply(c *Ctx, n *ir.Node) bool {
	return c.Dict.Len() > 0 && isPayload(n)
}

func (DictOverwrite) Mutate(c *Ctx, n *ir.Node) bool {
	tok := c.Dict.Token(c.Rand)
	if len(tok) == 0 || len(tok) > len(n.Raw) {
		return false
	}
	at := c.Rand.Intn(len(n.Raw) - len(tok) + 1)
	copy(n.Raw[at:], tok)
	return true
}

// DictInsert splices a dictionary token into a payload without displacing
// anything, which is what reaches keyword handling in text and tagged formats.
type DictInsert struct{}

func (DictInsert) Name() string { return "dict-insert" }
func (DictInsert) Kind() Kind   { return KindDictionary }
func (DictInsert) CanApply(c *Ctx, n *ir.Node) bool {
	return c.Dict.Len() > 0 && isWritable(n) && c.canGrow(n) > 0
}

func (DictInsert) Mutate(c *Ctx, n *ir.Node) bool {
	tok := c.Dict.Token(c.Rand)
	if len(tok) == 0 || len(tok) > c.canGrow(n) {
		return false
	}
	at := c.Rand.Intn(len(n.Raw) + 1)
	n.Raw = insertRun(c, n.Raw, at, len(tok), 0)
	copy(n.Raw[at:], tok)
	return true
}
