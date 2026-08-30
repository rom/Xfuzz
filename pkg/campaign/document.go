package campaign

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Document is a campaign file kept as it was written.
//
// The console edits campaigns by editing their file (ADR-0011), so what comes
// back from an edit has to be the same file with one thing changed — not a
// re-rendering of what the daemon understood it to mean. Two properties make
// that true and both are load-bearing: comments survive, because a campaign
// file is where a team writes down why a timeout is what it is; and the diff
// is small, because a config that reflows entirely on every save is one nobody
// can review and nobody will keep in git.
//
// Resolution is deliberately not part of this. A Document knows what the file
// says, never what it means — no defaults, no profiles, no validation. Those
// belong to Resolved, which is built by reading a Document rather than by
// replacing it.
type Document struct {
	node   yaml.Node
	blanks map[string]bool
	indent int
}

// DefaultIndent is the indentation a campaign file is written with. It is two
// because that is what every example and the starter file use, and a console
// that reindented a file on save would make its own diff.
const DefaultIndent = 2

// ParseDocument reads a campaign file without resolving it.
func ParseDocument(b []byte) (*Document, error) {
	d := &Document{blanks: blankLineOwners(b), indent: DefaultIndent}
	if err := yaml.Unmarshal(b, &d.node); err != nil {
		return nil, fmt.Errorf("campaign: %w", err)
	}
	if d.node.Kind == 0 {
		// An empty file is a document with nothing in it rather than an error:
		// the console has to be able to start from one.
		d.node = yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{
			{Kind: yaml.MappingNode, Tag: "!!map"},
		}}
	}
	if root := d.root(); root == nil {
		return nil, fmt.Errorf("campaign: the document is not a mapping")
	}
	return d, nil
}

// root returns the top-level mapping, or nil when the document is not one.
func (d *Document) root() *yaml.Node {
	if len(d.node.Content) == 0 {
		return nil
	}
	r := d.node.Content[0]
	if r.Kind != yaml.MappingNode {
		return nil
	}
	return r
}

// Get returns the scalar at a dotted path, and whether the path exists.
func (d *Document) Get(path string) (string, bool) {
	n := d.lookup(strings.Split(path, "."), false)
	if n == nil || n.Kind != yaml.ScalarNode {
		return "", false
	}
	return n.Value, true
}

// Set writes a scalar at a dotted path, creating the mappings it needs.
//
// Only the value node is touched where the key already exists, so the comment
// somebody wrote above it, the one they wrote beside it, and the position of
// the key among its siblings all stay where they were.
func (d *Document) Set(path string, value any) error {
	parts := strings.Split(path, ".")
	if path == "" || len(parts) == 0 {
		return fmt.Errorf("campaign: no field named %q", path)
	}
	n := d.lookup(parts, true)
	if n == nil {
		return fmt.Errorf("campaign: %s is not a mapping, so %s cannot be set",
			strings.Join(parts[:len(parts)-1], "."), path)
	}
	return setScalar(n, value)
}

// Unset removes a key and whatever was written about it.
func (d *Document) Unset(path string) bool {
	parts := strings.Split(path, ".")
	parent := d.root()
	for _, p := range parts[:len(parts)-1] {
		v := childValue(parent, p)
		if v == nil || v.Kind != yaml.MappingNode {
			return false
		}
		parent = v
	}
	last := parts[len(parts)-1]
	for i := 0; i+1 < len(parent.Content); i += 2 {
		if parent.Content[i].Value == last {
			parent.Content = append(parent.Content[:i], parent.Content[i+2:]...)
			return true
		}
	}
	return false
}

// Bytes renders the document back to YAML.
func (d *Document) Bytes() ([]byte, error) {
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(d.indent)
	if err := enc.Encode(&d.node); err != nil {
		return nil, fmt.Errorf("campaign: rendering the document: %w", err)
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return restoreBlankLines(buf.Bytes(), d.blanks), nil
}

// Resolved parses the document the ordinary way, so that what an edit produces
// is checked by exactly the code a campaign file is checked by.
func (d *Document) Resolved(name string, profiles ...string) (*Resolved, error) {
	b, err := d.Bytes()
	if err != nil {
		return nil, err
	}
	return Parse(b, name, profiles...)
}

// lookup walks a path, optionally creating the mappings along the way, and
// returns the value node at the end.
func (d *Document) lookup(parts []string, create bool) *yaml.Node {
	parent := d.root()
	for _, p := range parts[:len(parts)-1] {
		v := childValue(parent, p)
		if v == nil {
			if !create {
				return nil
			}
			v = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
			parent.Content = append(parent.Content,
				&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: p}, v)
		}
		if v.Kind != yaml.MappingNode {
			return nil
		}
		parent = v
	}

	last := parts[len(parts)-1]
	if v := childValue(parent, last); v != nil {
		return v
	}
	if !create {
		return nil
	}
	v := &yaml.Node{Kind: yaml.ScalarNode}
	parent.Content = append(parent.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: last}, v)
	return v
}

func childValue(m *yaml.Node, key string) *yaml.Node {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}

// setScalar writes a Go value into a node, keeping YAML's own idea of type.
//
// Typed rather than stringly, because "8" and 8 are different YAML and a
// campaign file that grew quotes around every number on its first save would
// be a file the console had visibly damaged.
func setScalar(n *yaml.Node, value any) error {
	n.Content = nil
	n.Style = 0
	switch v := value.(type) {
	case nil:
		n.Kind, n.Tag, n.Value = yaml.ScalarNode, "!!null", "null"
	case bool:
		n.Kind, n.Tag, n.Value = yaml.ScalarNode, "!!bool", strconv.FormatBool(v)
	case int:
		n.Kind, n.Tag, n.Value = yaml.ScalarNode, "!!int", strconv.Itoa(v)
	case int64:
		n.Kind, n.Tag, n.Value = yaml.ScalarNode, "!!int", strconv.FormatInt(v, 10)
	case float64:
		// Whole floats come back from JSON as floats and are almost always
		// counts. Writing 4 rather than 4.0 keeps the file readable and keeps
		// a JSON client from changing a field's YAML type by touching it.
		if v == float64(int64(v)) {
			n.Kind, n.Tag, n.Value = yaml.ScalarNode, "!!int", strconv.FormatInt(int64(v), 10)
			return nil
		}
		n.Kind, n.Tag, n.Value = yaml.ScalarNode, "!!float", strconv.FormatFloat(v, 'g', -1, 64)
	case string:
		n.Kind, n.Tag, n.Value = yaml.ScalarNode, "!!str", v
	default:
		// Lists and mappings: let the encoder decide their shape.
		var out yaml.Node
		if err := out.Encode(value); err != nil {
			return fmt.Errorf("campaign: %T cannot be written to a campaign file: %w", value, err)
		}
		head, line, foot := n.HeadComment, n.LineComment, n.FootComment
		*n = out
		n.HeadComment, n.LineComment, n.FootComment = head, line, foot
	}
	return nil
}

// blankLineOwners records which keys had a blank line before them.
//
// yaml.v3 keeps comments and drops blank lines, and a campaign file's blank
// lines are its paragraphs: they are what separates the target from the seeds
// from the stopping conditions. A save that ran them all together would reflow
// the whole file, and a diff nobody can read is a diff nobody will approve.
//
// Keys are recorded by their dotted path, so restoring is by identity rather
// than by line number and survives the edit that changed the file's length.
func blankLineOwners(src []byte) map[string]bool {
	out := map[string]bool{}
	lines := strings.Split(string(src), "\n")

	var stack []pathPart
	blank := false      // the previous non-comment line was blank
	commentRun := false // we are inside a comment block that a blank line preceded
	pending := false

	for _, raw := range lines {
		trimmed := strings.TrimSpace(raw)
		switch {
		case trimmed == "":
			blank, commentRun, pending = true, false, true
			continue
		case strings.HasPrefix(trimmed, "#"):
			// A comment block belongs to the key under it, so a blank line
			// before the block is a blank line before that key.
			if blank && !commentRun {
				pending = true
			}
			commentRun = true
			blank = false
			continue
		}

		key, ok := mappingKey(trimmed)
		if ok {
			indent := len(raw) - len(strings.TrimLeft(raw, " "))
			stack = pushPath(stack, indent, key)
			if pending {
				out[joinPath(stack)] = true
			}
		}
		blank, commentRun, pending = false, false, false
	}
	return out
}

type pathPart struct {
	indent int
	key    string
}

func pushPath(stack []pathPart, indent int, key string) []pathPart {
	for len(stack) > 0 && stack[len(stack)-1].indent >= indent {
		stack = stack[:len(stack)-1]
	}
	return append(stack, pathPart{indent: indent, key: key})
}

func joinPath(stack []pathPart) string {
	parts := make([]string, 0, len(stack))
	for _, p := range stack {
		parts = append(parts, p.key)
	}
	return strings.Join(parts, ".")
}

// mappingKey reports the key a line opens, if it opens one.
func mappingKey(trimmed string) (string, bool) {
	if strings.HasPrefix(trimmed, "-") {
		// A sequence item. Its own keys are not addressed by path here, and
		// treating them as though they were would put blank lines inside
		// lists on the wrong entry.
		return "", false
	}
	i := strings.Index(trimmed, ":")
	if i <= 0 {
		return "", false
	}
	key := strings.TrimSpace(trimmed[:i])
	if key == "" || strings.ContainsAny(key, " \"'#") {
		return "", false
	}
	return key, true
}

// restoreBlankLines puts back the paragraph breaks the encoder dropped.
func restoreBlankLines(out []byte, blanks map[string]bool) []byte {
	if len(blanks) == 0 {
		return out
	}
	lines := strings.Split(strings.TrimRight(string(out), "\n"), "\n")

	var (
		result     []string
		stack      []pathPart
		commentRun = -1 // index in result where the current comment block began
	)
	for _, raw := range lines {
		trimmed := strings.TrimSpace(raw)
		if strings.HasPrefix(trimmed, "#") {
			if commentRun < 0 {
				commentRun = len(result)
			}
			result = append(result, raw)
			continue
		}

		if key, ok := mappingKey(trimmed); ok {
			indent := len(raw) - len(strings.TrimLeft(raw, " "))
			stack = pushPath(stack, indent, key)
			if blanks[joinPath(stack)] {
				at := len(result)
				if commentRun >= 0 {
					at = commentRun
				}
				if at > 0 && strings.TrimSpace(result[at-1]) != "" {
					result = append(result[:at], append([]string{""}, result[at:]...)...)
				}
			}
		}
		commentRun = -1
		result = append(result, raw)
	}
	return []byte(strings.Join(result, "\n") + "\n")
}
