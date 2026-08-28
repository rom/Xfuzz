package ir

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Step is one hop in a reference path: a named field or a positional index.
type Step struct {
	Name    string
	Index   int
	ByIndex bool
}

func (s Step) String() string {
	if s.ByIndex {
		return "[" + strconv.Itoa(s.Index) + "]"
	}
	return s.Name
}

// Ref names another node relative to the node that holds the reference.
//
// Resolution is deliberately relative rather than absolute, because the common
// case is a field referring to its sibling — a chunk's length field refers to
// that chunk's data, and the same schema is reused for every chunk in a Repeat.
// An absolute path from the root is available for the rarer cases.
//
// Nodes carry no parent pointers: keeping them out makes Node smaller, cloning
// cheaper, and copy-on-write path copying simpler. References are therefore
// resolved against an explicit ancestor chain supplied by the walk that needs
// them.
type Ref struct {
	Self     bool   // the referring node itself
	Absolute bool   // resolve from the tree root
	Up       int    // levels above the referring node's parent
	Steps    []Step // path down from the resolution base
}

// Sibling refers to a named sibling of the referring node.
func Sibling(name string) Ref { return Ref{Steps: []Step{{Name: name}}} }

// SiblingAt refers to a positional sibling of the referring node.
func SiblingAt(i int) Ref { return Ref{Steps: []Step{{Index: i, ByIndex: true}}} }

// Parent refers to the referring node's parent.
func Parent() Ref { return Ref{} }

// Self refers to the referring node itself.
func Self() Ref { return Ref{Self: true} }

// Absolute refers to a path from the tree root.
func Absolute(steps ...Step) Ref { return Ref{Absolute: true, Steps: steps} }

// Named builds a name step.
func Named(name string) Step { return Step{Name: name} }

// At builds an index step.
func At(i int) Step { return Step{Index: i, ByIndex: true} }

// ErrNoSuchNode is returned when a reference does not resolve.
var ErrNoSuchNode = errors.New("ir: reference does not resolve")

// Resolve locates the node a reference names.
//
// ancestors is the chain from the tree root to the referring node's parent,
// inclusive, and self is the referring node. Both may be nil for an absolute
// reference from root.
func (r *Ref) Resolve(root *Node, ancestors []*Node, self *Node) (*Node, error) {
	if r == nil {
		return nil, fmt.Errorf("%w: nil reference", ErrNoSuchNode)
	}
	if r.Self {
		if self == nil {
			return nil, fmt.Errorf("%w: self reference with no referring node", ErrNoSuchNode)
		}
		return self, nil
	}

	var base *Node
	switch {
	case r.Absolute:
		base = root
	default:
		i := len(ancestors) - 1 - r.Up
		if i < 0 {
			return nil, fmt.Errorf("%w: %s rises %d level(s) above the root", ErrNoSuchNode, r, r.Up)
		}
		base = ancestors[i]
	}
	if base == nil {
		return nil, fmt.Errorf("%w: %s has no resolution base", ErrNoSuchNode, r)
	}

	cur := base
	for _, s := range r.Steps {
		if s.ByIndex {
			if s.Index < 0 || s.Index >= len(cur.Children) {
				return nil, fmt.Errorf("%w: %s: index %d out of range (%d children)",
					ErrNoSuchNode, r, s.Index, len(cur.Children))
			}
			cur = cur.Children[s.Index]
			continue
		}
		next := cur.Child(s.Name)
		if next == nil {
			return nil, fmt.Errorf("%w: %s: no child named %q under %s", ErrNoSuchNode, r, s.Name, cur)
		}
		cur = next
	}
	return cur, nil
}

func (r Ref) String() string {
	var b strings.Builder
	switch {
	case r.Self:
		return "."
	case r.Absolute:
		b.WriteString("/")
	default:
		b.WriteString("^")
		for i := 0; i < r.Up; i++ {
			b.WriteString("^")
		}
	}
	for i, s := range r.Steps {
		if i > 0 && !s.ByIndex {
			b.WriteString(".")
		}
		b.WriteString(s.String())
	}
	return b.String()
}

func (r *Ref) equal(o *Ref) bool {
	if r == nil || o == nil {
		return r == o
	}
	if r.Self != o.Self || r.Absolute != o.Absolute || r.Up != o.Up || len(r.Steps) != len(o.Steps) {
		return false
	}
	for i := range r.Steps {
		if r.Steps[i] != o.Steps[i] {
			return false
		}
	}
	return true
}

// IsZero reports whether the reference was never set.
func (r Ref) IsZero() bool {
	return !r.Self && !r.Absolute && r.Up == 0 && len(r.Steps) == 0
}

// ParseRef reads the textual form produced by Ref.String.
//
//	.            the referring node itself
//	^data        a sibling named data
//	^^hdr.len    a field of the grandparent
//	/chunks[0]   an absolute path from the root
func ParseRef(s string) (Ref, error) {
	if s == "" {
		return Ref{}, fmt.Errorf("ir: empty reference")
	}
	if s == "." {
		return Ref{Self: true}, nil
	}
	var r Ref
	switch {
	case s[0] == '/':
		r.Absolute = true
		s = s[1:]
	case s[0] == '^':
		i := 0
		for i < len(s) && s[i] == '^' {
			i++
		}
		r.Up = i - 1
		s = s[i:]
	default:
		return Ref{}, fmt.Errorf("ir: reference %q must start with '.', '^' or '/'", s)
	}

	for s != "" {
		switch {
		case s[0] == '[':
			end := strings.IndexByte(s, ']')
			if end < 0 {
				return Ref{}, fmt.Errorf("ir: reference %q has an unclosed index", s)
			}
			i, err := strconv.Atoi(s[1:end])
			if err != nil {
				return Ref{}, fmt.Errorf("ir: reference index %q: %w", s[1:end], err)
			}
			r.Steps = append(r.Steps, At(i))
			s = s[end+1:]
		case s[0] == '.':
			s = s[1:]
		default:
			end := strings.IndexAny(s, ".[")
			if end < 0 {
				end = len(s)
			}
			if end == 0 {
				return Ref{}, fmt.Errorf("ir: reference has an empty name step")
			}
			r.Steps = append(r.Steps, Named(s[:end]))
			s = s[end:]
		}
	}
	return r, nil
}
