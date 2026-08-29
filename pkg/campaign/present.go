package campaign

import (
	"strings"

	"gopkg.in/yaml.v3"
)

// KeySet records which keys a campaign file actually contained.
//
// It exists because zero is a real value. Defaulting fills in an unset
// `triage.trials` with 5, and without knowing whether the key was present, a
// file that says `trials: 0` is indistinguishable from one that says nothing —
// so the tool silently runs five trials against a file that asked for none, and
// validation cannot tell the user their value was rejected because it never
// sees it.
//
// Comparing against the default value instead is not the same thing and is
// wrong in a way that matters: a file that deliberately sets `map_size: 65536`
// would be reported by `explain` as having taken the default, which is exactly
// the distinction `explain` exists to draw.
type KeySet map[string]bool

// Has reports whether a dotted path was present in the file.
func (k KeySet) Has(path string) bool { return k[path] }

// Add records a path.
func (k KeySet) Add(path string) { k[path] = true }

// Union merges another set in, for includes and profile overlays: a key set by
// any contributing document was set by the campaign.
func (k KeySet) Union(other KeySet) {
	for p := range other {
		k[p] = true
	}
}

// keysOf walks a YAML document and records every mapping key as a dotted path.
//
// Sequence elements are not indexed. A campaign file's lists are lists of
// values or of small blocks, and "workers.strategies was set" is the useful
// fact; "workers.strategies[2].schedule was set" would only matter if profiles
// merged into list elements, which they deliberately do not — slices replace.
func keysOf(node *yaml.Node, prefix string, out KeySet) {
	switch node.Kind {
	case yaml.DocumentNode:
		for _, c := range node.Content {
			keysOf(c, prefix, out)
		}
	case yaml.MappingNode:
		for i := 0; i+1 < len(node.Content); i += 2 {
			key := node.Content[i].Value
			path := key
			if prefix != "" {
				path = prefix + "." + key
			}
			out.Add(path)
			keysOf(node.Content[i+1], path, out)
		}
	case yaml.SequenceNode:
		for _, c := range node.Content {
			keysOf(c, prefix, out)
		}
	}
}

// profileKeys extracts the key set contributed by one profile, rebased so its
// paths read as the file's own — a profile that sets `workers.count` has set
// `workers.count`, not `profiles.ci.workers.count`.
func profileKeys(all KeySet, name string) KeySet {
	prefix := "profiles." + name + "."
	out := KeySet{}
	for p := range all {
		if rest, ok := strings.CutPrefix(p, prefix); ok {
			out.Add(rest)
		}
	}
	return out
}
