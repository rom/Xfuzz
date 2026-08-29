package campaign

import (
	"fmt"
	"io"
	"reflect"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Explain renders the fully resolved configuration, including every default.
//
// This is what makes ADR-0016's promise checkable: the file never hides
// behaviour, because there is a command that prints what will actually run. A
// value that came from a default is marked, so the reader can tell what the file
// said from what the tool decided — which is the distinction that matters when a
// campaign behaves unexpectedly.
func (r *Resolved) Explain(w io.Writer) error {
	fmt.Fprintf(w, "# campaign %s\n", r.Name)
	fmt.Fprintf(w, "# resolved from %s\n", r.Path)
	if len(r.Profiles) > 0 {
		fmt.Fprintf(w, "# profiles applied: %s\n", strings.Join(r.Profiles, ", "))
	}
	if len(r.Include) > 0 {
		fmt.Fprintf(w, "# includes: %s\n", strings.Join(r.Include, ", "))
	}
	if r.Stop.IsZero() {
		fmt.Fprintf(w, "# no termination condition: this campaign runs until interrupted\n")
	}
	fmt.Fprintln(w, "#")
	fmt.Fprintf(w, "# %-38s value\n", "setting")

	rows := explainRows(reflect.ValueOf(r.File), r.Set, "")
	width := 0
	for _, row := range rows {
		if len(row.path) > width {
			width = len(row.path)
		}
	}
	if width > 46 {
		width = 46
	}
	for _, row := range rows {
		mark := ""
		if row.isDefault {
			mark = "  (default)"
		}
		fmt.Fprintf(w, "%-*s  %s%s\n", width, row.path, row.value, mark)
	}
	return nil
}

// ExplainString renders the resolved configuration to a string.
func (r *Resolved) ExplainString() string {
	var b strings.Builder
	_ = r.Explain(&b)
	return b.String()
}

// YAML renders the resolved configuration as a campaign file.
//
// Round-tripping matters: `xfuzz explain --yaml > pinned.yaml` must produce a
// file that runs the same campaign, which is how a run gets pinned to an
// artefact after the fact.
func (r *Resolved) YAML() ([]byte, error) {
	var b strings.Builder
	enc := yaml.NewEncoder(&b)
	enc.SetIndent(2)
	if err := enc.Encode(r.File); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return []byte(b.String()), nil
}

type explainRow struct {
	path      string
	value     string
	isDefault bool
}

// explainRows walks the resolved config and the default config together, so
// every row can say whether the value came from the file or from the tool.
func explainRows(v reflect.Value, set KeySet, prefix string) []explainRow {
	var out []explainRow

	switch v.Kind() {
	case reflect.Pointer:
		if v.IsNil() {
			return nil
		}
		return explainRows(v.Elem(), set, prefix)

	case reflect.Struct:
		t := v.Type()
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			name := yamlName(f)
			if name == "" || name == "-" {
				continue
			}
			out = append(out, explainRows(v.Field(i), set, join(prefix, name))...)
		}
		return out

	case reflect.Map:
		if v.Len() == 0 {
			return nil
		}
		keys := make([]string, 0, v.Len())
		for _, k := range v.MapKeys() {
			keys = append(keys, fmt.Sprint(k.Interface()))
		}
		sort.Strings(keys)
		for _, k := range keys {
			mv := v.MapIndex(reflect.ValueOf(k))
			out = append(out, explainRows(mv, set, join(prefix, k))...)
		}
		return out

	case reflect.Slice:
		if v.Len() == 0 {
			return nil
		}
		if isScalarSlice(v) {
			return []explainRow{{
				path:      prefix,
				value:     scalarSliceString(v),
				isDefault: !set.Has(prefix),
			}}
		}
		for i := 0; i < v.Len(); i++ {
			out = append(out, explainRows(v.Index(i), set,
				fmt.Sprintf("%s[%d]", prefix, i))...)
		}
		return out
	}

	// A scalar. Empty values are shown too: "the map size in force is 65536" is
	// the point of the command, and hiding zeros would hide exactly the settings
	// somebody is checking.
	//
	// Whether it is a default is answered from what the file contained, not by
	// comparing against the default value — a file that deliberately writes the
	// same number the tool would have chosen has still chosen it, and reporting
	// that as a default is precisely the confusion this command exists to end.
	return []explainRow{{
		path:      prefix,
		value:     scalarString(v),
		isDefault: !set.Has(prefix),
	}}
}

func join(prefix, name string) string {
	if prefix == "" {
		return name
	}
	return prefix + "." + name
}

func yamlName(f reflect.StructField) string {
	tag := f.Tag.Get("yaml")
	if tag == "" {
		return strings.ToLower(f.Name)
	}
	name, _, _ := strings.Cut(tag, ",")
	if name == "" {
		return strings.ToLower(f.Name)
	}
	return name
}

func isScalarSlice(v reflect.Value) bool {
	switch v.Type().Elem().Kind() {
	case reflect.String, reflect.Int, reflect.Int64, reflect.Bool, reflect.Float64:
		return true
	}
	return false
}

func scalarSliceString(v reflect.Value) string {
	parts := make([]string, v.Len())
	for i := range parts {
		parts[i] = scalarString(v.Index(i))
	}
	return "[" + strings.Join(parts, ", ") + "]"
}

func scalarString(v reflect.Value) string {
	if !v.IsValid() {
		return ""
	}
	if v.Kind() == reflect.Pointer {
		if v.IsNil() {
			return "unset"
		}
		return scalarString(v.Elem())
	}
	if d, ok := v.Interface().(Duration); ok {
		return d.String()
	}
	switch v.Kind() {
	case reflect.String:
		s := v.String()
		if s == "" {
			return `""`
		}
		if strings.ContainsAny(s, " \t") {
			return fmt.Sprintf("%q", s)
		}
		return s
	default:
		return fmt.Sprint(v.Interface())
	}
}
