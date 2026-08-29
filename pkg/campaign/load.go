package campaign

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// FormatVersion is the campaign file format this build writes.
const FormatVersion = 1

// MaxIncludeDepth bounds include nesting.
//
// Includes exist so a house safety scope is written once. They are not a
// programming language, and a chain twenty deep is a configuration nobody can
// reason about — which for a file whose job is to say exactly what ran defeats
// the purpose.
const MaxIncludeDepth = 8

// ErrNotFound is returned when a campaign file does not exist.
var ErrNotFound = errors.New("campaign: file not found")

// Load reads, resolves, and validates a campaign file.
//
// Resolution is the whole job: includes merged in order, the selected profiles
// overlaid, defaults filled in, and every path made absolute relative to the
// file that mentioned it. What comes back is what will actually run, which is
// what `xfuzz explain` renders and what the daemon records — a resolved config
// that differs from the file is a file that hides behaviour (ADR-0016).
func Load(path string, profiles ...string) (*Resolved, error) {
	f, set, err := loadFile(path, 0, map[string]bool{})
	if err != nil {
		return nil, err
	}
	return resolve(f, set, path, profiles...)
}

// Parse resolves a campaign from bytes rather than a file, for an API client
// that has the document in hand. Includes are refused: a document that arrived
// over the network must not be able to name a path on the daemon's filesystem.
func Parse(b []byte, name string, profiles ...string) (*Resolved, error) {
	f, set, err := decode(b, name)
	if err != nil {
		return nil, err
	}
	if len(f.Include) > 0 {
		return nil, fmt.Errorf("campaign: %s uses include, which is only available when loading from a file", name)
	}
	return resolve(f, set, name, profiles...)
}

// Resolve applies profiles and defaults to an already-parsed file.
//
// It cannot know which keys the file contained, so every field that was left at
// its zero value is treated as unset. Prefer Load or Parse, which do know.
func Resolve(f *File, path string, profiles ...string) (*Resolved, error) {
	return resolve(f, KeySet{}, path, profiles...)
}

func resolve(f *File, set KeySet, path string, profiles ...string) (*Resolved, error) {
	applied := make([]string, 0, len(profiles))
	for _, p := range profiles {
		overlay, ok := f.Profiles[p]
		if !ok {
			return nil, fmt.Errorf("campaign: %s has no profile %q (it has %s)",
				path, p, profileNames(f))
		}
		merge(f, overlay)
		set.Union(profileKeys(set, p))
		applied = append(applied, p)
	}
	// Profiles are consumed by resolution. Leaving them in the resolved config
	// would invite the question of whether they still apply, and they do not.
	f.Profiles = nil

	if dir := filepath.Dir(path); dir != "" && dir != "." {
		absolutise(f, dir)
	}
	defaults(f, set)

	r := &Resolved{File: *f, Path: path, Profiles: applied, Set: set}
	if err := r.Validate(); err != nil {
		return r, err
	}
	return r, nil
}

// Resolved is a campaign file with everything filled in.
type Resolved struct {
	File

	// Path is where the file came from, for error messages that name it.
	Path string

	// Profiles are the overlays that were applied, in order.
	Profiles []string

	// Set records which keys the file actually contained, so that "unset" and
	// "set to zero" are distinguishable — by validation, which must reject an
	// explicit zero it would otherwise never see, and by Explain, which reports
	// which values the tool chose.
	Set KeySet
}

// WasSet reports whether a dotted key was present in the campaign file.
func (r *Resolved) WasSet(path string) bool { return r.Set.Has(path) }

func loadFile(path string, depth int, seen map[string]bool) (*File, KeySet, error) {
	if depth > MaxIncludeDepth {
		return nil, nil, fmt.Errorf("campaign: include nesting exceeds %d at %s", MaxIncludeDepth, path)
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, nil, err
	}
	if seen[abs] {
		return nil, nil, fmt.Errorf("campaign: include cycle at %s", path)
	}
	seen[abs] = true
	defer delete(seen, abs)

	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil, fmt.Errorf("%w: %s", ErrNotFound, path)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("campaign: reading %s: %w", path, err)
	}

	f, set, err := decode(b, path)
	if err != nil {
		return nil, nil, err
	}

	// Included files are merged in order and *under* the including file, so a
	// file always wins against what it includes. The alternative — an include
	// silently overriding the file that asked for it — is the behaviour nobody
	// expects and everybody debugs once.
	if len(f.Include) == 0 {
		return f, set, nil
	}
	base := &File{}
	merged := KeySet{}
	dir := filepath.Dir(path)
	for _, inc := range f.Include {
		incPath := inc
		if !filepath.IsAbs(incPath) {
			incPath = filepath.Join(dir, incPath)
		}
		sub, subSet, err := loadFile(incPath, depth+1, seen)
		if err != nil {
			return nil, nil, fmt.Errorf("campaign: %s includes %s: %w", path, inc, err)
		}
		merged.Union(subSet)
		// The included file's own paths are relative to *it*, so they are
		// resolved before the merge. Otherwise a shared fragment could only be
		// included from a sibling directory.
		absolutise(sub, filepath.Dir(incPath))
		merge(base, sub)
	}
	merge(base, f)
	merged.Union(set)
	base.Include = f.Include
	return base, merged, nil
}

func decode(b []byte, name string) (*File, KeySet, error) {
	var node yaml.Node
	if err := yaml.Unmarshal(b, &node); err != nil {
		return nil, nil, fmt.Errorf("campaign: %s: %w", name, err)
	}
	set := KeySet{}
	keysOf(&node, "", set)

	var f File
	dec := yaml.NewDecoder(strings.NewReader(string(b)))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil {
		// A typo in a key is the commonest campaign-file mistake and the one
		// that silently does nothing, so unknown fields are an error rather
		// than a warning.
		return nil, nil, fmt.Errorf("campaign: %s: %w", name, err)
	}
	if f.Version != 0 && f.Version != FormatVersion {
		return nil, nil, fmt.Errorf("campaign: %s declares format version %d; this build understands %d",
			name, f.Version, FormatVersion)
	}
	return &f, set, nil
}

func profileNames(f *File) string {
	if len(f.Profiles) == 0 {
		return "none"
	}
	names := make([]string, 0, len(f.Profiles))
	for n := range f.Profiles {
		names = append(names, n)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

// defaults fills in every unset field, so that the resolved configuration is
// complete and `explain` shows the value in force rather than a blank.
//
// "Unset" means the file did not contain the key, not that the value is zero.
// Filling in a zero the file wrote would silently override it — a campaign
// asking for `triage.trials: 0` would run five — and would also hide the value
// from validation, which could then never tell the operator it was rejected.
func defaults(f *File, set KeySet) {
	// unset reports whether a key may be defaulted. A field whose zero value is
	// never meaningful does not need to consult it; the ones that do are the
	// counts, sizes and budgets where zero is a thing somebody might write.
	unset := func(path string) bool { return !set.Has(path) }

	if f.Version == 0 {
		f.Version = FormatVersion
	}
	if f.Target == nil {
		f.Target = &Target{}
	}
	if f.Target.Executor == "" {
		f.Target.Executor = ExecutorAuto
	}
	if f.Target.Input == "" {
		f.Target.Input = InputStdin
	}
	if f.Target.Timeout == 0 && unset("target.timeout") {
		f.Target.Timeout = Duration(defaultTimeout)
	}

	if f.Seeds == nil {
		f.Seeds = &Seeds{}
	}
	if f.Seeds.Format == "" {
		f.Seeds.Format = "auto"
	}
	if f.Seeds.MaxFileSize == 0 && unset("seeds.max_file_size") {
		f.Seeds.MaxFileSize = defaultMaxSeedBytes
	}

	if f.Format == nil {
		f.Format = &Format{}
	}
	if f.Format.Codec == "" {
		f.Format.Codec = "raw"
	}
	if f.Format.MaxInputBytes == 0 && unset("format.max_input_bytes") {
		f.Format.MaxInputBytes = defaultMaxInputBytes
	}

	if f.Mutation == nil {
		f.Mutation = &Mutation{}
	}
	if f.Mutation.Stack == 0 && unset("mutation.stack") {
		f.Mutation.Stack = defaultStack
	}
	if f.Mutation.TrimBudget == 0 && unset("mutation.trim_budget") {
		f.Mutation.TrimBudget = defaultTrimBudget
	}

	if f.Feedback == nil {
		f.Feedback = &Feedback{}
	}
	if f.Feedback.Coverage == "" {
		f.Feedback.Coverage = "sancov"
	}
	if f.Feedback.MapSize == 0 && unset("feedback.map_size") {
		f.Feedback.MapSize = defaultMapSize
	}
	if len(f.Feedback.Objectives) == 0 {
		f.Feedback.Objectives = []string{"crash", "hang", "oom", "sanitizer"}
	}

	if f.Workers == nil {
		f.Workers = &Workers{}
	}
	if f.Workers.Count == 0 && unset("workers.count") {
		f.Workers.Count = runtime.NumCPU()
	}
	if f.Workers.SyncInterval == 0 && unset("workers.sync_interval") {
		f.Workers.SyncInterval = Duration(defaultSyncInterval)
	}

	if f.Safety == nil {
		f.Safety = &Safety{}
	}
	if f.Safety.Isolation == "" {
		f.Safety.Isolation = "minimal"
	}
	if f.Safety.MemoryLimit == 0 && unset("safety.memory_limit") {
		f.Safety.MemoryLimit = defaultMemoryLimit
	}
	if f.Safety.ProcessLimit == 0 && unset("safety.process_limit") {
		f.Safety.ProcessLimit = defaultProcessLimit
	}
	if f.Safety.Scope == nil {
		f.Safety.Scope = &Scope{}
	}
	if f.Safety.Scope.Loopback == nil {
		t := true
		f.Safety.Scope.Loopback = &t
	}

	if f.Storage == nil {
		f.Storage = &Storage{}
	}
	if f.Storage.CheckpointInterval == 0 && unset("storage.checkpoint_interval") {
		f.Storage.CheckpointInterval = Duration(defaultCheckpointInterval)
	}

	if f.Triage == nil {
		f.Triage = &Triage{}
	}
	if f.Triage.Enabled == nil {
		t := true
		f.Triage.Enabled = &t
	}
	if f.Triage.Minimize == nil {
		t := true
		f.Triage.Minimize = &t
	}
	if f.Triage.Trials == 0 && unset("triage.trials") {
		f.Triage.Trials = defaultTrials
	}
	if f.Triage.MinimizeBudget == 0 && unset("triage.minimize_budget") {
		f.Triage.MinimizeBudget = defaultMinimizeBudget
	}
	if f.Triage.Strategy == "" {
		f.Triage.Strategy = "chain"
	}

	if f.Stop == nil {
		f.Stop = &Stop{}
	}
}

// absolutise rewrites every path in the file relative to dir.
//
// A campaign file names a target, a grammar, and seed directories. Resolving
// them against the file rather than the process's working directory is what
// makes the file portable: `xfuzz run ../campaigns/png.yaml` has to mean the
// same thing as running it from beside the file.
func absolutise(f *File, dir string) {
	abs := func(p string) string {
		if p == "" || filepath.IsAbs(p) {
			return p
		}
		return filepath.Join(dir, p)
	}
	if f.Target != nil {
		f.Target.Path = abs(f.Target.Path)
		f.Target.Dir = abs(f.Target.Dir)
	}
	if f.Format != nil {
		f.Format.Grammar = abs(f.Format.Grammar)
		f.Format.Dictionary = abs(f.Format.Dictionary)
	}
	if f.Seeds != nil {
		for i, d := range f.Seeds.Dirs {
			f.Seeds.Dirs[i] = abs(d)
		}
	}
	if f.Storage != nil {
		f.Storage.Dir = abs(f.Storage.Dir)
	}
	if f.Safety != nil {
		for i, p := range f.Safety.Writable {
			f.Safety.Writable[i] = abs(p)
		}
	}
}

// Defaults returns a fully defaulted empty campaign, which is what the JSON
// Schema's defaults and `xfuzz explain` on an empty file both describe.
func Defaults() *File {
	f := &File{}
	defaults(f, KeySet{})
	return f
}
