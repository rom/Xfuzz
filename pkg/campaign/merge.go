package campaign

import (
	"reflect"
	"time"
)

// Delivery tiers and input modes, named so that a typo is caught by validation
// rather than by a campaign that silently ran the wrong way.
const (
	ExecutorAuto       = "auto"
	ExecutorForkServer = "forkserver"
	ExecutorPool       = "pool"
	ExecutorSubprocess = "subprocess"
	ExecutorInProc     = "inproc"
	ExecutorEmulated   = "emulated"

	InputStdin = "stdin"
	InputFile  = "file"
	InputArg   = "arg"
)

// Defaults. They are named constants rather than literals in the defaulting
// code because `xfuzz explain` reports them and the JSON Schema publishes them,
// and a default that appears in three places will eventually differ in one.
const (
	defaultTimeout            = 5 * time.Second
	defaultMaxSeedBytes       = 16 << 20
	defaultMaxInputBytes      = 1 << 20
	defaultStack              = 4
	defaultTrimBudget         = 48
	defaultMapSize            = 1 << 16
	defaultSyncInterval       = 5 * time.Second
	defaultMemoryLimit        = 2 << 30
	defaultProcessLimit       = 64
	defaultCheckpointInterval = 30 * time.Second
	defaultTrials             = 5
	defaultMinimizeBudget     = 4000

	// Session defaults. The quiet period is the one that matters: idle framing
	// waits it out once per message, so it sets the ceiling on a stateful
	// campaign's throughput more than anything else in this file.
	defaultQuietPeriod    = 5 * time.Millisecond
	defaultConnectTimeout = 2 * time.Second
	defaultReadTimeout    = 250 * time.Millisecond
	defaultSessionTimeout = 10 * time.Second
	defaultReadLimit      = 1 << 20

	// A session that grows without bound explores nothing: the sequence
	// operators insert and duplicate, and a campaign left to itself converges
	// on sessions of thousands of messages that each take a second.
	defaultMaxMessages = 64

	// API defaults. The per-request bound is the one that matters, and it is
	// deliberately much shorter than a client library's: a campaign sends
	// malformed requests constantly, and every one that leaves the service
	// waiting for a body costs this whole bound — then costs it again for each
	// verification and each minimisation step. Measured against a local service,
	// five seconds here turned a finding into a ten-minute stall; one second
	// turns the same campaign into two. A service that has not answered in a
	// second, during a fuzzing run, has stopped answering, and the latency
	// oracle is what reports a service that is merely slow.
	defaultAPIPerRequest = time.Second
	defaultAPITimeout    = 30 * time.Second

	// Driver defaults. Settle is the tier's throughput: the driver waits for
	// the interface to go quiet rather than for a fixed interval, and this is
	// how long quiet has to last.
	defaultDriverCols         = 80
	defaultDriverRows         = 24
	defaultDriverSettle       = 50 * time.Millisecond
	defaultDriverStartTimeout = 5 * time.Second
	defaultDriverTimeout      = 30 * time.Second
	defaultDriverMaxEvents    = 256
	defaultDriverMaxOutput    = 8 << 20

	// Triage on the slow tiers. What makes these different is not taste: at a
	// few executions a second, the default budget is an hour of shrinking one
	// reproducer while the campaign finds nothing else.
	defaultSlowMinimizeBudget   = 64
	defaultDriverMinimizeBudget = 16
	defaultSlowTrials           = 3

	defaultExplore  = 0.7
	defaultTailBias = 0.8
)

// merge overlays src onto dst, field by field.
//
// The rule is uniform and deliberately dull: a field set in the overlay wins, a
// field left unset in the overlay leaves the base alone. Slices and maps replace
// rather than append, because appending makes it impossible to *remove*
// something a base file set — a profile that wants three mutators instead of ten
// has no way to say so if lists concatenate.
//
// Nested structs recurse, so a profile that sets only `safety.isolation` does
// not silently erase the rest of the safety block. That is the one place where
// "replace" would be wrong, and it is the reason this is a walk rather than a
// struct assignment.
func merge(dst, src *File) {
	if src == nil {
		return
	}
	mergeValue(reflect.ValueOf(dst).Elem(), reflect.ValueOf(src).Elem())
}

func mergeValue(dst, src reflect.Value) {
	switch src.Kind() {
	case reflect.Struct:
		for i := 0; i < src.NumField(); i++ {
			if !dst.Field(i).CanSet() {
				continue
			}
			mergeValue(dst.Field(i), src.Field(i))
		}
	case reflect.Pointer:
		if src.IsNil() {
			return
		}
		if dst.IsNil() {
			dst.Set(reflect.New(src.Type().Elem()))
		}
		// A pointer to a struct is a block, and blocks merge. A pointer to
		// anything else is an explicit optional scalar — *bool for a flag whose
		// default is true — and those replace, because that is the whole reason
		// they are pointers.
		if src.Type().Elem().Kind() == reflect.Struct {
			mergeValue(dst.Elem(), src.Elem())
			return
		}
		dst.Set(src)
	case reflect.Map:
		if src.Len() == 0 {
			return
		}
		if dst.IsNil() {
			dst.Set(reflect.MakeMap(src.Type()))
		}
		// Maps merge key by key: a profile adjusting one mutator weight should
		// not have to restate the others. This is the exception to "replace",
		// and it is the behaviour a map of overrides is written to have.
		for _, k := range src.MapKeys() {
			dst.SetMapIndex(k, src.MapIndex(k))
		}
	case reflect.Slice:
		if src.Len() == 0 {
			return
		}
		dst.Set(src)
	default:
		if src.IsZero() {
			return
		}
		dst.Set(src)
	}
}

// Coverage backends, named for the same reason the tiers are (ADR-0002).
const (
	CoverageSancov   = "sancov"
	CoveragePtraceBB = "ptrace-bb"
	CoverageQemu     = "qemu"
	CoverageFrida    = "frida"
	CoverageBlackbox = "blackbox"
	CoverageNone     = "none"
)

// IsBinaryOnlyCoverage reports whether a backend works by watching a process run
// rather than by asking an instrumented build what it did.
//
// The distinction decides which tier can carry it, what granularity a campaign
// may require, and whether the target needs rebuilding at all — so it is one
// predicate rather than three copies of the same list.
func IsBinaryOnlyCoverage(backend string) bool {
	switch backend {
	case CoveragePtraceBB, CoverageQemu, CoverageFrida:
		return true
	}
	return false
}
