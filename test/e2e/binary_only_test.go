//go:build integration

// The v0.2 claim, measured through the shipped binaries: a campaign against a
// stripped native executable, with no instrumentation and no source, finds a
// planted bug.
//
// Everything else in this suite fuzzes a target built by xfuzz-cc, which links
// the coverage runtime in. That is the fast path and it needs the target's
// author to cooperate. This file is the case ADR-0002 names as the reason the
// backend interface exists at all — a binary nobody can rebuild — and it is the
// only test here whose target has been deliberately made as opaque as a real
// engagement's would be.

package e2e

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/rom/Xfuzz/internal/platform"
	"github.com/rom/Xfuzz/internal/testenv"
)

// binaryOnlyEnv is newEnvFor with the target built the way a T5 campaign meets
// one: by an ordinary compiler, and stripped.
func binaryOnlyEnv(t *testing.T, target string) *env {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("the ptrace-bb backend is Linux-only (ADR-0002)")
	}
	if !platform.TraceSupported() {
		t.Skip("this host does not permit tracing a child by ptrace")
	}
	bin := testenv.ReachableDir(t)
	for _, cmd := range []string{"xfuzz", "xfuzzd", "xfuzz-worker", "xfuzz-sandbox"} {
		testenv.BuildBinary(t, bin, cmd)
	}
	e := &env{
		t:       t,
		binDir:  bin,
		dataDir: testenv.ReachableDir(t),
		target:  testenv.BuildStrippedTarget(t, target),
	}
	t.Cleanup(e.reapTargets)
	t.Cleanup(e.stopDaemon)
	return e
}

// writeBinaryOnlyCampaign writes a campaign that names a binary-only backend.
func (e *env) writeBinaryOnlyCampaign(name, backend string, after time.Duration, extra string) string {
	e.t.Helper()
	body := fmt.Sprintf(`
name: %s
target:
  path: %s
  input: stdin
  timeout: 2s
seeds:
  inline: ["A", "B", "C", "D"]
feedback:
  coverage: %s
%sworkers:
  count: 1
  sync_interval: 2s
stop:
  after: %s
`, name, e.target, backend, extra, after)
	path := filepath.Join(e.dataDir, name+".yaml")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		e.t.Fatal(err)
	}
	return path
}

// TestPtraceBackendFindsABugInAStrippedBinary is the v0.2 acceptance test.
//
// The target is compiled by clang without xfuzz-cc, so it carries no coverage
// runtime, and then stripped, so it carries no symbols either. Everything the
// campaign learns about it, it learns by watching it run.
func TestPtraceBackendFindsABugInAStrippedBinary(t *testing.T) {
	e := binaryOnlyEnv(t, "simple_parser")
	path := e.writeBinaryOnlyCampaign("binary-only", "ptrace-bb", 120*time.Second, "")

	e.mustRun(30*time.Second, "validate", path)
	e.mustRun(60*time.Second, "run", path, "--detach")

	st := e.waitFor("binary-only", 200*time.Second, func(s campaignStatus) bool {
		return s.Metrics.Findings > 0 || s.State == "finished"
	}, "a finding from the stripped target")

	t.Logf("state=%s execs=%d coverage=%d corpus=%d findings=%d",
		st.State, st.Metrics.Execs, st.Metrics.Coverage, st.Metrics.CorpusSize, st.Metrics.Findings)

	if st.Metrics.Execs == 0 {
		t.Fatal("the campaign completed no executions at all; the tier did not run")
	}
	if st.Metrics.Coverage == 0 {
		t.Fatal("the campaign covered nothing. With no instrumentation and no symbols, " +
			"coverage comes from breakpoints at statically recovered block starts, " +
			"and none of them fired")
	}
	if st.Metrics.Findings == 0 {
		t.Errorf("no finding in %d executions against a target with three planted bugs; "+
			"coverage was %d entries, so the tier was collecting signal and the campaign "+
			"still did not climb", st.Metrics.Execs, st.Metrics.Coverage)
	}
}

// TestBinaryOnlyCoverageBeatsBlackBox is what justifies the tier's cost.
//
// The T5 tier is one to two orders of magnitude slower than a subprocess run. It
// is worth that only if the signal it buys actually guides the campaign, so the
// same target is fuzzed twice for the same wall-clock window — once watching the
// process, once seeing only its output — and the guided run must keep more
// distinct behaviour. Corpus size rather than coverage, because the black-box
// run has no coverage to compare against: what is measured is whether the
// guidance found more, not whether the instrument reported more.
func TestBinaryOnlyCoverageBeatsBlackBox(t *testing.T) {
	if testing.Short() {
		t.Skip("this runs two campaigns to completion")
	}
	e := binaryOnlyEnv(t, "simple_parser")
	const window = 45 * time.Second

	run := func(name, backend, extra string) campaignStatus {
		path := e.writeBinaryOnlyCampaign(name, backend, window, extra)
		e.mustRun(60*time.Second, "run", path, "--detach")
		return e.waitFor(name, window+120*time.Second, func(s campaignStatus) bool {
			return s.State == "finished"
		}, "the campaign to finish")
	}

	guided := run("guided", "ptrace-bb", "")
	// A black-box campaign has to be told that novel output is what counts, or
	// it has no signal at all and validation refuses it.
	blind := run("blind", "blackbox", "  novelty: true\n")

	t.Logf("ptrace-bb: %d execs, %d corpus, %d coverage, %d findings",
		guided.Metrics.Execs, guided.Metrics.CorpusSize, guided.Metrics.Coverage, guided.Metrics.Findings)
	t.Logf("blackbox:  %d execs, %d corpus, %d findings",
		blind.Metrics.Execs, blind.Metrics.CorpusSize, blind.Metrics.Findings)

	if guided.Metrics.CorpusSize <= blind.Metrics.CorpusSize {
		t.Errorf("watching the process kept %d corpus entries and seeing only its output "+
			"kept %d, in the same window. The tier costs one to two orders of magnitude "+
			"in throughput and is worth it only if the signal guides the campaign",
			guided.Metrics.CorpusSize, blind.Metrics.CorpusSize)
	}
}

// TestBinaryOnlyBackendsRefuseTheWrongTier keeps a misconfiguration from looking
// like a target with no branches.
//
// A backend that works by watching the process needs the tier that watches it.
// Pairing one with the fork server would produce a campaign that collected no
// coverage for any input and reported nothing wrong.
func TestBinaryOnlyBackendsRefuseTheWrongTier(t *testing.T) {
	e := binaryOnlyEnv(t, "simple_parser")
	path := e.writeBinaryOnlyCampaign("mismatched", "ptrace-bb", 10*time.Second,
		"")
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	updated := strings.Replace(string(body), "  input: stdin\n",
		"  input: stdin\n  executor: forkserver\n", 1)
	if err := os.WriteFile(path, []byte(updated), 0o644); err != nil {
		t.Fatal(err)
	}

	out, err := e.xfuzz(30*time.Second, "validate", path)
	if err == nil {
		t.Fatalf("a fork-server campaign asking for breakpoint coverage validated:\n%s", out)
	}
	if !strings.Contains(out, "emulated") {
		t.Errorf("the refusal does not say which tier would work:\n%s", out)
	}
}

// TestDoctorReportsTheBinaryOnlyBackends is what an operator reads before
// concluding that stripped binaries are not supported.
func TestDoctorReportsTheBinaryOnlyBackends(t *testing.T) {
	e := newEnv(t)
	out := e.mustRun(60*time.Second, "doctor", "--json")

	var report struct {
		Capabilities []struct {
			Name      string `json:"name"`
			Available bool   `json:"available"`
			Detail    string `json:"detail"`
		} `json:"capabilities"`
	}
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatalf("doctor did not produce readable JSON: %v\n%s", err, out)
	}

	byName := map[string]string{}
	seen := map[string]bool{}
	for _, c := range report.Capabilities {
		byName[c.Name] = c.Detail
		seen[c.Name] = true
	}
	for _, backend := range []string{"ptrace-bb", "qemu", "frida"} {
		if !seen[backend] {
			t.Errorf("doctor does not mention the %s backend, so an operator whose target "+
				"cannot be rebuilt has no way to learn whether this host supports it", backend)
			continue
		}
		if byName[backend] == "" {
			t.Errorf("the %s row has no detail; unavailable with no reason is a message "+
				"nobody can act on", backend)
		}
	}
}
