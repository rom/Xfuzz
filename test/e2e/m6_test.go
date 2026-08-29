//go:build integration

// M6's exit criteria: stateful fuzzing, measured against the shipped binaries.
//
// The criteria are about reaching a bug through a *sequence*, and there is no
// way to check that from inside a package: it needs a real server on a real
// socket, a campaign that assembles a handshake, and a finding that replays as
// the conversation it was.

package e2e

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// statefulEnv is an environment holding the stateful_proto target, its
// dictionary, and seed conversations.
type statefulEnv struct {
	*env
	dict  string
	seeds string
}

func newStatefulEnv(t *testing.T) *statefulEnv {
	t.Helper()
	e := newEnvFor(t, "stateful_proto")

	// The target's own directory: the campaign refers to files beside it, and
	// the sandbox has to let the target reach them.
	dir := filepath.Dir(e.target)

	dict := filepath.Join(dir, "stateful_proto.dict")
	src, err := os.ReadFile(filepath.Join(repoRoot(t), "testdata", "targets", "stateful_proto.dict"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dict, src, 0o644); err != nil {
		t.Fatal(err)
	}

	// Seeds are conversations, one message per line: an example of the protocol
	// being spoken correctly is the single most useful thing a person can
	// supply to a stateful campaign, and the session codec reads a file as one.
	seeds := filepath.Join(dir, "seeds")
	if err := os.MkdirAll(seeds, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{
		"full":  "HELLO 1\r\nAUTH LETMEIN\r\nSET k v\r\nGET k\r\n",
		"reset": "HELLO 1\r\nAUTH LETMEIN\r\nRESET\r\nGET k\r\n",
		"bulk":  "HELLO 1\r\nAUTH LETMEIN\r\nBULK 2\r\na\r\nb\r\n",
		"quit":  "HELLO 1\r\nQUIT\r\n",
	} {
		if err := os.WriteFile(filepath.Join(seeds, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return &statefulEnv{env: e, dict: dict, seeds: seeds}
}

// campaignFile writes a stateful campaign and returns its path.
func (e *statefulEnv) campaignFile(name string, workers int, after time.Duration, extra string) string {
	e.t.Helper()
	// A socket per worker: each worker runs its own copy of the server, and a
	// shared address means the second binds what the first holds. Under the
	// system temporary directory because the target runs as an unprivileged
	// identity of its own and has to be able to create it.
	sock := filepath.Join(os.TempDir(), "xfuzz-"+name+"-{worker}.sock")

	body := fmt.Sprintf(`
name: %s
target:
  path: %s
session:
  address: unix:%s
  framing: line
  reset: reconnect
state:
  fn: status
format:
  dictionary: %s
seeds:
  dirs: [%s]
feedback:
  coverage: sancov
triage:
  markers: ["XFUZZ-BUG-"]
workers:
  count: %d
stop:
  after: %s
%s`, name, e.target, sock, e.dict, e.seeds, workers, after, extra)

	path := filepath.Join(e.dataDir, name+".yaml")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		e.t.Fatal(err)
	}
	return path
}

// stateModel is the protocol graph as the API reports it.
type stateModel struct {
	Fn     string `json:"fn"`
	States []struct {
		Label    string `json:"label"`
		Count    int    `json:"count"`
		Exemplar string `json:"exemplar"`
	} `json:"states"`
	Transitions []struct {
		From  string `json:"from"`
		To    string `json:"to"`
		Count int    `json:"count"`
	} `json:"transitions"`
}

func (m stateModel) reached(label string) bool {
	for _, s := range m.States {
		if s.Label == label {
			return true
		}
	}
	return false
}

func (e *statefulEnv) states(name string) stateModel {
	e.t.Helper()
	out := e.mustRun(60*time.Second, "states", name, "--json")
	var m stateModel
	if err := json.Unmarshal([]byte(out), &m); err != nil {
		e.t.Fatalf("decoding the state model: %v\n%s", err, out)
	}
	return m
}

// findingDetail is what a finding says about itself.
type findingDetail struct {
	ID         int    `json:"id"`
	Kind       string `json:"kind"`
	Detail     string `json:"detail"`
	Reproducer []byte `json:"reproducer"`
}

func (e *statefulEnv) findings(name string) []findingDetail {
	e.t.Helper()
	var list struct {
		Findings []struct {
			ID int `json:"id"`
		} `json:"findings"`
	}
	out := e.mustRun(60*time.Second, "findings", "list", name, "--json")
	if err := json.Unmarshal([]byte(out), &list); err != nil {
		e.t.Fatalf("decoding the finding list: %v\n%s", err, out)
	}

	var all []findingDetail
	for _, f := range list.Findings {
		one := e.mustRun(60*time.Second, "findings", "get", name, fmt.Sprint(f.ID), "--json")
		var d findingDetail
		if err := json.Unmarshal([]byte(one), &d); err != nil {
			e.t.Fatalf("decoding finding %d: %v", f.ID, err)
		}
		all = append(all, d)
	}
	return all
}

// bucketsOf maps each finding to the bucket triage filed it under.
func (e *statefulEnv) bucketsOf(name string) map[int]int64 {
	e.t.Helper()
	var list struct {
		Findings []struct {
			ID     int   `json:"id"`
			Bucket int64 `json:"bucket"`
		} `json:"findings"`
	}
	out := e.mustRun(60*time.Second, "findings", "list", name, "--json")
	if err := json.Unmarshal([]byte(out), &list); err != nil {
		e.t.Fatalf("decoding the finding list: %v\n%s", err, out)
	}
	m := map[int]int64{}
	for _, f := range list.Findings {
		m[f.ID] = f.Bucket
	}
	return m
}

// bugsFound returns which planted bugs the campaign reported, by number.
//
// From the target's own marker rather than from a signal or a bucket count: the
// criterion is about *which* bug was reached, and stateful_proto's bugs are
// graded precisely so that reaching one says nothing about reaching another.
func bugsFound(fs []findingDetail) map[string]bool {
	out := map[string]bool{}
	for _, f := range fs {
		for _, n := range []string{"1", "2", "3", "4"} {
			if strings.Contains(f.Detail, "XFUZZ-BUG-"+n) {
				out[n] = true
			}
		}
	}
	return out
}

// M6's central criterion: a bug reachable only past a valid handshake.
//
// Bug 2 needs HELLO, then AUTH with the right token, then a SET whose value is
// too long. A fuzzer that sends messages independently cannot reach it however
// long it runs, and neither can one that mutates a random message of a random
// session — the handshake is a funnel, and every mutation that lands in it
// closes the path behind. That is what state-then-message scheduling is for.
func TestStatefulCampaignReachesBugsBehindTheHandshake(t *testing.T) {
	e := newStatefulEnv(t)
	const budget = 4 * time.Minute
	path := e.campaignFile("proto", 2, budget, "")

	e.mustRun(budget+3*time.Minute, "run", path)

	s := e.status("proto")
	model := e.states("proto")
	found := bugsFound(e.findings("proto"))

	t.Logf("%d sessions at %.0f/s, %d edges, %d states, %d transitions, bugs %v",
		s.Metrics.Execs, s.Metrics.ExecsPerS, s.Metrics.Coverage,
		s.Metrics.States, s.Metrics.Transitions, sortedKeys(found))
	for _, st := range model.States {
		t.Logf("  state %-8s %6d visits  %s", st.Label, st.Count, st.Exemplar)
	}

	if s.Metrics.Execs == 0 {
		t.Fatal("the campaign completed no sessions")
	}
	// The handshake itself. Without it nothing past it is reachable, and the
	// rest of this test would be measuring the wrong thing.
	if !model.reached("235") {
		t.Fatalf("the campaign never authenticated, so it never entered the "+
			"half of the protocol the planted bugs live in:\n%+v", model.States)
	}
	if !found["1"] {
		t.Error("the shallow bug was not found; the session tier itself is not working")
	}
	if !found["2"] {
		t.Errorf("the bug behind the handshake was not found in %s; "+
			"the campaign authenticated but never reached past it", budget)
	}

	// Two bugs the target itself distinguishes must not share a bucket. They
	// die of the same signal at the same depth, so a bucketing that reads only
	// the signal reports one bug and the second is discarded as a duplicate of
	// the first — which is how finding it stops counting as finding it.
	buckets := e.bucketsOf("proto")
	byBug := map[string]int64{}
	for _, f := range e.findings("proto") {
		for _, n := range []string{"1", "2", "3", "4"} {
			if strings.Contains(f.Detail, "XFUZZ-BUG-"+n) {
				byBug[n] = buckets[f.ID]
			}
		}
	}
	if a, b := byBug["1"], byBug["2"]; a != 0 && b != 0 && a == b {
		t.Errorf("the shallow bug and the bug behind the handshake share bucket %d; "+
			"the target names them apart and triage does not", a)
	}
}

// M6's reporting criterion: protocol coverage is reported separately from code
// coverage, and the graph behind it is inspectable.
//
// Separately because they answer different questions: a campaign can hold code
// coverage flat while discovering a new state, and averaging the two away is
// how "have we explored this protocol?" stops being a measurable question. And
// inspectable because a state label is a hash — ADR-0006 makes inference
// quality the fuzzer's quality on a black-box target, so a bad clustering has
// to be visible rather than guessed at.
func TestProtocolCoverageIsReportedSeparately(t *testing.T) {
	e := newStatefulEnv(t)
	path := e.campaignFile("cover", 1, 45*time.Second, "")
	e.mustRun(4*time.Minute, "run", path)

	s := e.status("cover")
	if s.Metrics.States == 0 || s.Metrics.Transitions == 0 {
		t.Fatalf("no protocol coverage was reported: %d states, %d transitions",
			s.Metrics.States, s.Metrics.Transitions)
	}
	// Transitions outnumber states in any protocol worth fuzzing, and counting
	// only states would hide the pairs the bugs live in.
	if s.Metrics.Transitions <= s.Metrics.States {
		t.Errorf("%d transitions against %d states; transitions are not being counted separately",
			s.Metrics.Transitions, s.Metrics.States)
	}

	model := e.states("cover")
	if model.Fn == "" {
		t.Error("the state model does not say which function produced its labels")
	}
	if len(model.States) != s.Metrics.States {
		t.Errorf("the graph has %d states and the counter says %d", len(model.States), s.Metrics.States)
	}

	// Every state carries the response that produced it. Without that a label
	// is a hash and a campaign reporting four hundred states is a number
	// nobody can act on.
	for _, st := range model.States {
		if st.Label == "?" || st.Label == "closed" {
			continue // no response produced these
		}
		if st.Exemplar == "" {
			t.Errorf("state %q has no exemplar, so nothing says what the target actually said", st.Label)
		}
	}
}

// M6's replay criterion: a stateful finding replays as a full session.
//
// The reproducer has to be the conversation, not the last message of it.
// Storing one message would make a finding that needs a handshake
// unreproducible by construction, and triage would then dismiss every real bug
// with a number that looks like evidence.
func TestStatefulFindingsReplayAsSessions(t *testing.T) {
	e := newStatefulEnv(t)
	path := e.campaignFile("replay", 1, 60*time.Second, "")
	e.mustRun(5*time.Minute, "run", path)

	fs := e.findings("replay")
	if len(fs) == 0 {
		t.Fatal("the campaign reported no findings to replay")
	}

	multi := 0
	for _, f := range fs {
		lines := strings.Count(string(f.Reproducer), "\n")
		t.Logf("finding %d: %d message(s), detail %q", f.ID, lines, strings.TrimSpace(f.Detail))
		if lines > 1 {
			multi++
		}
		// The target's own account of what went wrong. A finding that says only
		// "terminated abnormally" cannot be bucketed by marker and cannot be
		// acted on by a person.
		if !strings.Contains(f.Detail, "XFUZZ-BUG-") {
			t.Errorf("finding %d carries no marker from the target: %q", f.ID, f.Detail)
		}
	}
	if multi == 0 {
		t.Error("every reproducer is a single message; findings are not being stored as sessions")
	}

	// And replaying one through the daemon reproduces it. This is the half that
	// was silently broken: triage replayed a conversation as a blob on standard
	// input, which is not the same execution, and reported every finding
	// unreproducible.
	out := e.mustRun(3*time.Minute, "replay", "replay", fmt.Sprint(fs[0].ID))
	t.Logf("replay: %s", strings.TrimSpace(out))
	if strings.Contains(out, "0 of") {
		t.Errorf("a finding recorded by a session campaign did not reproduce as a session:\n%s", out)
	}
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

// repoRoot returns the directory holding go.mod.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := filepath.Abs(".")
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("no go.mod above the test directory")
		}
		dir = parent
	}
}
