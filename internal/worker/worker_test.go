//go:build integration

// A worker end to end: it builds an engine from a campaign file, fuzzes a real
// instrumented target, and reports what it finds over the protocol.
//
// Behind the integration tag because it compiles and runs a target.

package worker

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/rom/Xfuzz/internal/daemon"
	"github.com/rom/Xfuzz/internal/testenv"
	"github.com/rom/Xfuzz/pkg/campaign"
	"github.com/rom/Xfuzz/pkg/corpus"
)

// campaignFor writes a campaign file around a target.
func campaignFor(t *testing.T, target, extra string) *campaign.Resolved {
	t.Helper()
	body := "name: wtest\n" +
		"target:\n  path: " + target + "\n  input: stdin\n  timeout: 2s\n" +
		"seeds:\n  inline: [\"Z\", \"Axx\", \"B\"]\n" +
		"feedback:\n  coverage: sancov\n" + extra
	path := filepath.Join(t.TempDir(), "c.yaml")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := campaign.Load(path)
	if err != nil {
		t.Fatalf("loading the campaign: %v\n%s", err, body)
	}
	return cfg
}

// pipes wires a worker to a fake daemon.
type pipes struct {
	control  *os.File // the daemon writes here
	toWorker *os.File // the worker reads here
	status   *os.File // the worker writes here
	fromWork *os.File // the daemon reads here
}

func newPipes(t *testing.T) *pipes {
	t.Helper()
	ctlR, ctlW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stR, stW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	p := &pipes{control: ctlW, toWorker: ctlR, status: stW, fromWork: stR}
	t.Cleanup(func() {
		p.control.Close()
		p.toWorker.Close()
		p.status.Close()
		p.fromWork.Close()
	})
	return p
}

// observer collects what a worker reports.
type observer struct {
	mu       sync.Mutex
	ready    *daemon.ReadyInfo
	execs    uint64
	corpus   [][]byte
	findings int
	logs     []string
	stopped  string
}

func (o *observer) watch(p *pipes) {
	dec := daemon.NewDecoder(p.fromWork)
	for {
		m, err := dec.Decode()
		if err != nil {
			return
		}
		o.mu.Lock()
		switch m.Type {
		case daemon.MsgReady:
			o.ready = m.Ready
		case daemon.MsgMetrics:
			if m.Metrics != nil {
				o.execs = m.Metrics.Execs
			}
		case daemon.MsgCorpus:
			for _, e := range m.Entries {
				o.corpus = append(o.corpus, e.Payload)
			}
		case daemon.MsgFinding:
			o.findings++
		case daemon.MsgLog:
			o.logs = append(o.logs, m.Level+": "+m.Text)
		case daemon.MsgStopped:
			o.stopped = m.Reason
		}
		o.mu.Unlock()
	}
}

func (o *observer) get(fn func(*observer) bool) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	return fn(o)
}

func TestWorkerFuzzesAndReportsOverTheProtocol(t *testing.T) {
	cfg := campaignFor(t, testenv.BuildTarget(t, "simple_parser"), "")
	p := newPipes(t)
	obs := &observer{}
	go obs.watch(p)

	w := New(Options{
		Config: cfg, ID: 0, Seed: 0x5EED,
		Control: p.toWorker, Status: p.status,
		ReportInterval: 100 * time.Millisecond,
	})
	defer w.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- w.Run(ctx) }()

	waitFor(t, obs, 30*time.Second, func(o *observer) bool { return o.ready != nil },
		"the worker never announced itself")
	obs.mu.Lock()
	t.Logf("ready: executor=%s isolation=%s seeds=%d", obs.ready.Executor, obs.ready.Isolation, obs.ready.Seeds)
	if obs.ready.Seeds == 0 {
		t.Error("the worker started with no seeds")
	}
	obs.mu.Unlock()

	waitFor(t, obs, 60*time.Second, func(o *observer) bool { return o.execs > 1000 },
		"the worker reported no executions")
	waitFor(t, obs, 60*time.Second, func(o *observer) bool { return len(o.corpus) > 0 },
		"the worker admitted nothing to the corpus")
	waitFor(t, obs, 120*time.Second, func(o *observer) bool { return o.findings > 0 },
		"the worker found nothing in a target with three planted bugs")

	if err := daemon.NewEncoder(p.control).Encode(&daemon.Message{Type: daemon.CmdStop}); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("the worker did not stop when asked")
	}

	obs.mu.Lock()
	t.Logf("execs=%d corpus=%d findings=%d stopped=%q", obs.execs, len(obs.corpus), obs.findings, obs.stopped)
	obs.mu.Unlock()
}

func TestWorkerDoesNotEchoSyncedEntries(t *testing.T) {
	cfg := campaignFor(t, testenv.BuildTarget(t, "simple_parser"), "")
	p := newPipes(t)
	obs := &observer{}
	go obs.watch(p)

	w := New(Options{
		Config: cfg, ID: 1, Seed: 7,
		Control: p.toWorker, Status: p.status,
		ReportInterval: 100 * time.Millisecond,
	})
	defer w.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	go w.Run(ctx)

	waitFor(t, obs, 30*time.Second, func(o *observer) bool { return o.ready != nil }, "no ready message")

	sibling := []byte("A\x01ZZ")
	err := daemon.NewEncoder(p.control).Encode(&daemon.Message{
		Type: daemon.CmdSync,
		Entries: []daemon.CorpusEntry{{
			Digest: corpus.DigestOf(sibling).String(), Payload: sibling, Origin: "sync:worker-0",
		}},
	})
	if err != nil {
		t.Fatal(err)
	}

	// It must not come straight back as this worker's own discovery, which
	// would loop the entry around the campaign forever.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(200 * time.Millisecond)
		if obs.get(func(o *observer) bool {
			for _, payload := range o.corpus {
				if string(payload) == string(sibling) {
					return true
				}
			}
			return false
		}) {
			t.Fatal("a synced entry was reported back to the daemon as a discovery")
		}
	}
}

func waitFor(t *testing.T, o *observer, limit time.Duration, cond func(*observer) bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(limit)
	for time.Now().Before(deadline) {
		if o.get(cond) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	o.mu.Lock()
	logs := append([]string(nil), o.logs...)
	o.mu.Unlock()
	if len(logs) > 0 {
		t.Logf("worker said:\n  %s", joinLines(logs))
	}
	t.Fatal(msg)
}

func joinLines(s []string) string {
	out := ""
	for i, line := range s {
		if i > 0 {
			out += "\n  "
		}
		out += line
	}
	return out
}
