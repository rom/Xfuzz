package daemon

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rom/Xfuzz/internal/safety"
	"github.com/rom/Xfuzz/internal/testenv"
	"github.com/rom/Xfuzz/pkg/campaign"
	"github.com/rom/Xfuzz/pkg/feedback"
)

// A shell script that fails loudly, which is all triage needs: something whose
// exit and output it can classify.
const echoer = `#!/bin/sh
read line
echo "XFUZZ-MARKER: $line"
`

func triageFor(t *testing.T, script string) *Triage {
	t.Helper()
	dir := testenv.ReachableDir(t)
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return triageForTarget(t, target)
}

func triageForTarget(t *testing.T, target string) *Triage {
	t.Helper()
	dir := filepath.Dir(target)
	doc := "name: triage-test\n" +
		"target:\n  path: " + target + "\n  input: stdin\n  timeout: 5s\n" +
		"seeds:\n  inline: [\"x\"]\n"
	path := filepath.Join(dir, "c.yaml")
	if err := os.WriteFile(path, []byte(doc), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := campaign.Load(path)
	if err != nil {
		t.Fatal(err)
	}

	sandbox := &safety.Sandbox{Name: cfg.Name, Target: target}
	t.Cleanup(func() { sandbox.Close() })
	if err := sandbox.Check(context.Background()); err != nil {
		t.Skipf("this host cannot confine a target: %v", err)
	}
	tr := NewTriage(cfg, sandbox)
	t.Cleanup(func() { tr.Close() })
	return tr
}

// The daemon can re-run a campaign's target, delivering the input and keeping
// what the target said about it.
//
// Both halves matter downstream. Without delivery the reproducer is not being
// reproduced at all, and every finding would read as unverified. Without the
// output, bucketing loses the marker a program printed — which is better
// evidence of which bug this is than any signal number, and on a black-box
// target is the only evidence there is.
func TestTriageRunnerDeliversInputAndKeepsOutput(t *testing.T) {
	tr := triageFor(t, echoer)

	out, err := tr.Run(context.Background(), []byte("hello\n"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	t.Logf("exit=%v signal=%d output=%q", out.Exit, out.Signal, out.Output)

	if out.Exit != feedback.ExitOK {
		t.Errorf("a target that exited cleanly was reported as %v", out.Exit)
	}
	if !strings.Contains(out.Output, "XFUZZ-MARKER: hello") {
		t.Errorf("the input was not delivered or the output was lost; got %q", out.Output)
	}
}
