package worker

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rom/Xfuzz/pkg/campaign"
	"github.com/rom/Xfuzz/pkg/executor"
)

// The worker is mostly exercised end to end, under the integration tag. What
// is here is the pure part: the file it reads and the specifications it
// derives from a campaign, which are wrong quietly when they are wrong.

func TestSecretsFileIsPlaceholderEqualsValue(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets")
	os.WriteFile(path, []byte("# written by xfuzz capture\n\n{{TOKEN}}=abc123\n {{COOKIE}} = sess=1;x=2\n"), 0o600)

	sub, err := loadSecrets(path)
	if err != nil {
		t.Fatal(err)
	}
	got := sub([]byte("Authorization: Bearer {{TOKEN}}\r\nCookie: {{COOKIE}}\r\n"))
	if string(got) != "Authorization: Bearer abc123\r\nCookie:  sess=1;x=2\r\n" {
		t.Errorf("substituted = %q", got)
	}

	bad := filepath.Join(dir, "bad")
	os.WriteFile(bad, []byte("{{TOKEN}}=ok\nno equals here\n"), 0o600)
	if _, err := loadSecrets(bad); err == nil || !strings.Contains(err.Error(), "line 2") {
		t.Errorf("a malformed line: %v", err)
	}
	empty := filepath.Join(dir, "empty")
	os.WriteFile(empty, []byte("# only a comment\n"), 0o600)
	if _, err := loadSecrets(empty); err == nil || !strings.Contains(err.Error(), "no placeholder=value pairs") {
		t.Errorf("an empty file: %v", err)
	}
	if _, err := loadSecrets(filepath.Join(dir, "absent")); err == nil {
		t.Error("a missing file was read")
	}
}

func TestProcSpecCarriesTheTargetBlock(t *testing.T) {
	cfg, err := campaign.Parse([]byte(`
name: spec
target:
  path: /bin/echo
  args: ["--mode=parse", "@@"]
  env: {LANG: C}
  dir: /tmp
  timeout: 2s
  input: file
seeds:
  inline: ["x"]
`), "spec.yaml")
	if err != nil {
		t.Fatal(err)
	}
	spec := procSpecFor(cfg)
	if spec.Path != "/bin/echo" || strings.Join(spec.Args, " ") != "/bin/echo --mode=parse @@" {
		t.Errorf("argv = %v", spec.Args)
	}
	if len(spec.Env) != 1 || spec.Env[0] != "LANG=C" {
		t.Errorf("env = %v", spec.Env)
	}
	if spec.Dir != "/tmp" || spec.Timeout.Seconds() != 2 || !spec.CaptureOutput {
		t.Errorf("spec = %+v", spec)
	}
	if deliveryFor(cfg) != executor.DeliverFile {
		t.Errorf("input: file delivers as %v", deliveryFor(cfg))
	}
	cfg.Target.Input = campaign.InputArg
	if deliveryFor(cfg) != executor.DeliverArg {
		t.Error("input: arg")
	}
	cfg.Target.Input = campaign.InputStdin
	if deliveryFor(cfg) != executor.DeliverStdin {
		t.Error("input: stdin")
	}
}

func TestAWorkerUnderADaemonCarriesNoBudgetOfItsOwn(t *testing.T) {
	cfg, err := campaign.Parse([]byte("name: b\ntarget:\n  path: /bin/true\nseeds:\n  inline: [\"x\"]\nstop:\n  execs: 500\n  after: 3s\n"), "b.yaml")
	if err != nil {
		t.Fatal(err)
	}
	standalone := &Worker{opts: Options{Config: cfg}}
	if b := standalone.budget(); b.MaxExecs != 500 || b.MaxTime.Seconds() != 3 {
		t.Errorf("a standalone worker's budget = %+v", b)
	}
	// Under a daemon the campaign's stop conditions are the campaign's,
	// enforced once across every worker; a worker with its own copy would
	// run the budget N times over.
	supervised := &Worker{opts: Options{Config: cfg, Control: os.Stdin}}
	if b := supervised.budget(); b.MaxExecs != 0 || b.MaxTime != 0 {
		t.Errorf("a supervised worker's budget = %+v", b)
	}
}
