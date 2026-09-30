package safety

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/rom/Xfuzz/internal/platform"
	"github.com/rom/Xfuzz/pkg/campaign"
	"github.com/rom/Xfuzz/pkg/executor"
)

func TestAuthorizationRendersItsDigest(t *testing.T) {
	a := &Authorization{Operator: "rom", Reference: "ENG-1", Attestation: "authorised", Recorded: time.Unix(1_700_000_000, 0)}
	s := a.String()
	if !strings.HasPrefix(s, "rom under ENG-1 at 2023-11-14T22:13:20Z (") || !strings.HasSuffix(s, ")") {
		t.Errorf("String() = %q", s)
	}
	if !strings.Contains(s, a.Digest()) {
		t.Error("the rendering does not carry the digest that ties it to the audit entry")
	}
	changed := *a
	changed.Attestation = "authorised, later"
	if changed.Digest() == a.Digest() {
		t.Error("changing the attestation did not change the digest")
	}
}

func TestLimitsForMapsEveryCapAndNeverACore(t *testing.T) {
	cfg, err := campaign.Parse([]byte(`
name: caps
target:
  path: /bin/true
seeds:
  inline: ["x"]
safety:
  memory_limit: 64MB
  process_limit: 7
  file_size_limit: 1MB
  cpu_limit: 30s
`), "caps.yaml")
	if err != nil {
		t.Fatal(err)
	}
	l := LimitsFor(cfg)
	if l.AddressSpaceBytes != 64<<20 || l.Processes != 7 || l.FileSizeBytes != 1<<20 || l.CPUSeconds != 30 {
		t.Errorf("LimitsFor = %+v", l)
	}
	if !l.DisableCore {
		t.Error("a fuzzer writes reproducers, not core files")
	}
}

func TestCloneIsADeepCopy(t *testing.T) {
	s := &Sandbox{Require: LevelModerate, Writable: []string{"/a"}, Creates: []string{"/b"}, Network: true,
		Limits: platform.Limits{Processes: 3}}
	c := s.Clone()
	c.Writable[0] = "/changed"
	c.Creates = append(c.Creates, "/c")
	if s.Writable[0] != "/a" || len(s.Creates) != 1 {
		t.Error("Clone shares its slices with the original")
	}
	if c.Require != LevelModerate || !c.Network || c.Limits.Processes != 3 {
		t.Errorf("Clone lost fields: %+v", c)
	}
}

func TestFindProgramAndTargetIdentity(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("sh")
	}
	if p, err := FindProgram("sh"); err != nil || !filepath.IsAbs(p) {
		t.Errorf("FindProgram(sh) = %q, %v", p, err)
	}
	if _, err := FindProgram("no-such-program-xfuzz"); err == nil || !strings.Contains(err.Error(), "not found on PATH") {
		t.Errorf("a missing program: %v", err)
	}
	uid, gid := (&Sandbox{}).TargetIdentity()
	if os.Getuid() != 0 && (uid != -1 || gid != -1) {
		t.Errorf("an unprivileged fuzzer reported a target identity %d:%d; it cannot give the target one", uid, gid)
	}
}

func TestAPeerIsAConversation(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("cat")
	}
	s := NewSpawner()
	s.Sandbox = &Sandbox{Unconfined: true}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// cat echoes its input, and says something on stderr first.
	peer, err := s.StartPeer(ctx, executor.ProcSpec{Path: "sh", Args: []string{"sh", "-c", "echo starting >&2; exec cat"}})
	if err != nil {
		t.Fatal(err)
	}
	if peer.Pid() == 0 {
		t.Error("no pid")
	}
	if _, err := io.WriteString(peer.Stdin(), "hello\n"); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	n, err := peer.Stdout().Read(buf)
	if err != nil || string(buf[:n]) != "hello\n" {
		t.Errorf("the peer answered %q, %v", buf[:n], err)
	}
	// Closing stdin ends cat; what it said on stderr is retained.
	peer.Stdin().Close()
	res, err := peer.Wait()
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode != 0 {
		t.Errorf("exit = %+v", res)
	}
	deadline := time.Now().Add(2 * time.Second)
	for !strings.Contains(peer.Diagnose(), "starting") && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if d := peer.Diagnose(); !strings.Contains(d, "starting") {
		t.Errorf("Diagnose = %q", d)
	}
}

func TestKillingAPeerUnblocksItsReader(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("sleep")
	}
	s := NewSpawner()
	s.Sandbox = &Sandbox{Unconfined: true}
	peer, err := s.StartPeer(context.Background(), executor.ProcSpec{Path: "sleep", Args: []string{"sleep", "30"}})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := peer.Stdout().Read(make([]byte, 1))
		done <- err
	}()
	time.Sleep(50 * time.Millisecond)
	peer.Kill()
	select {
	case err := <-done:
		if err == nil {
			t.Error("the read returned data from a killed peer")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the reader stayed blocked after Kill")
	}
	if res, _ := peer.Wait(); res.Signal == 0 {
		t.Errorf("a killed peer reports no signal: %+v", res)
	}
}

func TestACancelledContextKillsAPeer(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("sleep")
	}
	s := NewSpawner()
	s.Sandbox = &Sandbox{Unconfined: true}
	ctx, cancel := context.WithCancel(context.Background())
	peer, err := s.StartPeer(ctx, executor.ProcSpec{Path: "sleep", Args: []string{"sleep", "30"}})
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	done := make(chan struct{})
	go func() { peer.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the peer outlived its context")
	}
}

func TestTheStderrTailKeepsTheEnd(t *testing.T) {
	// A plugin that is about to die explains itself last, so the tail is what
	// is kept when the limit is exceeded.
	tl := &tail{limit: 10}
	io.WriteString(tl, "012345")
	if got := tl.String(); got != "012345" {
		t.Errorf("under the limit nothing is marked dropped: %q", got)
	}
	io.WriteString(tl, "6789")
	io.WriteString(tl, "abcdef")
	if got := tl.String(); got != "...6789abcdef" {
		t.Errorf("tail = %q", got)
	}
	big := &tail{limit: 4}
	io.WriteString(big, "a very long line indeed")
	if got := big.String(); got != "...deed" {
		t.Errorf("a single write longer than the limit: %q", got)
	}
	s := NewSpawner()
	s.MaxOutputBytes = 0
	if s.peerOutputLimit() != 1<<20 {
		t.Errorf("no configured limit gave %d", s.peerOutputLimit())
	}
}

func TestATargetOnAPTYRunsToCompletion(t *testing.T) {
	if !PTYSupported() {
		t.Skip("no pseudo-terminal here")
	}
	s := NewSpawner()
	s.Sandbox = &Sandbox{Unconfined: true}
	p, err := s.StartPTY(context.Background(), executor.ProcSpec{Path: "sh", Args: []string{"sh", "-c", "printf drawn; read line; echo got:$line; exit 4"}}, 30, 8)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if p.Pid() == 0 {
		t.Error("no pid")
	}
	if !p.Alive() {
		t.Error("not alive at start")
	}
	if _, err := p.Write([]byte("typed\n")); err != nil {
		t.Fatal(err)
	}
	var out []byte
	buf := make([]byte, 256)
	for {
		n, rerr := p.Read(buf)
		out = append(out, buf[:n]...)
		if rerr != nil {
			break
		}
	}
	if !strings.Contains(string(out), "drawn") || !strings.Contains(string(out), "got:typed") {
		t.Errorf("the terminal saw %q", out)
	}
	select {
	case <-p.Exited():
	case <-time.After(5 * time.Second):
		t.Fatal("the target never exited")
	}
	if p.Alive() {
		t.Error("alive after exit")
	}
	if res := p.Result(); res.ExitCode != 4 || res.Signal != 0 {
		t.Errorf("result = %+v", res)
	}
	if err := p.Resize(40, 10); err != nil {
		t.Errorf("Resize after exit: %v", err)
	}
}

func TestAPTYTargetCanBeSignalledAndKilled(t *testing.T) {
	if !PTYSupported() {
		t.Skip("no pseudo-terminal here")
	}
	s := NewSpawner()
	s.Sandbox = &Sandbox{Unconfined: true}
	p, err := s.StartPTY(context.Background(), executor.ProcSpec{Path: "sleep", Args: []string{"sleep", "30"}}, 30, 8)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Signal(false); err != nil {
		t.Errorf("Signal: %v", err)
	}
	select {
	case <-p.Exited():
	case <-time.After(5 * time.Second):
		p.Kill()
		t.Fatal("a terminated target did not exit")
	}
	if res := p.Result(); res.Signal == 0 {
		t.Errorf("a signalled target reports no signal: %+v", res)
	}
	if err := p.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
	if err := p.Kill(); err != nil {
		t.Errorf("Kill after exit is not an error: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	p, err = s.StartPTY(ctx, executor.ProcSpec{Path: "sleep", Args: []string{"sleep", "30"}}, 30, 8)
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	select {
	case <-p.Exited():
	case <-time.After(5 * time.Second):
		t.Fatal("the target outlived its context")
	}
	p.Close()
}

func TestTraceTempFilesAreReadableAndBounded(t *testing.T) {
	in, err := stdinTemp([]byte("input bytes"))
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(in.Name())
	defer in.Close()
	b, _ := io.ReadAll(in)
	if string(b) != "input bytes" {
		t.Errorf("the input file reads %q; it must be rewound", b)
	}
	if fi, _ := in.Stat(); fi.Mode().Perm()&0o004 == 0 {
		t.Error("the input file is not readable by another user, and the target may be one")
	}

	out, err := captureTemp()
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(out.Name())
	defer out.Close()
	if fi, _ := out.Stat(); fi.Mode().Perm()&0o002 == 0 {
		t.Error("the output file is not writable by another user")
	}
	io.WriteString(out, "0123456789")
	if got := readCapture(out, 4); string(got) != "0123" {
		t.Errorf("readCapture with a limit = %q", got)
	}
	if got := readCapture(out, 0); string(got) != "0123456789" {
		t.Errorf("readCapture unlimited = %q", got)
	}
	if readCapture(nil, 4) != nil {
		t.Error("readCapture(nil) is not nil")
	}
}

func TestRunTracedRefusesWhereItCannotTrace(t *testing.T) {
	s := NewSpawner()
	s.Sandbox = &Sandbox{Unconfined: true}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, err := s.RunTraced(ctx, executor.ProcSpec{Path: "true"}, platform.TraceOptions{})
	if err == nil {
		t.Fatal("a cancelled context traced something")
	}
	if platform.TraceSupported() && err != context.Canceled {
		t.Errorf("err = %v, want the context's", err)
	}
}
