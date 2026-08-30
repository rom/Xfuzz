package engine

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rom/Xfuzz/internal/platform"
	"github.com/rom/Xfuzz/internal/safety"
	"github.com/rom/Xfuzz/pkg/executor"
	"github.com/rom/Xfuzz/pkg/feedback"
)

// forkRate measures sustained executions per second for a target under the fork
// server.
func forkRate(t testing.TB, name string, withCoverage bool) float64 {
	t.Helper()
	target := buildTarget(t, name)

	fs := executor.NewForkServer("fs", safety.NewSpawner(), executor.ProcSpec{
		Path: target, Args: []string{target},
	})
	fs.Timeout = time.Second
	var obs []feedback.Observer
	if withCoverage {
		p := platform.NewSharedMemoryProvider()
		if !p.Available() {
			t.Skip("shared memory is unavailable")
		}
		shm, err := p.Create(feedback.DefaultMapSize)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { shm.Close() })
		cov := feedback.NewCoverageMap("cov", feedback.DefaultMapSize)
		cov.SetBuffer(shm.Bytes())
		fs.Coverage, fs.Shm = cov, shm
		obs = append(obs, cov)
	}
	if err := fs.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { fs.Close() })

	in := executor.Input{Bytes: []byte("Z\x00")}
	// Warm up, so page faults and first-touch costs are not counted.
	for i := 0; i < 200; i++ {
		if _, err := fs.Run(context.Background(), in, obs); err != nil {
			t.Fatal(err)
		}
	}
	const runFor = 2 * time.Second
	start, n := time.Now(), 0
	for time.Since(start) < runFor {
		if _, err := fs.Run(context.Background(), in, obs); err != nil {
			t.Fatal(err)
		}
		n++
	}
	return float64(n) / time.Since(start).Seconds()
}

func BenchmarkForkServer(b *testing.B) {
	for _, tc := range []struct {
		name     string
		coverage bool
	}{
		{"nop", false},          // the protocol floor: no work of the target's own
		{"nop", true},           // what coverage collection costs
		{"simple_parser", true}, // a realistic small target
	} {
		label := tc.name
		if tc.coverage {
			label += "+coverage"
		}
		b.Run(label, func(b *testing.B) {
			rate := forkRate(b, tc.name, tc.coverage)
			b.ReportMetric(rate, "exec/s")
		})
	}
}

func BenchmarkSubprocess(b *testing.B) {
	target := buildTarget(b, "simple_parser")
	e := executor.NewSubprocess("sub", safety.NewSpawner(), executor.ProcSpec{
		Path: target, Args: []string{target}, Timeout: time.Second,
	})
	defer e.Close()
	in := executor.Input{Bytes: []byte("Z\x00")}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := e.Run(context.Background(), in, nil); err != nil {
			b.Fatal(err)
		}
	}
	b.ReportMetric(float64(b.N)/b.Elapsed().Seconds(), "exec/s")
}

// BenchmarkInProc measures the T0 tier: a Go harness called directly, with no
// process boundary at all.
//
// It is the floor of the whole system and the number every other tier is a
// fraction of. Gating it is what makes a regression in the engine's own
// bookkeeping visible: the fork server's rate is dominated by the fork, so a
// change that doubles the per-execution cost inside Xfuzz barely moves it and
// moves this by half.
func BenchmarkInProc(b *testing.B) {
	var sink uint64
	e := executor.NewInProc("inproc", func(data []byte) error {
		for _, c := range data {
			sink = sink*31 + uint64(c)
		}
		return nil
	})
	defer e.Close()

	in := executor.Input{Bytes: []byte("Z\x00the quick brown fox")}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := e.Run(context.Background(), in, nil); err != nil {
			b.Fatal(err)
		}
	}
	b.ReportMetric(float64(b.N)/b.Elapsed().Seconds(), "exec/s")
	if sink == 0 {
		b.Fatal("optimised away")
	}
}

// BenchmarkSession measures the T6 tier: one conversation with a live server.
//
// Sessions per second rather than messages, because a session is what the
// engine schedules and what a stop budget counts. The rate is dominated by the
// framing wait — a reply is complete when the target has been quiet for the
// quiet period — so this number is mostly a measurement of that constant, which
// is exactly why it needs a gate: a change that adds one round trip per message
// to the tier would otherwise be invisible until somebody wondered why a
// stateful campaign took a week.
func BenchmarkSession(b *testing.B) {
	target := buildTarget(b, "stateful_proto")

	dir, err := os.MkdirTemp("", "xfuzz-bench-")
	if err != nil {
		b.Fatal(err)
	}
	defer os.RemoveAll(dir)
	if err := os.Chmod(dir, 0o755); err != nil {
		b.Fatal(err)
	}
	sock := filepath.Join(dir, "bench.sock")

	e := executor.NewSession("session", &plainDialer{}, executor.SessionOptions{
		Network: "unix", Address: sock,
		Reset:   executor.ResetReconnect,
		Framing: executor.FrameIdle,
	})
	e.Manage(safety.NewTrustedSpawner(), executor.ProcSpec{
		Path: target, Args: []string{target, "--listen", "unix:" + sock},
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := e.Start(ctx); err != nil {
		b.Skipf("the stateful target would not start here: %v", err)
	}
	defer e.Close()

	// A handshake and one request: the shortest conversation that is a
	// conversation rather than a single message.
	in := executor.Input{Bytes: []byte("HELLO 1\nAUTH LETMEIN\nGET k\n")}
	for i := 0; i < 20; i++ {
		if _, err := e.Run(ctx, in, nil); err != nil {
			b.Skipf("the stateful target is not answering here: %v", err)
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := e.Run(ctx, in, nil); err != nil {
			b.Fatal(err)
		}
	}
	b.ReportMetric(float64(b.N)/b.Elapsed().Seconds(), "session/s")
}

// plainDialer connects without the scope guard, which a benchmark against a
// socket in its own temporary directory does not need and which would make the
// measurement one of the guard rather than of the tier.
type plainDialer struct{ d net.Dialer }

func (p *plainDialer) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	return p.d.DialContext(ctx, network, address)
}

// BenchmarkProcPool measures the T3 tier against the T4 it exists to beat.
//
// The claim is narrow and worth checking rather than assuming: a pool cannot
// make a target start faster, it can only stop the fuzzer waiting for it. So
// the win is the whole of the spawn cost on a target whose own work is small,
// and nothing at all on one whose work dominates. This measures the first case,
// which is the one the tier is for.
func BenchmarkProcPool(b *testing.B) {
	target := buildTarget(b, "nop")

	e := executor.NewProcPool("pool", safety.NewSpawner(), executor.ProcSpec{
		Path: target, Args: []string{target}, Timeout: time.Second,
	})
	if err := e.Start(context.Background()); err != nil {
		b.Skipf("the pool would not start here: %v", err)
	}
	defer e.Close()

	in := executor.Input{Bytes: []byte("Z\x00")}
	for i := 0; i < 10; i++ {
		if _, err := e.Run(context.Background(), in, nil); err != nil {
			b.Fatal(err)
		}
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := e.Run(context.Background(), in, nil); err != nil {
			b.Fatal(err)
		}
	}
	b.ReportMetric(float64(b.N)/b.Elapsed().Seconds(), "exec/s")
}

// BenchmarkSubprocessNop is the comparison BenchmarkProcPool is against: the
// same target on the tier that spawns in front of every execution.
func BenchmarkSubprocessNop(b *testing.B) {
	target := buildTarget(b, "nop")
	e := executor.NewSubprocess("sub", safety.NewSpawner(), executor.ProcSpec{
		Path: target, Args: []string{target}, Timeout: time.Second,
	})
	defer e.Close()
	in := executor.Input{Bytes: []byte("Z\x00")}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := e.Run(context.Background(), in, nil); err != nil {
			b.Fatal(err)
		}
	}
	b.ReportMetric(float64(b.N)/b.Elapsed().Seconds(), "exec/s")
}
