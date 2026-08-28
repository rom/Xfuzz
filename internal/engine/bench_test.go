package engine

import (
	"context"
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
