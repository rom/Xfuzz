package driver

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rom/Xfuzz/internal/testenv"
	"github.com/rom/Xfuzz/pkg/executor"
	"github.com/rom/Xfuzz/pkg/feedback"
)

// The tier over the backend, which is where a campaign's input actually
// becomes a sequence of events: everything between a corpus entry and a finding
// runs here, and none of it knows which backend it has.
func TestWebTierTurnsASeedIntoAFinding(t *testing.T) {
	browser := testenv.Browser(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(plantedPage))
	}))
	defer srv.Close()

	backend := NewWeb(webSpawner(), WebOptions{
		URL: srv.URL, Browser: browser, BrowserSandbox: false,
		Width: 400, Height: 300,
		Settle: 60 * time.Millisecond, MaxSettle: 2 * time.Second,
		StartTimeout: 45 * time.Second,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			var dl net.Dialer
			return dl.DialContext(ctx, network, address)
		},
	})
	e := executor.NewDriver("web", backend, executor.DriverOptions{
		Timeout: 30 * time.Second, Settle: 60 * time.Millisecond, MaxEvents: 16,
	})
	out := feedback.NewOutputObserver("output")
	e.Output = out
	defer e.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if err := e.Start(ctx); err != nil {
		t.Fatalf("starting: %v", err)
	}

	// The seed a campaign file would carry, in the encoding the events codec
	// reads: one event per line.
	seed := []byte("click 100,20\ntext xyzz\nkey y\n")
	ek, err := e.Run(ctx, executor.Input{Bytes: seed}, []feedback.Observer{out})
	if err != nil {
		t.Fatalf("running the sequence: %v", err)
	}
	t.Logf("exit %v, skipped %d, stderr %q", ek, e.Skipped(), out.Stderr())

	oracle := feedback.NewUIExceptionObjective("ui-exception", out)
	found, f, err := oracle.IsFinding(nil, ek)
	if err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Fatalf("the seed reached the planted bug but no finding came out; "+
			"the tier recorded stderr %q and skipped %d events", out.Stderr(), e.Skipped())
	}
	if !strings.Contains(f.Detail, "explode") {
		t.Errorf("the finding does not name what failed: %+v", f)
	}
	if len(f.Frames) == 0 {
		t.Error("the finding has no frame, so two different exceptions would bucket together")
	}
}
