package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/rom/Xfuzz/internal/daemon"
)

// eventStream serves the live event stream as server-sent events.
//
// SSE rather than a WebSocket because the stream is server-to-client by design
// (ARCHITECTURE section 9): there is nothing for the client to send, SSE needs
// no framing library, and it reconnects on its own. A browser can consume it
// with three lines and no dependencies, and `curl` can consume it with none.
//
// The stream is lossy and says so. When a subscriber falls behind, the bus drops
// events and counts them; that count is reported in the stream itself, because a
// client showing an incomplete picture must be able to tell the difference
// between a quiet campaign and one it has stopped keeping up with.
func (s *Server) eventStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError,
			fmt.Errorf("this server cannot stream events"))
		return
	}

	kinds := parseKinds(r.URL.Query().Get("kinds"))
	campaignFilter := r.URL.Query().Get("campaign")

	sub := s.daemon.Bus().Subscribe(s.EventQueue, kinds...)
	defer sub.Close()

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	// Without this an intermediary may buffer the whole stream, which turns a
	// live view into a view that arrives when the campaign ends.
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	keepAlive := time.NewTicker(durationOrDefault(s.KeepAlive, 20*time.Second))
	defer keepAlive.Stop()

	var lastReported uint64
	for {
		select {
		case <-r.Context().Done():
			return

		case e, open := <-sub.Events():
			if !open {
				return
			}
			if campaignFilter != "" && e.Campaign != campaignFilter {
				continue
			}
			if dropped := sub.Dropped(); dropped != lastReported {
				// Told as an event of its own rather than a field on the next
				// one, so a client that ignores it still sees it in the log.
				writeSSE(w, "dropped", map[string]any{
					"dropped": dropped,
					"note": "events were dropped because this client fell behind; " +
						"the campaign was not slowed down",
				})
				lastReported = dropped
			}
			if !writeSSE(w, string(e.Kind), e) {
				return
			}
			flusher.Flush()

		case <-keepAlive.C:
			// A comment line. It keeps intermediaries from deciding an idle
			// stream is a dead one, and costs two bytes.
			if _, err := fmt.Fprint(w, ": keep-alive\n\n"); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}

// writeSSE writes one event frame. It reports whether the write succeeded.
func writeSSE(w http.ResponseWriter, kind string, v any) bool {
	b, err := json.Marshal(v)
	if err != nil {
		return true
	}
	if _, err := fmt.Fprintf(w, "event: %s\ndata: %s\n\n", kind, b); err != nil {
		return false
	}
	return true
}

// parseKinds turns a comma-separated filter into event kinds.
//
// An unknown kind is dropped rather than rejected: a newer console asking for a
// kind an older daemon does not publish should get the kinds it does publish,
// not an error.
func parseKinds(s string) []daemon.EventKind {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	known := map[string]daemon.EventKind{
		"metrics": daemon.EventMetrics, "coverage": daemon.EventCoverage,
		"corpus": daemon.EventCorpus, "finding": daemon.EventFinding,
		"triage": daemon.EventTriage, "worker": daemon.EventWorker,
		"campaign": daemon.EventCampaign, "log": daemon.EventLog,
	}
	var out []daemon.EventKind
	for _, part := range strings.Split(s, ",") {
		if k, ok := known[strings.TrimSpace(part)]; ok {
			out = append(out, k)
		}
	}
	return out
}
