package client

import (
	"bufio"
	"io"
	"strings"
)

// readSSE parses a server-sent event stream.
//
// The whole format: "event:" and "data:" lines, a blank line ends a frame, a
// line starting with ":" is a comment. Written out rather than pulled in as a
// dependency because it is fifteen lines and the alternative is a library to
// keep in step with.
func readSSE(r io.Reader, fn func(kind string, data []byte) bool) error {
	sc := bufio.NewScanner(r)
	// Events carry coverage maps and corpus payloads, so the default 64 KiB
	// line limit is not enough.
	sc.Buffer(make([]byte, 0, 1<<16), maxResponseBytes)

	var (
		kind string
		data strings.Builder
	)
	for sc.Scan() {
		line := sc.Text()
		switch {
		case line == "":
			if data.Len() > 0 {
				if !fn(kind, []byte(data.String())) {
					return nil
				}
			}
			kind, data = "", strings.Builder{}

		case strings.HasPrefix(line, ":"):
			// A keep-alive comment.

		case strings.HasPrefix(line, "event:"):
			kind = strings.TrimSpace(strings.TrimPrefix(line, "event:"))

		case strings.HasPrefix(line, "data:"):
			if data.Len() > 0 {
				data.WriteByte('\n')
			}
			data.WriteString(strings.TrimSpace(strings.TrimPrefix(line, "data:")))
		}
	}
	return sc.Err()
}
