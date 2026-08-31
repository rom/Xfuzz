// Command magic_go is a planted-bug target written in Go, for the coverage
// backend that reads a compiler's inline counters rather than a callback.
//
// It exists because the interesting claim is about the *language*, not the
// program: a Go binary carries no clang instrumentation and, until this backend,
// had no coverage at all. So the bug here is deliberately shallow — a header, a
// length, a bounds mistake — and what the test measures is whether coverage
// grows as an input gets further in, not whether the fuzzer is clever.
package main

import (
	"encoding/binary"
	"io"
	"os"
)

func main() {
	in, err := io.ReadAll(os.Stdin)
	if err != nil {
		return
	}
	parse(in)
}

// parse reads a tiny length-prefixed format: "GOFZ", a one-byte kind, a
// two-byte big-endian length, and that many bytes of payload.
func parse(b []byte) {
	if len(b) < 7 || string(b[:4]) != "GOFZ" {
		return
	}
	kind := b[4]
	n := int(binary.BigEndian.Uint16(b[5:7]))
	body := b[7:]

	switch kind {
	case 1:
		// The bug. The declared length is trusted against the body that is
		// actually there, so a header claiming more than it carries indexes past
		// the end. A Go slice bound turns that into a panic rather than a read
		// of somebody else's memory, which is the whole difference between this
		// and the C targets — and it is still a crash the fuzzer must find.
		sum := 0
		for i := 0; i < n; i++ {
			sum += int(body[i])
		}
		if sum > 1000 {
			os.Stdout.WriteString("heavy\n")
		}
	case 2:
		if n <= len(body) {
			os.Stdout.Write(body[:n])
		}
	case 3:
		if len(body) > 2 && body[0] == 'x' && body[1] == 'y' && body[2] == 'z' {
			os.Stdout.WriteString("xyz\n")
		}
	}
}
