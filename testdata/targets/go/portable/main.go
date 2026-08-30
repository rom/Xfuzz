// Command portable is a planted-bug target that needs no C toolchain.
//
// Every other target here is C compiled through xfuzz-cc, which gives coverage
// instrumentation and needs clang. This one exists for the platforms where that
// is not the path: macOS and Windows run subprocess campaigns black-box
// (ADR-0020), and a criterion that cannot be measured without clang is a
// criterion those platforms never actually meet.
//
// It is deliberately chatty. A black-box campaign has no coverage map; what it
// has is the exit status and what the target said, so a target that says the
// same thing about every input gives novelty feedback nothing to work with —
// and would test the harness rather than the fuzzer.
//
// XFUZZ-BUGS: 2
package main

import (
	"fmt"
	"io"
	"os"
)

func main() {
	in, err := io.ReadAll(io.LimitReader(os.Stdin, 1<<16))
	if err != nil || len(in) == 0 {
		fmt.Println("empty")
		return
	}
	parse(in)
}

func parse(in []byte) {
	// Something to say that distinguishes regions of the input space without
	// distinguishing every input in one.
	//
	// The classes are coarse on purpose. Printing the exact length and first
	// byte would make almost every input novel, and a black-box campaign
	// against a target like that admits everything: the corpus becomes a copy
	// of the search rather than a summary of it. Measured before this: 2,430
	// entries kept out of 4,048 executions.
	fmt.Printf("kind=%s size=%s\n", class(in[0]), sizeClass(len(in)))

	switch in[0] {
	case 'A':
		// Bug 1: an index taken from the input and trusted. Two bytes deep, so
		// a black-box campaign that keeps what it learns reaches it and one
		// that mutates at random mostly does not.
		if len(in) < 3 {
			fmt.Println("A: short")
			return
		}
		table := []string{"alpha", "beta", "gamma"}
		fmt.Println("A:", table[int(in[1])%4]) // 4, not 3: index 3 is out of range

	case 'B':
		// Bug 2: a length prefix trusted over the bytes that follow.
		if len(in) < 2 {
			fmt.Println("B: short")
			return
		}
		want := int(in[1])
		// Copied so that its capacity is its length. Re-slicing the read
		// buffer instead would read past the message into bytes the last input
		// left behind — a real bug, and a quieter one than this target is for:
		// it produces wrong output rather than a crash, and a black-box
		// campaign has no way to notice.
		body := append([]byte(nil), in[2:]...)
		fmt.Println("B:", string(body[:want]))

	case 'C':
		fmt.Println("C: nothing here")

	default:
		fmt.Println("unrecognised")
	}
}

// class names the branch an input takes, without naming the input.
func class(b byte) string {
	switch b {
	case 'A', 'B', 'C':
		return string(b)
	default:
		return "other"
	}
}

// sizeClass buckets a length logarithmically, the way a coverage map buckets a
// hit count: enough to tell a short input from a long one, not enough to tell
// two short ones apart.
func sizeClass(n int) string {
	switch {
	case n < 4:
		return "tiny"
	case n < 16:
		return "small"
	case n < 256:
		return "medium"
	default:
		return "large"
	}
}
