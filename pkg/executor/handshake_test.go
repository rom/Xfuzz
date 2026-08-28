package executor

import (
	"context"
	"encoding/binary"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

// A fork server's status pipe is the one thing in the executor that reads bytes
// chosen by the target. The target is the program being fuzzed, so those bytes
// are hostile by assumption — this is threat T2 in docs/SECURITY.md, and the row
// "Malformed fork-server handshake: rejected without memory corruption" in
// docs/TESTS.md section 12.
//
// What is asserted is not only that a bad handshake is refused, but that it is
// refused with an error naming what happened: the commonest cause by far is a
// target that was never instrumented, and a fuzzer that reports that as a
// generic failure costs somebody an afternoon.

// scriptedHandle is a fork server that says whatever the test tells it to.
type scriptedHandle struct {
	control *os.File
	status  *os.File
	peer    *os.File
	killed  bool
}

func newScriptedHandle(t *testing.T, reply []byte) *scriptedHandle {
	t.Helper()
	statusRead, statusWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	ctlRead, ctlWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { statusRead.Close(); statusWrite.Close(); ctlRead.Close(); ctlWrite.Close() })

	if len(reply) > 0 {
		go func() { statusWrite.Write(reply) }()
	} else {
		// Nothing at all, then end-of-file: a target that died before it could
		// speak, which is what an uninstrumented binary does.
		statusWrite.Close()
	}
	return &scriptedHandle{control: ctlWrite, status: statusRead, peer: statusWrite}
}

func (h *scriptedHandle) Pid() int          { return 4242 }
func (h *scriptedHandle) Control() *os.File { return h.control }
func (h *scriptedHandle) Status() *os.File  { return h.status }
func (h *scriptedHandle) Wait() (ProcResult, error) {
	return ProcResult{ExitCode: 1}, nil
}
func (h *scriptedHandle) Kill() error { h.killed = true; return nil }

// scriptedSpawner hands out a scripted fork server.
type scriptedSpawner struct {
	handle *scriptedHandle
	err    error
}

func (s *scriptedSpawner) Run(context.Context, ProcSpec) (ProcResult, error) {
	return ProcResult{}, errors.New("not supported")
}
func (s *scriptedSpawner) Start(context.Context, ProcSpec) (Handle, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.handle, nil
}
func (s *scriptedSpawner) IsolationLevel() string { return "none" }

func startWithReply(t *testing.T, reply []byte) (*ForkServer, *scriptedHandle, error) {
	t.Helper()
	h := newScriptedHandle(t, reply)
	fs := NewForkServer("fs", &scriptedSpawner{handle: h},
		ProcSpec{Path: "/bin/true", Args: []string{"/bin/true"}})
	// Short, because these tests are about what a bad handshake does rather
	// than about how long a good one may take.
	fs.HandshakeTimeout = 250 * time.Millisecond
	t.Cleanup(func() { fs.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return fs, h, fs.Start(ctx)
}

func TestForkServerRejectsSilence(t *testing.T) {
	_, h, err := startWithReply(t, nil)
	if err == nil {
		t.Fatal("a fork server that said nothing was accepted")
	}
	if !strings.Contains(err.Error(), "xfuzz-cc") {
		t.Errorf("the error does not point at the likely cause:\n%v", err)
	}
	if !h.killed {
		t.Error("the failed fork server was left running")
	}
}

func TestForkServerRejectsAWrongMagic(t *testing.T) {
	// Four bytes that are not the protocol's, which is what a target built
	// against a different runtime version sends.
	_, h, err := startWithReply(t, []byte{0xde, 0xad, 0xbe, 0xef})
	if err == nil {
		t.Fatal("a fork server with the wrong protocol word was accepted")
	}
	if !strings.Contains(err.Error(), "disagree about the protocol") {
		t.Errorf("the error does not say what is wrong:\n%v", err)
	}
	if !h.killed {
		t.Error("the mismatched fork server was left running")
	}
}

func TestForkServerRejectsATruncatedHandshake(t *testing.T) {
	// Three bytes of a four-byte word, then end of file. A reader that trusted
	// a short read would act on a partly initialised value.
	_, _, err := startWithReply(t, []byte{0x58, 0x46, 0x5a})
	if err == nil {
		t.Fatal("a truncated handshake was accepted")
	}
}

func TestForkServerRejectsAFloodOfGarbage(t *testing.T) {
	// A megabyte of noise. The handshake reads a fixed four bytes, so the rest
	// must be ignored rather than buffered: a reader sized by the sender is a
	// reader the target controls.
	flood := make([]byte, 1<<20)
	for i := range flood {
		flood[i] = byte(i)
	}
	_, _, err := startWithReply(t, flood)
	if err == nil {
		t.Fatal("a flood of garbage was accepted as a handshake")
	}
}

func TestForkServerAcceptsTheRealHandshake(t *testing.T) {
	// The negative tests above are only meaningful if the positive one passes:
	// otherwise they would pass against a fork server that rejected everything.
	var hello [4]byte
	binary.LittleEndian.PutUint32(hello[:], forkServerHello)
	_, h, err := startWithReply(t, hello[:])
	if err != nil {
		t.Fatalf("the real handshake was rejected: %v", err)
	}
	if h.killed {
		t.Error("a valid fork server was killed")
	}
}
