package triage

import (
	"bytes"
	"context"
	"encoding/binary"
	"hash/crc32"
	"testing"

	"github.com/rom/Xfuzz/pkg/ir"
)

// checksummedFormat is the smallest format that defeats byte-level
// minimisation: a sequence of records, each with a length and a CRC over
// itself. Deleting any byte inside a record invalidates both.
func checksummedRecord(tag string, payload []byte) *ir.Node {
	return ir.Struct("record",
		ir.Magic("tag", []byte(tag)),
		ir.LenOf("length", 2, ir.BigEndian, ir.Sibling("payload")),
		ir.Blob("payload", payload),
		ir.CRC("crc", "crc32", 4, ir.BigEndian, ir.Sibling("tag"), ir.Sibling("payload")),
	)
}

func checksummedFile(records ...*ir.Node) *ir.Node {
	return ir.Struct("file", ir.Magic("magic", []byte("REC0")),
		ir.Repeat("records", records...))
}

// parseChecksummed is the fake target: it walks the records, rejects the whole
// input on the first bad checksum, and fails when it sees the trigger record.
func parseChecksummed(in []byte) Outcome {
	if !bytes.HasPrefix(in, []byte("REC0")) {
		return ok()
	}
	off := 4
	for off+10 <= len(in) {
		tag := in[off : off+4]
		length := int(binary.BigEndian.Uint16(in[off+4 : off+6]))
		if off+10+length > len(in) {
			return ok()
		}
		claimed := binary.BigEndian.Uint32(in[off+6+length : off+10+length])
		// The CRC covers the span from the tag through the payload, which
		// includes the length field between them.
		if claimed != crc32.ChecksumIEEE(in[off:off+6+length]) {
			return ok()
		}
		if string(tag) == "BOOM" {
			return crash(11, "")
		}
		off += 10 + length
	}
	return ok()
}

func checksummedRunner() *fakeRunner {
	return &fakeRunner{fn: parseChecksummed}
}

func TestStructuredMinimizationBeatsByteMinimizationOnChecksums(t *testing.T) {
	ctx := context.Background()
	pad := func() *ir.Node { return checksummedRecord("PADD", make([]byte, 64)) }
	tree := checksummedFile(pad(), pad(), pad(),
		checksummedRecord("BOOM", []byte{1}), pad(), pad(), pad())

	encoded, err := ir.NewFixer().Fix(tree, ir.Suppress{})
	if err != nil {
		t.Fatal(err)
	}
	input := append([]byte(nil), encoded...)

	// The premise: the input fails, and the fake target agrees.
	if !parseChecksummed(input).Crashed() {
		t.Fatal("the constructed input does not reach the trigger")
	}

	_, byteRep, err := Minimize(ctx, checksummedRunner(), input, MinimizeOptions{MaxRuns: 5000})
	if err != nil {
		t.Fatalf("byte minimisation: %v", err)
	}

	_, structBytes, structRep, err := MinimizeStructured(ctx, checksummedRunner(), tree,
		MinimizeOptions{MaxRuns: 5000})
	if err != nil {
		t.Fatalf("structured minimisation: %v", err)
	}

	if structRep.Reduction() < 0.80 {
		t.Errorf("structured minimisation reduced only %.0f%%: %s",
			100*structRep.Reduction(), structRep)
	}
	if structRep.Reduction() <= byteRep.Reduction() {
		t.Errorf("structured minimisation (%s) did no better than byte minimisation (%s); "+
			"on a checksummed format it must", structRep, byteRep)
	}
	if !parseChecksummed(structBytes).Crashed() {
		t.Fatal("the structured minimum no longer fails")
	}
	t.Logf("bytes: %s", byteRep)
	t.Logf("structured: %s", structRep)
}

func TestStructuredMinimizationRespectsRepeatMinimum(t *testing.T) {
	ctx := context.Background()
	tree := checksummedFile(checksummedRecord("BOOM", []byte{1}),
		checksummedRecord("PADD", make([]byte, 32)),
		checksummedRecord("PADD", make([]byte, 32)))
	// The format insists on at least two records. A minimiser that ignores the
	// bound produces an input the format does not admit, which is not a
	// reproducer at all.
	tree.Children[1].MinLen = 2

	out, _, _, err := MinimizeStructured(ctx, checksummedRunner(), tree, MinimizeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if got := len(out.Children[1].Children); got < 2 {
		t.Fatalf("minimised to %d records, below the format's minimum of 2", got)
	}
}

func TestStructuredMinimizationShrinksPayloads(t *testing.T) {
	ctx := context.Background()
	tree := checksummedFile(checksummedRecord("BOOM", make([]byte, 512)))

	out, encoded, rep, err := MinimizeStructured(ctx, checksummedRunner(), tree, MinimizeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	payload := out.Children[1].Children[0].Children[2]
	if len(payload.Raw) > 8 {
		t.Errorf("the payload was only reduced to %d bytes: %s", len(payload.Raw), rep)
	}
	if !parseChecksummed(encoded).Crashed() {
		t.Fatal("the minimum no longer fails")
	}
}

func TestStructuredMinimizationRefusesANonFailingInput(t *testing.T) {
	tree := checksummedFile(checksummedRecord("PADD", []byte{1}))
	_, _, _, err := MinimizeStructured(context.Background(), checksummedRunner(), tree, MinimizeOptions{})
	if err == nil {
		t.Fatal("minimising a non-failing tree reported success")
	}
}

func TestStructuredMinimizationNeedsATree(t *testing.T) {
	_, _, _, err := MinimizeStructured(context.Background(), checksummedRunner(), nil, MinimizeOptions{})
	if err == nil {
		t.Fatal("minimising a nil tree reported success")
	}
}

func TestWorkerUsesStructuredMinimizationWhenGivenATree(t *testing.T) {
	pad := func() *ir.Node { return checksummedRecord("PADD", make([]byte, 64)) }
	tree := checksummedFile(pad(), pad(), checksummedRecord("BOOM", []byte{1}), pad(), pad())
	encoded, err := ir.NewFixer().Fix(tree, ir.Suppress{})
	if err != nil {
		t.Fatal(err)
	}
	input := append([]byte(nil), encoded...)

	w := NewWorker(Config{Runner: checksummedRunner(), Trials: 1, Strategy: SignalStrategy{}})
	res := w.Triage(context.Background(), Job{ID: 1, Input: input, Node: tree})

	if res.Err != nil {
		t.Fatal(res.Err)
	}
	if res.MinimizedNode == nil {
		t.Fatal("the worker did not produce a minimised tree")
	}
	if res.Minimize.Reduction() < 0.80 {
		t.Fatalf("reduction = %s", res.Minimize)
	}
	if !parseChecksummed(res.Minimized).Crashed() {
		t.Fatal("the minimised reproducer no longer fails")
	}
}
