package binary_test

import (
	"bufio"
	"encoding/hex"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"

	"github.com/rom/Xfuzz/pkg/binary"
)

// TestDecodeKnownEncodings checks the encodings that are easy to get wrong, by
// hand, so a failure names the rule that broke rather than an address in a
// binary.
func TestDecodeKnownEncodings(t *testing.T) {
	cases := []struct {
		name string
		hex  string
		len  int
		kind binary.Kind
		to   uint64 // absolute target, when the kind has one
	}{
		{"push rbp", "55", 1, binary.KindOther, 0},
		{"ret", "c3", 1, binary.KindReturn, 0},
		{"int3", "cc", 1, binary.KindTrap, 0},
		{"ud2", "0f0b", 2, binary.KindTrap, 0},
		{"nop", "90", 1, binary.KindOther, 0},

		// Immediates whose width depends on a prefix.
		{"mov eax, imm32", "b878563412", 5, binary.KindOther, 0},
		{"mov ax, imm16 (66)", "66b83412", 4, binary.KindOther, 0},
		{"movabs rax, imm64 (rex.w)", "48b80102030405060708", 10, binary.KindOther, 0},
		{"add eax, imm32", "0578563412", 5, binary.KindOther, 0},
		{"add ax, imm16 (66)", "66053412", 4, binary.KindOther, 0},

		// Addressing forms.
		{"mov rax,[rbx]", "488b03", 3, binary.KindOther, 0},
		{"mov rax,[rbx+0x10]", "488b4310", 4, binary.KindOther, 0},
		{"mov rax,[rbx+0x1000]", "488b8300100000", 7, binary.KindOther, 0},
		{"mov rax,[rip+0x0]", "488b0500000000", 7, binary.KindOther, 0},
		{"mov rax,[rsp]", "488b0424", 4, binary.KindOther, 0},
		{"mov rax,[rsp+0x10]", "488b442410", 5, binary.KindOther, 0},
		{"mov eax,[rcx*4+0x0]", "8b048d00000000", 7, binary.KindOther, 0},

		// The F6/F7 group, where /0 and /1 alone carry an immediate.
		{"test byte [rax], imm8", "f60001", 3, binary.KindOther, 0},
		{"not qword [rax]", "48f710", 3, binary.KindOther, 0},
		{"test dword [rax], imm32", "f70001000000", 6, binary.KindOther, 0},

		// Branches, and their absolute targets from a known pc.
		{"jmp rel8", "eb05", 2, binary.KindJump, 0x1007},
		{"jmp rel32", "e900010000", 5, binary.KindJump, 0x1105},
		{"je rel8", "7410", 2, binary.KindCondJump, 0x1012},
		{"je rel32 (0f 84)", "0f8400010000", 6, binary.KindCondJump, 0x1106},
		{"call rel32", "e8fbffffff", 5, binary.KindCall, 0x1000},
		{"call rax", "ffd0", 2, binary.KindIndirectCall, 0},
		{"jmp rax", "ffe0", 2, binary.KindIndirectJump, 0},
		{"jmp [rip+0x0]", "ff2500000000", 6, binary.KindIndirectJump, 0},
		{"push qword [rax]", "ff30", 2, binary.KindOther, 0},

		// Backwards, which is where a sign error shows up.
		{"jmp rel8 backwards", "ebfe", 2, binary.KindJump, 0x1000},

		// SSE and VEX, which must measure correctly even though nothing here
		// reads them.
		{"movaps xmm0,[rdi]", "0f2807", 3, binary.KindOther, 0},
		{"pshufd xmm0,xmm1,0x0", "660f70c100", 5, binary.KindOther, 0},
		{"vzeroupper (2-byte vex)", "c5f877", 3, binary.KindOther, 0},
		{"vpxor (2-byte vex)", "c5f9efc0", 4, binary.KindOther, 0},
		{"vpermq (3-byte vex, imm8)", "c4e3fd00c100", 6, binary.KindOther, 0},
		{"pcmpeqb (0f 38)", "660f3829c1", 5, binary.KindOther, 0},

		// enter, whose two immediates are the only such encoding.
		{"enter 0x10,0", "c8100000", 4, binary.KindOther, 0},
		{"ret imm16", "c21000", 3, binary.KindReturn, 0},

		// Segment-prefixed, which compilers emit for thread-local storage.
		{"mov rax,fs:[0x28]", "64488b0425 28000000", 9, binary.KindOther, 0},
	}

	const pc = 0x1000
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			code, err := hex.DecodeString(strings.ReplaceAll(c.hex, " ", ""))
			if err != nil {
				t.Fatal(err)
			}
			in, err := binary.Decode(code, pc)
			if err != nil {
				t.Fatalf("decoding %s: %v", c.hex, err)
			}
			if in.Len != c.len {
				t.Errorf("length %d, want %d", in.Len, c.len)
			}
			if in.Kind != c.kind {
				t.Errorf("kind %v, want %v", in.Kind, c.kind)
			}
			if c.to != 0 {
				if !in.HasTarget {
					t.Fatalf("no target; want %#x", c.to)
				}
				if in.Target != c.to {
					t.Errorf("target %#x, want %#x", in.Target, c.to)
				}
			}
		})
	}
}

// TestDecodeRefusesRatherThanGuesses checks the two failure modes stay
// distinguishable, because a caller treats them differently: a truncated
// instruction means "read more bytes", an undecodable one means "stop here".
func TestDecodeRefusesRatherThanGuesses(t *testing.T) {
	if _, err := binary.Decode(nil, 0); err == nil {
		t.Error("decoding nothing succeeded")
	}
	// A four-byte immediate with only two bytes present.
	if _, err := binary.Decode([]byte{0xb8, 0x01, 0x02}, 0); err == nil {
		t.Error("decoding a truncated immediate succeeded")
	}
	// 0x06 is PUSH ES, which does not exist in 64-bit mode.
	if _, err := binary.Decode([]byte{0x06}, 0); err == nil {
		t.Error("decoding a 32-bit-only opcode succeeded")
	}
	// A prefix run with no opcode after it must not loop.
	if _, err := binary.Decode([]byte{0x66, 0x66, 0x66, 0x66}, 0); err == nil {
		t.Error("decoding a bare prefix run succeeded")
	}
}

// TestDecodeAgreesWithObjdump is the assertion that matters.
//
// Hand-written cases check the rules the author thought of. This checks every
// instruction a real compiler and a real linker actually emitted, against a
// disassembler nobody here wrote — which is the only way to find the encoding
// that was never considered. It runs over whatever large binaries the host has,
// because the point is variety: a C program built here, the Go toolchain's own
// output, and the system's own C library consumers between them cover hand-
// written assembly, AVX, and every addressing form in use.
//
// The comparison is per-instruction rather than per-sweep: objdump's address for
// an instruction is compared against this decoder's length at that same address.
// That way a single disagreement is reported once, at its address, instead of
// desynchronising the rest of the section into thousands of false differences.
func TestDecodeAgreesWithObjdump(t *testing.T) {
	if testing.Short() {
		t.Skip("this disassembles several megabytes")
	}
	objdump, err := exec.LookPath("objdump")
	if err != nil {
		t.Skip("objdump is not installed; this is the only external check of the decoder")
	}

	candidates := []string{
		exeOf(t), // the test binary itself: Go's assembler output
		"/bin/ls", "/usr/bin/ls",
		"/usr/bin/objdump",
		"/bin/bash", "/usr/bin/bash",
	}
	ran := 0
	for _, path := range candidates {
		st, err := os.Stat(path)
		if err != nil || st.IsDir() {
			continue
		}
		if !runObjdumpComparison(t, objdump, path) {
			continue
		}
		ran++
	}
	if ran == 0 {
		t.Skip("no comparable binary on this host")
	}
}

func exeOf(t *testing.T) string {
	p, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// runObjdumpComparison decodes every instruction objdump found and reports
// whether the file was usable at all.
func runObjdumpComparison(t *testing.T, objdump, path string) bool {
	t.Helper()

	img, err := binary.Open(path)
	if err != nil {
		t.Logf("%s: %v", path, err)
		return false
	}
	defer img.Close()
	if img.Arch != binary.ArchAMD64 {
		t.Logf("%s: %v, not amd64", path, img.Arch)
		return false
	}

	cmd := exec.Command(objdump, "-d", "--no-show-raw-insn", "-j", ".text", path)
	out, err := cmd.Output()
	if err != nil {
		t.Logf("%s: objdump: %v", path, err)
		return false
	}

	var checked, bad int
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	sc.Buffer(make([]byte, 1<<20), 1<<20)

	var prev uint64
	var havePrev bool
	report := func(addr uint64) {
		// objdump's next address minus this one is the length it decoded.
		want := int(addr - prev)
		code, ok := img.At(prev, maxInst)
		if !ok {
			havePrev = false
			return
		}
		in, err := binary.Decode(code, prev)
		checked++
		switch {
		case err != nil:
			bad++
			if bad <= 10 {
				t.Errorf("%s: %#x: %v (objdump says %d bytes: % x)",
					path, prev, err, want, code[:min(want, len(code))])
			}
		case in.Len != want:
			bad++
			if bad <= 10 {
				t.Errorf("%s: %#x: decoded %d bytes, objdump %d (% x)",
					path, prev, in.Len, want, code[:min(want, len(code))])
			}
		}
	}

	for sc.Scan() {
		line := sc.Text()
		addr, ok := objdumpAddr(line)
		if !ok {
			havePrev = false
			continue
		}
		if strings.Contains(line, "(bad)") {
			// objdump could not decode it either, so there is nothing to
			// compare against and the next address is not a boundary this
			// decoder should be held to.
			havePrev = false
			prev = addr
			continue
		}
		if havePrev && addr > prev && addr-prev <= maxInst {
			report(addr)
		}
		prev, havePrev = addr, true
	}

	if checked < 1000 {
		t.Logf("%s: only %d instructions compared", path, checked)
		return checked > 0
	}
	t.Logf("%s: %d instructions, %d disagreements", path, checked, bad)
	return true
}

const maxInst = 16

// objdumpAddr pulls the address off a disassembly line, which looks like
// "  1150:\tpush   %rbp".
func objdumpAddr(line string) (uint64, bool) {
	i := strings.IndexByte(line, ':')
	if i <= 0 {
		return 0, false
	}
	f := strings.TrimSpace(line[:i])
	if f == "" || strings.ContainsAny(f, " \t<") {
		return 0, false
	}
	v, err := strconv.ParseUint(f, 16, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}
