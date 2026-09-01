package tracer_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rom/Xfuzz/internal/safety"
	"github.com/rom/Xfuzz/internal/testenv"
	"github.com/rom/Xfuzz/internal/tracer"
	"github.com/rom/Xfuzz/pkg/binary"
	"github.com/rom/Xfuzz/pkg/executor"
	"github.com/rom/Xfuzz/pkg/feedback"
)

// The qemu and frida backends drive tools that are not installed on most hosts,
// and were not installed on the host where they were written. Leaving them
// untested until someone happens to have both would mean shipping two backends
// nobody has run.
//
// So the tools are stood in for. A stub emulator runs the guest and writes the
// execution log QEMU writes; a stub instrumentation tool runs the target and
// writes the DRcov file a Stalker agent writes. Everything on this side of the
// boundary is then exercised for real: the command that is built, the process
// that is spawned through the safety layer, the file that is read back, the
// addresses that are rebased, the map that is folded, the exit status that is
// classified.
//
// What it does not test is the tools' own semantics — whether QEMU's log really
// lists every translation block, whether Stalker really sees every compile. That
// needs the tools, and the tests below that do use them skip when they are
// absent, so a host that has them checks the rest.

// stubTool writes a Go program into dir under the given name and builds it.
func stubTool(t *testing.T, dir, name, src string) string {
	t.Helper()
	sub := filepath.Join(dir, name+"-src")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, "main.go"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, "go.mod"), []byte("module stub\n\ngo 1.24\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, testenv.ExeName(name))
	cmd := exec.Command("go", "build", "-o", out, ".")
	cmd.Dir = sub
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("building the %s stub: %v\n%s", name, err, b)
	}
	if err := os.Chmod(out, 0o755); err != nil {
		t.Fatal(err)
	}
	return out
}

// The stub emulator: parses the arguments the qemu backend passes, runs the
// guest for real, and writes an execution log naming blocks of the guest image
// at a load base of its own choosing — which is exactly the problem the backend
// has to solve, since QEMU does not report where it put the guest either.
const qemuStubSrc = `
package main

import (
	"debug/elf"
	"debug/pe"
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"sort"
)

const base = 0x5555_5555_4000

func main() {
	args := os.Args[1:]
	var logPath string
	var guest []string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-d":
			i++
		case "-D":
			i++
			logPath = args[i]
		case "--":
			guest = args[i+1:]
			i = len(args)
		}
	}
	if len(guest) == 0 {
		fmt.Fprintln(os.Stderr, "stub: no guest")
		os.Exit(2)
	}

	// Which blocks "ran" is decided by the guest's own exit status, so the
	// backend sees more coverage for an input that got further -- the property
	// the tier exists to provide.
	cmd := exec.Command(guest[0], guest[1:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	err := cmd.Run()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		fmt.Fprintln(os.Stderr, "stub:", err)
		os.Exit(2)
	}

	addrs := textAddrs(guest[0])
	n := 4 + code*3
	if n > len(addrs) {
		n = len(addrs)
	}
	f, ferr := os.Create(logPath)
	if ferr != nil {
		fmt.Fprintln(os.Stderr, "stub:", ferr)
		os.Exit(2)
	}
	for _, a := range addrs[:n] {
		fmt.Fprintf(f, "Trace 0: 0x7f0000000000 [00000000/%016x/00000033/ff020000]\n", base+a)
	}
	f.Close()
	os.Exit(code)
}
` + stubTextAddrsSrc

// The stub instrumentation tool: runs the target and writes a DRcov file, the
// way a Stalker agent does.
const fridaStubSrc = `
package main

import (
	"debug/elf"
	"debug/pe"
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
)

func main() {
	args := os.Args[1:]
	var agent string
	var target []string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-l":
			i++
			agent = args[i]
		case "-f":
			target = args[i+1:]
			i = len(args)
		case "-q", "--stdio=pipe":
		default:
			if strings.HasPrefix(args[i], "--runtime=") {
				continue
			}
		}
	}
	if agent == "" || len(target) == 0 {
		fmt.Fprintln(os.Stderr, "stub: no agent or no target")
		os.Exit(2)
	}
	// The output path is baked into the agent as a literal, exactly as the
	// backend writes it.
	src, err := os.ReadFile(agent)
	if err != nil {
		fmt.Fprintln(os.Stderr, "stub:", err)
		os.Exit(2)
	}
	out := between(string(src), "const OUTPUT = '", "';")
	if out == "" {
		fmt.Fprintln(os.Stderr, "stub: the agent names no output file")
		os.Exit(2)
	}

	cmd := exec.Command(target[0], target[1:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	rerr := cmd.Run()
	code := 0
	if ee, ok := rerr.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if rerr != nil {
		fmt.Fprintln(os.Stderr, "stub:", rerr)
		os.Exit(2)
	}

	addrs := textAddrs(target[0])
	n := 4 + code*3
	if n > len(addrs) {
		n = len(addrs)
	}
	writeDRcov(out, target[0], addrs[:n])
	os.Exit(code)
}

func between(s, a, b string) string {
	i := strings.Index(s, a)
	if i < 0 {
		return ""
	}
	rest := s[i+len(a):]
	j := strings.Index(rest, b)
	if j < 0 {
		return ""
	}
	return rest[:j]
}

func writeDRcov(path, module string, offsets []uint64) {
	f, err := os.Create(path)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprint(f, "DRCOV VERSION: 2\n")
	fmt.Fprint(f, "DRCOV FLAVOR: stub\n")
	fmt.Fprint(f, "Module Table: version 2, count 2\n")
	fmt.Fprint(f, "Columns: id, base, end, entry, checksum, timestamp, path\n")
	fmt.Fprintf(f, "  0, 0x%016x, 0x%016x, 0x0, 0x0, 0x0, %s\n", 0x555555554000, 0x555555600000, module)
	fmt.Fprintf(f, "  1, 0x%016x, 0x%016x, 0x0, 0x0, 0x0, /lib/libc.so.6\n", 0x7ffff7dd7000, 0x7ffff7ff4000)
	fmt.Fprintf(f, "BB Table: %d bbs\n", len(offsets)+1)
	for _, o := range offsets {
		binary.Write(f, binary.LittleEndian, struct {
			Offset uint32
			Size   uint16
			Module uint16
		}{uint32(o), 16, 0})
	}
	// One block from another module, which must not reach the target's map.
	binary.Write(f, binary.LittleEndian, struct {
		Offset uint32
		Size   uint16
		Module uint16
	}{0x900, 16, 1})
}
` + stubTextAddrsSrc

// stubTextAddrsSrc is the half of both stubs that decides which addresses a
// trace would contain: where the guest's functions begin, as offsets into the
// module, which is what a real tool reports and what the backends rebase.
//
// An ELF names them in its symbol table. A PE names them nowhere — the
// Microsoft toolchain writes names to a separate PDB, so an ordinary Windows
// build has no symbol table at all — and its exception directory is read
// instead, which the x64 ABI requires an entry in for every non-leaf function.
// Without the second half a stub on Windows reports an empty trace, and the
// backend under test is handed nothing to rebase.
const stubTextAddrsSrc = `

func textAddrs(path string) []uint64 {
	if out := elfFuncs(path); len(out) > 0 {
		return out
	}
	return peFuncs(path)
}

func elfFuncs(path string) []uint64 {
	fh, err := elf.Open(path)
	if err != nil {
		return nil
	}
	defer fh.Close()
	var out []uint64
	syms, _ := fh.Symbols()
	for _, s := range syms {
		if elf.ST_TYPE(s.Info) == elf.STT_FUNC && s.Value != 0 {
			out = append(out, s.Value)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func peFuncs(path string) []uint64 {
	fh, err := pe.Open(path)
	if err != nil {
		return nil
	}
	defer fh.Close()
	var pdata []byte
	for _, sec := range fh.Sections {
		if sec.Name != ".pdata" {
			continue
		}
		b, err := sec.Data()
		if err != nil {
			return nil
		}
		if sec.VirtualSize > 0 && uint32(len(b)) > sec.VirtualSize {
			b = b[:sec.VirtualSize]
		}
		pdata = b
	}
	var out []uint64
	for i := 0; i+12 <= len(pdata); i += 12 {
		rva := binary.LittleEndian.Uint32(pdata[i:])
		if rva != 0 {
			out = append(out, uint64(rva))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
`

// ladderExitSrc reports how far the input got through its exit status, so a
// stub tool can turn "got further" into "covered more" without pretending to
// emulate anything.
const ladderExitSrc = `
#include <stdio.h>
int main(void) {
	char b[64];
	size_t n = fread(b, 1, sizeof b - 1, stdin);
	b[n] = 0;
	if (n < 1 || b[0] != 'F') return 0;
	if (n < 2 || b[1] != 'U') return 1;
	if (n < 3 || b[2] != 'Z') return 2;
	if (n < 4 || b[3] != 'Z') return 3;
	return 4;
}
`

func buildUnstripped(t *testing.T, dir, src string) string {
	t.Helper()
	cc, err := exec.LookPath("clang")
	if err != nil {
		if cc, err = exec.LookPath("gcc"); err != nil {
			t.Skip("no C compiler")
		}
	}
	in := filepath.Join(dir, "t.c")
	if err := os.WriteFile(in, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	// With the platform's extension, because Windows decides what may be
	// executed by it: a file named "target" cannot be started at all, and the
	// stub tool that tries reports only that it could not run the guest.
	out := filepath.Join(dir, testenv.ExeName("target"))
	if b, err := exec.Command(cc, "-O0", "-o", out, in).CombinedOutput(); err != nil {
		t.Skipf("compiling the fixture failed (%v): %s", err, b)
	}
	return out
}

func TestQemuBackendAgainstAStubEmulator(t *testing.T) {
	if testing.Short() {
		t.Skip("this builds a stub tool")
	}
	dir := testenv.ReachableDir(t)
	target := buildUnstripped(t, dir, ladderExitSrc)
	stub := stubTool(t, dir, "qemu-x86_64", qemuStubSrc)

	q := tracer.NewQemu(safety.NewSpawner(), target)
	q.Emulator = stub
	e := executor.NewEmulated("t5-qemu", q, executor.ProcSpec{
		Path: target, Args: []string{target}, Timeout: 20 * time.Second,
	})
	cov := feedback.NewCoverageMap("coverage", feedback.DefaultMapSize)
	e.Coverage = cov
	if err := e.Start(t.Context()); err != nil {
		t.Fatalf("the qemu backend would not start against the stub: %v", err)
	}
	defer e.Close()

	covered := func(in string) int {
		cov.Reset()
		if _, err := e.Run(t.Context(), executor.Input{Bytes: []byte(in)}, nil); err != nil {
			t.Fatalf("running %q: %v", in, err)
		}
		return cov.Covered()
	}

	shallow := covered("xxxx")
	deep := covered("FUZZ")
	t.Logf("stub emulator: %q covered %d, %q covered %d", "xxxx", shallow, "FUZZ", deep)
	if shallow == 0 {
		t.Fatal("no coverage at all: the execution log was not read, or the guest " +
			"load address was never resolved")
	}
	if deep <= shallow {
		t.Errorf("the deeper input covered %d entries and the shallower one %d", deep, shallow)
	}
	if n := q.Unresolved(); n != 0 {
		t.Errorf("%d executions produced a trace that could not be related to the image; "+
			"their coverage was dropped", n)
	}

	// The same input twice must give the same coverage, or the rebasing is not
	// doing its job.
	if a, b := covered("FUZZ"), covered("FUZZ"); a != b {
		t.Errorf("the same input covered %d entries and then %d", a, b)
	}
}

func TestQemuBackendNamesTheEmulatorItCannotFind(t *testing.T) {
	dir := testenv.ReachableDir(t)
	target := buildUnstripped(t, dir, ladderExitSrc)

	q := tracer.NewQemu(safety.NewSpawner(), target)
	q.Emulator = "qemu-definitely-not-installed"
	err := q.Start(t.Context())
	if err == nil {
		t.Fatal("starting against an emulator that does not exist succeeded")
	}
	if got := err.Error(); !containsAll(got, "qemu-definitely-not-installed") {
		t.Errorf("the error does not name what is missing: %v", err)
	}
}

func TestFridaBackendAgainstAStubTool(t *testing.T) {
	if testing.Short() {
		t.Skip("this builds a stub tool")
	}
	dir := testenv.ReachableDir(t)
	target := buildUnstripped(t, dir, ladderExitSrc)
	stub := stubTool(t, dir, "frida", fridaStubSrc)

	f := tracer.NewFrida(safety.NewSpawner(), target)
	f.Tool = stub
	e := executor.NewEmulated("t5-frida", f, executor.ProcSpec{
		Path: target, Args: []string{target}, Timeout: 20 * time.Second,
	})
	cov := feedback.NewCoverageMap("coverage", feedback.DefaultMapSize)
	e.Coverage = cov
	if err := e.Start(t.Context()); err != nil {
		t.Fatalf("the frida backend would not start against the stub: %v", err)
	}
	defer e.Close()

	covered := func(in string) int {
		cov.Reset()
		if _, err := e.Run(t.Context(), executor.Input{Bytes: []byte(in)}, nil); err != nil {
			t.Fatalf("running %q: %v", in, err)
		}
		return cov.Covered()
	}

	shallow := covered("xxxx")
	deep := covered("FUZZ")
	t.Logf("stub instrumentation: %q covered %d, %q covered %d", "xxxx", shallow, "FUZZ", deep)
	if shallow == 0 {
		t.Fatal("no coverage at all: the DRcov file was not read, or every block was " +
			"attributed to another module")
	}
	if deep <= shallow {
		t.Errorf("the deeper input covered %d entries and the shallower one %d", deep, shallow)
	}
	if a, b := covered("FUZZ"), covered("FUZZ"); a != b {
		t.Errorf("the same input covered %d entries and then %d", a, b)
	}
}

func TestFridaBackendSaysWhatIsMissing(t *testing.T) {
	dir := testenv.ReachableDir(t)
	target := buildUnstripped(t, dir, ladderExitSrc)

	f := tracer.NewFrida(safety.NewSpawner(), target)
	f.Tool = "frida-definitely-not-installed"
	err := f.Start(t.Context())
	if err == nil {
		t.Fatal("starting against a tool that does not exist succeeded")
	}
	if !containsAll(err.Error(), "frida-definitely-not-installed") {
		t.Errorf("the error does not name what is missing: %v", err)
	}
}

// TestBackendsReportTheirAvailabilityHonestly is what the capability report and
// xfuzz doctor are built on. An operator asking why a campaign is running at the
// slowest tier needs to be told which tool would make it faster.
func TestBackendsReportTheirAvailabilityHonestly(t *testing.T) {
	name, ok := tracer.QemuAvailable(binary.ArchAMD64)
	t.Logf("qemu for amd64: %q available=%v", name, ok)
	if name == "" {
		t.Error("no emulator name for amd64, so an operator would not be told what to install")
	}
	if _, ok := tracer.QemuAvailable(binary.ArchOther); ok {
		t.Error("an emulator was reported for an architecture with no known one")
	}

	name, ok = tracer.FridaAvailable()
	t.Logf("frida: %q available=%v", name, ok)
	if name == "" {
		t.Error("no tool name reported for frida")
	}
}

func containsAll(s string, parts ...string) bool {
	for _, p := range parts {
		if !strings.Contains(s, p) {
			return false
		}
	}
	return true
}
