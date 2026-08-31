package platform

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSeatbeltProfileDeniesWritesAndTheNetwork(t *testing.T) {
	p := SeatbeltProfile([]string{"/tmp/campaign"}, false)
	for _, want := range []string{
		"(version 1)",
		"(deny file-write*)",
		"(deny network*)",
		`(allow file-write* (subpath "/tmp/campaign"))`,
	} {
		if !strings.Contains(p, want) {
			t.Errorf("the profile does not contain %s:\n%s", want, p)
		}
	}
}

func TestSeatbeltProfileAllowsTheNetworkWhenAsked(t *testing.T) {
	// A campaign whose target is a network client is not a campaign that wants
	// its target unable to connect: the denial would look like the target being
	// broken, and every input would produce the same failure.
	p := SeatbeltProfile([]string{"/tmp/campaign"}, true)
	if strings.Contains(p, "deny network") {
		t.Fatalf("the network was denied although the campaign allows it:\n%s", p)
	}
}

func TestSeatbeltAllowsComeAfterTheDeny(t *testing.T) {
	// The profile language takes the last matching rule, so an allow written
	// before the blanket deny is a rule that never applies. The symptom would be
	// a target that cannot write its own working directory — reported as a
	// broken target rather than as a sandbox that is ordered wrongly.
	p := SeatbeltProfile([]string{"/tmp/campaign"}, false)
	deny := strings.Index(p, "(deny file-write*)")
	allow := strings.Index(p, "(allow file-write* (subpath")
	if deny < 0 || allow < 0 {
		t.Fatalf("the profile is missing a rule:\n%s", p)
	}
	if allow < deny {
		t.Fatalf("the writable allowance precedes the deny, so it never applies:\n%s", p)
	}
}

func TestSeatbeltProfileEscapesAPathThatWouldEndItsOwnString(t *testing.T) {
	// A working directory whose name carries a quote would otherwise close the
	// string and let the rest of the name be read as policy — a sandbox escape
	// written by whoever chose the directory.
	p := SeatbeltProfile([]string{`/tmp/a") (allow file-write*) (deny nothing "`}, false)
	// Checked line by line rather than by substring: the injected text is still
	// present inside the quoted path, which is exactly right — what must not
	// happen is its appearing as a rule of its own.
	for _, line := range strings.Split(p, "\n") {
		if line == "(allow file-write*)" {
			t.Fatalf("a path escaped its quoting and added a rule:\n%s", p)
		}
	}
	if !strings.Contains(p, `\"`) {
		t.Fatalf("the quote in the path was not escaped:\n%s", p)
	}

	// A backslash must be escaped too, or a path ending in one escapes the
	// closing quote instead of itself.
	q := SeatbeltProfile([]string{`/tmp/a\`}, false)
	if !strings.Contains(q, `"/tmp/a\\"`) {
		t.Fatalf("a trailing backslash was not escaped:\n%s", q)
	}
}

func TestSeatbeltProfileSkipsEmptyPaths(t *testing.T) {
	// An empty writable entry would become (subpath "") — which sandbox-exec
	// rejects, taking the whole profile with it and leaving the target
	// unrunnable rather than unconfined.
	p := SeatbeltProfile([]string{"", "/tmp/campaign", ""}, false)
	if strings.Contains(p, `(subpath "")`) {
		t.Fatalf("an empty writable path reached the profile:\n%s", p)
	}
	if strings.Count(p, "(subpath") != 1 {
		t.Fatalf("want one subpath rule:\n%s", p)
	}
}

func TestSeatbeltProfileAllowsThePathTheKernelWillSee(t *testing.T) {
	// The kernel matches a subpath rule against the real path, and macOS hands
	// out working directories that are not one: a temporary directory is under
	// /var/folders, and /var is a symbolic link to /private/var. A profile that
	// named only what the caller was given would deny every write to the
	// directory it meant to allow.
	real := filepath.Join(t.TempDir(), "real")
	if err := os.Mkdir(real, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("this host cannot make a symbolic link: %v", err)
	}

	p := SeatbeltProfile([]string{link}, false)
	for _, want := range []string{link, real} {
		if !strings.Contains(p, `(subpath "`+want+`")`) {
			t.Errorf("%s is not writable under the profile:\n%s", want, p)
		}
	}

	// And a path that is *already* the resolved one is named once, not twice: a
	// rule repeated is a profile that is harder to read for no additional
	// permission. Resolved rather than merely real, because on the platform
	// this is for there is hardly any such thing — a macOS temporary directory
	// nobody linked is still under /var, which is itself a link to /private/var.
	resolved, err := filepath.EvalSymlinks(real)
	if err != nil {
		t.Skipf("this host cannot resolve %s: %v", real, err)
	}
	q := SeatbeltProfile([]string{resolved}, false)
	if n := strings.Count(q, "(subpath"); n != 1 {
		t.Errorf("an already-resolved path produced %d subpath rules:\n%s", n, q)
	}
}

func TestSeatbeltProfileRefusesARelativePath(t *testing.T) {
	// sandbox-exec rejects a relative subpath and rejects the whole profile
	// with it, so a relative writable entry would leave the target unrunnable.
	// It becomes absolute, against the directory the child would have inherited.
	p := SeatbeltProfile([]string{"scratch"}, false)
	for _, line := range strings.Split(p, "\n") {
		if !strings.HasPrefix(line, "(allow file-write* (subpath") {
			continue
		}
		if strings.Contains(line, `"scratch"`) {
			t.Fatalf("a relative path reached the profile:\n%s", p)
		}
	}
	cwd, err := os.Getwd()
	if err != nil {
		t.Skip("no working directory")
	}
	if !strings.Contains(p, filepath.Join(cwd, "scratch")) {
		t.Errorf("the relative path was dropped rather than resolved:\n%s", p)
	}
}

func TestSeatbeltProfileKeepsTheStandardDevicesWritable(t *testing.T) {
	// Denying these denies the C library rather than the target: a program that
	// cannot write to stderr cannot report the crash it was fuzzed for.
	p := SeatbeltProfile(nil, false)
	for _, dev := range []string{"/dev/null", "/dev/stdout", "/dev/stderr"} {
		if !strings.Contains(p, `(literal "`+dev+`")`) {
			t.Errorf("%s is not writable under the profile:\n%s", dev, p)
		}
	}
}

func TestSeatbeltCommandRunsTheTargetUnderTheProfile(t *testing.T) {
	profile := SeatbeltProfile([]string{"/tmp/c"}, false)
	path, argv := SeatbeltCommand(profile, "/bin/target", []string{"target", "--flag", "@@"})
	if path != SandboxExecPath {
		t.Fatalf("the command runs %s, not the sandbox front end", path)
	}
	want := []string{SandboxExecPath, "-p", profile, "/bin/target", "--flag", "@@"}
	if len(argv) != len(want) {
		t.Fatalf("argv = %q; want %q", argv, want)
	}
	for i := range want {
		if argv[i] != want[i] {
			t.Fatalf("argv = %q; want %q", argv, want)
		}
	}
}

func TestSeatbeltCommandWithNoArgumentsStillRunsTheTarget(t *testing.T) {
	// An executor that passes only the program name must not lose it: appending
	// argv[1:] of a one-element slice is the off-by-one that would.
	_, argv := SeatbeltCommand("(version 1)", "/bin/target", []string{"target"})
	if len(argv) != 4 || argv[3] != "/bin/target" {
		t.Fatalf("argv = %q; want the target as the last element", argv)
	}
}
