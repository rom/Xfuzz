package licensecheck

import (
	"os"
	"path/filepath"
	"testing"
)

// TestRepositoryLicensePolicy is the gate described in docs/TESTS.md section 11.
func TestRepositoryLicensePolicy(t *testing.T) {
	root, err := FindRepoRoot(".")
	if err != nil {
		t.Fatal(err)
	}
	ps, err := Check(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range ps {
		t.Errorf("%s", p)
	}
}

func TestPolicySetsAreDisjoint(t *testing.T) {
	for lic := range Allowed {
		if Forbidden[lic] {
			t.Errorf("%s appears in both the allowed and forbidden sets", lic)
		}
		if _, ok := Conditional[lic]; ok {
			t.Errorf("%s appears in both the allowed and conditional sets", lic)
		}
	}
	for lic := range Conditional {
		if Forbidden[lic] {
			t.Errorf("%s appears in both the conditional and forbidden sets", lic)
		}
	}
}

func TestDetectsPolicyBreaches(t *testing.T) {
	cases := []struct {
		name   string
		gomod  string
		notice string
		want   string
	}{
		{
			name:   "forbidden license",
			gomod:  "module x\n\ngo 1.24\n\nrequire example.com/gpl v1.0.0\n",
			notice: "## Components\n\n| Module | Version | License | Used for |\n| --- | --- | --- | --- |\n| example.com/gpl | v1.0.0 | GPL-3.0 | things |\n",
			want:   "forbidden",
		},
		{
			name:   "dependency missing from NOTICE",
			gomod:  "module x\n\ngo 1.24\n\nrequire (\n\texample.com/a v1.0.0\n)\n",
			notice: "## Components\n\n| Module | Version | License | Used for |\n| --- | --- | --- | --- |\n",
			want:   "missing from NOTICE",
		},
		{
			name:   "stale NOTICE entry",
			gomod:  "module x\n\ngo 1.24\n",
			notice: "## Components\n\n| Module | Version | License | Used for |\n| --- | --- | --- | --- |\n| example.com/gone | v1.0.0 | MIT | things |\n",
			want:   "stale entry",
		},
		{
			name:   "version drift",
			gomod:  "module x\n\ngo 1.24\n\nrequire example.com/a v1.2.0\n",
			notice: "## Components\n\n| Module | Version | License | Used for |\n| --- | --- | --- | --- |\n| example.com/a | v1.0.0 | MIT | things |\n",
			want:   "NOTICE records version",
		},
		{
			// The dangerous case: a module under both licences where one is
			// forbidden. Accepting it because the other arm is allowed would
			// let a GPL obligation in under an MIT label.
			name:   "conjunction with a forbidden term",
			gomod:  "module x\n\ngo 1.24\n\nrequire example.com/a v1.0.0\n",
			notice: "## Components\n\n| Module | Version | License | Used for |\n| --- | --- | --- | --- |\n| example.com/a | v1.0.0 | MIT AND GPL-3.0 | things |\n",
			want:   "forbidden",
		},
		{
			name:   "disjunction is not interpreted",
			gomod:  "module x\n\ngo 1.24\n\nrequire example.com/a v1.0.0\n",
			notice: "## Components\n\n| Module | Version | License | Used for |\n| --- | --- | --- | --- |\n| example.com/a | v1.0.0 | MIT OR GPL-3.0 | things |\n",
			want:   "not in the ADR-0018 allowed set",
		},
		{
			name:   "unknown license",
			gomod:  "module x\n\ngo 1.24\n\nrequire example.com/a v1.0.0\n",
			notice: "## Components\n\n| Module | Version | License | Used for |\n| --- | --- | --- | --- |\n| example.com/a | v1.0.0 | WTFPL | things |\n",
			want:   "not in the ADR-0018 allowed set",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			write(t, filepath.Join(dir, "go.mod"), tc.gomod)
			write(t, filepath.Join(dir, "NOTICE"), tc.notice)
			ps, err := Check(dir)
			if err != nil {
				t.Fatal(err)
			}
			if len(ps) == 0 {
				t.Fatalf("expected a problem containing %q, got none", tc.want)
			}
			if !containsSubstr(ps, tc.want) {
				t.Errorf("expected a problem containing %q, got %v", tc.want, ps)
			}
		})
	}
}

func TestAcceptsAConjunctionOfAllowedLicenses(t *testing.T) {
	// gopkg.in/yaml.v3 is the real instance: the libyaml-derived files are MIT
	// and the rest is Apache-2.0, so the module is under both at once.
	dir := t.TempDir()
	write(t, filepath.Join(dir, "go.mod"),
		"module x\n\ngo 1.24\n\nrequire example.com/dual v1.0.0\n")
	write(t, filepath.Join(dir, "NOTICE"),
		"## Components\n\n| Module | Version | License | Used for |\n| --- | --- | --- | --- |\n"+
			"| example.com/dual | v1.0.0 | MIT AND Apache-2.0 | things |\n")

	ps, err := Check(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(ps) != 0 {
		t.Fatalf("a module under two allowed licences was rejected: %v", ps)
	}
}

func TestSplitLicense(t *testing.T) {
	for in, want := range map[string][]string{
		"MIT":                       {"MIT"},
		"MIT AND Apache-2.0":        {"MIT", "Apache-2.0"},
		"  MIT AND  BSD-3-Clause  ": {"MIT", "BSD-3-Clause"},
		"MIT OR GPL-3.0":            {"MIT OR GPL-3.0"},
	} {
		got := SplitLicense(in)
		if len(got) != len(want) {
			t.Errorf("SplitLicense(%q) = %v, want %v", in, got, want)
			continue
		}
		for i := range got {
			if got[i] != want[i] {
				t.Errorf("SplitLicense(%q) = %v, want %v", in, got, want)
				break
			}
		}
	}
}

func TestAcceptsCompliantDependency(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "go.mod"),
		"module x\n\ngo 1.24\n\nrequire (\n\texample.com/a v1.0.0 // indirect\n)\n")
	write(t, filepath.Join(dir, "NOTICE"),
		"## Components\n\n| Module | Version | License | Used for |\n| --- | --- | --- | --- |\n| example.com/a | v1.0.0 | Apache-2.0 | things |\n")
	ps, err := Check(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(ps) != 0 {
		t.Errorf("compliant dependency reported problems: %v", ps)
	}
}

func write(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func containsSubstr(ps []Problem, want string) bool {
	for _, p := range ps {
		if len(want) > 0 && contains(p.String(), want) {
			return true
		}
	}
	return false
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
