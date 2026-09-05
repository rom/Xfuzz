// The console/API parity test (ASR-0005).
//
// ADR-0003 defines every capability once as an API method and both clients
// against that surface. cmd/xfuzz/parity_test.go proves that for the CLI, in
// both directions. Nothing proved it for the console — and ASR-0005's
// acceptance criterion is explicitly two-way: "every action available in the
// console has a documented CLI equivalent and vice versa, verified by a parity
// test over the API surface". The vice-versa half was never checked, and eight
// routes had drifted out of the console's reach before anyone noticed.
//
// The console is TypeScript, so this reads what it actually calls rather than a
// list it declares: web/src is scanned for calls through the single client in
// api.ts, plus the event stream's own EventSource. A declared list would be the
// same discipline that let the drift happen — the CLI can be checked against a
// struct field because the commands are Go, and this cannot.
//
// It is an external test package because internal/api imports internal/console
// to serve the bundle, and the route table lives in internal/api.
package console_test

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/rom/Xfuzz/internal/api"
	"github.com/rom/Xfuzz/internal/daemon"
	"github.com/rom/Xfuzz/internal/testenv"
	"github.com/rom/Xfuzz/tools/docslint"
)

// A backtick cannot appear in a Go raw string, and every pattern below has to
// name one: a template literal is how the console writes any path with a value
// in it.
const tick = "\x60"

var (
	// callRe matches a call through the console's HTTP client. The optional
	// <...> is the type argument, which the calls always carry and which can
	// run over several lines; [^(] rather than .*? because a response type
	// contains braces, brackets and semicolons but never a parenthesis, so
	// this stops exactly at the call's own opening bracket.
	callRe = regexp.MustCompile(`\bapi\.(get|post|del)\b\s*(?:<[^(]*>)?\s*\(\s*(?:"([^"]*)"|` +
		tick + `([^` + tick + `]*)` + tick + `)`)

	// eventRe matches the live stream, which does not go through that client:
	// an EventSource opens its own connection (ADR-0024).
	eventRe = regexp.MustCompile(`new EventSource\(\s*(?:"([^"]*)"|` +
		tick + `([^` + tick + `]*)` + tick + `)`)

	interpolation = regexp.MustCompile(`\$\{[^}]*\}`)
)

// call is one request the console can make.
type call struct {
	method string
	path   string // interpolations reduced to {}, query string dropped
	where  string // file:line, so a failure names the line to look at
}

// consoleCalls reads every request the console source can issue.
func consoleCalls(t *testing.T) []call {
	t.Helper()

	var calls []call
	for _, path := range consoleSources(t) {
		src := string(testenv.ReadDoc(t, path))

		for _, m := range callRe.FindAllStringSubmatchIndex(src, -1) {
			verb := strings.ToUpper(src[m[2]:m[3]])
			if verb == "DEL" {
				verb = "DELETE"
			}
			calls = append(calls, call{
				method: verb,
				path:   normalise(literal(src, m)),
				where:  fmt.Sprintf("%s:%d", filepath.Base(path), lineOf(src, m[0])),
			})
		}
		for _, m := range eventRe.FindAllStringSubmatchIndex(src, -1) {
			calls = append(calls, call{
				method: "GET",
				path:   normalise(literal(src, m)),
				where:  fmt.Sprintf("%s:%d", filepath.Base(path), lineOf(src, m[0])),
			})
		}
	}
	if len(calls) == 0 {
		t.Fatal("no API calls found in web/src; the console's client was moved or renamed, " +
			"and this test is measuring nothing")
	}
	return calls
}

// consoleSources lists the console's TypeScript, which is in the repository
// whether or not the bundle has been built — so this test needs no Node.
func consoleSources(t *testing.T) []string {
	t.Helper()

	root, err := docslint.FindRepoRoot(".")
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, "web", "src")

	var files []string
	err = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(path, ".ts") {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(files)
	return files
}

// literal returns whichever of the two string forms the match captured.
func literal(src string, m []int) string {
	if m[4] >= 0 {
		return src[m[4]:m[5]]
	}
	return src[m[6]:m[7]]
}

// normalise turns a written path into the shape a route can be compared with:
// every interpolated value becomes {}, and the query string goes, because no
// route is identified by one.
func normalise(path string) string {
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path = path[:i]
	}
	return interpolation.ReplaceAllString(path, "{}")
}

func lineOf(src string, offset int) int {
	return 1 + strings.Count(src[:offset], "\n")
}

func apiRoutes(t *testing.T) []api.Route {
	t.Helper()

	d, err := daemon.New(daemon.Options{DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close(t.Context())

	return api.NewServer(d).Routes()
}

// reaches reports whether a call could arrive at a route.
//
// Could, not does. A console segment that is {} is a value the console computes
// at run time, and this cannot know which values: service.action posts to
// `/v1/campaigns/${name}/${what}`, where what is one of start, pause, resume
// and stop, and all four are counted as reachable through it. So the claim this
// test makes is "the console's client can address every route", not "a button
// exists for each" — the second needs a person, and the first is what silently
// stopped being true.
func reaches(c call, r api.Route) bool {
	if c.method != r.Method {
		return false
	}
	got, want := strings.Split(c.path, "/"), strings.Split(r.Path, "/")
	if len(got) != len(want) {
		return false
	}
	for i := range want {
		switch {
		case got[i] == "{}":
			// An interpolated value; it could be anything the route names.
		case strings.HasPrefix(want[i], "{"):
			// A route parameter, given a constant. Sound, if unusual.
		case got[i] != want[i]:
			return false
		}
	}
	return true
}

func TestEveryAPIRouteIsReachableFromTheConsole(t *testing.T) {
	// Routes the console does not call, each by decision. When this test was
	// first run it also found six gaps — forget, corpus import and export,
	// minimise, the doctor's capabilities and the campaign-file schema — which
	// were closed in the change after; a route lands here only with the reason
	// it is not a gap, and a gap is closed rather than listed.
	//
	// The list cannot rot into a rubber stamp: a route named here that becomes
	// reachable fails the test, and so does a name that is not a route.
	unreached := map[string]string{
		"metrics.get": "campaign.get already carries the metrics block, and a second " +
			"request for the same numbers is one more thing to keep in step",
		"admin.openapi": "the OpenAPI document describes this API to generated clients, " +
			"and the console is not one — it is written by hand against these routes",
	}

	routes := apiRoutes(t)
	calls := consoleCalls(t)

	reachable := map[string]bool{}
	for _, r := range routes {
		for _, c := range calls {
			if reaches(c, r) {
				reachable[r.Name] = true
				break
			}
		}
	}

	var missing []string
	for _, r := range routes {
		if reachable[r.Name] {
			if _, excused := unreached[r.Name]; excused {
				t.Errorf("route %q is listed as out of the console's reach and the console reaches it; "+
					"delete the entry", r.Name)
			}
			continue
		}
		if reason, excused := unreached[r.Name]; excused {
			if strings.TrimSpace(reason) == "" {
				t.Errorf("route %q is excused with no reason", r.Name)
			}
			continue
		}
		missing = append(missing, fmt.Sprintf("%s (%s %s)", r.Name, r.Method, r.Path))
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		t.Errorf("the API has capabilities the console cannot reach (ASR-0005):\n  %s\n"+
			"add the call to web/src/api.ts, or name the route in this test with the reason it has none",
			strings.Join(missing, "\n  "))
	}

	byName := map[string]bool{}
	for _, r := range routes {
		byName[r.Name] = true
	}
	for name := range unreached {
		if !byName[name] {
			t.Errorf("this test excuses %q, which is not a route", name)
		}
	}
}

func TestEveryConsoleCallReachesARealRoute(t *testing.T) {
	// The other direction. A console that calls a path the daemon does not
	// serve fails in the browser, where the only report is a person saying the
	// page is blank — and a path that was renamed on the server keeps compiling
	// here, because it is a string.
	routes := apiRoutes(t)

	for _, c := range consoleCalls(t) {
		found := false
		for _, r := range routes {
			if reaches(c, r) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("%s calls %s %s, which no route serves", c.where, c.method, c.path)
		}
	}
}

func TestEveryConsoleRequestGoesThroughTheClient(t *testing.T) {
	// The guard on the two tests above. Both read the console through two
	// patterns, and a request made some other way — a bare fetch, a new
	// helper — would be invisible to them: parity would still be reported as
	// held while the console reached a route nothing here could see. So every
	// path the console *writes* must sit inside a match.
	//
	// Written, not mentioned: what counts is a /v1/ that opens a string, which
	// is what a request is, rather than one in a sentence, which is what a
	// comment about a request is. The comments here name routes in prose and
	// this must not make that a test failure. The case it still catches
	// wrongly is a path quoted with backticks inside a comment, which reads as
	// a template literal; there is none today, and a `/v1/...` written that way
	// should be named below rather than reworded to please a test.
	type span struct{ from, to int }

	for _, path := range consoleSources(t) {
		src := string(testenv.ReadDoc(t, path))

		var spans []span
		for _, re := range []*regexp.Regexp{callRe, eventRe} {
			for _, m := range re.FindAllStringSubmatchIndex(src, -1) {
				if m[4] >= 0 {
					spans = append(spans, span{m[4], m[5]})
					continue
				}
				spans = append(spans, span{m[6], m[7]})
			}
		}

		for at := 0; ; {
			i := strings.Index(src[at:], "/v1/")
			if i < 0 {
				break
			}
			i += at
			at = i + 1
			if i == 0 || !strings.ContainsRune("\"'"+tick, rune(src[i-1])) {
				continue // a mention rather than a request
			}

			covered := false
			for _, s := range spans {
				if i >= s.from && i < s.to {
					covered = true
					break
				}
			}
			if !covered {
				t.Errorf("%s:%d writes a /v1/ path outside a call this test can see; "+
					"route it through the client in api.ts, or teach this test the new shape",
					filepath.Base(path), lineOf(src, i))
			}
		}
	}
}
