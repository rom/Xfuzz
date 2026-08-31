package campaign

import (
	"strings"
	"testing"
)

func TestSplitAddressRequiresAScheme(t *testing.T) {
	for _, tc := range []struct {
		addr    string
		network string
		want    string
		bad     bool
	}{
		{addr: "tcp:127.0.0.1:9000", network: "tcp", want: "127.0.0.1:9000"},
		{addr: "unix:/run/t.sock", network: "unix", want: "/run/t.sock"},
		{addr: "tcp:127.0.0.1:{worker}", network: "tcp", want: "127.0.0.1:{worker}"},
		// A bare host:port is a plausible TCP address and a plausible filename.
		// Guessing gives a campaign that fails with a message about the wrong
		// thing, so the scheme is required.
		{addr: "127.0.0.1:9000", bad: true},
		{addr: "tcp:127.0.0.1", bad: true},
		{addr: "tcp:127.0.0.1:99999", bad: true},
		{addr: "http:example.com:80", bad: true},
		{addr: "", bad: true},
	} {
		t.Run(tc.addr, func(t *testing.T) {
			n, a, err := SplitAddress(tc.addr)
			if tc.bad {
				if err == nil {
					t.Fatalf("SplitAddress(%q) = %q %q, want an error", tc.addr, n, a)
				}
				return
			}
			if err != nil {
				t.Fatalf("SplitAddress(%q): %v", tc.addr, err)
			}
			if n != tc.network || a != tc.want {
				t.Errorf("= %q %q, want %q %q", n, a, tc.network, tc.want)
			}
		})
	}
}

// A port is a number, so the worker index is added to it. Substituting the
// index literally into "9000{worker}" gives 90000, which is not a port.
func TestResolveAddressAddsToAPortAndSubstitutesAPath(t *testing.T) {
	for _, tc := range []struct {
		addr   string
		worker int
		want   string
	}{
		{"tcp:127.0.0.1:{worker}", 3, "tcp:127.0.0.1:3"},
		{"tcp:127.0.0.1:9000{worker}", 0, "tcp:127.0.0.1:9000"},
		{"tcp:127.0.0.1:9000{worker}", 5, "tcp:127.0.0.1:9005"},
		{"unix:/run/t-{worker}.sock", 2, "unix:/run/t-2.sock"},
		{"tcp:127.0.0.1:9000", 4, "tcp:127.0.0.1:9000"},
	} {
		if got := ResolveAddress(tc.addr, tc.worker); got != tc.want {
			t.Errorf("ResolveAddress(%q, %d) = %q, want %q", tc.addr, tc.worker, got, tc.want)
		}
	}
}

func TestParseTransition(t *testing.T) {
	from, to, err := ParseTransition("greeting -> auth-ok")
	if err != nil || from != "greeting" || to != "auth-ok" {
		t.Errorf("= %q %q %v", from, to, err)
	}
	for _, bad := range []string{"greeting", "->to", "from->", ""} {
		if _, _, err := ParseTransition(bad); err == nil {
			t.Errorf("ParseTransition(%q) was accepted", bad)
		}
	}
}

// loadSession parses a session campaign and returns it resolved.
func loadSession(t *testing.T, body string) (*Resolved, error) {
	t.Helper()
	doc := "name: s\ntarget:\n  path: " + trueBin + "\n" + body
	return Parse([]byte(doc), "t.yaml")
}

func TestSessionDefaultsApplyOnlyToSessionCampaigns(t *testing.T) {
	// A file campaign gets no session block, so `explain` does not show it an
	// address and a reset policy that mean nothing.
	plain, err := Parse([]byte("name: s\ntarget:\n  path: "+trueBin+"\nseeds:\n  inline: [\"a\"]\n"), "t.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if plain.Session != nil || plain.State != nil {
		t.Errorf("a file campaign was given session=%+v state=%+v", plain.Session, plain.State)
	}

	r, err := loadSession(t, "session:\n  address: unix:/tmp/t.sock\nseeds:\n  inline: [\"a\"]\n")
	if err != nil {
		t.Fatal(err)
	}
	if r.Session.Framing != "idle" || r.Session.Reset != "reconnect" {
		t.Errorf("defaults = framing %q reset %q", r.Session.Framing, r.Session.Reset)
	}
	if r.Session.Managed == nil || !*r.Session.Managed {
		t.Error("a campaign naming a target.path did not default to managing it")
	}
	// The state block appears with the session block, because state guidance is
	// the reason to fuzz sessions at all.
	if r.State == nil || r.State.Fn != "fingerprint" {
		t.Errorf("state = %+v, want a fingerprint default", r.State)
	}
	if r.State.Guide == nil || !*r.State.Guide {
		t.Error("state guidance was not on by default")
	}
}

func TestSessionValidationCatchesTheWaysItGoesWrong(t *testing.T) {
	for _, tc := range []struct {
		name, body, want string
	}{
		{
			"no address",
			"session:\n  framing: line\nseeds:\n  inline: [\"a\"]\n",
			"session.address",
		},
		{
			// Every worker runs its own copy of the target, so one address
			// means the second worker binds what the first holds.
			"shared address across workers",
			"session:\n  address: tcp:127.0.0.1:9000\nworkers:\n  count: 4\nseeds:\n  inline: [\"a\"]\n",
			"session.address",
		},
		{
			"snapshot reset",
			"session:\n  address: unix:/tmp/t.sock\n  reset: snapshot\nseeds:\n  inline: [\"a\"]\n",
			"session.reset",
		},
		{
			"unknown framing",
			"session:\n  address: unix:/tmp/t.sock\n  framing: magic\nseeds:\n  inline: [\"a\"]\n",
			"session.framing",
		},
		{
			// Nothing reads a reply, so there is no response to label.
			"guidance with no replies",
			"session:\n  address: unix:/tmp/t.sock\n  framing: none\nstate:\n  guide: true\nseeds:\n  inline: [\"a\"]\n",
			"state.guide",
		},
		{
			"session timeout below read timeout",
			"session:\n  address: unix:/tmp/t.sock\n  read_timeout: 5s\n  session_timeout: 1s\nseeds:\n  inline: [\"a\"]\n",
			"session.session_timeout",
		},
		{
			"unknown state function",
			"session:\n  address: unix:/tmp/t.sock\nstate:\n  fn: telepathy\nseeds:\n  inline: [\"a\"]\n",
			"state.fn",
		},
		{
			"probability out of range",
			"session:\n  address: unix:/tmp/t.sock\nstate:\n  explore: 4\nseeds:\n  inline: [\"a\"]\n",
			"state.explore",
		},
		{
			"malformed declared transition",
			"session:\n  address: unix:/tmp/t.sock\nstate:\n  declare: [\"greeting\"]\nseeds:\n  inline: [\"a\"]\n",
			"state.declare",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := loadSession(t, tc.body)
			if err == nil {
				t.Fatalf("%s was accepted", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("the error does not name %s:\n%v", tc.want, err)
			}
		})
	}
}

// A state block with no session configures machinery nothing will run, which is
// worth saying rather than ignoring.
func TestStateWithoutASessionIsRefused(t *testing.T) {
	_, err := Parse([]byte("name: s\ntarget:\n  path: "+trueBin+"\nstate:\n  fn: status\nseeds:\n  inline: [\"a\"]\n"), "t.yaml")
	if err == nil || !strings.Contains(err.Error(), "state") {
		t.Fatalf("a state block with no session gave %v", err)
	}
}

// A valid stateful campaign parses, and resolution leaves it runnable.
func TestAStatefulCampaignResolves(t *testing.T) {
	r, err := loadSession(t, `session:
  address: unix:/tmp/t-{worker}.sock
  framing: line
  reset: restart
state:
  fn: status
  declare: ["start->220", "220->235"]
  explore: 0.5
seeds:
  inline: ["HELLO 1\r\n"]
`)
	if err != nil {
		t.Fatalf("a valid stateful campaign was refused: %v", err)
	}
	if r.State.Explore != 0.5 {
		t.Errorf("explore = %v, want the file's 0.5", r.State.Explore)
	}
	if len(r.State.Declare) != 2 {
		t.Errorf("declare = %v", r.State.Declare)
	}
}

// The resolved form of a campaign must itself be a valid campaign.
//
// This is not a tidiness property. The daemon writes the resolved configuration
// into the run's directory and points every worker at that copy, so a
// configuration that resolves and then fails its own validation is a campaign
// that starts and whose workers all die — which is exactly what happened when
// defaulting filled in state.normalise for a campaign using the status function
// and validation then rejected it as irrelevant.
func TestResolvedCampaignsReloadAsThemselves(t *testing.T) {
	for _, body := range []string{
		"session:\n  address: unix:/tmp/t.sock\nstate:\n  fn: status\nseeds:\n  inline: [\"a\"]\n",
		"session:\n  address: unix:/tmp/t.sock\nstate:\n  fn: fingerprint\nseeds:\n  inline: [\"a\"]\n",
		"session:\n  address: tcp:127.0.0.1:9000\n  framing: none\nstate:\n  guide: false\nseeds:\n  inline: [\"a\"]\n",
		"session:\n  address: unix:/tmp/t.sock\n  reset: none\nstate:\n  declare: [\"start->220\"]\nseeds:\n  inline: [\"a\"]\n",
		"seeds:\n  inline: [\"a\"]\n",
		"format:\n  codec: png\nseeds:\n  inline: [\"a\"]\n",
	} {
		t.Run(body, func(t *testing.T) {
			first, err := loadSession(t, body)
			if err != nil {
				t.Fatalf("the campaign did not resolve: %v", err)
			}
			rendered, err := first.YAML()
			if err != nil {
				t.Fatal(err)
			}
			second, err := Parse(rendered, "resolved.yaml")
			if err != nil {
				t.Fatalf("the resolved form was refused:\n%v\n---\n%s", err, rendered)
			}
			// And it means the same thing, or the worker runs a different
			// campaign from the one that was reviewed.
			if second.Format.Codec != first.Format.Codec {
				t.Errorf("codec changed on the round trip: %q then %q",
					first.Format.Codec, second.Format.Codec)
			}
			if (first.Session == nil) != (second.Session == nil) {
				t.Errorf("the session block did not survive: %v then %v",
					first.Session, second.Session)
			}
			if first.Session != nil && second.Session.Reset != first.Session.Reset {
				t.Errorf("reset changed on the round trip: %q then %q",
					first.Session.Reset, second.Session.Reset)
			}
		})
	}
}

// A session campaign reads its seeds as conversations without being told to.
func TestSessionCampaignsDefaultToTheSessionCodec(t *testing.T) {
	r, err := loadSession(t, "session:\n  address: unix:/tmp/t.sock\nseeds:\n  inline: [\"a\"]\n")
	if err != nil {
		t.Fatal(err)
	}
	if r.Format.Codec != "session" {
		t.Errorf("codec = %q, want session", r.Format.Codec)
	}
	// And a campaign that chose one keeps it.
	r, err = loadSession(t, "session:\n  address: unix:/tmp/t.sock\nformat:\n  codec: raw\nseeds:\n  inline: [\"a\"]\n")
	if err != nil {
		t.Fatal(err)
	}
	if r.Format.Codec != "raw" {
		t.Errorf("codec = %q; the file said raw", r.Format.Codec)
	}
}
