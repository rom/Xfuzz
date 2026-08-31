package campaign

import (
	"fmt"
	"os"
	"strings"
)

// The names an api or driver block may use, in one place so that validation,
// the worker and the published JSON Schema cannot drift apart.

// How values chain between requests.
const (
	APILinksInfer = "infer"
	APILinksNone  = "none"
)

// What an identity should get, for the authorization oracle.
const (
	APIExpectAllowed = "allowed"
	APIExpectDenied  = "denied"
	APIExpectUnknown = "unknown"
)

// The response oracles.
const (
	APIOracleStatus        = "status"
	APIOracleSchema        = "schema"
	APIOracleLatency       = "latency"
	APIOracleAuthorization = "authorization"
)

// APILinkModes, APIExpectations and APIOracles list what the file may say.
var (
	APILinkModes    = []string{APILinksInfer, APILinksNone}
	APIExpectations = []string{APIExpectAllowed, APIExpectDenied, APIExpectUnknown}
	APIOracles      = []string{
		APIOracleStatus, APIOracleSchema, APIOracleLatency, APIOracleAuthorization,
	}
)

// The driver backends. One, for now: ADR-0013's desktop backends each need a
// platform, a session and a display, and none of them is implemented.
const DriverTUI = "tui"

// The interface oracles.
const (
	DriverOracleDiagnostic   = "diagnostic"
	DriverOracleUnresponsive = "unresponsive"
	DriverOracleTrap         = "trap"
)

// DriverKinds and DriverOracles list what the file may say.
var (
	DriverKinds   = []string{DriverTUI}
	DriverOracles = []string{
		DriverOracleDiagnostic, DriverOracleUnresponsive, DriverOracleTrap,
	}
)

// oneOf reports whether v is in the list, and renders the list for a message.
func oneOf(v string, list []string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func listOf(items []string) string { return strings.Join(items, ", ") }

// validateAPI checks an API campaign's block.
func (r *Resolved) validateAPI(add addFunc) {
	if r.API == nil {
		return
	}
	a := r.API

	// The three tier-selecting blocks are mutually exclusive. A file with two
	// of them has asked for two different things to be fuzzed and there is no
	// reading of it that is what somebody meant.
	if r.Session != nil {
		add("api", "cannot be combined with a session block",
			"a session block fuzzes a raw protocol and an api block replays HTTP; "+
				"pick the one that matches the target")
	}
	if r.Driver != nil {
		add("api", "cannot be combined with a driver block",
			"a driver block fuzzes a user interface")
	}

	if a.Address == "" {
		add("api.address", "is required", "the campaign has nothing to send requests to")
	} else if _, _, err := SplitAddress(a.Address); err != nil {
		add("api.address", err.Error(), "write it as tcp:HOST:PORT")
	}
	if !oneOf(a.Links, APILinkModes) {
		add("api.links", fmt.Sprintf("%q is not a link mode", a.Links),
			"one of "+listOf(APILinkModes))
	}
	if !oneOf(a.Expect, APIExpectations) {
		add("api.expect", fmt.Sprintf("%q is not an expectation", a.Expect),
			"one of "+listOf(APIExpectations))
	}
	for _, o := range a.Oracles {
		if !oneOf(o, APIOracles) {
			add("api.oracles", fmt.Sprintf("%q is not an oracle", o),
				"one of "+listOf(APIOracles))
		}
	}

	// The authorization oracle is a comparison rather than a rule: it needs to
	// know whose credentials the session carries and what should happen, or it
	// has nothing to compare and reports every 200 a public endpoint gives.
	if oneOf(APIOracleAuthorization, a.Oracles) {
		if a.Identity == "" {
			add("api.identity", "is required by the authorization oracle",
				"the oracle reports a session that succeeded as an identity that "+
					"should not have; without a name the finding says nothing")
		}
		if a.Expect == APIExpectUnknown {
			add("api.expect", "must be allowed or denied for the authorization oracle",
				"the oracle compares what happened against what should have; "+
					"\"unknown\" is the campaign declining to say")
		}
	}
	if a.Capture == "" && len(r.Seeds.Dirs) == 0 && len(r.Seeds.Inline) == 0 &&
		r.Format.Grammar == "" {
		add("api.capture", "is required when the campaign has no seeds and no grammar",
			"an API campaign replays requests; without a capture, a corpus or a "+
				"grammar there is nothing to send")
	}
	if a.Capture != "" {
		mustRead(add, "api.capture", a.Capture)
	}
	if a.Secrets != "" {
		mustRead(add, "api.secrets", a.Secrets)
	}
	for _, code := range a.IgnoreStatus {
		if code < 100 || code > 599 {
			add("api.ignore_status", fmt.Sprintf("%d is not an HTTP status", code), "")
		}
	}
}

// validateDriver checks a user-interface campaign's block.
func (r *Resolved) validateDriver(add addFunc) {
	if r.Driver == nil {
		return
	}
	d := r.Driver

	if r.Session != nil {
		add("driver", "cannot be combined with a session block",
			"a session block fuzzes a protocol and a driver block a user interface")
	}
	if !oneOf(d.Kind, DriverKinds) {
		add("driver.kind", fmt.Sprintf("%q is not a driver backend", d.Kind),
			"one of "+listOf(DriverKinds))
	}
	if d.Cols < 8 || d.Cols > 1000 {
		add("driver.cols", fmt.Sprintf("%d is outside 8..1000", d.Cols),
			"a terminal narrower than eight columns is not one a program draws in")
	}
	if d.Rows < 4 || d.Rows > 1000 {
		add("driver.rows", fmt.Sprintf("%d is outside 4..1000", d.Rows), "")
	}
	if d.MaxEvents < 1 {
		add("driver.max_events", "must be at least 1",
			"a sequence with no events delivers nothing")
	}
	switch d.Reset {
	case "restart", "none":
	default:
		add("driver.reset", fmt.Sprintf("%q is not a reset policy for an interface", d.Reset),
			"restart or none; restarting is the only reset an interface has")
	}
	for _, n := range d.Normalise {
		if normaliserNames[n] {
			continue
		}
		add("driver.normalise", fmt.Sprintf("%q is not a normalisation step", n),
			"one of digits, quoted, space, spinner, runs")
	}
	for _, o := range d.Oracles {
		if !oneOf(o, DriverOracles) {
			add("driver.oracles", fmt.Sprintf("%q is not an oracle", o),
				"one of "+listOf(DriverOracles))
		}
	}
	if d.Guide != nil && !*d.Guide && len(d.Oracles) == 0 {
		add("driver.guide", "is off and no oracles are set",
			"an interface campaign with neither has no signal at all: it would run "+
				"sequences and never find anything interesting or report anything")
	}
}

// mustRead reports a path the campaign named and the tool cannot open.
//
// Checked when the file is validated rather than when the worker starts, so a
// typo in a path is a message about the field rather than a campaign that
// launches, reports two live workers and does nothing.
func mustRead(add addFunc, field, path string) {
	f, err := os.Open(path)
	if err != nil {
		add(field, fmt.Sprintf("%s cannot be read: %v", path, err), "")
		return
	}
	f.Close()
}

// normaliserNames is what a driver's screen fingerprint may be told to remove.
// It matches pkg/state's registry, which is what actually reads these.
var normaliserNames = map[string]bool{
	"digits": true, "quoted": true, "space": true, "spinner": true, "runs": true,
}
