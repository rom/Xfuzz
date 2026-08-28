package safety

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func goodAuth() *Authorization {
	return &Authorization{
		Operator:    "rom",
		Reference:   "ENG-2026-114",
		Attestation: "written approval from the asset owner, attached to the engagement",
	}
}

func TestAuthorizationRequiresEveryField(t *testing.T) {
	for _, missing := range []string{"operator", "reference", "attestation"} {
		a := goodAuth()
		switch missing {
		case "operator":
			a.Operator = "  "
		case "reference":
			a.Reference = ""
		case "attestation":
			a.Attestation = ""
		}
		err := a.Validate()
		if !errors.Is(err, ErrNoAuthorization) {
			t.Fatalf("a record with no %s was accepted: %v", missing, err)
		}
		if !strings.Contains(err.Error(), missing) {
			t.Fatalf("the error does not name the missing field: %v", err)
		}
	}
}

func TestAuthorizationStampsItself(t *testing.T) {
	a := goodAuth()
	if err := a.Validate(); err != nil {
		t.Fatal(err)
	}
	if a.Recorded.IsZero() {
		t.Fatal("Validate did not record when the attestation was made")
	}
	if time.Since(a.Recorded) > time.Minute {
		t.Fatalf("Recorded = %v", a.Recorded)
	}
}

func TestAuthorizationDigestCoversEveryField(t *testing.T) {
	base := goodAuth()
	base.Recorded = time.Unix(1000, 0).UTC()
	base.ScopeSummary = "10.0.0.0/8"
	want := base.Digest()

	for name, mutate := range map[string]func(*Authorization){
		"operator":    func(a *Authorization) { a.Operator = "other" },
		"reference":   func(a *Authorization) { a.Reference = "ENG-2026-115" },
		"attestation": func(a *Authorization) { a.Attestation = "different" },
		"scope":       func(a *Authorization) { a.ScopeSummary = "0.0.0.0/0" },
		"time":        func(a *Authorization) { a.Recorded = time.Unix(1001, 0).UTC() },
	} {
		a := *base
		mutate(&a)
		if a.Digest() == want {
			t.Errorf("changing the %s did not change the digest", name)
		}
	}

	// The digest is length-prefixed, so moving a character across a field
	// boundary must change it too.
	shifted := *base
	shifted.Operator = "ro"
	shifted.Reference = "mENG-2026-114"
	if shifted.Digest() == want {
		t.Error("moving a character between fields did not change the digest")
	}
}

func TestAuthorizeSkipsLocalCampaigns(t *testing.T) {
	if err := Authorize(context.Background(), nil, NewScope(), nil, false); err != nil {
		t.Fatalf("a local campaign was made to produce an authorization record: %v", err)
	}
}

func TestAuthorizeRefusesRemoteWithoutARecord(t *testing.T) {
	s := NewScope()
	s.MustAllow("10.0.0.0/8")
	err := Authorize(context.Background(), &recordingAuditor{}, s, nil, true)
	if !errors.Is(err, ErrNoAuthorization) {
		t.Fatalf("a remote campaign started with no authorization: %v", err)
	}
}

func TestAuthorizeRefusesRemoteWithoutAScope(t *testing.T) {
	err := Authorize(context.Background(), &recordingAuditor{}, NewScope(), goodAuth(), true)
	if !errors.Is(err, ErrNoScope) {
		t.Fatalf("a remote campaign started with no allowlist: %v", err)
	}
}

func TestAuthorizeRecordsScopeAndAudits(t *testing.T) {
	a := &recordingAuditor{}
	s := NewScope()
	s.MustAllow("10.0.0.0/8")
	auth := goodAuth()

	if err := Authorize(context.Background(), a, s, auth, true); err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if auth.ScopeSummary == "" || !strings.Contains(auth.ScopeSummary, "10.0.0.0/8") {
		t.Fatalf("the record did not capture the scope it attested to: %q", auth.ScopeSummary)
	}
	if a.count(AuditAuthzRecord) != 1 {
		t.Fatalf("the authorization was not audited: %v", a.entries)
	}
	if !strings.Contains(a.entries[0], auth.Digest()) {
		t.Fatalf("the audit entry does not carry the record's digest: %q", a.entries[0])
	}
	if !strings.Contains(a.entries[0], "rom|") {
		t.Fatalf("the audit entry does not name the operator: %q", a.entries[0])
	}

	// The captured summary must not follow a later widening of the scope: what
	// was authorised is a fact about the past.
	before := auth.ScopeSummary
	s.MustAllow("172.16.0.0/12")
	if auth.ScopeSummary != before {
		t.Fatal("widening the scope changed what the operator is recorded as having authorised")
	}
}

func TestAuthorizeRefusesWithoutAnAuditLog(t *testing.T) {
	s := NewScope()
	s.MustAllow("10.0.0.0/8")
	err := Authorize(context.Background(), nil, s, goodAuth(), true)
	if err == nil {
		t.Fatal("an unaudited authorization was accepted; nobody could check it afterwards")
	}
}
