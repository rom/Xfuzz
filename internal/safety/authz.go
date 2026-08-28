package safety

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ErrNoAuthorization is returned when a remote campaign has no authorization
// record.
var ErrNoAuthorization = errors.New("safety: a campaign against a remote target requires an authorization record")

// Authorization is the record a remote campaign must carry before its first
// packet (SECURITY.md section 3.3).
//
// This is not bureaucracy transplanted into a config file. A fuzzer pointed at
// somebody else's host is either an engagement or an intrusion, and the only
// thing that distinguishes them is a record made *before* the traffic, naming
// who ran it and what authorised them. Requiring it at start rather than
// accepting it afterwards is the whole point: an authorization written after the
// packets is not an authorization.
type Authorization struct {
	// Operator identifies who is running the campaign.
	Operator string

	// Reference is the engagement identifier, ticket, or approval document the
	// operator is acting under.
	Reference string

	// Attestation is the operator's statement that they are authorised to test
	// the declared scope. It is free text because what makes an engagement
	// lawful varies, and a dropdown would only teach people to pick the first
	// item.
	Attestation string

	// Recorded is when the record was made. It is set by Validate when zero,
	// from the caller's clock, and is part of what the audit entry commits to.
	Recorded time.Time

	// ScopeSummary is the allowlist the operator attested to, captured at the
	// moment of attestation. Storing it here rather than only in the scope is
	// what makes a later widening of scope visible: the record says what was
	// authorised, and it does not change when the campaign does.
	ScopeSummary string
}

// Validate checks that a record is complete enough to mean anything.
func (a *Authorization) Validate() error {
	var missing []string
	if strings.TrimSpace(a.Operator) == "" {
		missing = append(missing, "operator")
	}
	if strings.TrimSpace(a.Reference) == "" {
		missing = append(missing, "reference")
	}
	if strings.TrimSpace(a.Attestation) == "" {
		missing = append(missing, "attestation")
	}
	if len(missing) > 0 {
		return fmt.Errorf("%w: missing %s", ErrNoAuthorization, strings.Join(missing, ", "))
	}
	if a.Recorded.IsZero() {
		a.Recorded = time.Now().UTC()
	}
	return nil
}

// Digest is a stable identifier for the record, for attaching to findings.
//
// A finding exported from a campaign carries this rather than the record
// itself: the reference may name a customer and the attestation may quote a
// contract, and neither belongs in an artefact that gets forwarded around.
func (a *Authorization) Digest() string {
	h := sha256.New()
	for _, f := range []string{a.Operator, a.Reference, a.Attestation, a.ScopeSummary} {
		fmt.Fprintf(h, "%d:", len(f))
		h.Write([]byte(f))
	}
	fmt.Fprintf(h, "%d", a.Recorded.UTC().UnixNano())
	return hex.EncodeToString(h.Sum(nil))[:16]
}

func (a *Authorization) String() string {
	return fmt.Sprintf("%s under %s at %s (%s)",
		a.Operator, a.Reference, a.Recorded.UTC().Format(time.RFC3339), a.Digest())
}

// Authorize validates the record, ties it to the scope, and audits it.
//
// remote reports whether the campaign will leave the host. A local campaign
// needs no record, and demanding one would make the common case tedious enough
// that people would fake it — which would make every record worthless.
func Authorize(ctx context.Context, auditor Auditor, scope *Scope, auth *Authorization, remote bool) error {
	if scope == nil {
		scope = NewScope()
	}
	if err := scope.Validate(remote); err != nil {
		return err
	}
	if !remote {
		return nil
	}
	if auth == nil {
		return ErrNoAuthorization
	}
	auth.ScopeSummary = scope.Summary()
	if err := auth.Validate(); err != nil {
		return err
	}
	if auditor == nil {
		// An unaudited authorization is a claim nobody can check afterwards,
		// which is the state the record exists to leave behind.
		return fmt.Errorf("safety: an authorization record requires an audit log to record it in")
	}
	return auditor.Audit(ctx, auth.Operator, AuditAuthzRecord,
		fmt.Sprintf("ref=%q digest=%s scope=%q", auth.Reference, auth.Digest(), auth.ScopeSummary))
}
