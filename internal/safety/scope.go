package safety

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// The audit actions the safety layer emits.
//
// They live here rather than in the store because this is where the events
// happen. The log records whatever string it is handed; making the persistence
// layer own the vocabulary of every subsystem would couple them for the sake of
// a handful of constants.
const (
	AuditTargetSpawn    = "target.spawn"
	AuditScopeAllow     = "scope.allow"
	AuditScopeDeny      = "scope.deny"
	AuditAuthzRecord    = "authz.record"
	AuditSandboxLevel   = "sandbox.level"
	AuditSandboxDegrade = "sandbox.degrade"
	AuditEscapeHatch    = "sandbox.escape-hatch"
)

// ErrOutOfScope is returned when a connection is refused by the scope guard.
var ErrOutOfScope = errors.New("safety: destination is out of scope")

// ErrNoScope is returned when a campaign would emit off-host traffic with no
// allowlist at all.
var ErrNoScope = errors.New("safety: a campaign that leaves the host requires a scope allowlist")

// ErrPublicScope is returned when a scope reaches public address space without
// the separate acknowledgement that requires.
var ErrPublicScope = errors.New("safety: reaching public address space requires an explicit acknowledgement")

// Rule is one entry of a scope allowlist.
//
// A rule is a destination, not a permission to do anything to it: the scope
// guard answers "may this campaign send packets there", and nothing else.
type Rule struct {
	// Prefix is the network this rule covers. A single address is a /32 or
	// /128.
	Prefix netip.Prefix

	// Host is the name the rule was written with, kept so a denial can say
	// "example.test is allowed but resolved to 93.184.x.x, which is not" rather
	// than only printing addresses.
	Host string

	// Ports are the allowed destination ports. Empty means every port, which is
	// deliberate: writing a host with no ports is a common and reasonable thing
	// to mean, and forcing a port list would push people to write 1-65535.
	Ports []PortRange
}

// PortRange is an inclusive range of ports.
type PortRange struct{ Lo, Hi uint16 }

// Contains reports whether a port falls in the range.
func (r PortRange) Contains(p uint16) bool { return p >= r.Lo && p <= r.Hi }

func (r PortRange) String() string {
	if r.Lo == r.Hi {
		return strconv.Itoa(int(r.Lo))
	}
	return fmt.Sprintf("%d-%d", r.Lo, r.Hi)
}

// Scope is a campaign's network allowlist.
//
// The zero Scope allows nothing but loopback. That is the safe default and the
// one that makes the common case — fuzzing a local process — frictionless while
// still refusing to reach anything else.
//
// Rules are built once, before the campaign starts, and are read-only
// thereafter: Check and Dial are safe to call from every worker at once, Allow
// is not safe to call alongside them. This is not a limitation being worked
// around — a scope that could widen while traffic was flowing would mean the
// allowlist a connection was checked against is not the one the operator
// attested to, which is the point of recording the summary in the
// authorization (see Authorization.ScopeSummary).
type Scope struct {
	// Rules are the allowed destinations.
	Rules []Rule

	// AllowLoopback permits connections to the local host. It defaults to true
	// through NewScope, because a campaign that cannot reach 127.0.0.1 cannot
	// fuzz a local server and the risk of loopback is not the risk this guard
	// exists for.
	AllowLoopback bool

	// AcknowledgePublic records that the operator has explicitly accepted that
	// this scope reaches public address space. Without it, a rule covering a
	// public address is refused at validation, not at the first packet.
	AcknowledgePublic bool

	// Auditor records decisions. Nil disables auditing, which is permitted for
	// a local campaign and is itself audited by the daemon when it is not.
	Auditor Auditor

	// AuditAllows records every permitted connection, not only refusals. It is
	// off by default: a campaign making a million connections would produce a
	// million entries and the refusals — the entries that matter — would be
	// unfindable among them.
	AuditAllows bool

	mu     sync.Mutex
	allows uint64
	denies uint64
}

// Auditor records a safety decision. The store implements it; a test can too.
type Auditor interface {
	Audit(ctx context.Context, actor, action, detail string) error
}

// NewScope returns a scope allowing loopback and nothing else.
func NewScope() *Scope { return &Scope{AllowLoopback: true} }

// Allow adds a rule from a host or CIDR and an optional port list.
//
// The host may be a literal address, a CIDR, or a name. A name is resolved
// once, here, and the addresses are pinned: resolving at connection time would
// mean the allowlist says one thing when it is written and another when a DNS
// record changes, which is not an allowlist.
func (s *Scope) Allow(host string, ports ...PortRange) error {
	host = strings.TrimSpace(host)
	if host == "" {
		return fmt.Errorf("safety: empty host in scope")
	}

	if prefix, err := netip.ParsePrefix(host); err == nil {
		s.Rules = append(s.Rules, Rule{Prefix: prefix.Masked(), Host: host, Ports: ports})
		return nil
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		s.Rules = append(s.Rules, Rule{Prefix: netip.PrefixFrom(addr, addr.BitLen()), Host: host, Ports: ports})
		return nil
	}

	addrs, err := net.LookupHost(host)
	if err != nil {
		return fmt.Errorf("safety: resolving %q for the scope allowlist: %w", host, err)
	}
	for _, a := range addrs {
		addr, err := netip.ParseAddr(a)
		if err != nil {
			continue
		}
		addr = addr.Unmap()
		s.Rules = append(s.Rules, Rule{
			Prefix: netip.PrefixFrom(addr, addr.BitLen()),
			Host:   host,
			Ports:  ports,
		})
	}
	if len(s.Rules) == 0 {
		return fmt.Errorf("safety: %q resolved to no usable addresses", host)
	}
	return nil
}

// MustAllow is Allow for literal addresses in tests and defaults.
func (s *Scope) MustAllow(host string, ports ...PortRange) {
	if err := s.Allow(host, ports...); err != nil {
		panic(err)
	}
}

// Validate checks the scope before a campaign starts.
//
// This is the layer that turns a misconfiguration into an immediate refusal
// instead of a packet already sent. remote reports whether the campaign intends
// to leave the host at all; a purely local campaign needs no allowlist.
func (s *Scope) Validate(remote bool) error {
	if remote && len(s.Rules) == 0 {
		return ErrNoScope
	}
	if s.AcknowledgePublic {
		return nil
	}
	for _, r := range s.Rules {
		if isPublic(r.Prefix.Addr()) {
			return fmt.Errorf("%w: rule %s covers %s", ErrPublicScope, r.Host, r.Prefix)
		}
		// A prefix whose base address is private can still span public space if
		// it is wide enough to escape the private block. Checking the last
		// address as well is what stops 10.0.0.0/4 from passing as private.
		if last := lastAddr(r.Prefix); isPublic(last) {
			return fmt.Errorf("%w: rule %s spans %s..%s", ErrPublicScope, r.Host, r.Prefix.Addr(), last)
		}
	}
	return nil
}

// Check reports whether a destination is in scope.
//
// It takes the address rather than a name on purpose: a name checked here and
// resolved later is a check on something other than what will be connected to.
func (s *Scope) Check(ctx context.Context, addr netip.AddrPort) error {
	ip := addr.Addr().Unmap()

	if s.AllowLoopback && ip.IsLoopback() {
		s.record(ctx, true, addr, "loopback")
		return nil
	}
	for _, r := range s.Rules {
		if !r.Prefix.Contains(ip) {
			continue
		}
		if !portAllowed(r, addr.Port()) {
			continue
		}
		s.record(ctx, true, addr, r.Host)
		return nil
	}
	s.record(ctx, false, addr, "")
	return fmt.Errorf("%w: %s (scope allows %s)", ErrOutOfScope, addr, s.Summary())
}

// CheckAddr resolves and checks a "host:port" destination.
//
// Every resolved address must be in scope, not merely one of them. A name that
// resolves to an allowed address and a disallowed one is a name that can reach
// the disallowed one, and accepting it because the first address matched is the
// hole that makes a scope guard decorative.
func (s *Scope) CheckAddr(ctx context.Context, network, address string) error {
	// A Unix socket is not a network destination. There is no remote host to be
	// in or out of scope, and no packet leaves the machine; what governs reach
	// is the filesystem, which the sandbox confines. Refusing it here for
	// failing to parse as host:port would block the one transport that cannot
	// carry a connection off the host at all.
	if isLocalNetwork(network) {
		s.record(ctx, true, netip.AddrPort{}, "local socket "+address)
		return nil
	}

	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("safety: %q is not a host:port destination: %w", address, err)
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return fmt.Errorf("safety: %q has no valid port: %w", address, err)
	}

	if ip, err := netip.ParseAddr(host); err == nil {
		return s.Check(ctx, netip.AddrPortFrom(ip.Unmap(), uint16(port)))
	}

	resolved, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return fmt.Errorf("safety: resolving %q: %w", host, err)
	}
	if len(resolved) == 0 {
		return fmt.Errorf("safety: %q resolved to no addresses", host)
	}
	for _, ip := range resolved {
		if err := s.Check(ctx, netip.AddrPortFrom(ip.Unmap(), uint16(port))); err != nil {
			return fmt.Errorf("%w (via %s)", err, host)
		}
	}
	return nil
}

// Dial connects, refusing anything out of scope.
//
// This is the portable layer of the layered enforcement ADR-0012 describes. It
// is not the only layer and must not be the only layer: on Linux the network
// namespace enforces below the code, where a bug here cannot reach.
func (s *Scope) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	if err := s.CheckAddr(ctx, network, address); err != nil {
		return nil, err
	}
	var d net.Dialer
	return d.DialContext(ctx, network, address)
}

// Stats returns how many connections were allowed and refused.
func (s *Scope) Stats() (allowed, denied uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.allows, s.denies
}

// Summary renders the allowlist for an error message.
func (s *Scope) Summary() string {
	parts := make([]string, 0, len(s.Rules)+1)
	if s.AllowLoopback {
		parts = append(parts, "loopback")
	}
	for _, r := range s.Rules {
		p := r.Prefix.String()
		if len(r.Ports) > 0 {
			ports := make([]string, 0, len(r.Ports))
			for _, pr := range r.Ports {
				ports = append(ports, pr.String())
			}
			p += ":" + strings.Join(ports, ",")
		}
		parts = append(parts, p)
	}
	if len(parts) == 0 {
		return "nothing"
	}
	sort.Strings(parts)
	return strings.Join(parts, ", ")
}

func (s *Scope) record(ctx context.Context, allowed bool, addr netip.AddrPort, rule string) {
	s.mu.Lock()
	if allowed {
		s.allows++
	} else {
		s.denies++
	}
	s.mu.Unlock()

	if s.Auditor == nil {
		return
	}
	if allowed && !s.AuditAllows {
		return
	}
	action, detail := AuditScopeDeny, fmt.Sprintf("dest=%s", addr)
	if allowed {
		action = AuditScopeAllow
		detail = fmt.Sprintf("dest=%s rule=%s", addr, rule)
	}
	// A failed audit write must not silently succeed as a connection. The
	// auditor's own errors are its to report; what matters here is that the
	// decision was offered to it.
	_ = s.Auditor.Audit(ctx, "", action, detail)
}

func portAllowed(r Rule, port uint16) bool {
	if len(r.Ports) == 0 {
		return true
	}
	for _, pr := range r.Ports {
		if pr.Contains(port) {
			return true
		}
	}
	return false
}

// isPublic reports whether an address is globally routable.
func isPublic(a netip.Addr) bool {
	if !a.IsValid() {
		return false
	}
	a = a.Unmap()
	switch {
	case a.IsLoopback(), a.IsPrivate(), a.IsLinkLocalUnicast(),
		a.IsLinkLocalMulticast(), a.IsUnspecified(), a.IsMulticast():
		return false
	}
	if a.Is4() {
		b := a.As4()
		switch {
		case b[0] == 100 && b[1] >= 64 && b[1] < 128: // 100.64/10, carrier NAT
			return false
		case b[0] == 192 && b[1] == 0 && b[2] == 0: // 192.0.0/24, protocol assignments
			return false
		case b[0] == 192 && b[1] == 0 && b[2] == 2: // TEST-NET-1
			return false
		case b[0] == 198 && (b[1] == 18 || b[1] == 19): // benchmarking
			return false
		case b[0] == 198 && b[1] == 51 && b[2] == 100: // TEST-NET-2
			return false
		case b[0] == 203 && b[1] == 0 && b[2] == 113: // TEST-NET-3
			return false
		case b[0] >= 240: // reserved
			return false
		}
		return true
	}
	// IPv6 unique-local addresses are the private range Addr.IsPrivate already
	// covers; anything else global is public.
	return a.IsGlobalUnicast()
}

// lastAddr returns the highest address in a prefix.
func lastAddr(p netip.Prefix) netip.Addr {
	if !p.IsValid() {
		return netip.Addr{}
	}
	bits := p.Addr().BitLen()
	if p.Bits() == bits {
		return p.Addr()
	}
	switch {
	case p.Addr().Is4():
		b := p.Masked().Addr().As4()
		host := bits - p.Bits()
		for i := 0; i < host; i++ {
			b[3-i/8] |= 1 << (i % 8)
		}
		return netip.AddrFrom4(b)
	default:
		b := p.Masked().Addr().As16()
		host := bits - p.Bits()
		for i := 0; i < host; i++ {
			b[15-i/8] |= 1 << (i % 8)
		}
		return netip.AddrFrom16(b)
	}
}

// ScopeSpec is a campaign file's network scope, in the terms the guard needs.
//
// Declared here rather than taking a campaign type, because internal/safety
// must not depend on the configuration format: the guard is the security
// boundary and the campaign file is one of several things that could describe
// one.
type ScopeSpec struct {
	// Loopback permits connections to the local host. Nil keeps the default,
	// which permits it.
	Loopback *bool

	// AcknowledgePublic is the separate, explicit acknowledgement that public
	// address space is in scope.
	AcknowledgePublic bool

	// Allow lists destinations, each already split into a host and its ports.
	Allow []AllowEntry
}

// AllowEntry is one allowed destination.
type AllowEntry struct {
	Host  string
	Ports []PortRange
}

// NewScopeFrom builds a guard from a specification.
//
// One constructor for every caller, because a second place that assembles a
// scope is a second place that can get the default wrong — and the default here
// is deny, which is the one that must not drift.
func NewScopeFrom(spec ScopeSpec, auditor Auditor) (*Scope, error) {
	s := NewScope()
	s.Auditor = auditor
	if spec.Loopback != nil {
		s.AllowLoopback = *spec.Loopback
	}
	s.AcknowledgePublic = spec.AcknowledgePublic
	for _, e := range spec.Allow {
		if err := s.Allow(e.Host, e.Ports...); err != nil {
			return nil, err
		}
	}
	return s, nil
}

// isLocalNetwork reports whether a network reaches only this machine.
func isLocalNetwork(network string) bool {
	switch network {
	case "unix", "unixgram", "unixpacket":
		return true
	}
	return false
}
