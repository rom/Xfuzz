package safety

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
)

// recordingAuditor captures decisions instead of persisting them.
type recordingAuditor struct {
	mu      sync.Mutex
	entries []string
}

func (a *recordingAuditor) Audit(_ context.Context, actor, action, detail string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.entries = append(a.entries, actor+"|"+action+"|"+detail)
	return nil
}

func (a *recordingAuditor) count(action string) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	n := 0
	for _, e := range a.entries {
		if strings.Contains(e, "|"+action+"|") {
			n++
		}
	}
	return n
}

func addr(s string) netip.AddrPort {
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		panic(err)
	}
	return ap
}

func TestScopeDeniesByDefault(t *testing.T) {
	s := NewScope()
	ctx := context.Background()

	if err := s.Check(ctx, addr("127.0.0.1:8080")); err != nil {
		t.Fatalf("loopback must be allowed by default: %v", err)
	}
	if err := s.Check(ctx, addr("10.0.0.5:80")); !errors.Is(err, ErrOutOfScope) {
		t.Fatalf("an unlisted host was allowed: %v", err)
	}
	if err := s.Check(ctx, addr("[::1]:80")); err != nil {
		t.Fatalf("IPv6 loopback must be allowed: %v", err)
	}
}

func TestScopeAllowsWhatItIsTold(t *testing.T) {
	s := NewScope()
	s.MustAllow("10.0.0.0/8", PortRange{80, 80}, PortRange{8000, 8999})
	ctx := context.Background()

	if err := s.Check(ctx, addr("10.1.2.3:80")); err != nil {
		t.Fatalf("an allowed destination was refused: %v", err)
	}
	if err := s.Check(ctx, addr("10.1.2.3:8443")); err != nil {
		t.Fatalf("a port inside an allowed range was refused: %v", err)
	}
	if err := s.Check(ctx, addr("10.1.2.3:9000")); !errors.Is(err, ErrOutOfScope) {
		t.Fatal("a port outside every allowed range was permitted")
	}
	if err := s.Check(ctx, addr("11.1.2.3:80")); !errors.Is(err, ErrOutOfScope) {
		t.Fatal("an address outside the allowed prefix was permitted")
	}
}

func TestScopeWithNoPortsAllowsEveryPort(t *testing.T) {
	s := NewScope()
	s.MustAllow("192.168.1.10")
	ctx := context.Background()
	for _, p := range []string{"192.168.1.10:22", "192.168.1.10:65535", "192.168.1.10:1"} {
		if err := s.Check(ctx, addr(p)); err != nil {
			t.Fatalf("%s was refused by a rule with no port list: %v", p, err)
		}
	}
}

func TestScopeRefusesARemoteCampaignWithNoAllowlist(t *testing.T) {
	s := NewScope()
	if err := s.Validate(false); err != nil {
		t.Fatalf("a local campaign needs no allowlist: %v", err)
	}
	if err := s.Validate(true); !errors.Is(err, ErrNoScope) {
		t.Fatalf("a remote campaign with no allowlist was accepted: %v", err)
	}
}

func TestScopeRefusesPublicSpaceWithoutAcknowledgement(t *testing.T) {
	s := NewScope()
	s.MustAllow("93.184.216.34")
	if err := s.Validate(true); !errors.Is(err, ErrPublicScope) {
		t.Fatalf("a public address was accepted without acknowledgement: %v", err)
	}
	s.AcknowledgePublic = true
	if err := s.Validate(true); err != nil {
		t.Fatalf("an acknowledged public scope was still refused: %v", err)
	}
}

func TestScopeCatchesAPrefixThatEscapesPrivateSpace(t *testing.T) {
	// 10.0.0.0/4 has a private base address and spans 10.0.0.0 to 31.255.255.255,
	// most of which is public. Checking only the base would let it through.
	s := NewScope()
	s.MustAllow("10.0.0.0/4")
	err := s.Validate(true)
	if !errors.Is(err, ErrPublicScope) {
		t.Fatalf("a prefix spanning public space was accepted: %v", err)
	}
	if !strings.Contains(err.Error(), "spans") {
		t.Fatalf("the error does not say why: %v", err)
	}
}

func TestScopeAcceptsPrivatePrefixes(t *testing.T) {
	s := NewScope()
	for _, p := range []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fd00::/8"} {
		s.MustAllow(p)
	}
	if err := s.Validate(true); err != nil {
		t.Fatalf("a private scope was refused: %v", err)
	}
}

func TestScopeAuditsRefusalsButNotEveryAllow(t *testing.T) {
	a := &recordingAuditor{}
	s := NewScope()
	s.Auditor = a
	s.MustAllow("10.0.0.0/8")
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		_ = s.Check(ctx, addr("10.0.0.1:80"))
	}
	_ = s.Check(ctx, addr("172.16.0.1:80"))

	if got := a.count(AuditScopeDeny); got != 1 {
		t.Fatalf("%d refusals audited, want 1", got)
	}
	if got := a.count(AuditScopeAllow); got != 0 {
		t.Fatalf("%d allows audited; a campaign making millions of connections "+
			"would bury the refusals", got)
	}

	s.AuditAllows = true
	_ = s.Check(ctx, addr("10.0.0.1:80"))
	if got := a.count(AuditScopeAllow); got != 1 {
		t.Fatalf("%d allows audited with AuditAllows set, want 1", got)
	}
}

func TestScopeCountsDecisions(t *testing.T) {
	s := NewScope()
	s.MustAllow("10.0.0.0/8")
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		_ = s.Check(ctx, addr("10.0.0.1:80"))
	}
	for i := 0; i < 2; i++ {
		_ = s.Check(ctx, addr("172.16.0.1:80"))
	}
	allowed, denied := s.Stats()
	if allowed != 3 || denied != 2 {
		t.Fatalf("stats = %d allowed, %d denied; want 3 and 2", allowed, denied)
	}
}

func TestScopeCheckAddrRequiresEveryResolvedAddressToBeInScope(t *testing.T) {
	// Constructed directly rather than through Allow, so the test does not
	// depend on DNS: what is under test is the decision, not the resolver.
	s := NewScope()
	s.MustAllow("10.0.0.1")
	ctx := context.Background()

	if err := s.CheckAddr(ctx, "tcp", "10.0.0.1:80"); err != nil {
		t.Fatalf("a literal in-scope address was refused: %v", err)
	}
	if err := s.CheckAddr(ctx, "tcp", "10.0.0.2:80"); !errors.Is(err, ErrOutOfScope) {
		t.Fatalf("a literal out-of-scope address was allowed: %v", err)
	}
	if err := s.CheckAddr(ctx, "tcp", "not-a-destination"); err == nil {
		t.Fatal("a malformed destination was accepted")
	}
	if err := s.CheckAddr(ctx, "tcp", "10.0.0.1:notaport"); err == nil {
		t.Fatal("a destination with no valid port was accepted")
	}
}

func TestScopeDialRefusesBeforeConnecting(t *testing.T) {
	s := NewScope()
	s.AllowLoopback = false
	// Port 1 on loopback, which nothing is listening on: a dial that reached
	// the network would fail with a connection error rather than the scope
	// error, so the error identity is what proves the check ran first.
	_, err := s.Dial(context.Background(), "tcp", "127.0.0.1:1")
	if !errors.Is(err, ErrOutOfScope) {
		t.Fatalf("Dial error = %v, want ErrOutOfScope", err)
	}
}

func TestScopeSummaryIsStable(t *testing.T) {
	build := func() string {
		s := NewScope()
		s.MustAllow("10.0.0.0/8", PortRange{80, 80})
		s.MustAllow("192.168.0.0/16")
		return s.Summary()
	}
	if a, b := build(), build(); a != b {
		t.Fatalf("summary is not stable: %q vs %q", a, b)
	}
	if got := build(); !strings.Contains(got, "loopback") || !strings.Contains(got, "10.0.0.0/8:80") {
		t.Fatalf("summary = %q", got)
	}
}

func TestLastAddr(t *testing.T) {
	cases := map[string]string{
		"10.0.0.0/8":     "10.255.255.255",
		"192.168.1.0/24": "192.168.1.255",
		"10.1.2.3/32":    "10.1.2.3",
		"fd00::/8":       "fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
	}
	for in, want := range cases {
		p := netip.MustParsePrefix(in)
		if got := lastAddr(p); got.String() != want {
			t.Errorf("lastAddr(%s) = %s, want %s", in, got, want)
		}
	}
}

func TestDialControlRefusesAnythingButLoopback(t *testing.T) {
	// The exception is narrow on purpose: it exists so a fuzzer can talk to a
	// browser it just launched, and a harness this fuzzer started is always on
	// loopback. Anything else reaching through it would be an unaudited hole
	// straight past the allowlist.
	s, err := NewScopeFrom(ScopeSpec{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, addr := range []string{"93.184.216.34:80", "10.0.0.5:9222", "[2001:db8::1]:9222"} {
		if _, err := s.DialControl(context.Background(), "tcp", addr); err == nil {
			t.Errorf("DialControl(%s) connected", addr)
		} else if !errors.Is(err, ErrOutOfScope) {
			t.Errorf("DialControl(%s) failed for the wrong reason: %v", addr, err)
		}
	}
	// A name rather than an address is refused too: resolution is where a
	// loopback check can be made to lie.
	if _, err := s.DialControl(context.Background(), "tcp", "localhost:9222"); err == nil {
		t.Error("DialControl accepted a hostname")
	}
}

func TestDialControlReachesALoopbackHarness(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err == nil {
			c.Close()
		}
	}()
	s, err := NewScopeFrom(ScopeSpec{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c, err := s.DialControl(context.Background(), "tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("a loopback control channel was refused: %v", err)
	}
	c.Close()
	// Recorded, because a connection the fuzzer makes is one the operator is
	// entitled to see even when no rule had to permit it.
	if allowed, _ := s.Stats(); allowed == 0 {
		t.Error("the control connection was not counted")
	}
}
