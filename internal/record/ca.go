package record

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"sync"
	"time"
)

// Recording HTTPS means terminating the client's TLS, which means presenting a
// certificate the client will accept for a host the proxy does not own. That is
// interception, and it is a thing an operator has to set up deliberately: they
// generate an authority, they install it in the client they are recording, and
// they accept that anything trusting that authority can have its traffic read.
//
// So the authority is supplied rather than conjured. A proxy that quietly
// generated one and trusted it would be a proxy that could read any traffic it
// was pointed at, which is not a property to acquire by accident — and ADR-0014
// says operator-supplied for exactly this reason.

// Authority signs interception certificates.
type Authority struct {
	cert *x509.Certificate
	key  any

	mu     sync.Mutex
	issued map[string]*tls.Certificate
}

// LoadAuthority reads a PEM certificate and private key.
func LoadAuthority(certPath, keyPath string) (*Authority, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("record: reading the certificate: %w", err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("record: reading the private key: %w", err)
	}
	return NewAuthority(certPEM, keyPEM)
}

// NewAuthority builds an authority from PEM blocks.
func NewAuthority(certPEM, keyPEM []byte) (*Authority, error) {
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("record: the certificate and key do not form a pair: %w", err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("record: parsing the certificate: %w", err)
	}
	if !leaf.IsCA {
		return nil, fmt.Errorf("record: %q is not a certificate authority, so it cannot "+
			"sign the certificates the proxy needs to present", leaf.Subject.CommonName)
	}
	return &Authority{cert: leaf, key: pair.PrivateKey, issued: map[string]*tls.Certificate{}}, nil
}

// GenerateAuthority creates a new authority and returns its PEM blocks.
//
// For an operator setting one up, and for tests. It is a separate step from
// using one on purpose: the certificate has to be installed in the client being
// recorded, and that is a decision with consequences beyond this campaign.
func GenerateAuthority(name string, validFor time.Duration) (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: name, Organization: []string{"Xfuzz recording proxy"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(validFor),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM, nil
}

// For returns a certificate for a host, issuing and caching one on first use.
func (a *Authority) For(host string) (*tls.Certificate, error) {
	a.mu.Lock()
	if c, ok := a.issued[host]; ok {
		a.mu.Unlock()
		return c, nil
	}
	a.mu.Unlock()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    time.Now().Add(-time.Hour),
		// Deliberately short. An interception certificate that outlives the
		// recording session is one that can be used later by anyone who
		// extracted it from the proxy's memory or its cache.
		NotAfter:    time.Now().Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, a.cert, &key.PublicKey, a.key)
	if err != nil {
		return nil, fmt.Errorf("record: signing a certificate for %s: %w", host, err)
	}
	cert := &tls.Certificate{Certificate: [][]byte{der, a.cert.Raw}, PrivateKey: key}

	a.mu.Lock()
	a.issued[host] = cert
	a.mu.Unlock()
	return cert, nil
}

// GenerateLeafForTest returns a certificate that is not an authority.
//
// Exported for the test that checks a leaf is refused, because that refusal is
// the guard against the one configuration mistake here with consequences: an
// authority the operator did not generate deliberately.
func GenerateLeafForTest() (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "leaf.example"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"leaf.example"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), nil
}
