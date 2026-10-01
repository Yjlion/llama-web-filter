package certs

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"net"
	"sync"
	"time"
)

const (
	// leafValidity is deliberately short, mirroring mitmproxy's own
	// short-lived-leaf approach - well under browser max-cert-lifetime
	// limits, and it caps how long a stale-but-still-cached leaf can be
	// trusted after e.g. a CA rotation.
	leafValidity  = 72 * time.Hour
	leafClockSkew = 5 * time.Minute
)

// LeafIssuer issues and caches per-host leaf certificates signed by a CA,
// for use as a tls.Config.GetCertificate callback during MITM interception.
type LeafIssuer struct {
	ca *CA

	// leafKey is reused across every issued leaf: the CA's signature is
	// what establishes trust, so a single proxy-wide leaf key is fine and
	// saves a keygen per intercepted host.
	leafKey *ecdsa.PrivateKey

	mu    sync.RWMutex
	cache map[string]*cachedLeaf
}

type cachedLeaf struct {
	cert    *tls.Certificate
	expires time.Time
}

// NewLeafIssuer creates a LeafIssuer backed by ca, generating the shared
// leaf signing key once.
func NewLeafIssuer(ca *CA) (*LeafIssuer, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate leaf key: %w", err)
	}
	return &LeafIssuer{
		ca:      ca,
		leafKey: key,
		cache:   make(map[string]*cachedLeaf),
	}, nil
}

// GetCertificate is a tls.Config.GetCertificate callback: it issues (or
// returns a cached) leaf certificate for the SNI hostname in hello.
func (li *LeafIssuer) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	host := hello.ServerName
	if host == "" {
		return nil, fmt.Errorf("no SNI hostname in ClientHello")
	}
	return li.CertificateFor(host)
}

// CertificateFor returns a cached or freshly-issued leaf certificate for
// host (a DNS name or IP literal).
func (li *LeafIssuer) CertificateFor(host string) (*tls.Certificate, error) {
	li.mu.RLock()
	entry, ok := li.cache[host]
	li.mu.RUnlock()
	if ok && time.Now().Before(entry.expires) {
		return entry.cert, nil
	}

	cert, expires, err := li.issue(host)
	if err != nil {
		return nil, err
	}
	li.mu.Lock()
	li.cache[host] = &cachedLeaf{cert: cert, expires: expires}
	li.mu.Unlock()
	return cert, nil
}

// Clear evicts every cached leaf, forcing re-issuance under the current CA
// - called after a CA import so old leaves signed by a replaced CA are
// never served again.
func (li *LeafIssuer) Clear() {
	li.mu.Lock()
	li.cache = make(map[string]*cachedLeaf)
	li.mu.Unlock()
}

func (li *LeafIssuer) issue(host string) (*tls.Certificate, time.Time, error) {
	serial, err := randomSerial()
	if err != nil {
		return nil, time.Time{}, err
	}
	now := time.Now()
	notBefore := now.Add(-leafClockSkew)
	notAfter := now.Add(leafValidity)

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, li.ca.Cert, &li.leafKey.PublicKey, li.ca.Key)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("issue leaf certificate for %s: %w", host, err)
	}

	cert := &tls.Certificate{
		Certificate: [][]byte{der, li.ca.Cert.Raw},
		PrivateKey:  li.leafKey,
	}
	return cert, notAfter, nil
}
