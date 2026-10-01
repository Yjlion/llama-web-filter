package certs_test

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/yjlion/llama-web-filter/internal/certs"
)

func TestLoadOrCreateCAGeneratesAndPersists(t *testing.T) {
	dir := t.TempDir()
	ca1, err := certs.LoadOrCreateCA(dir)
	if err != nil {
		t.Fatalf("LoadOrCreateCA (generate): %v", err)
	}
	if !ca1.Cert.IsCA {
		t.Errorf("generated cert IsCA = false, want true")
	}

	// A second call against the same dir loads the persisted CA rather
	// than generating a new one.
	ca2, err := certs.LoadOrCreateCA(dir)
	if err != nil {
		t.Fatalf("LoadOrCreateCA (load): %v", err)
	}
	if ca1.Cert.SerialNumber.Cmp(ca2.Cert.SerialNumber) != 0 {
		t.Errorf("second load generated a different CA (serial mismatch) - should have loaded the persisted one")
	}
}

func TestLoadOrCreateCARegeneratesWhenExistingCertUsesRSAKey(t *testing.T) {
	dir := t.TempDir()
	keyMaterial, err := certs.LoadOrCreateCA(t.TempDir())
	if err != nil {
		t.Fatalf("LoadOrCreateCA (key material): %v", err)
	}
	rsaCertPEM, rsaSerial := testRSACACertPEM(t)

	if err := os.WriteFile(filepath.Join(dir, "ca.crt"), rsaCertPEM, 0o644); err != nil {
		t.Fatalf("write RSA CA cert: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ca.key"), keyMaterial.KeyPEM, 0o600); err != nil {
		t.Fatalf("write CA key material: %v", err)
	}

	ca, err := certs.LoadOrCreateCA(dir)
	if err != nil {
		t.Fatalf("LoadOrCreateCA should regenerate after rejecting RSA CA cert without panic: %v", err)
	}
	if ca.Cert.SerialNumber.Cmp(rsaSerial) == 0 {
		t.Fatalf("LoadOrCreateCA loaded RSA CA cert; want regeneration with an ECDSA CA")
	}
	if _, ok := ca.Cert.PublicKey.(*ecdsa.PublicKey); !ok {
		t.Fatalf("regenerated CA public key type = %T, want *ecdsa.PublicKey", ca.Cert.PublicKey)
	}
}

func testRSACACertPEM(t *testing.T) ([]byte, *big.Int) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("generate serial: %v", err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "RSA Test Root CA"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create RSA CA cert: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), serial
}

func TestLeafIssuerIssuesCertSignedByCA(t *testing.T) {
	dir := t.TempDir()
	ca, err := certs.LoadOrCreateCA(dir)
	if err != nil {
		t.Fatalf("LoadOrCreateCA: %v", err)
	}
	issuer, err := certs.NewLeafIssuer(ca)
	if err != nil {
		t.Fatalf("NewLeafIssuer: %v", err)
	}

	leaf, err := issuer.CertificateFor("example.com")
	if err != nil {
		t.Fatalf("CertificateFor: %v", err)
	}
	if len(leaf.Certificate) != 2 {
		t.Fatalf("leaf chain has %d certs, want 2 (leaf + CA)", len(leaf.Certificate))
	}
	leafCert, err := x509.ParseCertificate(leaf.Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf cert: %v", err)
	}
	if leafCert.DNSNames[0] != "example.com" {
		t.Errorf("leaf DNSNames = %v, want [example.com]", leafCert.DNSNames)
	}

	// Verify chain validation against the CA as a trusted root.
	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)
	if _, err := leafCert.Verify(x509.VerifyOptions{DNSName: "example.com", Roots: pool}); err != nil {
		t.Errorf("leaf cert did not verify against the CA: %v", err)
	}
}

func TestLeafIssuerCachesByHost(t *testing.T) {
	dir := t.TempDir()
	ca, _ := certs.LoadOrCreateCA(dir)
	issuer, _ := certs.NewLeafIssuer(ca)

	a, _ := issuer.CertificateFor("a.example.com")
	b, _ := issuer.CertificateFor("a.example.com")
	if &a.Certificate[0][0] == nil || &b.Certificate[0][0] == nil {
		t.Fatal("unexpected nil cert bytes")
	}
	// Same host should return the identical cached *tls.Certificate.
	if a != b {
		t.Errorf("expected cached certificate to be reused for the same host")
	}
}

func TestLeafIssuerIPLiteralUsesIPAddresses(t *testing.T) {
	dir := t.TempDir()
	ca, _ := certs.LoadOrCreateCA(dir)
	issuer, _ := certs.NewLeafIssuer(ca)

	leaf, err := issuer.CertificateFor("192.0.2.1")
	if err != nil {
		t.Fatalf("CertificateFor: %v", err)
	}
	leafCert, _ := x509.ParseCertificate(leaf.Certificate[0])
	if len(leafCert.IPAddresses) != 1 || !leafCert.IPAddresses[0].Equal(net.ParseIP("192.0.2.1")) {
		t.Errorf("leaf IPAddresses = %v, want [192.0.2.1]", leafCert.IPAddresses)
	}
	if len(leafCert.DNSNames) != 0 {
		t.Errorf("leaf DNSNames = %v, want empty for an IP-literal host", leafCert.DNSNames)
	}
}

// TestFullTLSHandshakeAgainstGeneratedCA is the Phase 3 verification from
// the project plan: spin up a real tls.Listener using GetCertificate,
// connect with crypto/tls.Dial and a RootCAs pool containing the
// generated CA, and confirm full chain validation succeeds for an
// arbitrary SNI hostname - the Go-native equivalent of
// `openssl s_client -connect ... -servername example.com`.
func TestFullTLSHandshakeAgainstGeneratedCA(t *testing.T) {
	dir := t.TempDir()
	ca, err := certs.LoadOrCreateCA(dir)
	if err != nil {
		t.Fatalf("LoadOrCreateCA: %v", err)
	}
	issuer, err := certs.NewLeafIssuer(ca)
	if err != nil {
		t.Fatalf("NewLeafIssuer: %v", err)
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		GetCertificate: issuer.GetCertificate,
	})
	if err != nil {
		t.Fatalf("tls.Listen: %v", err)
	}
	defer ln.Close()

	serverDone := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		defer conn.Close()
		buf := make([]byte, 5)
		_, err = conn.Read(buf)
		serverDone <- err
	}()

	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)

	dialer := &net.Dialer{Timeout: 5 * time.Second}
	rawConn, err := dialer.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	client := tls.Client(rawConn, &tls.Config{
		ServerName: "example.com",
		RootCAs:    pool,
	})
	defer client.Close()

	if err := client.Handshake(); err != nil {
		t.Fatalf("TLS handshake against generated CA failed: %v", err)
	}
	state := client.ConnectionState()
	if len(state.PeerCertificates) == 0 || state.PeerCertificates[0].Subject.CommonName != "example.com" {
		t.Errorf("unexpected peer certificate: %+v", state.PeerCertificates)
	}

	if _, err := client.Write([]byte("hello")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := <-serverDone; err != nil {
		t.Fatalf("server-side read failed: %v", err)
	}
}

func TestImportBundleReplacesCAAndValidates(t *testing.T) {
	srcDir := t.TempDir()
	src, err := certs.LoadOrCreateCA(srcDir)
	if err != nil {
		t.Fatalf("LoadOrCreateCA: %v", err)
	}

	dstDir := t.TempDir()
	// Seed the destination with its own (different) CA first.
	original, err := certs.LoadOrCreateCA(dstDir)
	if err != nil {
		t.Fatalf("LoadOrCreateCA (dst): %v", err)
	}

	imported, err := certs.ImportBundle(dstDir, src.BundlePEM())
	if err != nil {
		t.Fatalf("ImportBundle: %v", err)
	}
	if imported.Cert.SerialNumber.Cmp(src.Cert.SerialNumber) != 0 {
		t.Errorf("imported CA serial does not match the source CA")
	}
	if imported.Cert.SerialNumber.Cmp(original.Cert.SerialNumber) == 0 {
		t.Errorf("imported CA should differ from the original destination CA")
	}

	// Reloading from disk should now return the imported CA.
	reloaded, err := certs.LoadOrCreateCA(dstDir)
	if err != nil {
		t.Fatalf("LoadOrCreateCA (reload): %v", err)
	}
	if reloaded.Cert.SerialNumber.Cmp(src.Cert.SerialNumber) != 0 {
		t.Errorf("reloaded CA does not match the imported one")
	}
}

func TestImportBundleRejectsMismatchedKey(t *testing.T) {
	dir1 := t.TempDir()
	ca1, _ := certs.LoadOrCreateCA(dir1)
	dir2 := t.TempDir()
	ca2, _ := certs.LoadOrCreateCA(dir2)

	// Frankenstein bundle: cert from ca1, key from ca2 - must be rejected.
	bad := append(append([]byte{}, ca1.CertPEM...), ca2.KeyPEM...)

	dstDir := t.TempDir()
	if _, err := certs.ImportBundle(dstDir, bad); err == nil {
		t.Errorf("ImportBundle should reject a cert/key pair that don't match")
	}
}

func TestImportBundleRejectsMissingKey(t *testing.T) {
	dir := t.TempDir()
	ca, _ := certs.LoadOrCreateCA(dir)
	if _, err := certs.ImportBundle(t.TempDir(), ca.CertPEM); err == nil {
		t.Errorf("ImportBundle should reject a bundle with no private key")
	}
}

func TestLeafIssuerClearEvictsCache(t *testing.T) {
	dir := t.TempDir()
	ca, _ := certs.LoadOrCreateCA(dir)
	issuer, _ := certs.NewLeafIssuer(ca)

	first, _ := issuer.CertificateFor("cache-test.example.com")
	issuer.Clear()
	second, _ := issuer.CertificateFor("cache-test.example.com")
	if first == second {
		t.Errorf("expected Clear() to force re-issuance, got the same cached certificate")
	}
}
