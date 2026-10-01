// Package certs implements the locally-generated MITM root CA and
// per-host leaf certificate issuance that stand in for mitmproxy's own
// certificate engine (which has no direct Go equivalent) - built from
// crypto/x509 primitives directly, the same approach mkcert and Caddy's
// internal CA use.
package certs

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

const (
	caCertFile = "ca.crt"
	caKeyFile  = "ca.key"

	caValidity = 10 * 365 * 24 * time.Hour
	// caClockSkew backdates NotBefore so clients with a slightly-behind
	// clock don't reject a CA minted "in the future".
	caClockSkew = 5 * time.Minute
)

// CA is the root certificate authority used to sign per-host leaf certs
// for TLS interception.
type CA struct {
	dir  string
	Cert *x509.Certificate
	Key  *ecdsa.PrivateKey

	// CertPEM/KeyPEM are the PEM-encoded forms, cached so API downloads
	// don't need to re-encode on every request.
	CertPEM []byte
	KeyPEM  []byte
}

// LoadOrCreateCA loads certs/ca.crt + certs/ca.key from dir if both exist
// and parse/validate; otherwise it generates a new CA and persists it.
func LoadOrCreateCA(dir string) (*CA, error) {
	certPath := filepath.Join(dir, caCertFile)
	keyPath := filepath.Join(dir, caKeyFile)

	certPEM, certErr := os.ReadFile(certPath)
	keyPEM, keyErr := os.ReadFile(keyPath)
	if certErr == nil && keyErr == nil {
		ca, err := parseCA(dir, certPEM, keyPEM)
		if err == nil {
			return ca, nil
		}
		// Fall through to regeneration on any parse/validation failure -
		// mirrors the Python original's "generate if missing or invalid"
		// startup behavior rather than hard-failing on a corrupt CA file.
	}
	return generateCA(dir)
}

func generateCA(dir string) (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate CA key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "WebFilter Proxy Root CA", Organization: []string{"WebFilter Proxy"}},
		NotBefore:             now.Add(-caClockSkew),
		NotAfter:              now.Add(caValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("create CA certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse generated CA certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal CA key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("create cert dir: %w", err)
	}
	if err := atomicWriteFile(filepath.Join(dir, caCertFile), certPEM, 0o644); err != nil {
		return nil, err
	}
	if err := atomicWriteFile(filepath.Join(dir, caKeyFile), keyPEM, 0o600); err != nil {
		return nil, err
	}

	return &CA{dir: dir, Cert: cert, Key: key, CertPEM: certPEM, KeyPEM: keyPEM}, nil
}

func parseCA(dir string, certPEM, keyPEM []byte) (*CA, error) {
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, errors.New("no PEM certificate block found")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CA certificate: %w", err)
	}
	if time.Now().After(cert.NotAfter) {
		return nil, errors.New("CA certificate expired")
	}
	key, err := parseECKey(keyPEM)
	if err != nil {
		return nil, err
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("CA certificate public key is not ECDSA")
	}
	if !pub.Equal(&key.PublicKey) {
		return nil, errors.New("CA key does not match CA certificate")
	}
	return &CA{dir: dir, Cert: cert, Key: key, CertPEM: certPEM, KeyPEM: keyPEM}, nil
}

func parseECKey(keyPEM []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, errors.New("no PEM key block found")
	}
	switch block.Type {
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(block.Bytes)
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		ecKey, ok := key.(*ecdsa.PrivateKey)
		if !ok {
			return nil, errors.New("PKCS8 key is not ECDSA")
		}
		return ecKey, nil
	default:
		return nil, fmt.Errorf("unsupported private key PEM type %q", block.Type)
	}
}

func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, limit)
}

func atomicWriteFile(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create dir %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}
	if err := os.Chmod(tmpPath, perm); err != nil {
		return fmt.Errorf("chmod temp file: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("rename into place: %w", err)
	}
	return nil
}
