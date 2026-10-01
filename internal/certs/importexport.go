package certs

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"path/filepath"
)

// BundlePEM returns the CA certificate and private key concatenated as a
// single PEM bundle, for the "export the full CA for migration to another
// instance" download.
func (c *CA) BundlePEM() []byte {
	var buf bytes.Buffer
	buf.Write(c.CertPEM)
	buf.Write(c.KeyPEM)
	return buf.Bytes()
}

// ImportBundle validates an uploaded PEM bundle (must contain exactly one
// CERTIFICATE block and one private key block, with the key matching the
// cert's public key) and, if valid, atomically replaces the CA files under
// dir. The returned CA's leaf issuer cache must be cleared by the caller
// (LeafIssuer.Clear) so no certificates signed by the old CA are served
// again.
func ImportBundle(dir string, bundlePEM []byte) (*CA, error) {
	var certBlock, keyBlock *pem.Block
	rest := bundlePEM
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		switch block.Type {
		case "CERTIFICATE":
			if certBlock != nil {
				return nil, errors.New("bundle contains more than one certificate")
			}
			certBlock = block
		case "EC PRIVATE KEY", "PRIVATE KEY", "RSA PRIVATE KEY":
			if keyBlock != nil {
				return nil, errors.New("bundle contains more than one private key")
			}
			keyBlock = block
		}
	}
	if certBlock == nil {
		return nil, errors.New("bundle is missing a CERTIFICATE block")
	}
	if keyBlock == nil {
		return nil, errors.New("bundle is missing a PRIVATE KEY block")
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse certificate: %w", err)
	}
	if !cert.IsCA {
		return nil, errors.New("certificate is not a CA certificate")
	}
	key, err := parseECKey(pem.EncodeToMemory(keyBlock))
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || !pub.Equal(&key.PublicKey) {
		return nil, errors.New("private key does not match certificate")
	}

	certPEM := pem.EncodeToMemory(certBlock)
	keyPEM := pem.EncodeToMemory(keyBlock)

	if err := atomicWriteFile(filepath.Join(dir, caCertFile), certPEM, 0o644); err != nil {
		return nil, err
	}
	if err := atomicWriteFile(filepath.Join(dir, caKeyFile), keyPEM, 0o600); err != nil {
		return nil, err
	}

	return &CA{dir: dir, Cert: cert, Key: key, CertPEM: certPEM, KeyPEM: keyPEM}, nil
}
