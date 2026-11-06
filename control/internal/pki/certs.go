package pki

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"strings"
	"time"
)

// ControlTowerName is the subject of the client certificate the Control Tower
// presents to a node, and the only client name a node's API accepts from the
// authority.
const ControlTowerName = "Jolt Control Tower"

// Fingerprint is the SHA-256 of a certificate, lowercase hex without
// separators: the form a join token pins.
func Fingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

// DisplayFingerprint groups a fingerprint in pairs, for a person to compare.
func DisplayFingerprint(fingerprint string) string {
	var parts []string
	for i := 0; i+2 <= len(fingerprint); i += 2 {
		parts = append(parts, strings.ToUpper(fingerprint[i:i+2]))
	}
	return strings.Join(parts, ":")
}

// ParseCertificate reads one PEM certificate and nothing else.
func ParseCertificate(data []byte) (*x509.Certificate, error) {
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" || len(strings.TrimSpace(string(rest))) != 0 {
		return nil, errors.New("expected exactly one PEM certificate")
	}
	return x509.ParseCertificate(block.Bytes)
}

// Chain verifies that leaf was issued by one of the intermediates under one of
// the roots, for the given usage and instant.
func Chain(leaf *x509.Certificate, roots, intermediates []*x509.Certificate, usage x509.ExtKeyUsage, now time.Time) error {
	rootPool, intermediatePool := x509.NewCertPool(), x509.NewCertPool()
	for _, cert := range roots {
		rootPool.AddCert(cert)
	}
	for _, cert := range intermediates {
		intermediatePool.AddCert(cert)
	}
	_, err := leaf.Verify(x509.VerifyOptions{Roots: rootPool, Intermediates: intermediatePool, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{usage}})
	return err
}
