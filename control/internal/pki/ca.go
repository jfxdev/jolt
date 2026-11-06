// Package pki is the certificate authority the Control Tower runs for itself:
// a root that only signs intermediates, an intermediate that signs every leaf,
// the Ed25519 keys that sign authorization contexts, and the signed trust
// bundle that carries all of that to the nodes.
package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"strings"
	"time"
)

const (
	RootValidity         = 10 * 365 * 24 * time.Hour
	IntermediateValidity = 2 * 365 * 24 * time.Hour
	// DefaultLeafValidity is how long a server or client certificate lives
	// unless the operator picks another value in [MinLeafValidity, MaxLeafValidity].
	DefaultLeafValidity = 90 * 24 * time.Hour
	MinLeafValidity     = 7 * 24 * time.Hour
	MaxLeafValidity     = 180 * 24 * time.Hour

	// clockSkew is how far a certificate's start is moved back, so a node whose
	// clock runs a little behind still accepts it.
	clockSkew = 5 * time.Minute
)

// Authority is a certificate together with the key that signs for it.
type Authority struct {
	Cert *x509.Certificate
	Key  *ecdsa.PrivateKey
}

// PEM returns the authority's certificate.
func (a *Authority) PEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: a.Cert.Raw})
}

// LeafSpec describes a certificate that is not a CA.
type LeafSpec struct {
	CommonName string
	DNSNames   []string
	IPs        []net.IP
	Usage      x509.ExtKeyUsage
	Validity   time.Duration
}

func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 127)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, err
	}
	// Zero is not a valid serial number.
	return serial.Add(serial, big.NewInt(1)), nil
}

func generateKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// NewRoot creates a self-signed root. It signs intermediates and nothing else.
func NewRoot(now time.Time) (*Authority, error) {
	key, err := generateKey()
	if err != nil {
		return nil, err
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "Jolt Root CA " + serial.Text(16)[:8], Organization: []string{"Jolt"}},
		NotBefore:             now.Add(-clockSkew),
		NotAfter:              now.Add(RootValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &Authority{Cert: cert, Key: key}, nil
}

// NewIntermediate creates an intermediate signed by the root. It can sign
// leaves and cannot sign another CA.
func (root *Authority) NewIntermediate(now time.Time) (*Authority, error) {
	key, err := generateKey()
	if err != nil {
		return nil, err
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	notAfter := now.Add(IntermediateValidity)
	if notAfter.After(root.Cert.NotAfter) {
		return nil, errors.New("the root expires before the intermediate would")
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "Jolt Issuing CA " + now.UTC().Format("2006-01-02") + " " + serial.Text(16)[:6], Organization: []string{"Jolt"}},
		NotBefore:             now.Add(-clockSkew),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, root.Cert, &key.PublicKey, root.Key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &Authority{Cert: cert, Key: key}, nil
}

// Issue signs a leaf certificate for the given public key. The validity is
// clamped to the issuer's own and to the allowed range.
func (ca *Authority) Issue(now time.Time, public crypto.PublicKey, spec LeafSpec) (*x509.Certificate, error) {
	validity := spec.Validity
	if validity == 0 {
		validity = DefaultLeafValidity
	}
	if validity < MinLeafValidity || validity > MaxLeafValidity {
		return nil, fmt.Errorf("certificate validity must be between %s and %s", MinLeafValidity, MaxLeafValidity)
	}
	if spec.Usage != x509.ExtKeyUsageServerAuth && spec.Usage != x509.ExtKeyUsageClientAuth {
		return nil, errors.New("a leaf certificate is for a server or a client")
	}
	if spec.Usage == x509.ExtKeyUsageServerAuth && len(spec.DNSNames) == 0 && len(spec.IPs) == 0 {
		return nil, errors.New("a server certificate needs at least one name")
	}
	notAfter := now.Add(validity)
	if notAfter.After(ca.Cert.NotAfter) {
		notAfter = ca.Cert.NotAfter
	}
	if !notAfter.After(now) {
		return nil, errors.New("the issuer has expired")
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: spec.CommonName, Organization: []string{"Jolt"}},
		NotBefore:             now.Add(-clockSkew),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{spec.Usage},
		BasicConstraintsValid: true,
		DNSNames:              spec.DNSNames,
		IPAddresses:           spec.IPs,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.Cert, public, ca.Key)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

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
