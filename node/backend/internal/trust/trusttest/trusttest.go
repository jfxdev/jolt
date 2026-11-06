// Package trusttest builds throwaway authorities for tests of code that uses
// internal/trust. Nothing here is for production.
package trusttest

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/jfxdev/jolt/backend/internal/trust"
)

// Epoch is the instant every certificate here is built around.
var Epoch = time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)

// CA is a root and an intermediate with the signing keys of a bundle.
type CA struct {
	// Now is the instant this authority's certificates are built around.
	Now                time.Time
	Root, Issuer       *x509.Certificate
	rootKey, issuerKey *ecdsa.PrivateKey
	signing            map[string]ed25519.PrivateKey
}

func serial() *big.Int {
	n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 100))
	return n.Add(n, big.NewInt(1))
}

func sign(t testing.TB, template, parent *x509.Certificate, public any, key *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, template, parent, public, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// New builds a root and an intermediate around Epoch.
func New(t testing.TB) *CA { return NewAt(t, Epoch) }

// NewAt builds a root and an intermediate around the given instant. Tests that
// go through a real TLS handshake need it to be the real time.
func NewAt(t testing.TB, now time.Time) *CA {
	t.Helper()
	rootKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rootTemplate := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: "root"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(10 * 365 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true, MaxPathLen: 1}
	root := sign(t, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	issuerKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	issuerTemplate := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: "issuer"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(2 * 365 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true, MaxPathLen: 0, MaxPathLenZero: true}
	issuer := sign(t, issuerTemplate, root, &issuerKey.PublicKey, rootKey)
	return &CA{Now: now, Root: root, Issuer: issuer, rootKey: rootKey, issuerKey: issuerKey, signing: map[string]ed25519.PrivateKey{}}
}

// Pin is the fingerprint a join token would pin.
func (c *CA) Pin() string { return trust.Fingerprint(c.Root) }

// Leaf issues a certificate under the intermediate.
func (c *CA) Leaf(t testing.TB, public any, name string, usage x509.ExtKeyUsage, notAfter time.Time, hosts ...string) *x509.Certificate {
	t.Helper()
	template := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: name}, NotBefore: c.Now.Add(-time.Hour), NotAfter: notAfter,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}, BasicConstraintsValid: true}
	for _, host := range hosts {
		if ip := net.ParseIP(host); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, host)
		}
	}
	return sign(t, template, c.Issuer, public, c.issuerKey)
}

// PEM encodes certificates one after another.
func PEM(certs ...*x509.Certificate) string {
	var out []byte
	for _, cert := range certs {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})...)
	}
	return string(out)
}

// SigningKey returns, creating it on first use, the private key for an ID.
func (c *CA) SigningKey(id string) ed25519.PrivateKey {
	if key, ok := c.signing[id]; ok {
		return key
	}
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	c.signing[id] = key
	return key
}

// Bundle builds a bundle with the given version, signed by signer, holding the
// listed signing keys.
func (c *CA) Bundle(t testing.TB, version int64, signer string, revoked []string, ids ...string) trust.Bundle {
	t.Helper()
	b := trust.Bundle{Version: version, IssuedAt: c.Now, Roots: []string{PEM(c.Root)}, Intermediates: []string{PEM(c.Issuer)}, RevokedSerials: revoked}
	if b.RevokedSerials == nil {
		b.RevokedSerials = []string{}
	}
	for _, id := range ids {
		b.SigningKeys = append(b.SigningKeys, trust.BundleKey{ID: id, Key: base64.StdEncoding.EncodeToString(c.SigningKey(id).Public().(ed25519.PublicKey)), NotAfter: c.Now.Add(90 * 24 * time.Hour)})
	}
	signed, err := b.Sign(signer, c.SigningKey(signer))
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

// APIPair makes the key and certificate chain a node would be enrolled with.
func (c *CA) APIPair(t testing.TB, host string) (chain string, keyDER []byte) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	leaf := c.Leaf(t, &key.PublicKey, "n1", x509.ExtKeyUsageServerAuth, c.Now.Add(90*24*time.Hour), host)
	return PEM(leaf, c.Issuer), der
}
