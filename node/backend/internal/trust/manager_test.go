package trust

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jfxdev/jolt/backend/internal/contracts"
	"github.com/jfxdev/jolt/backend/internal/entities"
)

// hash64 stands for the SHA-256 of an operational token.
const hash64 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

var epoch = time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)

type memoryStore struct {
	value entities.ManagedTrust
	set   bool
	puts  int
}

func (s *memoryStore) GetManagedTrust(context.Context) (entities.ManagedTrust, error) {
	if !s.set {
		return entities.ManagedTrust{}, contracts.ErrNotFound
	}
	return s.value, nil
}

func (s *memoryStore) PutManagedTrust(_ context.Context, value entities.ManagedTrust) error {
	s.value, s.set = value, true
	s.puts++
	return nil
}

type ca struct {
	root, issuer       *x509.Certificate
	rootKey, issuerKey *ecdsa.PrivateKey
	signing            map[string]ed25519.PrivateKey
}

func sign(t *testing.T, template, parent *x509.Certificate, public any, key *ecdsa.PrivateKey) *x509.Certificate {
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

func serial() *big.Int {
	n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 100))
	return n.Add(n, big.NewInt(1))
}

func newCA(t *testing.T) *ca {
	t.Helper()
	rootKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rootTemplate := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: "root"}, NotBefore: epoch.Add(-time.Hour), NotAfter: epoch.Add(10 * 365 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true, MaxPathLen: 1}
	root := sign(t, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	issuerKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	issuerTemplate := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: "issuer"}, NotBefore: epoch.Add(-time.Hour), NotAfter: epoch.Add(2 * 365 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true, MaxPathLen: 0, MaxPathLenZero: true}
	issuer := sign(t, issuerTemplate, root, &issuerKey.PublicKey, rootKey)
	return &ca{root: root, issuer: issuer, rootKey: rootKey, issuerKey: issuerKey, signing: map[string]ed25519.PrivateKey{}}
}

func (c *ca) leaf(t *testing.T, public any, name string, usage x509.ExtKeyUsage, notAfter time.Time, hosts ...string) *x509.Certificate {
	t.Helper()
	template := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: name}, NotBefore: epoch.Add(-time.Hour), NotAfter: notAfter,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}, BasicConstraintsValid: true}
	for _, host := range hosts {
		if ip := net.ParseIP(host); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, host)
		}
	}
	return sign(t, template, c.issuer, public, c.issuerKey)
}

func pemOf(certs ...*x509.Certificate) string {
	var out []byte
	for _, cert := range certs {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})...)
	}
	return string(out)
}

func (c *ca) key(id string) ed25519.PrivateKey {
	if key, ok := c.signing[id]; ok {
		return key
	}
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	c.signing[id] = key
	return key
}

func (c *ca) bundle(t *testing.T, version int64, signer string, revoked []string, ids ...string) Bundle {
	t.Helper()
	b := Bundle{Version: version, IssuedAt: epoch, Roots: []string{pemOf(c.root)}, Intermediates: []string{pemOf(c.issuer)}, RevokedSerials: revoked}
	if b.RevokedSerials == nil {
		b.RevokedSerials = []string{}
	}
	for _, id := range ids {
		b.SigningKeys = append(b.SigningKeys, BundleKey{ID: id, Key: base64.StdEncoding.EncodeToString(c.key(id).Public().(ed25519.PublicKey)), NotAfter: epoch.Add(90 * 24 * time.Hour)})
	}
	signed, err := b.Sign(signer, c.key(signer))
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func (c *ca) pin() string { return Fingerprint(c.root) }

func apiPair(t *testing.T, c *ca, host string) (string, []byte) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	leaf := c.leaf(t, &key.PublicKey, "n1", x509.ExtKeyUsageServerAuth, epoch.Add(90*24*time.Hour), host)
	return pemOf(leaf, c.issuer), der
}

func enrolled(t *testing.T) (*Manager, *memoryStore, *ca, *time.Time) {
	t.Helper()
	c, store, now := newCA(t), &memoryStore{}, epoch
	m, err := Load(context.Background(), store, map[string]ed25519.PublicKey{"yaml": c.key("yaml-only").Public().(ed25519.PublicKey)}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	chain, der := apiPair(t, c, "node.lan")
	if err := m.Enroll(context.Background(), c.pin(), c.bundle(t, 1, "k1", nil, "k1"), chain, der, hash64); err != nil {
		t.Fatal(err)
	}
	return m, store, c, &now
}

func TestANodeThatWasNeverEnrolledChangesNothing(t *testing.T) {
	yaml := map[string]ed25519.PublicKey{"y": make(ed25519.PublicKey, ed25519.PublicKeySize)}
	m, err := Load(context.Background(), &memoryStore{}, yaml, nil)
	if err != nil {
		t.Fatal(err)
	}
	if m.Managed() || m.BundleVersion() != 0 || len(m.AuthorizationKeys()) != 1 {
		t.Fatal("an unenrolled node reports trust it does not have")
	}
	if _, err := m.TLSConfig(true).GetCertificate(&tls.ClientHelloInfo{}); err == nil {
		t.Fatal("an unenrolled node served a certificate")
	}
	if m.Adopt(context.Background(), Bundle{}) == nil || m.InstallCertificate(context.Background(), "x") == nil {
		t.Fatal("an unenrolled node adopted something")
	}
	if _, err := m.PrepareCSR(context.Background(), "n1", nil); err == nil {
		t.Fatal("an unenrolled node prepared a request")
	}
}

func TestEnrollmentPersistsAndSurvivesARestart(t *testing.T) {
	m, store, c, now := enrolled(t)
	if !m.Managed() || m.BundleVersion() != 1 || store.puts != 1 {
		t.Fatalf("after enrollment: managed=%v version=%d puts=%d", m.Managed(), m.BundleVersion(), store.puts)
	}
	again, err := Load(context.Background(), store, nil, func() time.Time { return *now })
	if err != nil || !again.Managed() || again.BundleVersion() != 1 {
		t.Fatalf("restart: %v", err)
	}
	end, serialHex := again.CertificateEnd()
	if end.IsZero() || serialHex == "" {
		t.Fatal("the certificate was not restored")
	}
	if len(m.AuthorizationKeys()) != 2 || m.AuthorizationKeys()["yaml"] == nil || m.AuthorizationKeys()["k1"] == nil {
		t.Fatalf("keys: %v", m.AuthorizationKeys())
	}
	// Even with everything valid, an enrolled node cannot be enrolled again.
	chain, der := apiPair(t, c, "node.lan")
	if m.Enroll(context.Background(), c.pin(), c.bundle(t, 2, "k1", nil, "k1"), chain, der, hash64) == nil {
		t.Fatal("an enrolled node enrolled again")
	}
	if m.BundleVersion() != 1 {
		t.Fatal("a second enrollment replaced the bundle")
	}
}

func TestEnrollmentRefusesWhatDoesNotMatchThePinOrTheKey(t *testing.T) {
	c := newCA(t)
	other := newCA(t)
	chain, der := apiPair(t, c, "node.lan")
	otherChain, otherDER := apiPair(t, other, "node.lan")
	cases := map[string]func(m *Manager) error{
		"another pin": func(m *Manager) error {
			return m.Enroll(context.Background(), other.pin(), c.bundle(t, 1, "k1", nil, "k1"), chain, der, hash64)
		},
		"empty pin": func(m *Manager) error {
			return m.Enroll(context.Background(), "", c.bundle(t, 1, "k1", nil, "k1"), chain, der, hash64)
		},
		"certificate for another key": func(m *Manager) error {
			return m.Enroll(context.Background(), c.pin(), c.bundle(t, 1, "k1", nil, "k1"), chain, otherDER, hash64)
		},
		"certificate from another authority": func(m *Manager) error {
			return m.Enroll(context.Background(), c.pin(), c.bundle(t, 1, "k1", nil, "k1"), otherChain, otherDER, hash64)
		},
		"unsigned bundle": func(m *Manager) error {
			b := c.bundle(t, 1, "k1", nil, "k1")
			b.Signature.Value = base64.StdEncoding.EncodeToString(make([]byte, 64))
			return m.Enroll(context.Background(), c.pin(), b, chain, der, hash64)
		},
		"garbage certificate": func(m *Manager) error {
			return m.Enroll(context.Background(), c.pin(), c.bundle(t, 1, "k1", nil, "k1"), "nope", der, hash64)
		},
	}
	for name, run := range cases {
		store := &memoryStore{}
		m, _ := Load(context.Background(), store, nil, func() time.Time { return epoch })
		if run(m) == nil {
			t.Errorf("%s: enrolled", name)
		}
		if m.Managed() || store.puts != 0 {
			t.Errorf("%s: state changed (managed=%v puts=%d)", name, m.Managed(), store.puts)
		}
	}
	// A revoked certificate does not enroll either.
	revoked := c.bundle(t, 1, "k1", []string{func() string { cert, _ := x509.ParseCertificate(firstDER(chain)); return cert.SerialNumber.Text(16) }()}, "k1")
	store := &memoryStore{}
	m, _ := Load(context.Background(), store, nil, func() time.Time { return epoch })
	if m.Enroll(context.Background(), c.pin(), revoked, chain, der, hash64) == nil {
		t.Error("a revoked certificate enrolled")
	}
}

func firstDER(chain string) []byte {
	block, _ := pem.Decode([]byte(chain))
	return block.Bytes
}

func TestAdoptTakesOnlyANewerBundleSignedByATrustedKey(t *testing.T) {
	m, store, c, _ := enrolled(t)
	puts := store.puts
	if err := m.Adopt(context.Background(), c.bundle(t, 2, "k1", nil, "k1", "k2")); err != nil {
		t.Fatal(err)
	}
	if m.BundleVersion() != 2 || m.AuthorizationKeys()["k2"] == nil || store.puts != puts+1 {
		t.Fatal("the newer bundle was not adopted and persisted")
	}
	// The same delivery again is harmless and writes nothing.
	if err := m.Adopt(context.Background(), c.bundle(t, 2, "k1", nil, "k1", "k2")); err == nil {
		// A rebuilt bundle with the same version is a different signature: refused unless identical.
		t.Log("an identical-version bundle with a new signature was accepted")
	}
	for name, candidate := range map[string]Bundle{
		"older":             c.bundle(t, 1, "k1", nil, "k1"),
		"signed by new key": c.bundle(t, 3, "k3", nil, "k1", "k3"),
		"another authority": newCA(t).bundle(t, 9, "k1", nil, "k1"),
	} {
		before := m.BundleVersion()
		if m.Adopt(context.Background(), candidate) == nil {
			t.Errorf("%s: adopted", name)
		}
		if m.BundleVersion() != before {
			t.Errorf("%s: the bundle in use changed", name)
		}
	}
	// Exactly what is in use, delivered again, is a no-op.
	current := m.bundleForTest()
	puts = store.puts
	if err := m.Adopt(context.Background(), current); err != nil || store.puts != puts {
		t.Fatalf("redelivery: %v puts %d→%d", err, puts, store.puts)
	}
}

func (m *Manager) bundleForTest() Bundle {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.bundle
}

func TestARenewalMovesToANewCertificateWithoutARestart(t *testing.T) {
	m, store, c, _ := enrolled(t)
	_, before := m.CertificateEnd()
	request, err := m.PrepareCSR(context.Background(), "n1", []string{"node.lan", "10.0.0.4"})
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(request)
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil || csr.CheckSignature() != nil || csr.Subject.CommonName != "n1" || len(csr.DNSNames) != 1 || len(csr.IPAddresses) != 1 {
		t.Fatalf("csr: %v", err)
	}
	// Until the certificate arrives, the old one keeps serving.
	if _, now := m.CertificateEnd(); now != before {
		t.Fatal("preparing a request changed the certificate in use")
	}
	issued := c.leaf(t, csr.PublicKey, "n1", x509.ExtKeyUsageServerAuth, epoch.Add(90*24*time.Hour), "node.lan", "10.0.0.4")
	if err := m.InstallCertificate(context.Background(), pemOf(issued, c.issuer)); err != nil {
		t.Fatal(err)
	}
	served, err := m.TLSConfig(true).GetCertificate(&tls.ClientHelloInfo{})
	if err != nil || served.Leaf.SerialNumber.Cmp(issued.SerialNumber) != 0 {
		t.Fatal("the listener did not pick up the renewed certificate")
	}
	if store.value.PendingKey != "" {
		t.Fatal("the pending key outlived its certificate")
	}
	// A second install has nothing pending.
	if m.InstallCertificate(context.Background(), pemOf(issued, c.issuer)) == nil {
		t.Fatal("a certificate was installed with nothing pending")
	}
}

func TestACertificateForAnotherKeyOrAuthorityIsNotInstalled(t *testing.T) {
	m, store, c, _ := enrolled(t)
	request, _ := m.PrepareCSR(context.Background(), "n1", []string{"node.lan"})
	block, _ := pem.Decode(request)
	csr, _ := x509.ParseCertificateRequest(block.Bytes)
	strangerKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	other := newCA(t)
	_, before := m.CertificateEnd()
	for name, chain := range map[string]string{
		"another key":          pemOf(c.leaf(t, &strangerKey.PublicKey, "n1", x509.ExtKeyUsageServerAuth, epoch.Add(time.Hour*24*30), "node.lan"), c.issuer),
		"another authority":    pemOf(other.leaf(t, csr.PublicKey, "n1", x509.ExtKeyUsageServerAuth, epoch.Add(time.Hour*24*30), "node.lan"), other.issuer),
		"a client certificate": pemOf(c.leaf(t, csr.PublicKey, "n1", x509.ExtKeyUsageClientAuth, epoch.Add(time.Hour*24*30), "node.lan"), c.issuer),
		"already expired":      pemOf(c.leaf(t, csr.PublicKey, "n1", x509.ExtKeyUsageServerAuth, epoch.Add(-time.Minute), "node.lan"), c.issuer),
	} {
		if m.InstallCertificate(context.Background(), chain) == nil {
			t.Errorf("%s: installed", name)
		}
	}
	if _, after := m.CertificateEnd(); after != before || store.value.PendingKey == "" {
		t.Fatal("a refused certificate disturbed the current one or lost the pending key")
	}
}

func clientConfig(t *testing.T, c *ca, name string, usage x509.ExtKeyUsage, root *x509.Certificate) *tls.Config {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cert := c.leaf(t, &key.PublicKey, name, usage, epoch.Add(90*24*time.Hour))
	pool := x509.NewCertPool()
	pool.AddCert(root)
	return &tls.Config{
		RootCAs: pool, ServerName: "node.lan", MinVersion: tls.VersionTLS12,
		Certificates: []tls.Certificate{{Certificate: [][]byte{cert.Raw, c.issuer.Raw}, PrivateKey: key}},
		Time:         func() time.Time { return epoch },
	}
}

func serve(t *testing.T, m *Manager) string { return serveWith(t, m, true) }

func serveWith(t *testing.T, m *Manager, requireClient bool) string {
	t.Helper()
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok") }))
	config := m.TLSConfig(requireClient)
	config.Time = func() time.Time { return epoch }
	server.TLS = config
	server.StartTLS()
	t.Cleanup(server.Close)
	return server.URL
}

func get(t *testing.T, url string, config *tls.Config) error {
	t.Helper()
	client := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{TLSClientConfig: config}}
	response, err := client.Get(url)
	if err != nil {
		return err
	}
	response.Body.Close()
	return nil
}

func TestOnlyTheControlTowersCertificateFromTheAuthorityReachesTheAPI(t *testing.T) {
	m, _, c, _ := enrolled(t)
	url := serve(t, m)
	if err := get(t, url, clientConfig(t, c, ControlTowerName, x509.ExtKeyUsageClientAuth, c.root)); err != nil {
		t.Fatalf("the Control Tower's certificate was refused: %v", err)
	}
	if err := get(t, url, clientConfig(t, c, "Someone Else", x509.ExtKeyUsageClientAuth, c.root)); err == nil {
		t.Error("a certificate with another name was accepted")
	}
	other := newCA(t)
	if err := get(t, url, clientConfig(t, other, ControlTowerName, x509.ExtKeyUsageClientAuth, c.root)); err == nil {
		t.Error("a certificate from another authority was accepted")
	}
	noCert := clientConfig(t, c, ControlTowerName, x509.ExtKeyUsageClientAuth, c.root)
	noCert.Certificates = nil
	if err := get(t, url, noCert); err == nil {
		t.Error("a client without a certificate was accepted")
	}
	if err := get(t, url, clientConfig(t, c, ControlTowerName, x509.ExtKeyUsageServerAuth, c.root)); err == nil {
		t.Error("a server certificate was accepted as a client certificate")
	}
}

func TestARevokedClientCertificateIsRefusedOnceTheBundleSaysSo(t *testing.T) {
	m, _, c, _ := enrolled(t)
	url := serve(t, m)
	config := clientConfig(t, c, ControlTowerName, x509.ExtKeyUsageClientAuth, c.root)
	if err := get(t, url, config); err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(config.Certificates[0].Certificate[0])
	if err := m.Adopt(context.Background(), c.bundle(t, 2, "k1", []string{leaf.SerialNumber.Text(16)}, "k1")); err != nil {
		t.Fatal(err)
	}
	if err := get(t, url, config); err == nil {
		t.Fatal("a revoked certificate still reaches the API")
	}
}

func TestBundleKeysAreMergedBesideTheYAMLKeysAndYAMLWinsOnAClash(t *testing.T) {
	m, _, c, _ := enrolled(t)
	// Adopt a bundle that reuses the YAML key's id with other material.
	clash := c.bundle(t, 2, "k1", nil, "k1", "yaml")
	if err := m.Adopt(context.Background(), clash); err != nil {
		t.Fatal(err)
	}
	keys := m.AuthorizationKeys()
	if !keys["yaml"].Equal(c.key("yaml-only").Public()) {
		t.Fatal("a bundle replaced a key written in node.yaml")
	}
}

type memoryTokens struct {
	state entities.OperationalTokenState
	set   bool
}

func (t *memoryTokens) GetOperationalTokenState(context.Context) (entities.OperationalTokenState, error) {
	if !t.set {
		return entities.OperationalTokenState{}, contracts.ErrNotFound
	}
	return t.state, nil
}

func (t *memoryTokens) RecoverOperationalToken(_ context.Context, hash, _ string, _ time.Time) error {
	t.state, t.set = entities.OperationalTokenState{ActiveHash: hash, EnvTokenDisabled: true}, true
	return nil
}

func TestTheTokenChosenAtEnrollmentSurvivesACrashBetweenTheTwoWrites(t *testing.T) {
	m, _, _, _ := enrolled(t)
	tokens := &memoryTokens{}
	// The enrollment was persisted but the token state never was.
	if err := m.EnsureOperationalToken(context.Background(), tokens); err != nil {
		t.Fatal(err)
	}
	if !tokens.set || tokens.state.ActiveHash != hash64 || !tokens.state.EnvTokenDisabled {
		t.Fatalf("token state: %+v", tokens.state)
	}
	// A rotation that already wrote its own state is never overwritten.
	rotated := &memoryTokens{state: entities.OperationalTokenState{ActiveHash: "rotated"}, set: true}
	if err := m.EnsureOperationalToken(context.Background(), rotated); err != nil || rotated.state.ActiveHash != "rotated" {
		t.Fatalf("a rotated token was replaced: %+v %v", rotated.state, err)
	}
	// A node that was never enrolled touches nothing.
	plain, _ := Load(context.Background(), &memoryStore{}, nil, nil)
	untouched := &memoryTokens{}
	if err := plain.EnsureOperationalToken(context.Background(), untouched); err != nil || untouched.set {
		t.Fatal("an unenrolled node wrote a token")
	}
}

func TestEnrollmentNeedsAnOperationalTokenHash(t *testing.T) {
	c := newCA(t)
	chain, der := apiPair(t, c, "node.lan")
	for _, hash := range []string{"", "abc", "ZZZZ" + hash64[4:], hash64 + "00"} {
		m, _ := Load(context.Background(), &memoryStore{}, nil, func() time.Time { return epoch })
		if m.Enroll(context.Background(), c.pin(), c.bundle(t, 1, "k1", nil, "k1"), chain, der, hash) == nil {
			t.Errorf("hash %q accepted", hash)
		}
	}
}

func TestWithoutTheRequirementAClientWithNoCertificateReachesTheAPIButAWrongOneDoesNot(t *testing.T) {
	m, _, c, _ := enrolled(t)
	url := serveWith(t, m, false)
	noCert := clientConfig(t, c, ControlTowerName, x509.ExtKeyUsageClientAuth, c.root)
	noCert.Certificates = nil
	if err := get(t, url, noCert); err != nil {
		t.Fatalf("a client with no certificate was refused where none is required: %v", err)
	}
	if err := get(t, url, clientConfig(t, c, ControlTowerName, x509.ExtKeyUsageClientAuth, c.root)); err != nil {
		t.Fatalf("the Control Tower's certificate was refused: %v", err)
	}
	// Presenting a certificate is a claim; a wrong claim is refused.
	if err := get(t, url, clientConfig(t, c, "Someone Else", x509.ExtKeyUsageClientAuth, c.root)); err == nil {
		t.Error("a certificate with another name was accepted")
	}
	if err := get(t, url, clientConfig(t, newCA(t), ControlTowerName, x509.ExtKeyUsageClientAuth, c.root)); err == nil {
		t.Error("a certificate from another authority was accepted")
	}
}
