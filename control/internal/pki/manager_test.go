package pki

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jfxdev/jolt/control/internal/store"
)

type memoryRepo struct {
	mu      sync.Mutex
	objects map[string]store.PKIObject
	saves   int
	fail    error
}

func newMemoryRepo() *memoryRepo { return &memoryRepo{objects: map[string]store.PKIObject{}} }

func (r *memoryRepo) ListPKIObjects(context.Context) ([]store.PKIObject, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []store.PKIObject
	for _, object := range r.objects {
		out = append(out, object)
	}
	// Same order as the real store: oldest first, then by id.
	for i := range out {
		for j := i + 1; j < len(out); j++ {
			if out[j].CreatedAt.Before(out[i].CreatedAt) || (out[j].CreatedAt.Equal(out[i].CreatedAt) && out[j].ID < out[i].ID) {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out, nil
}

func (r *memoryRepo) SavePKIObjects(_ context.Context, put []store.PKIObject, remove []string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.fail != nil {
		return r.fail
	}
	r.saves++
	for _, id := range remove {
		delete(r.objects, id)
	}
	for _, object := range put {
		if existing, ok := r.objects[object.ID]; ok {
			existing.State, existing.Public, existing.Secret, existing.NotAfter = object.State, object.Public, object.Secret, object.NotAfter
			r.objects[object.ID] = existing
			continue
		}
		r.objects[object.ID] = object
	}
	return nil
}

func (r *memoryRepo) kind(kind string) (out []store.PKIObject) {
	objects, _ := r.ListPKIObjects(context.Background())
	for _, object := range objects {
		if object.Kind == kind {
			out = append(out, object)
		}
	}
	return out
}

type clock struct{ now time.Time }

func (c *clock) Now() time.Time          { return c.now }
func (c *clock) advance(d time.Duration) { c.now = c.now.Add(d) }

var databaseKey = []byte("0123456789abcdef0123456789abcdef")

func newManager(t *testing.T, repo *memoryRepo, c *clock, names ...string) *Manager {
	t.Helper()
	m, err := NewManager(repo, Options{Key: databaseKey, Names: names, Now: c.Now})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func ensure(t *testing.T, m *Manager) {
	t.Helper()
	if err := m.Ensure(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func servedChainIsValid(t *testing.T, m *Manager, name string, now time.Time) *x509.Certificate {
	t.Helper()
	served, err := m.TLSConfig().GetCertificate(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(served.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	roots, intermediates, err := m.Bundle().Certificates()
	if err != nil {
		t.Fatal(err)
	}
	if err := Chain(leaf, roots, intermediates, x509.ExtKeyUsageServerAuth, now); err != nil {
		t.Fatalf("served certificate does not chain: %v", err)
	}
	if err := leaf.VerifyHostname(name); err != nil {
		t.Fatal(err)
	}
	return leaf
}

func TestTheFirstPassCreatesEverythingAndTheSecondChangesNothing(t *testing.T) {
	repo, c := newMemoryRepo(), &clock{epoch}
	m := newManager(t, repo, c, "control.lan")
	ensure(t, m)
	if len(repo.kind(store.PKIRoot)) != 1 || len(repo.kind(store.PKIIntermediate)) != 1 || len(repo.kind(store.PKISigningKey)) != 1 || len(repo.kind(store.PKIBundle)) != 1 {
		t.Fatalf("objects: %+v", repo.objects)
	}
	if bundle := m.Bundle(); bundle.Version != 1 || VerifyBundle(bundle, nil, m.RootFingerprint(), c.now) != nil {
		t.Fatalf("first bundle: %+v", bundle)
	}
	id, key := m.Current()
	if id == "" || len(key) != ed25519.PrivateKeySize || m.Public()[id] == nil {
		t.Fatalf("signing key: %q", id)
	}
	served := servedChainIsValid(t, m, "control.lan", c.now)

	// A restart reads the same authority back and issues nothing.
	saves := repo.saves
	again := newManager(t, repo, c, "control.lan")
	ensure(t, again)
	if repo.saves != saves {
		t.Fatalf("an idle pass wrote %d times", repo.saves-saves)
	}
	againID, _ := again.Current()
	if again.RootFingerprint() != m.RootFingerprint() || againID != id || again.Bundle().Version != 1 {
		t.Fatal("a restart changed the authority")
	}
	if servedAgain := servedChainIsValid(t, again, "control.lan", c.now); servedAgain.SerialNumber.Cmp(served.SerialNumber) == 0 {
		t.Log("the HTTPS certificate is rebuilt in memory on restart, as designed")
	}
}

func TestNoSecretIsStoredInTheClear(t *testing.T) {
	repo, c := newMemoryRepo(), &clock{epoch}
	m := newManager(t, repo, c)
	ensure(t, m)
	_, signing := m.Current()
	for _, object := range repo.kind(store.PKIRoot) {
		if object.Secret == "" || strings.Contains(object.Secret, "PRIVATE KEY") || strings.Contains(object.Public, "PRIVATE KEY") {
			t.Fatalf("root secret: %q", object.Secret)
		}
	}
	for _, object := range repo.objects {
		if strings.Contains(object.Secret, string(signing.Seed())) || strings.Contains(object.Public, string(signing.Seed())) {
			t.Fatal("a seed is stored in the clear")
		}
	}
	// Another database key cannot read any of it.
	wrong, err := NewManager(repo, Options{Key: []byte("ffffffffffffffffffffffffffffffff"), Now: c.Now})
	if err != nil {
		t.Fatal(err)
	}
	if err := wrong.Ensure(context.Background()); err == nil {
		t.Fatal("a different database key unlocked the authority")
	}
}

func TestEachKindOfSecretIsSealedUnderItsOwnKey(t *testing.T) {
	repo, c := newMemoryRepo(), &clock{epoch}
	m := newManager(t, repo, c)
	ensure(t, m)
	root := repo.kind(store.PKIRoot)[0]
	if _, err := m.unseal(store.PKIIntermediate, root.Secret); err == nil {
		t.Fatal("a root secret opened as an intermediate secret")
	}
	if _, err := m.unseal(store.PKISigningKey, root.Secret); err == nil {
		t.Fatal("a root secret opened as a signing key")
	}
	if _, err := m.unseal(store.PKIRoot, root.Secret); err != nil {
		t.Fatal(err)
	}
}

func TestTheHTTPSCertificateIsRenewedAtTwoThirdsWithoutARestart(t *testing.T) {
	repo, c := newMemoryRepo(), &clock{epoch}
	m := newManager(t, repo, c, "control.lan")
	ensure(t, m)
	firstBundle := m.Bundle()
	first := servedChainIsValid(t, m, "control.lan", c.now)
	c.advance(59 * 24 * time.Hour)
	ensure(t, m)
	if same := servedChainIsValid(t, m, "control.lan", c.now); same.SerialNumber.Cmp(first.SerialNumber) != 0 {
		t.Fatal("renewed too early")
	}
	c.advance(2 * 24 * time.Hour)
	ensure(t, m)
	renewed := servedChainIsValid(t, m, "control.lan", c.now)
	if renewed.SerialNumber.Cmp(first.SerialNumber) == 0 {
		t.Fatal("not renewed at two thirds of its life")
	}
	if renewed.NotAfter.Sub(renewed.NotBefore) < 89*24*time.Hour {
		t.Fatalf("lifetime %s", renewed.NotAfter.Sub(renewed.NotBefore))
	}
	// Day 60 also publishes the next signing key, so the version may move; what
	// a leaf renewal must never touch is the CA that nodes pin.
	after := m.Bundle()
	if strings.Join(after.Roots, "") != strings.Join(firstBundle.Roots, "") || strings.Join(after.Intermediates, "") != strings.Join(firstBundle.Intermediates, "") {
		t.Fatal("a leaf renewal changed the roots or intermediates nodes trust")
	}
}

func TestChangingTheNamesReissuesTheHTTPSCertificate(t *testing.T) {
	repo, c := newMemoryRepo(), &clock{epoch}
	ensure(t, newManager(t, repo, c, "old.lan"))
	m := newManager(t, repo, c, "new.lan", "10.1.2.3")
	ensure(t, m)
	leaf := servedChainIsValid(t, m, "new.lan", c.now)
	if leaf.VerifyHostname("old.lan") == nil {
		t.Fatal("the old name is still covered")
	}
	if leaf.VerifyHostname("10.1.2.3") != nil || leaf.VerifyHostname("localhost") != nil || leaf.VerifyHostname("127.0.0.1") != nil {
		t.Fatal("a default or configured address is not covered")
	}
}

func TestTheSigningKeyIsRotatedWithOverlapAndEveryBundleChainsToThePrevious(t *testing.T) {
	repo, c := newMemoryRepo(), &clock{epoch}
	m := newManager(t, repo, c)
	ensure(t, m)
	first := m.Bundle()
	oldID, _ := m.Current()

	c.advance(59 * 24 * time.Hour)
	ensure(t, m)
	if m.Bundle().Version != 1 {
		t.Fatal("rotated too early")
	}

	c.advance(2 * 24 * time.Hour) // day 61: the successor is published, still not signing
	ensure(t, m)
	published := m.Bundle()
	if published.Version != 2 || len(published.SigningKeys) != 2 {
		t.Fatalf("successor not published: %+v", published)
	}
	if published.Signature.KeyID != oldID {
		t.Fatal("the bundle that adds a key must be signed by the key nodes already trust")
	}
	if err := VerifyBundle(published, &first, "", c.now); err != nil {
		t.Fatal(err)
	}
	if id, _ := m.Current(); id != oldID {
		t.Fatal("the successor signs before nodes had time to learn of it")
	}
	if len(m.Public()) != 1 {
		t.Fatal("a key that has not started to sign is accepted for verification")
	}

	c.advance(3 * 24 * time.Hour) // day 64: nodes have had too little time
	ensure(t, m)
	if id, _ := m.Current(); id != oldID {
		t.Fatal("the successor started to sign before the promotion delay")
	}

	c.advance(4 * 24 * time.Hour) // day 68: promoted, nothing new to tell nodes
	ensure(t, m)
	newID, newKey := m.Current()
	if newID == oldID || len(newKey) == 0 {
		t.Fatal("the successor was not promoted")
	}
	if m.Bundle().Version != 2 || len(m.Public()) != 2 {
		t.Fatal("promotion must not change the bundle, and both keys must still verify")
	}

	c.advance(7 * 24 * time.Hour) // day 75: overlap over, the old key leaves
	ensure(t, m)
	last := m.Bundle()
	if last.Version != 3 || len(last.SigningKeys) != 1 || last.SigningKeys[0].ID != newID || last.Signature.KeyID != newID {
		t.Fatalf("old key not dropped: %+v", last)
	}
	if err := VerifyBundle(last, &published, "", c.now); err != nil {
		t.Fatal(err)
	}
	if len(m.Public()) != 1 || m.Public()[newID] == nil {
		t.Fatal("verification set")
	}
	// The key that left cannot sign a next bundle.
	var stale Bundle = last
	stale.Version = 4
	stale, _ = stale.Sign(oldID, ed25519.NewKeyFromSeed(make([]byte, 32)))
	if VerifyBundle(stale, &last, "", c.now) == nil {
		t.Fatal("a dropped key still signs bundles")
	}
}

func TestTwoYearsOfPassesNeverBreakTheChain(t *testing.T) {
	repo, c := newMemoryRepo(), &clock{epoch}
	m := newManager(t, repo, c, "control.lan")
	ensure(t, m)
	previous := m.Bundle()
	rootPin := m.RootFingerprint()
	if err := VerifyBundle(previous, nil, rootPin, c.now); err != nil {
		t.Fatal(err)
	}
	versions, intermediates := map[int64]bool{previous.Version: true}, 1
	for day := 1; day <= 800; day++ {
		c.advance(24 * time.Hour)
		ensure(t, m)
		bundle := m.Bundle()
		if bundle.Version != previous.Version {
			if err := VerifyBundle(bundle, &previous, rootPin, c.now); err != nil {
				t.Fatalf("day %d: bundle %d does not follow %d: %v", day, bundle.Version, previous.Version, err)
			}
			versions[bundle.Version] = true
			previous = bundle
		}
		id, key := m.Current()
		if id == "" || len(key) == 0 || m.Public()[id] == nil {
			t.Fatalf("day %d: no usable signing key", day)
		}
		if len(bundle.Intermediates) > intermediates {
			intermediates = len(bundle.Intermediates)
		}
		if len(bundle.Roots) != 1 || len(bundle.Intermediates) > MaxBundleIssuers || len(bundle.SigningKeys) > 3 {
			t.Fatalf("day %d: bundle size roots=%d issuers=%d keys=%d", day, len(bundle.Roots), len(bundle.Intermediates), len(bundle.SigningKeys))
		}
		servedChainIsValid(t, m, "control.lan", c.now)
		if bundle.Signature.KeyID != id && !bundleHasKey(bundle, bundle.Signature.KeyID) {
			t.Fatalf("day %d: signed by a key not in its own bundle", day)
		}
	}
	if intermediates != 2 {
		t.Fatalf("the intermediate should have been renewed once with an overlap, saw at most %d", intermediates)
	}
	if len(repo.kind(store.PKIBundle)) > keepBundles {
		t.Fatalf("%d bundles kept", len(repo.kind(store.PKIBundle)))
	}
	if len(versions) < 8 {
		t.Fatalf("only %d bundle versions in two years: %v", len(versions), versions)
	}
	if got := len(repo.kind(store.PKIIntermediate)); got != 1 {
		t.Fatalf("%d intermediates kept; the retired one should be gone after it expired", got)
	}
}

func bundleHasKey(b Bundle, id string) bool {
	for _, key := range b.SigningKeys {
		if key.ID == id {
			return true
		}
	}
	return false
}

func TestRenewingTheIntermediateKeepsTheOldOneUntilItsLeavesAreGone(t *testing.T) {
	repo, c := newMemoryRepo(), &clock{epoch}
	m := newManager(t, repo, c, "control.lan")
	ensure(t, m)
	oldIssuer := repo.kind(store.PKIIntermediate)[0]
	c.advance(IntermediateValidity*2/3 + 24*time.Hour)
	ensure(t, m)
	issuers := repo.kind(store.PKIIntermediate)
	if len(issuers) != 2 {
		t.Fatalf("%d intermediates", len(issuers))
	}
	states := map[string]string{}
	for _, issuer := range issuers {
		states[issuer.ID] = issuer.State
	}
	if states[oldIssuer.ID] != stateRetired {
		t.Fatalf("states: %v", states)
	}
	if len(m.Bundle().Intermediates) != 2 {
		t.Fatal("nodes must keep trusting the old intermediate while its leaves live")
	}
	leaf := servedChainIsValid(t, m, "control.lan", c.now)
	if leaf.Issuer.CommonName == issuerCommonName(oldIssuer) {
		t.Fatal("the HTTPS certificate is still issued under the retired intermediate")
	}
	// The root never changed, so nothing a device installed is affected.
	if len(m.Bundle().Roots) != 1 {
		t.Fatal("roots")
	}
}

func TestTheRootKeyIsNotNeededUntilTheIntermediateMustBeRenewed(t *testing.T) {
	repo, c := newMemoryRepo(), &clock{epoch}
	m := newManager(t, repo, c, "control.lan")
	ensure(t, m)
	// The operator took the root key out of the database.
	root := repo.kind(store.PKIRoot)[0]
	sealedRoot, oldIssuerID := root.Secret, repo.kind(store.PKIIntermediate)[0].ID
	root.Secret = ""
	repo.objects[root.ID] = root
	for day := 0; day < 300; day++ {
		c.advance(24 * time.Hour)
		ensure(t, m) // leaves, signing keys and bundles keep working
	}
	c.advance(IntermediateValidity*2/3 - 300*24*time.Hour + 24*time.Hour)
	err := m.Ensure(context.Background())
	if !errors.Is(err, ErrRootUnavailable) {
		t.Fatalf("want ErrRootUnavailable, got %v", err)
	}
	// Due is not expired: the pass reports it and everything else keeps working.
	servedChainIsValid(t, m, "control.lan", c.now)
	if id, _ := m.Current(); id == "" {
		t.Fatal("signing stopped")
	}
	if len(repo.kind(store.PKIIntermediate)) != 1 {
		t.Fatal("an intermediate was issued without the root")
	}
	// Past its end, with no root, it is a hard failure.
	c.advance(IntermediateValidity)
	if err := m.Ensure(context.Background()); !errors.Is(err, ErrRootUnavailable) {
		t.Fatalf("expired: %v", err)
	}
	// Bringing the root back renews it.
	root.Secret = sealedRoot
	repo.objects[root.ID] = root
	ensure(t, m)
	// The old one had expired, so it is gone rather than kept as retired.
	if issuers := repo.kind(store.PKIIntermediate); len(issuers) != 1 || issuers[0].State != stateActive || issuers[0].ID == oldIssuerID {
		t.Fatalf("the intermediate was not renewed once the root came back: %+v", issuers)
	}
	servedChainIsValid(t, m, "control.lan", c.now)
}

func TestAFailedWriteChangesNothingAndIsRetried(t *testing.T) {
	repo, c := newMemoryRepo(), &clock{epoch}
	repo.fail = errors.New("disk full")
	m := newManager(t, repo, c)
	if err := m.Ensure(context.Background()); err == nil {
		t.Fatal("a failed write was reported as success")
	}
	if len(m.Bundle().Roots) != 0 || m.RootFingerprint() != "" {
		t.Fatal("a pass that was not saved was published")
	}
	if id, _ := m.Current(); id != "" {
		t.Fatal("a signing key that was not saved is in use")
	}
	repo.fail = nil
	ensure(t, m)
	if m.Bundle().Version != 1 {
		t.Fatal("the retry did not complete")
	}
}

func TestCorruptStateIsNotRepairedSilently(t *testing.T) {
	repo, c := newMemoryRepo(), &clock{epoch}
	ensure(t, newManager(t, repo, c))
	bundle := repo.kind(store.PKIBundle)[0]
	bundle.Public = "{"
	repo.objects[bundle.ID] = bundle
	if newManager(t, repo, c).Ensure(context.Background()) == nil {
		t.Fatal("a corrupt bundle was ignored")
	}
	repo2 := newMemoryRepo()
	ensure(t, newManager(t, repo2, c))
	key := repo2.kind(store.PKISigningKey)[0]
	other, _, _ := ed25519.GenerateKey(nil)
	key.Public = encode(other)
	repo2.objects[key.ID] = key
	if newManager(t, repo2, c).Ensure(context.Background()) == nil {
		t.Fatal("a public key that does not match its secret was accepted")
	}
}

func TestOptionsAreValidated(t *testing.T) {
	repo := newMemoryRepo()
	for name, opts := range map[string]Options{
		"short key":      {Key: []byte("short")},
		"short validity": {Key: databaseKey, LeafValidity: time.Hour},
		"long validity":  {Key: databaseKey, LeafValidity: 400 * 24 * time.Hour},
	} {
		if _, err := NewManager(repo, opts); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestTheInventoryCarriesDatesAndNoSecrets(t *testing.T) {
	repo, c := newMemoryRepo(), &clock{epoch}
	m := newManager(t, repo, c, "control.lan")
	ensure(t, m)
	kinds := map[string]bool{}
	for _, entry := range m.Inventory() {
		kinds[entry.Kind] = true
		if entry.Fingerprint == "" || entry.NotAfter.IsZero() || entry.State == "" {
			t.Fatalf("incomplete: %+v", entry)
		}
	}
	for _, kind := range []string{"root", "intermediate", "https", "signing_key"} {
		if !kinds[kind] {
			t.Fatalf("missing %s", kind)
		}
	}
}

func encode(key ed25519.PublicKey) string { return base64.StdEncoding.EncodeToString(key) }

func csrFor(t *testing.T, key any, name string, dns ...string) []byte {
	t.Helper()
	request, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: name}, DNSNames: dns}, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: request})
}

func TestTheClientCertificateChainsToTheBundleAndRenewsInMemory(t *testing.T) {
	repo, c := newMemoryRepo(), &clock{epoch}
	m := newManager(t, repo, c, "control.lan")
	if _, err := m.ClientCertificate(); err == nil {
		t.Fatal("a client certificate before the authority was ready")
	}
	ensure(t, m)
	check := func() *x509.Certificate {
		t.Helper()
		pair, err := m.ClientCertificate()
		if err != nil {
			t.Fatal(err)
		}
		roots, intermediates, _ := m.Bundle().Certificates()
		if err := Chain(pair.Leaf, roots, intermediates, x509.ExtKeyUsageClientAuth, c.now); err != nil {
			t.Fatalf("client certificate does not chain: %v", err)
		}
		if pair.Leaf.Subject.CommonName != ControlTowerName {
			t.Fatalf("name %q", pair.Leaf.Subject.CommonName)
		}
		if err := Chain(pair.Leaf, roots, intermediates, x509.ExtKeyUsageServerAuth, c.now); err == nil {
			t.Fatal("a client certificate is usable as a server certificate")
		}
		return pair.Leaf
	}
	first := check()
	c.advance(59 * 24 * time.Hour)
	ensure(t, m)
	if same := check(); same.SerialNumber.Cmp(first.SerialNumber) != 0 {
		t.Fatal("renewed too early")
	}
	c.advance(2 * 24 * time.Hour)
	ensure(t, m)
	if renewed := check(); renewed.SerialNumber.Cmp(first.SerialNumber) == 0 {
		t.Fatal("not renewed at two thirds of its life")
	}
	if m.RootPool() == nil {
		t.Fatal("no root pool")
	}
}

func TestANodeCertificateIsIssuedFromItsRequestForTheAnnouncedAddress(t *testing.T) {
	repo, c := newMemoryRepo(), &clock{epoch}
	m := newManager(t, repo, c)
	ensure(t, m)
	key, _ := generateKey()
	// The request asks for names the node was never announced under: they must not appear.
	chain, leaf, err := m.IssueServerCertificate(csrFor(t, key, "node-1", "evil.example", "control.lan"), "node-1", "node.lan")
	if err != nil {
		t.Fatal(err)
	}
	if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != "node.lan" || leaf.Subject.CommonName != "node-1" {
		t.Fatalf("names: %v / %q", leaf.DNSNames, leaf.Subject.CommonName)
	}
	if !leaf.PublicKey.(*ecdsa.PublicKey).Equal(&key.PublicKey) {
		t.Fatal("the certificate is not for the requested key")
	}
	roots, intermediates, _ := m.Bundle().Certificates()
	if err := Chain(leaf, roots, intermediates, x509.ExtKeyUsageServerAuth, c.now); err != nil {
		t.Fatalf("does not chain: %v", err)
	}
	if err := Chain(leaf, roots, intermediates, x509.ExtKeyUsageClientAuth, c.now); err == nil {
		t.Fatal("a node's server certificate works as a client certificate")
	}
	// The chain carries the intermediate and not the root.
	count := strings.Count(chain, "BEGIN CERTIFICATE")
	if count != 2 || strings.Count(chain, string(m.RootPEM())) != 0 {
		t.Fatalf("chain has %d certificates", count)
	}
	_, ipLeaf, err := m.IssueServerCertificate(csrFor(t, key, "node-1"), "node-1", "10.1.2.3")
	if err != nil || len(ipLeaf.IPAddresses) != 1 || ipLeaf.IPAddresses[0].String() != "10.1.2.3" || len(ipLeaf.DNSNames) != 0 {
		t.Fatalf("ip address: %v", err)
	}
}

func TestARequestThatIsNotForThisNodeOrNotP256IsRefused(t *testing.T) {
	repo, c := newMemoryRepo(), &clock{epoch}
	m := newManager(t, repo, c)
	ensure(t, m)
	p256, _ := generateKey()
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	good := csrFor(t, p256, "node-1")
	tampered := append([]byte(nil), good...)
	block, _ := pem.Decode(tampered)
	block.Bytes[len(block.Bytes)-3] ^= 0x01
	cases := map[string]struct {
		csr  []byte
		node string
		host string
	}{
		"another node id":  {good, "node-2", "node.lan"},
		"empty node id":    {good, "", "node.lan"},
		"P-384 key":        {csrFor(t, p384, "node-1"), "node-1", "node.lan"},
		"RSA key":          {csrFor(t, rsaKey, "node-1"), "node-1", "node.lan"},
		"broken signature": {pem.EncodeToMemory(block), "node-1", "node.lan"},
		"two requests":     {append(append([]byte(nil), good...), good...), "node-1", "node.lan"},
		"not a request":    {[]byte("nope"), "node-1", "node.lan"},
		"no address":       {good, "node-1", ""},
		"a certificate":    {pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: block.Bytes}), "node-1", "node.lan"},
	}
	for name, tc := range cases {
		if _, _, err := m.IssueServerCertificate(tc.csr, tc.node, tc.host); err == nil {
			t.Errorf("%s: issued", name)
		}
	}
	if _, _, err := newManager(t, newMemoryRepo(), c).IssueServerCertificate(good, "node-1", "node.lan"); err == nil {
		t.Error("issued by an authority that was never started")
	}
}
