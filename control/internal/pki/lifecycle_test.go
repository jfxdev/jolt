package pki

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"testing"
	"time"
)

func started(t *testing.T) (*Manager, *memoryRepo, *clock) {
	t.Helper()
	c := &clock{now: time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)}
	repo := newMemoryRepo()
	m := newManager(t, repo, c, "ct.lan")
	ensure(t, m)
	return m, repo, c
}

// adopts runs what a node does with a bundle the Control Tower publishes.
func adopts(t *testing.T, previous, next Bundle, now time.Time) {
	t.Helper()
	if err := VerifyBundle(next, &previous, "", now); err != nil {
		t.Fatalf("a node would refuse version %d: %v", next.Version, err)
	}
}

func servedLeaf(t *testing.T, m *Manager) *x509.Certificate {
	t.Helper()
	served, err := m.TLSConfig().GetCertificate(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(served.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	return leaf
}

func clientLeaf(t *testing.T, m *Manager) *x509.Certificate {
	t.Helper()
	pair, err := m.ClientCertificate()
	if err != nil {
		t.Fatal(err)
	}
	return pair.Leaf
}

func TestARevokedSerialJoinsTheNextBundleAndIsDroppedOnceItWouldHaveEndedAnyway(t *testing.T) {
	m, repo, c := started(t)
	before := m.Bundle()
	if before.Revoked("abc123") {
		t.Fatal("revoked before anyone asked")
	}
	end := c.now.Add(10 * 24 * time.Hour)
	if err := m.Revoke(context.Background(), Revocation{Serial: "ABC123", Subject: "node-1", Reason: "key leaked", NotAfter: end}); err != nil {
		t.Fatal(err)
	}
	after := m.Bundle()
	if !after.Revoked("abc123") || after.Version != before.Version+1 {
		t.Fatalf("bundle: version %d→%d, revoked %v", before.Version, after.Version, after.RevokedSerials)
	}
	adopts(t, before, after, c.now)
	// Asking again is not a new fact: no new bundle.
	if err := m.Revoke(context.Background(), Revocation{Serial: "abc123"}); err != nil || m.Bundle().Version != after.Version {
		t.Fatalf("a repeat made a bundle: %v %d", err, m.Bundle().Version)
	}
	list, err := m.Revocations(context.Background())
	if err != nil || len(list) != 1 || list[0].Subject != "node-1" || list[0].Reason != "key leaked" {
		t.Fatalf("list: %+v %v", list, err)
	}
	// The serial stays while the certificate could still be presented, then goes.
	c.advance(10*24*time.Hour + time.Hour)
	ensure(t, m)
	if !m.Bundle().Revoked("abc123") {
		t.Fatal("dropped before the day of grace passed")
	}
	c.advance(24 * time.Hour)
	ensure(t, m)
	if m.Bundle().Revoked("abc123") || len(repo.kind("revocation")) != 0 {
		t.Fatal("an expired revocation is still listed")
	}
}

func TestOnlyAWellFormedSerialOfSomethingThatIsNotARootOrTheIssuerCanBeRevoked(t *testing.T) {
	m, _, _ := started(t)
	for _, bad := range []string{"", "xyz", "12 34", string(make([]byte, 65))} {
		if err := m.Revoke(context.Background(), Revocation{Serial: bad}); err == nil {
			t.Errorf("serial %q accepted", bad)
		}
	}
	var rootSerial, issuerSerial string
	for _, item := range m.Inventory() {
		switch item.Kind {
		case "root":
			rootSerial = item.Serial
		case "intermediate":
			issuerSerial = item.Serial
		}
	}
	if err := m.Revoke(context.Background(), Revocation{Serial: rootSerial}); !errors.Is(err, ErrCannotRevokeRoot) {
		t.Errorf("root: %v", err)
	}
	if err := m.Revoke(context.Background(), Revocation{Serial: issuerSerial}); !errors.Is(err, ErrUseRotation) {
		t.Errorf("active intermediate: %v", err)
	}
	if m.Bundle().Version != 1 {
		t.Errorf("a refusal made a bundle: %d", m.Bundle().Version)
	}
}

func TestTheControlTowerReplacesItsOwnCertificateWhenItIsRevoked(t *testing.T) {
	m, _, c := started(t)
	client, https := clientLeaf(t, m), servedLeaf(t, m)
	before := m.Bundle()
	for _, leaf := range []*x509.Certificate{client, https} {
		if err := m.Revoke(context.Background(), Revocation{Serial: leaf.SerialNumber.Text(16), NotAfter: leaf.NotAfter}); err != nil {
			t.Fatal(err)
		}
	}
	if clientLeaf(t, m).SerialNumber.Cmp(client.SerialNumber) == 0 || servedLeaf(t, m).SerialNumber.Cmp(https.SerialNumber) == 0 {
		t.Fatal("a revoked certificate is still the one in use")
	}
	adopts(t, before, m.Bundle(), c.now)
	if m.Bundle().ChainRevoked([]*x509.Certificate{clientLeaf(t, m)}) || m.Bundle().ChainRevoked([]*x509.Certificate{servedLeaf(t, m)}) {
		t.Fatal("the replacement is revoked too")
	}
}

func TestACompromisedIntermediateIsRevokedAtOnceAndEverythingItSignedIsReissued(t *testing.T) {
	m, _, c := started(t)
	var old *x509.Certificate
	roots, issuers, _ := m.Bundle().Certificates()
	old = issuers[0]
	oldClient, oldHTTPS := clientLeaf(t, m), servedLeaf(t, m)
	before := m.Bundle()
	if err := m.RotateIntermediate(context.Background(), true, "key leaked"); err != nil {
		t.Fatal(err)
	}
	after := m.Bundle()
	adopts(t, before, after, c.now)
	_, issuersNow, _ := after.Certificates()
	if len(issuersNow) != 1 || Fingerprint(issuersNow[0]) == Fingerprint(old) {
		t.Fatalf("the leaked intermediate is still listed: %d", len(issuersNow))
	}
	if !after.Revoked(old.SerialNumber.Text(16)) {
		t.Fatal("its serial is not revoked")
	}
	// What it signed is no longer in use: the HTTPS and client certificates
	// now chain to the new intermediate, and the old ones are revoked by chain.
	if clientLeaf(t, m).Issuer.CommonName == oldClient.Issuer.CommonName || servedLeaf(t, m).Issuer.CommonName == oldHTTPS.Issuer.CommonName {
		t.Fatal("a certificate signed by the leaked key is still served")
	}
	if !after.ChainRevoked([]*x509.Certificate{oldHTTPS, old}) {
		t.Fatal("what the old key signed is not refused by chain")
	}
	if err := Chain(servedLeaf(t, m), roots, issuersNow, x509.ExtKeyUsageServerAuth, c.now); err != nil {
		t.Fatalf("the new certificate does not chain: %v", err)
	}
	// The pass that follows keeps it all.
	ensure(t, m)
	if m.Bundle().Version != after.Version {
		t.Fatal("a quiet pass made a new bundle")
	}
}

func TestAPlannedIntermediateRotationKeepsTheOldOneUntilItExpires(t *testing.T) {
	m, _, c := started(t)
	before := m.Bundle()
	if err := m.RotateIntermediate(context.Background(), false, ""); err != nil {
		t.Fatal(err)
	}
	after := m.Bundle()
	adopts(t, before, after, c.now)
	roots, issuers, _ := after.Certificates()
	if len(issuers) != 2 || len(after.RevokedSerials) != 0 {
		t.Fatalf("intermediates %d, revoked %v", len(issuers), after.RevokedSerials)
	}
	// What the old one signed still verifies, and what is issued now uses the new one.
	if err := Chain(servedLeaf(t, m), roots, issuers, x509.ExtKeyUsageServerAuth, c.now); err != nil {
		t.Fatal(err)
	}
	// A third would break the bundle's limit.
	if err := m.RotateIntermediate(context.Background(), false, ""); !errors.Is(err, ErrTooManyIssuers) {
		t.Fatalf("third: %v", err)
	}
	// Revoking is allowed: it takes the others out of the bundle.
	if err := m.RotateIntermediate(context.Background(), true, ""); err != nil {
		t.Fatal(err)
	}
	if _, now, _ := m.Bundle().Certificates(); len(now) != 1 {
		t.Fatalf("after revoke: %d", len(now))
	}
}

func TestAnIntermediateRotationNeedsTheRootKey(t *testing.T) {
	m, repo, c := started(t)
	for id, object := range repo.objects {
		if object.Kind == "root" {
			object.Secret = ""
			repo.objects[id] = object
		}
	}
	version := m.Bundle().Version
	if err := m.RotateIntermediate(context.Background(), true, ""); !errors.Is(err, ErrRootUnavailable) {
		t.Fatalf("got %v", err)
	}
	if m.Bundle().Version != version || len(repo.kind("revocation")) != 0 {
		t.Fatal("a refused rotation changed something")
	}
	_ = c
}

func TestARootRotationWalksThroughPreparedPromotedAndRetired(t *testing.T) {
	m, _, c := started(t)
	ctx := context.Background()
	original := m.RootFingerprint()
	if m.Rotation().Phase != "none" || m.NextRootPEM() != nil {
		t.Fatalf("start: %+v", m.Rotation())
	}
	if err := m.PromoteRoot(ctx); !errors.Is(err, ErrNoRotation) {
		t.Fatalf("promote with none: %v", err)
	}
	if err := m.RetireRoot(ctx); !errors.Is(err, ErrNoRotation) {
		t.Fatalf("retire with none: %v", err)
	}

	// Prepared: both roots are published, nothing is signed by the new one yet.
	first := m.Bundle()
	if err := m.BeginRootRotation(ctx); err != nil {
		t.Fatal(err)
	}
	prepared := m.Bundle()
	adopts(t, first, prepared, c.now)
	if len(prepared.Roots) != 2 || m.Rotation().Phase != "prepared" || m.RootFingerprint() != original || m.NextRootPEM() == nil {
		t.Fatalf("prepared: roots %d %+v active %s", len(prepared.Roots), m.Rotation(), m.RootFingerprint())
	}
	if m.Rotation().Next == original {
		t.Fatal("the next root is the active one")
	}
	if err := m.BeginRootRotation(ctx); !errors.Is(err, ErrRotationBusy) {
		t.Fatalf("a second begin: %v", err)
	}
	pool := m.RootPool()
	if pool == nil || len(pool.Subjects()) != 2 { //nolint:staticcheck // counting roots in a test
		t.Fatal("the Control Tower does not trust both roots during a rotation")
	}
	httpsBefore := servedLeaf(t, m)
	if httpsBefore.Issuer.CommonName == "" {
		t.Fatal("no issuer")
	}

	// Promoted: the new root signs; the old one stays for what it issued.
	if err := m.PromoteRoot(ctx); err != nil {
		t.Fatal(err)
	}
	promoted := m.Bundle()
	adopts(t, prepared, promoted, c.now)
	if m.RootFingerprint() == original || m.Rotation().Phase != "promoted" || m.Rotation().Previous != original || len(promoted.Roots) != 2 {
		t.Fatalf("promoted: %+v active %s roots %d", m.Rotation(), m.RootFingerprint(), len(promoted.Roots))
	}
	roots, issuers, _ := promoted.Certificates()
	if len(issuers) != 2 {
		t.Fatalf("intermediates %d", len(issuers))
	}
	for leaf, usage := range map[*x509.Certificate]x509.ExtKeyUsage{servedLeaf(t, m): x509.ExtKeyUsageServerAuth, clientLeaf(t, m): x509.ExtKeyUsageClientAuth} {
		if leaf.Issuer.CommonName == httpsBefore.Issuer.CommonName {
			t.Fatal("a certificate is still signed by the old intermediate")
		}
		if err := Chain(leaf, roots, issuers, usage, c.now); err != nil {
			t.Fatalf("a certificate does not chain after the promotion: %v", err)
		}
	}
	var underRetired int
	for _, cert := range issuers {
		if m.UnderRetiredRoot(cert.SerialNumber.Text(16)) {
			underRetired++
		}
	}
	if underRetired != 1 {
		t.Fatalf("intermediates under the retired root: %d", underRetired)
	}
	if m.NextRootPEM() != nil {
		t.Fatal("a promoted rotation still offers a next root")
	}
	// The tokens a person creates from now pin the new root.
	if got := m.RootFingerprint(); m.Rotation().Previous == got {
		t.Fatal("the pin is the retired root")
	}

	// Retired: only the new chain remains.
	if err := m.RetireRoot(ctx); err != nil {
		t.Fatal(err)
	}
	done := m.Bundle()
	adopts(t, promoted, done, c.now)
	if len(done.Roots) != 1 || m.Rotation().Phase != "none" {
		t.Fatalf("retired: roots %d %+v", len(done.Roots), m.Rotation())
	}
	if _, left, _ := done.Certificates(); len(left) != 1 {
		t.Fatalf("intermediates left: %d", len(left))
	}
	if err := m.RetireRoot(ctx); !errors.Is(err, ErrNoRotation) {
		t.Fatalf("retire twice: %v", err)
	}
	ensure(t, m)
	if m.Bundle().Version != done.Version {
		t.Fatal("a quiet pass made a bundle")
	}
}

func TestARootRotationSurvivesARestartInEveryPhase(t *testing.T) {
	m, repo, c := started(t)
	ctx := context.Background()
	phases := []struct {
		name string
		step func() error
		want string
	}{
		{"begin", func() error { return m.BeginRootRotation(ctx) }, "prepared"},
		{"promote", func() error { return m.PromoteRoot(ctx) }, "promoted"},
		{"retire", func() error { return m.RetireRoot(ctx) }, "none"},
	}
	for _, phase := range phases {
		if err := phase.step(); err != nil {
			t.Fatalf("%s: %v", phase.name, err)
		}
		restarted := newManager(t, repo, c, "ct.lan")
		ensure(t, restarted)
		if restarted.Rotation().Phase != phase.want || restarted.Bundle().Version != m.Bundle().Version {
			t.Fatalf("%s: restarted at %+v version %d, want %s version %d", phase.name, restarted.Rotation(), restarted.Bundle().Version, phase.want, m.Bundle().Version)
		}
		if restarted.RootFingerprint() != m.RootFingerprint() {
			t.Fatalf("%s: a restart changed the active root", phase.name)
		}
	}
}

func TestTheRevocationListHasALimitAndAFullListStaysAValidBundle(t *testing.T) {
	m, _, c := started(t)
	ctx := context.Background()
	previous := m.Bundle()
	for i := 0; i < MaxRevokedSerials; i++ {
		if err := m.Revoke(ctx, Revocation{Serial: fmt.Sprintf("%x", 0x1000+i)}); err != nil {
			t.Fatalf("revocation %d: %v", i, err)
		}
	}
	full := m.Bundle()
	if len(full.RevokedSerials) != MaxRevokedSerials {
		t.Fatalf("listed %d", len(full.RevokedSerials))
	}
	adopts(t, previous, full, c.now)
	if err := m.Revoke(ctx, Revocation{Serial: "ffffff"}); !errors.Is(err, ErrTooManyRevoked) {
		t.Fatalf("past the limit: %v", err)
	}
	if m.Bundle().Version != full.Version {
		t.Fatal("a refused revocation made a bundle")
	}
	// Asking again for one already listed is still fine on a full list.
	if err := m.Revoke(ctx, Revocation{Serial: "1000"}); err != nil {
		t.Fatalf("a repeat on a full list: %v", err)
	}
}

func TestAPassThatDropsOneRevocationAndAddsAnotherStillPublishes(t *testing.T) {
	m, _, c := started(t)
	ctx := context.Background()
	if err := m.Revoke(ctx, Revocation{Serial: "aa01", NotAfter: c.now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	before := m.Bundle()
	// Nobody ran a pass for days, so the first revocation is due to leave in
	// the same pass that adds the second: the list keeps its length but not its
	// content, and nodes must still be told.
	c.advance(3 * 24 * time.Hour)
	if err := m.Revoke(ctx, Revocation{Serial: "bb02", NotAfter: c.now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	after := m.Bundle()
	if after.Version == before.Version || !after.Revoked("bb02") || after.Revoked("aa01") {
		t.Fatalf("version %d→%d, revoked %v", before.Version, after.Version, after.RevokedSerials)
	}
}
