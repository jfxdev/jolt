package pki

import (
	"crypto/ecdsa"
	"crypto/x509"
	"net"
	"strings"
	"testing"
	"time"
)

var epoch = time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)

func authorities(t *testing.T) (*Authority, *Authority) {
	t.Helper()
	root, err := NewRoot(epoch)
	if err != nil {
		t.Fatal(err)
	}
	intermediate, err := root.NewIntermediate(epoch)
	if err != nil {
		t.Fatal(err)
	}
	return root, intermediate
}

func TestALeafChainsToTheRootThroughTheIntermediate(t *testing.T) {
	root, intermediate := authorities(t)
	key, _ := generateKey()
	leaf, err := intermediate.Issue(epoch, &key.PublicKey, LeafSpec{CommonName: "control", DNSNames: []string{"control.lan"}, IPs: []net.IP{net.ParseIP("10.0.0.2")}, Usage: x509.ExtKeyUsageServerAuth})
	if err != nil {
		t.Fatal(err)
	}
	if err := Chain(leaf, []*x509.Certificate{root.Cert}, []*x509.Certificate{intermediate.Cert}, x509.ExtKeyUsageServerAuth, epoch.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := leaf.VerifyHostname("control.lan"); err != nil {
		t.Fatal(err)
	}
	if err := leaf.VerifyHostname("10.0.0.2"); err != nil {
		t.Fatal(err)
	}
	if got := leaf.NotAfter.Sub(epoch); got != DefaultLeafValidity {
		t.Fatalf("leaf lives %s, want %s", got, DefaultLeafValidity)
	}
	if _, ok := leaf.PublicKey.(*ecdsa.PublicKey); !ok {
		t.Fatalf("leaf key is %T", leaf.PublicKey)
	}
}

func TestTheRootIsNotEnoughWithoutTheIntermediate(t *testing.T) {
	root, intermediate := authorities(t)
	key, _ := generateKey()
	leaf, _ := intermediate.Issue(epoch, &key.PublicKey, LeafSpec{CommonName: "c", DNSNames: []string{"c"}, Usage: x509.ExtKeyUsageServerAuth})
	if err := Chain(leaf, []*x509.Certificate{root.Cert}, nil, x509.ExtKeyUsageServerAuth, epoch); err == nil {
		t.Fatal("a leaf was accepted without the intermediate that issued it")
	}
}

func TestAnIntermediateCannotIssueAnotherAuthority(t *testing.T) {
	root, intermediate := authorities(t)
	// A second-level CA under the intermediate must fail verification: the
	// intermediate's path length is zero.
	sub, err := (&Authority{Cert: intermediate.Cert, Key: intermediate.Key}).NewIntermediate(epoch)
	if err != nil {
		t.Fatal(err)
	}
	key, _ := generateKey()
	leaf, err := sub.Issue(epoch, &key.PublicKey, LeafSpec{CommonName: "c", DNSNames: []string{"c"}, Usage: x509.ExtKeyUsageServerAuth})
	if err != nil {
		t.Fatal(err)
	}
	err = Chain(leaf, []*x509.Certificate{root.Cert}, []*x509.Certificate{intermediate.Cert, sub.Cert}, x509.ExtKeyUsageServerAuth, epoch)
	if err == nil {
		t.Fatal("a certificate below the intermediate's path length was accepted")
	}
}

func TestACertificateIsRefusedOutsideItsValidityAndUsage(t *testing.T) {
	root, intermediate := authorities(t)
	key, _ := generateKey()
	leaf, _ := intermediate.Issue(epoch, &key.PublicKey, LeafSpec{CommonName: "c", DNSNames: []string{"c"}, Usage: x509.ExtKeyUsageServerAuth})
	roots, intermediates := []*x509.Certificate{root.Cert}, []*x509.Certificate{intermediate.Cert}
	if err := Chain(leaf, roots, intermediates, x509.ExtKeyUsageServerAuth, epoch.Add(DefaultLeafValidity+time.Minute)); err == nil {
		t.Fatal("an expired certificate was accepted")
	}
	if err := Chain(leaf, roots, intermediates, x509.ExtKeyUsageServerAuth, epoch.Add(-time.Hour)); err == nil {
		t.Fatal("a certificate that is not valid yet was accepted")
	}
	if err := Chain(leaf, roots, intermediates, x509.ExtKeyUsageClientAuth, epoch); err == nil {
		t.Fatal("a server certificate was accepted as a client certificate")
	}
}

func TestAnotherRootDoesNotVouchForTheLeaf(t *testing.T) {
	_, intermediate := authorities(t)
	other, _ := authorities(t)
	key, _ := generateKey()
	leaf, _ := intermediate.Issue(epoch, &key.PublicKey, LeafSpec{CommonName: "c", DNSNames: []string{"c"}, Usage: x509.ExtKeyUsageServerAuth})
	if err := Chain(leaf, []*x509.Certificate{other.Cert}, []*x509.Certificate{intermediate.Cert}, x509.ExtKeyUsageServerAuth, epoch); err == nil {
		t.Fatal("a leaf was accepted under a root that never signed its issuer")
	}
}

func TestIssueRefusesValuesOutsideTheAllowedRange(t *testing.T) {
	_, intermediate := authorities(t)
	key, _ := generateKey()
	for name, spec := range map[string]LeafSpec{
		"too short":     {CommonName: "c", DNSNames: []string{"c"}, Usage: x509.ExtKeyUsageServerAuth, Validity: time.Hour},
		"too long":      {CommonName: "c", DNSNames: []string{"c"}, Usage: x509.ExtKeyUsageServerAuth, Validity: 400 * 24 * time.Hour},
		"no usage":      {CommonName: "c", DNSNames: []string{"c"}},
		"a CA usage":    {CommonName: "c", DNSNames: []string{"c"}, Usage: x509.ExtKeyUsageAny},
		"server no SAN": {CommonName: "c", Usage: x509.ExtKeyUsageServerAuth},
	} {
		if _, err := intermediate.Issue(epoch, &key.PublicKey, spec); err == nil {
			t.Errorf("%s: issued", name)
		}
	}
}

func TestALeafNeverOutlivesItsIssuer(t *testing.T) {
	root, _ := authorities(t)
	late, err := root.NewIntermediate(epoch)
	if err != nil {
		t.Fatal(err)
	}
	key, _ := generateKey()
	near := late.Cert.NotAfter.Add(-24 * time.Hour)
	leaf, err := late.Issue(near, &key.PublicKey, LeafSpec{CommonName: "c", DNSNames: []string{"c"}, Usage: x509.ExtKeyUsageServerAuth})
	if err != nil {
		t.Fatal(err)
	}
	if leaf.NotAfter.After(late.Cert.NotAfter) {
		t.Fatalf("leaf %s outlives issuer %s", leaf.NotAfter, late.Cert.NotAfter)
	}
	if _, err := late.Issue(late.Cert.NotAfter.Add(time.Hour), &key.PublicKey, LeafSpec{CommonName: "c", DNSNames: []string{"c"}, Usage: x509.ExtKeyUsageServerAuth}); err == nil {
		t.Fatal("an expired issuer issued")
	}
}

func TestFingerprintsAreStableAndReadable(t *testing.T) {
	root, _ := authorities(t)
	plain := Fingerprint(root.Cert)
	if len(plain) != 64 || plain != strings.ToLower(plain) {
		t.Fatalf("fingerprint %q", plain)
	}
	shown := DisplayFingerprint(plain)
	if len(shown) != 64+31 || strings.ToUpper(shown) != shown || strings.Count(shown, ":") != 31 {
		t.Fatalf("display %q", shown)
	}
	parsed, err := ParseCertificate(root.PEM())
	if err != nil || Fingerprint(parsed) != plain {
		t.Fatalf("round trip: %v", err)
	}
	if _, err := ParseCertificate(append(root.PEM(), root.PEM()...)); err == nil {
		t.Fatal("two certificates were read as one")
	}
}
