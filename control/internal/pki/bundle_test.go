package pki

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

type bundleFixture struct {
	root, intermediate *Authority
	keys               map[string]ed25519.PrivateKey
	pin                string
}

func newBundleFixture(t *testing.T) *bundleFixture {
	t.Helper()
	root, intermediate := authorities(t)
	return &bundleFixture{root: root, intermediate: intermediate, keys: map[string]ed25519.PrivateKey{}, pin: Fingerprint(root.Cert)}
}

func (f *bundleFixture) key(id string) ed25519.PrivateKey {
	if key, ok := f.keys[id]; ok {
		return key
	}
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	f.keys[id] = key
	return key
}

func (f *bundleFixture) entry(id string, notAfter time.Time) BundleKey {
	return BundleKey{ID: id, Key: base64.StdEncoding.EncodeToString(f.key(id).Public().(ed25519.PublicKey)), NotAfter: notAfter}
}

func (f *bundleFixture) bundle(version int64, signer string, ids ...string) Bundle {
	var entries []BundleKey
	for _, id := range ids {
		entries = append(entries, f.entry(id, epoch.Add(90*24*time.Hour)))
	}
	b := Bundle{
		Version: version, IssuedAt: epoch, Roots: []string{string(f.root.PEM())}, Intermediates: []string{string(f.intermediate.PEM())},
		SigningKeys: entries, RevokedSerials: []string{},
	}
	signed, err := b.Sign(signer, f.key(signer))
	if err != nil {
		panic(err)
	}
	return signed
}

func TestTheFirstBundleIsAcceptedOnlyUnderThePinnedRoot(t *testing.T) {
	f := newBundleFixture(t)
	first := f.bundle(1, "k1", "k1")
	if err := VerifyBundle(first, nil, f.pin, epoch); err != nil {
		t.Fatal(err)
	}
	other := newBundleFixture(t)
	for name, pin := range map[string]string{"another root": other.pin, "no pin": "", "a prefix": f.pin[:16], "uppercase": strings.ToUpper(f.pin)} {
		if VerifyBundle(first, nil, pin, epoch) == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestTheFirstBundleMustBeSignedByOneOfItsOwnKeys(t *testing.T) {
	f := newBundleFixture(t)
	b := f.bundle(1, "k1", "k1")
	b.Signature.KeyID = "stranger"
	if VerifyBundle(b, nil, f.pin, epoch) == nil {
		t.Fatal("signed by a key the bundle does not list")
	}
}

func TestASuccessorMustBeNewerAndSignedByAKeyTheCurrentBundleListed(t *testing.T) {
	f := newBundleFixture(t)
	current := f.bundle(5, "k1", "k1")
	if err := VerifyBundle(f.bundle(6, "k1", "k1", "k2"), &current, "", epoch); err != nil {
		t.Fatalf("rotation step: %v", err)
	}
	cases := map[string]Bundle{
		"same version":                 f.bundle(5, "k1", "k1"),
		"older version":                f.bundle(4, "k1", "k1"),
		"signed by the key it adds":    f.bundle(6, "k2", "k1", "k2"),
		"signed by an unknown key":     f.bundle(6, "k3", "k3"),
		"drops the signer and nothing": f.bundle(6, "k2", "k2"),
	}
	for name, candidate := range cases {
		if VerifyBundle(candidate, &current, "", epoch) == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestAKeyTheCurrentBundleLetExpireCannotSignTheNext(t *testing.T) {
	f := newBundleFixture(t)
	current := f.bundle(5, "k1", "k1")
	late := epoch.Add(91 * 24 * time.Hour)
	// Keep the intermediate valid at that instant so only the key is at fault.
	next := f.bundle(6, "k1", "k1")
	if err := VerifyBundle(next, &current, "", late); err == nil {
		t.Fatal("an expired key signed a bundle")
	}
}

func TestASuccessorMustKeepARootOfTheCurrentBundle(t *testing.T) {
	f := newBundleFixture(t)
	current := f.bundle(5, "k1", "k1")
	other := newBundleFixture(t)
	foreign := Bundle{Version: 6, IssuedAt: epoch, Roots: []string{string(other.root.PEM())}, Intermediates: []string{string(other.intermediate.PEM())},
		SigningKeys: []BundleKey{f.entry("k1", epoch.Add(90*24*time.Hour))}, RevokedSerials: []string{}}
	foreign, _ = foreign.Sign("k1", f.key("k1"))
	if VerifyBundle(foreign, &current, "", epoch) == nil {
		t.Fatal("a bundle with an unrelated root replaced the current one")
	}
}

func TestARootMayBeAddedBesideTheOldOneButNotInstead(t *testing.T) {
	f := newBundleFixture(t)
	current := f.bundle(5, "k1", "k1")
	next, _ := NewRoot(epoch)
	nextIssuer, _ := next.NewIntermediate(epoch)
	both := f.bundle(6, "k1", "k1")
	both.Roots = append(both.Roots, string(next.PEM()))
	both.Intermediates = append(both.Intermediates, string(nextIssuer.PEM()))
	both, _ = both.Sign("k1", f.key("k1"))
	if err := VerifyBundle(both, &current, "", epoch); err != nil {
		t.Fatalf("overlap: %v", err)
	}
}

func TestEveryFieldIsCoveredByTheSignature(t *testing.T) {
	f := newBundleFixture(t)
	good := f.bundle(1, "k1", "k1", "k2")
	extra, _ := NewRoot(epoch)
	extraIssuer, _ := extra.NewIntermediate(epoch)
	tampers := map[string]func(*Bundle){
		"version":       func(b *Bundle) { b.Version = 2 },
		"issued_at":     func(b *Bundle) { b.IssuedAt = b.IssuedAt.Add(time.Second) },
		"roots":         func(b *Bundle) { b.Roots = append(b.Roots, string(extra.PEM())) },
		"intermediates": func(b *Bundle) { b.Intermediates = append(b.Intermediates, string(extraIssuer.PEM())) },
		"key material":  func(b *Bundle) { b.SigningKeys[1].Key = b.SigningKeys[0].Key },
		"key id":        func(b *Bundle) { b.SigningKeys[1].ID = "renamed" },
		"key expiry":    func(b *Bundle) { b.SigningKeys[1].NotAfter = b.SigningKeys[1].NotAfter.Add(24 * time.Hour) },
		"revoked":       func(b *Bundle) { b.RevokedSerials = append(b.RevokedSerials, "ab") },
		"signer":        func(b *Bundle) { b.Signature.KeyID = "k2" },
	}
	for name, tamper := range tampers {
		candidate := good
		candidate.SigningKeys = append([]BundleKey(nil), good.SigningKeys...)
		candidate.RevokedSerials = append([]string(nil), good.RevokedSerials...)
		candidate.Roots = append([]string(nil), good.Roots...)
		candidate.Intermediates = append([]string(nil), good.Intermediates...)
		tamper(&candidate)
		if VerifyBundle(candidate, nil, f.pin, epoch) == nil {
			t.Errorf("%s: a changed bundle verified", name)
		}
	}
	signature, _ := base64.StdEncoding.DecodeString(good.Signature.Value)
	signature[0] ^= 1
	good.Signature.Value = base64.StdEncoding.EncodeToString(signature)
	if VerifyBundle(good, nil, f.pin, epoch) == nil {
		t.Fatal("a flipped signature verified")
	}
}

func TestAnIntermediateNoListedRootSignedIsRefused(t *testing.T) {
	f := newBundleFixture(t)
	stray, _ := NewRoot(epoch)
	strayIssuer, _ := stray.NewIntermediate(epoch)
	b := f.bundle(1, "k1", "k1")
	b.Intermediates = []string{string(strayIssuer.PEM())}
	b, _ = b.Sign("k1", f.key("k1"))
	if VerifyBundle(b, nil, f.pin, epoch) == nil {
		t.Fatal("an intermediate from another root was accepted")
	}
	b.Intermediates = []string{string(f.root.PEM())}
	b, _ = b.Sign("k1", f.key("k1"))
	if VerifyBundle(b, nil, f.pin, epoch) == nil {
		t.Fatal("a root was accepted as an intermediate")
	}
}

func TestSizesAndIdentifiersAreBounded(t *testing.T) {
	f := newBundleFixture(t)
	many := make([]string, 0, 18)
	for i := 0; i < 17; i++ {
		many = append(many, "key"+string(rune('a'+i)))
	}
	cases := map[string]func() Bundle{
		"seventeen keys": func() Bundle { return f.bundle(1, many[0], many...) },
		"no keys":        func() Bundle { b := f.bundle(1, "k1", "k1"); b.SigningKeys = nil; return b },
		"duplicate key": func() Bundle {
			b := f.bundle(1, "k1", "k1")
			b.SigningKeys = append(b.SigningKeys, b.SigningKeys[0])
			return b
		},
		"bad key id":   func() Bundle { b := f.bundle(1, "k1", "k1"); b.SigningKeys[0].ID = "a b"; return b },
		"short key":    func() Bundle { b := f.bundle(1, "k1", "k1"); b.SigningKeys[0].Key = "AAAA"; return b },
		"bad serial":   func() Bundle { b := f.bundle(1, "k1", "k1"); b.RevokedSerials = []string{"xyz"}; return b },
		"no expiry":    func() Bundle { b := f.bundle(1, "k1", "k1"); b.SigningKeys[0].NotAfter = time.Time{}; return b },
		"version zero": func() Bundle { return f.bundle(0, "k1", "k1") },
	}
	for name, build := range cases {
		b := build()
		if signed, err := b.Sign(b.Signature.KeyID, f.key(b.Signature.KeyID)); err == nil {
			b = signed
		}
		if VerifyBundle(b, nil, f.pin, epoch) == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestParsingIsStrict(t *testing.T) {
	f := newBundleFixture(t)
	good, _ := f.bundle(1, "k1", "k1").Marshal()
	if _, err := ParseBundle(good); err != nil {
		t.Fatal(err)
	}
	var generic map[string]any
	_ = json.Unmarshal(good, &generic)
	generic["surprise"] = true
	withExtra, _ := json.Marshal(generic)
	for name, data := range map[string][]byte{
		"unknown field": withExtra,
		"trailing":      append(append([]byte{}, good...), []byte(` {}`)...),
		"not json":      []byte("nope"),
		"oversized":     append([]byte(`{"version":1,"x":"`), make([]byte, maxBundleBytes)...),
	} {
		if _, err := ParseBundle(data); err == nil {
			t.Errorf("%s: parsed", name)
		}
	}
}

func TestPublicKeysAndRevocationReadTheBundle(t *testing.T) {
	f := newBundleFixture(t)
	b := f.bundle(1, "k1", "k1", "k2")
	b.SigningKeys[1].NotAfter = epoch.Add(time.Hour)
	b.RevokedSerials = []string{"0a1b"}
	if keys := b.PublicKeys(epoch); len(keys) != 2 {
		t.Fatalf("keys: %d", len(keys))
	}
	if keys := b.PublicKeys(epoch.Add(2 * time.Hour)); len(keys) != 1 || keys["k1"] == nil {
		t.Fatalf("an expired key is still offered: %v", keys)
	}
	if !b.Revoked("0a1b") || b.Revoked("0a1c") {
		t.Fatal("revocation lookup")
	}
}
