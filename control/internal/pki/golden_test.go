package pki

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The Control Tower and the node each carry a copy of the bundle verifier. This
// corpus of bundles, built once and kept in testdata, is read by both: if the
// copies ever disagree on a case, one of the two tests fails.
type goldenBundleCase struct {
	Name     string          `json:"name"`
	Bundle   json.RawMessage `json:"bundle"`
	Previous json.RawMessage `json:"previous,omitempty"`
	Pin      string          `json:"pin,omitempty"`
	Now      time.Time       `json:"now"`
	Accepted bool            `json:"accepted"`
}

const goldenBundlePath = "../../../testdata/trust-bundle-cases.json"

func rawBundle(b Bundle) json.RawMessage {
	encoded, err := b.Marshal()
	if err != nil {
		panic(err)
	}
	return encoded
}

func buildGoldenBundleCases(t *testing.T) []goldenBundleCase {
	f := newBundleFixture(t)
	current := f.bundle(5, "k1", "k1")
	other := newBundleFixture(t)
	stray, _ := NewRoot(epoch)
	strayIssuer, _ := stray.NewIntermediate(epoch)
	next, _ := NewRoot(epoch)
	nextIssuer, _ := next.NewIntermediate(epoch)

	var cases []goldenBundleCase
	add := func(name string, candidate Bundle, previous *Bundle, pin string, now time.Time, accepted bool) {
		c := goldenBundleCase{Name: name, Bundle: rawBundle(candidate), Pin: pin, Now: now, Accepted: accepted}
		if previous != nil {
			c.Previous = rawBundle(*previous)
		}
		cases = append(cases, c)
	}
	resign := func(b Bundle, signer string) Bundle {
		b, err := b.Sign(signer, f.key(signer))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	clone := func(b Bundle) Bundle {
		b.SigningKeys = append([]BundleKey(nil), b.SigningKeys...)
		b.RevokedSerials = append([]string(nil), b.RevokedSerials...)
		b.Roots = append([]string(nil), b.Roots...)
		b.Intermediates = append([]string(nil), b.Intermediates...)
		return b
	}

	first := f.bundle(1, "k1", "k1", "k2")
	add("first bundle under the pinned root", first, nil, f.pin, epoch, true)
	add("first bundle under another pin", first, nil, other.pin, epoch, false)
	add("first bundle without a pin", first, nil, "", epoch, false)
	unknownSigner := clone(first)
	unknownSigner.Signature.KeyID = "stranger"
	add("first bundle signed by a key it does not list", unknownSigner, nil, f.pin, epoch, false)

	add("successor signed by a listed key", f.bundle(6, "k1", "k1", "k2"), &current, "", epoch, true)
	add("successor with the same version", f.bundle(5, "k1", "k1"), &current, "", epoch, false)
	add("successor with an older version", f.bundle(4, "k1", "k1"), &current, "", epoch, false)
	add("successor signed by the key it adds", f.bundle(6, "k2", "k1", "k2"), &current, "", epoch, false)
	add("successor signed by an unknown key", f.bundle(6, "k3", "k3"), &current, "", epoch, false)
	add("successor after the signing key expired", f.bundle(6, "k1", "k1"), &current, "", epoch.Add(91*24*time.Hour), false)

	foreign := Bundle{Version: 6, IssuedAt: epoch, Roots: []string{string(other.root.PEM())}, Intermediates: []string{string(other.intermediate.PEM())},
		SigningKeys: []BundleKey{f.entry("k1", epoch.Add(90*24*time.Hour))}, RevokedSerials: []string{}}
	add("successor with an unrelated root", resign(foreign, "k1"), &current, "", epoch, false)

	both := clone(f.bundle(6, "k1", "k1"))
	both.Roots = append(both.Roots, string(next.PEM()))
	both.Intermediates = append(both.Intermediates, string(nextIssuer.PEM()))
	add("successor with a second root beside the first", resign(both, "k1"), &current, "", epoch, true)

	strayBundle := clone(f.bundle(1, "k1", "k1"))
	strayBundle.Intermediates = []string{string(strayIssuer.PEM())}
	add("intermediate from another root", resign(strayBundle, "k1"), nil, f.pin, epoch, false)
	rootAsIssuer := clone(f.bundle(1, "k1", "k1"))
	rootAsIssuer.Intermediates = []string{string(f.root.PEM())}
	add("root listed as an intermediate", resign(rootAsIssuer, "k1"), nil, f.pin, epoch, false)

	good := f.bundle(1, "k1", "k1", "k2")
	tampers := map[string]func(*Bundle){
		"changed version":      func(b *Bundle) { b.Version = 2 },
		"changed issue time":   func(b *Bundle) { b.IssuedAt = b.IssuedAt.Add(time.Second) },
		"added root":           func(b *Bundle) { b.Roots = append(b.Roots, string(next.PEM())) },
		"added intermediate":   func(b *Bundle) { b.Intermediates = append(b.Intermediates, string(nextIssuer.PEM())) },
		"swapped key material": func(b *Bundle) { b.SigningKeys[1].Key = b.SigningKeys[0].Key },
		"renamed key":          func(b *Bundle) { b.SigningKeys[1].ID = "renamed" },
		"extended key expiry":  func(b *Bundle) { b.SigningKeys[1].NotAfter = b.SigningKeys[1].NotAfter.Add(24 * time.Hour) },
		"added revoked serial": func(b *Bundle) { b.RevokedSerials = append(b.RevokedSerials, "ab") },
		"changed signer":       func(b *Bundle) { b.Signature.KeyID = "k2" },
	}
	for name, tamper := range tampers {
		candidate := clone(good)
		tamper(&candidate)
		add("tampered: "+name, candidate, nil, f.pin, epoch, false)
	}
	flipped := clone(good)
	signature, _ := base64.StdEncoding.DecodeString(flipped.Signature.Value)
	signature[0] ^= 1
	flipped.Signature.Value = base64.StdEncoding.EncodeToString(signature)
	add("tampered: flipped signature bit", flipped, nil, f.pin, epoch, false)

	many := make([]string, 0, 17)
	for i := 0; i < 17; i++ {
		many = append(many, "key"+string(rune('a'+i)))
	}
	add("seventeen signing keys", f.bundle(1, many[0], many...), nil, f.pin, epoch, false)
	duplicate := clone(f.bundle(1, "k1", "k1"))
	duplicate.SigningKeys = append(duplicate.SigningKeys, duplicate.SigningKeys[0])
	add("duplicate key id", resign(duplicate, "k1"), nil, f.pin, epoch, false)
	badSerial := clone(f.bundle(1, "k1", "k1"))
	badSerial.RevokedSerials = []string{"xyz"}
	add("revoked serial that is not hex", resign(badSerial, "k1"), nil, f.pin, epoch, false)
	oddSerial := clone(f.bundle(1, "k1", "k1"))
	oddSerial.RevokedSerials = []string{"abc", "0a1b"}
	add("revoked serial of odd length", resign(oddSerial, "k1"), nil, f.pin, epoch, true)
	upperSerial := clone(f.bundle(1, "k1", "k1"))
	upperSerial.RevokedSerials = []string{"ABC"}
	add("revoked serial in uppercase", resign(upperSerial, "k1"), nil, f.pin, epoch, false)
	badKeyID := clone(f.bundle(1, "k1", "k1"))
	badKeyID.SigningKeys[0].ID = "a b"
	add("key id with a space", resign(badKeyID, "k1"), nil, f.pin, epoch, false)
	_ = ed25519.PublicKeySize
	return cases
}

func TestGoldenBundleCasesAgreeWithTheVerifier(t *testing.T) {
	path := filepath.Clean(goldenBundlePath)
	if os.Getenv("UPDATE_GOLDEN") != "" {
		cases := buildGoldenBundleCases(t)
		for _, c := range cases {
			// A case is written only if the verifier already agrees with it.
			assertGoldenCase(t, c)
		}
		encoded, err := json.MarshalIndent(cases, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, append(encoded, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("wrote %d cases", len(cases))
		return
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var cases []goldenBundleCase
	if err := json.Unmarshal(data, &cases); err != nil || len(cases) < 25 {
		t.Fatalf("golden file: %d cases, %v", len(cases), err)
	}
	for _, c := range cases {
		assertGoldenCase(t, c)
	}
}

func assertGoldenCase(t *testing.T, c goldenBundleCase) {
	t.Helper()
	t.Run(c.Name, func(t *testing.T) {
		candidate, err := ParseBundle(c.Bundle)
		if err != nil {
			if c.Accepted {
				t.Fatalf("a bundle that must be accepted does not parse: %v", err)
			}
			return
		}
		var previous *Bundle
		if len(c.Previous) > 0 {
			parsed, err := ParseBundle(c.Previous)
			if err != nil {
				t.Fatal(err)
			}
			previous = &parsed
		}
		err = VerifyBundle(candidate, previous, c.Pin, c.Now)
		if c.Accepted && err != nil {
			t.Fatalf("must be accepted: %v", err)
		}
		if !c.Accepted && err == nil {
			t.Fatal("must be refused")
		}
	})
}
