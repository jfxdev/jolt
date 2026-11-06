package pki

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/jfxdev/jolt/control/internal/signedauth"
)

const (
	bundleDomain      = "jolt-trust-bundle-v1\n"
	MaxBundleRoots    = 2
	MaxBundleIssuers  = 2
	MaxBundleKeys     = 16
	MaxRevokedSerials = 1024
	maxBundleBytes    = 256 << 10
)

// BundleKey is a public key that may sign authorization contexts.
type BundleKey struct {
	ID       string    `json:"id"`
	Key      string    `json:"key"`
	NotAfter time.Time `json:"not_after"`
}

// BundleSignature names the bundle key that signed the bundle.
type BundleSignature struct {
	KeyID string `json:"key_id"`
	Value string `json:"value"`
}

// Bundle is what the Control Tower tells a node to trust: the roots and
// intermediates of its CA, the keys that may sign contexts, and the serials it
// has revoked. It is signed by a key the previous bundle already contained.
type Bundle struct {
	Version        int64           `json:"version"`
	IssuedAt       time.Time       `json:"issued_at"`
	Roots          []string        `json:"roots"`
	Intermediates  []string        `json:"intermediates"`
	SigningKeys    []BundleKey     `json:"signing_keys"`
	RevokedSerials []string        `json:"revoked_serials"`
	Signature      BundleSignature `json:"signature"`
}

func (b Bundle) payload() ([]byte, error) {
	b.Signature = BundleSignature{}
	encoded, err := json.Marshal(b)
	if err != nil {
		return nil, err
	}
	return append([]byte(bundleDomain), encoded...), nil
}

// Sign returns the bundle signed with the given key.
func (b Bundle) Sign(keyID string, key ed25519.PrivateKey) (Bundle, error) {
	if !signedauth.ValidKeyID(keyID) || len(key) != ed25519.PrivateKeySize {
		return Bundle{}, errors.New("invalid bundle signing key")
	}
	payload, err := b.payload()
	if err != nil {
		return Bundle{}, err
	}
	b.Signature = BundleSignature{KeyID: keyID, Value: base64.StdEncoding.EncodeToString(ed25519.Sign(key, payload))}
	return b, nil
}

// Marshal encodes the bundle as the node will receive it.
func (b Bundle) Marshal() ([]byte, error) { return json.Marshal(b) }

// ParseBundle reads a bundle strictly: unknown fields, trailing data and
// oversized input are refused.
func ParseBundle(data []byte) (Bundle, error) {
	if len(data) > maxBundleBytes {
		return Bundle{}, errors.New("trust bundle is too large")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var bundle Bundle
	if err := decoder.Decode(&bundle); err != nil {
		return Bundle{}, fmt.Errorf("invalid trust bundle: %w", err)
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return Bundle{}, errors.New("trust bundle has trailing data")
	}
	return bundle, nil
}

// Certificates returns the roots and intermediates, parsed.
func (b Bundle) Certificates() (roots, intermediates []*x509.Certificate, err error) {
	for _, value := range b.Roots {
		cert, err := ParseCertificate([]byte(value))
		if err != nil {
			return nil, nil, err
		}
		roots = append(roots, cert)
	}
	for _, value := range b.Intermediates {
		cert, err := ParseCertificate([]byte(value))
		if err != nil {
			return nil, nil, err
		}
		intermediates = append(intermediates, cert)
	}
	return roots, intermediates, nil
}

// PublicKeys returns the signing keys that are valid at now, by ID.
func (b Bundle) PublicKeys(now time.Time) map[string]ed25519.PublicKey {
	keys := make(map[string]ed25519.PublicKey, len(b.SigningKeys))
	for _, entry := range b.SigningKeys {
		raw, err := base64.StdEncoding.DecodeString(entry.Key)
		if err == nil && len(raw) == ed25519.PublicKeySize && now.Before(entry.NotAfter) {
			keys[entry.ID] = ed25519.PublicKey(raw)
		}
	}
	return keys
}

// Revoked reports whether a serial (lowercase hex) has been revoked.
func (b Bundle) Revoked(serial string) bool {
	for _, value := range b.RevokedSerials {
		if value == serial {
			return true
		}
	}
	return false
}

// validate checks a bundle on its own: sizes, identifiers, and that every
// intermediate chains to a root it lists.
func (b Bundle) validate(now time.Time) error {
	if b.Version < 1 {
		return errors.New("trust bundle version must be positive")
	}
	if len(b.Roots) < 1 || len(b.Roots) > MaxBundleRoots || len(b.Intermediates) < 1 || len(b.Intermediates) > MaxBundleIssuers ||
		len(b.SigningKeys) < 1 || len(b.SigningKeys) > MaxBundleKeys || len(b.RevokedSerials) > MaxRevokedSerials {
		return errors.New("trust bundle has an unexpected number of entries")
	}
	seen := map[string]bool{}
	for _, entry := range b.SigningKeys {
		raw, err := base64.StdEncoding.DecodeString(entry.Key)
		if !signedauth.ValidKeyID(entry.ID) || err != nil || len(raw) != ed25519.PublicKeySize || seen[entry.ID] || entry.NotAfter.IsZero() {
			return errors.New("trust bundle has an invalid signing key")
		}
		seen[entry.ID] = true
	}
	for _, serial := range b.RevokedSerials {
		if !lowercaseHex(serial) {
			return errors.New("trust bundle has an invalid revoked serial")
		}
	}
	roots, intermediates, err := b.Certificates()
	if err != nil {
		return err
	}
	for _, root := range roots {
		if !root.IsCA || !root.BasicConstraintsValid || now.After(root.NotAfter) {
			return errors.New("trust bundle has an unusable root")
		}
	}
	for _, issuer := range intermediates {
		signedByRoot := false
		for _, root := range roots {
			// A root signs itself, so a root listed as an intermediate would
			// pass the signature check without being one.
			if Fingerprint(root) != Fingerprint(issuer) && issuer.CheckSignatureFrom(root) == nil {
				signedByRoot = true
			}
		}
		// An intermediate that signs its own certificate is a root in disguise.
		if issuer.CheckSignatureFrom(issuer) == nil {
			signedByRoot = false
		}
		if !issuer.IsCA || now.After(issuer.NotAfter) || !signedByRoot {
			return errors.New("trust bundle has an intermediate no listed root signed")
		}
	}
	return nil
}

// lowercaseHex accepts the form big.Int.Text(16) produces for a serial number:
// lowercase digits of any length up to 64, odd lengths included.
func lowercaseHex(value string) bool {
	if value == "" || len(value) > 64 {
		return false
	}
	for _, r := range value {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') {
			return false
		}
	}
	return true
}

func rootSet(b Bundle) map[string]bool {
	set := map[string]bool{}
	for _, value := range b.Roots {
		if cert, err := ParseCertificate([]byte(value)); err == nil {
			set[Fingerprint(cert)] = true
		}
	}
	return set
}

// VerifyBundle decides whether a node may adopt candidate.
//
// With a previous bundle, the candidate must be newer, must still share a root
// with it, and must be signed by a key the previous bundle listed and had not
// let expire. Without one this is the first bundle a node sees: it is accepted
// only when one of its roots has the SHA-256 the join token pinned, and it must
// then be signed by one of its own keys.
func VerifyBundle(candidate Bundle, previous *Bundle, rootPin string, now time.Time) error {
	if err := candidate.validate(now); err != nil {
		return err
	}
	var trusted map[string]ed25519.PublicKey
	if previous != nil {
		if candidate.Version <= previous.Version {
			return errors.New("trust bundle is not newer than the one in use")
		}
		kept := false
		previousRoots := rootSet(*previous)
		for fingerprint := range rootSet(candidate) {
			kept = kept || previousRoots[fingerprint]
		}
		if !kept {
			return errors.New("trust bundle drops every root of the one in use")
		}
		trusted = previous.PublicKeys(now)
	} else {
		pinned := false
		for fingerprint := range rootSet(candidate) {
			pinned = pinned || (rootPin != "" && fingerprint == rootPin)
		}
		if !pinned {
			return errors.New("trust bundle has no root with the pinned fingerprint")
		}
		trusted = candidate.PublicKeys(now)
	}
	key, ok := trusted[candidate.Signature.KeyID]
	if !ok {
		return errors.New("trust bundle is signed by a key that is not trusted")
	}
	signature, err := base64.StdEncoding.DecodeString(candidate.Signature.Value)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return errors.New("trust bundle signature is malformed")
	}
	payload, err := candidate.payload()
	if err != nil {
		return err
	}
	if !ed25519.Verify(key, payload, signature) {
		return errors.New("trust bundle signature is invalid")
	}
	return nil
}
