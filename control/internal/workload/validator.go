// Package workload validates workload tokens. It is not connected to HTTP
// authentication until durable credential mappings and agent controls exist.
package workload

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
	"unicode"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/jfxdev/jolt/control/internal/filetypes"
	"github.com/spiffe/go-spiffe/v2/bundle/jwtbundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
)

const maxTokenBytes = 16 << 10
const maxJWKSBytes = 1 << 20
const maxKeys = 64

var ErrInvalid = errors.New("invalid workload identity")

// Identity contains verified claims only, never the raw token.
type Identity struct {
	ProviderID string
	Issuer     string
	Subject    string
	Audience   string
	ExpiresAt  time.Time
}

type JWTConfig struct {
	ProviderID string
	Issuer     string
	Audience   string
	JWKSURL    string
	Algorithms []string
}

type JWTValidator struct {
	config               JWTConfig
	algorithms           []jose.SignatureAlgorithm
	client               *http.Client
	now                  func() time.Time
	mu                   sync.Mutex
	keys                 map[string]jose.JSONWebKey
	expires, lastAttempt time.Time
}

// NewJWTValidator accepts only asymmetric algorithms and an HTTPS JWKS URL,
// with plaintext permitted solely for a local loopback test issuer.
func NewJWTValidator(config JWTConfig) (*JWTValidator, error) {
	if !identityField(config.ProviderID) || !identityField(config.Issuer) || !identityField(config.Audience) || len(config.Algorithms) == 0 || len(config.Algorithms) > 10 {
		return nil, ErrInvalid
	}
	endpoint, err := url.Parse(config.JWKSURL)
	if err != nil || endpoint.Host == "" || endpoint.User != nil || endpoint.Fragment != "" {
		return nil, ErrInvalid
	}
	host := endpoint.Hostname()
	ip := net.ParseIP(host)
	if endpoint.Scheme != "https" && !(endpoint.Scheme == "http" && (strings.EqualFold(host, "localhost") || ip != nil && ip.IsLoopback())) {
		return nil, ErrInvalid
	}
	seen := map[string]bool{}
	var algorithms []jose.SignatureAlgorithm
	for _, algorithm := range config.Algorithms {
		switch jose.SignatureAlgorithm(algorithm) {
		case jose.RS256, jose.RS384, jose.RS512, jose.PS256, jose.PS384, jose.PS512, jose.ES256, jose.ES384, jose.ES512, jose.EdDSA:
		default:
			return nil, ErrInvalid
		}
		if seen[algorithm] {
			return nil, ErrInvalid
		}
		seen[algorithm] = true
		algorithms = append(algorithms, jose.SignatureAlgorithm(algorithm))
	}
	return &JWTValidator{config: config, algorithms: algorithms, now: time.Now, client: &http.Client{Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

func (v *JWTValidator) Verify(ctx context.Context, token string) (Identity, error) {
	if err := validateCompactToken(token); err != nil {
		return Identity{}, ErrInvalid
	}
	parsed, err := jwt.ParseSigned(token, v.algorithms)
	if err != nil || len(parsed.Headers) != 1 || !identityField(parsed.Headers[0].KeyID) {
		return Identity{}, ErrInvalid
	}
	header := parsed.Headers[0]
	key, err := v.key(ctx, header.KeyID, false)
	if err != nil {
		return Identity{}, ErrInvalid
	}
	var claims jwt.Claims
	if key.Algorithm != "" && key.Algorithm != header.Algorithm || parsed.Claims(key.Key, &claims) != nil {
		// Issuers sometimes replace key material without changing kid. Refresh
		// at most once per interval and verify again before checking claims.
		key, err = v.key(ctx, header.KeyID, true)
		claims = jwt.Claims{}
		if err != nil || key.Algorithm != "" && key.Algorithm != header.Algorithm || parsed.Claims(key.Key, &claims) != nil {
			return Identity{}, ErrInvalid
		}
	}
	if !validClaims(claims, v.config.Issuer, v.config.Audience, v.now()) {
		return Identity{}, ErrInvalid
	}
	return Identity{ProviderID: v.config.ProviderID, Issuer: claims.Issuer, Subject: claims.Subject, Audience: v.config.Audience, ExpiresAt: claims.Expiry.Time().UTC()}, nil
}

func (v *JWTValidator) key(ctx context.Context, id string, force bool) (jose.JSONWebKey, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	now := v.now()
	if key, ok := v.keys[id]; ok && now.Before(v.expires) && !force {
		return key, nil
	}
	// Unknown keys and failed refreshes cannot trigger a fetch more than once
	// per 10 seconds. An expired cache is never used after a refresh failure.
	if !v.lastAttempt.IsZero() && now.Sub(v.lastAttempt) < 10*time.Second {
		if key, ok := v.keys[id]; force && ok && now.Before(v.expires) {
			return key, nil
		}
		return jose.JSONWebKey{}, ErrInvalid
	}
	v.lastAttempt = now
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.config.JWKSURL, nil)
	if err != nil {
		return jose.JSONWebKey{}, ErrInvalid
	}
	response, err := v.client.Do(req)
	if err != nil {
		return jose.JSONWebKey{}, ErrInvalid
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return jose.JSONWebKey{}, ErrInvalid
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, maxJWKSBytes+1))
	if err != nil || len(data) > maxJWKSBytes {
		return jose.JSONWebKey{}, ErrInvalid
	}
	keys, err := parseKeys(data)
	if err != nil {
		return jose.JSONWebKey{}, ErrInvalid
	}
	v.keys, v.expires = keys, now.Add(5*time.Minute)
	key, ok := keys[id]
	if !ok {
		return jose.JSONWebKey{}, ErrInvalid
	}
	return key, nil
}

// SVIDValidator uses the Go SPIFFE validator and a trust-domain-specific JWT
// bundle, then applies strict expiration without the library's default leeway.
type SVIDValidator struct {
	providerID, audience string
	trustDomain          spiffeid.TrustDomain
	bundle               *jwtbundle.Bundle
	keys                 map[string]jose.JSONWebKey
}

func NewSVIDValidator(providerID, trustDomain, audience string, bundleJSON []byte) (*SVIDValidator, error) {
	if !identityField(providerID) || !identityField(audience) || len(bundleJSON) == 0 || len(bundleJSON) > maxJWKSBytes {
		return nil, ErrInvalid
	}
	td, err := spiffeid.TrustDomainFromString(trustDomain)
	if err != nil {
		return nil, ErrInvalid
	}
	keys, err := parseKeys(bundleJSON)
	if err != nil {
		return nil, ErrInvalid
	}
	bundle := jwtbundle.New(td)
	usable := make(map[string]jose.JSONWebKey, len(keys))
	for id, key := range keys {
		// go-spiffe's JWT-SVID parser accepts RSA, RSA-PSS and ECDSA,
		// but not EdDSA. Ignore unusable keys in mixed bundles and fail
		// provider loading if no usable authority remains.
		if !usableSVIDKey(key) {
			continue
		}
		if err := bundle.AddJWTAuthority(id, key.Key); err != nil {
			return nil, ErrInvalid
		}
		usable[id] = key
	}
	if len(usable) == 0 {
		return nil, ErrInvalid
	}
	return &SVIDValidator{providerID: providerID, audience: audience, trustDomain: td, bundle: bundle, keys: usable}, nil
}

func usableSVIDKey(key jose.JSONWebKey) bool {
	switch public := key.Key.(type) {
	case *rsa.PublicKey:
		switch key.Algorithm {
		case "", "RS256", "RS384", "RS512", "PS256", "PS384", "PS512":
			return true
		}
	case *ecdsa.PublicKey:
		return key.Algorithm == "" || public.Curve == elliptic.P256() && key.Algorithm == "ES256" || public.Curve == elliptic.P384() && key.Algorithm == "ES384" || public.Curve == elliptic.P521() && key.Algorithm == "ES512"
	}
	return false
}

func (v *SVIDValidator) Verify(token string) (Identity, error) {
	if err := validateCompactToken(token); err != nil {
		return Identity{}, ErrInvalid
	}
	parts := strings.Split(token, ".")
	headerBytes, err := base64.RawURLEncoding.Strict().DecodeString(parts[0])
	var header struct {
		KeyID     string `json:"kid"`
		Algorithm string `json:"alg"`
	}
	if err != nil || json.Unmarshal(headerBytes, &header) != nil {
		return Identity{}, ErrInvalid
	}
	key, ok := v.keys[header.KeyID]
	if !ok || key.Algorithm != "" && key.Algorithm != header.Algorithm {
		return Identity{}, ErrInvalid
	}
	result, err := jwtsvid.ParseAndValidate(token, v.bundle, []string{v.audience})
	if err != nil || result.ID.TrustDomain() != v.trustDomain {
		return Identity{}, ErrInvalid
	}
	data, err := base64.RawURLEncoding.Strict().DecodeString(parts[1])
	var claims jwt.Claims
	if err != nil || json.Unmarshal(data, &claims) != nil || !validClaims(claims, "", v.audience, time.Now()) {
		return Identity{}, ErrInvalid
	}
	return Identity{ProviderID: v.providerID, Subject: result.ID.String(), Audience: v.audience, ExpiresAt: result.Expiry.UTC()}, nil
}

func validClaims(claims jwt.Claims, issuer, audience string, now time.Time) bool {
	return identityField(claims.Subject) && claims.Expiry != nil && claims.Expiry.Time().After(now) && claims.ValidateWithLeeway(jwt.Expected{Issuer: issuer, AnyAudience: jwt.Audience{audience}, Time: now}, 0) == nil
}

func validateCompactToken(token string) error {
	if len(token) == 0 || len(token) > maxTokenBytes {
		return ErrInvalid
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return ErrInvalid
	}
	for index, part := range parts {
		data, err := base64.RawURLEncoding.Strict().DecodeString(part)
		if err != nil || len(data) == 0 || index < 2 && filetypes.ValidateUniqueJSON(data) != nil {
			return ErrInvalid
		}
	}
	return nil
}

func identityField(value string) bool {
	if value == "" || len(value) > 2048 || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func parseKeys(data []byte) (map[string]jose.JSONWebKey, error) {
	var set jose.JSONWebKeySet
	if filetypes.ValidateUniqueJSON(data) != nil || json.Unmarshal(data, &set) != nil || len(set.Keys) == 0 || len(set.Keys) > maxKeys {
		return nil, ErrInvalid
	}
	keys := make(map[string]jose.JSONWebKey)
	for _, key := range set.Keys {
		if !key.Valid() || !key.IsPublic() {
			return nil, ErrInvalid
		}
		if key.Use != "" && key.Use != "sig" {
			continue
		}
		if !identityField(key.KeyID) {
			return nil, ErrInvalid
		}
		switch public := key.Key.(type) {
		case *rsa.PublicKey:
			if public.N.BitLen() < 2048 {
				return nil, ErrInvalid
			}
		case *ecdsa.PublicKey:
			if public.Curve != elliptic.P256() && public.Curve != elliptic.P384() && public.Curve != elliptic.P521() {
				return nil, ErrInvalid
			}
		case ed25519.PublicKey:
			if len(public) != ed25519.PublicKeySize {
				return nil, ErrInvalid
			}
		default:
			return nil, ErrInvalid
		}
		if _, exists := keys[key.KeyID]; exists {
			return nil, ErrInvalid
		}
		keys[key.KeyID] = key
	}
	if len(keys) == 0 {
		return nil, ErrInvalid
	}
	return keys, nil
}
