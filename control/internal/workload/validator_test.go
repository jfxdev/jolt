package workload

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

func signingKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func jwks(t *testing.T, id string, key *rsa.PrivateKey) []byte {
	t.Helper()
	data, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: id, Use: "sig", Algorithm: "RS256"}}})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func sign(t *testing.T, key *rsa.PrivateKey, id string, claims jwt.Claims) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, (&jose.SignerOptions{}).WithHeader("kid", id).WithType("JWT"))
	if err != nil {
		t.Fatal(err)
	}
	token, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func TestJWTClaimsSignatureAndJWKSRotation(t *testing.T) {
	first, second, other := signingKey(t), signingKey(t), signingKey(t)
	firstJWKS, secondJWKS := jwks(t, "first", first), jwks(t, "second", second)
	var mu sync.Mutex
	current, status, fetches := firstJWKS, http.StatusOK, 0
	issuer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		fetches++
		w.WriteHeader(status)
		_, _ = w.Write(current)
	}))
	defer issuer.Close()
	v, err := NewJWTValidator(JWTConfig{ProviderID: "local", Issuer: "issuer", Audience: "jolt", JWKSURL: issuer.URL, Algorithms: []string{"RS256"}})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	v.now = func() time.Time { return now }
	claims := jwt.Claims{Issuer: "issuer", Subject: "workload", Audience: jwt.Audience{"jolt"}, Expiry: jwt.NewNumericDate(now.Add(time.Hour))}
	token := sign(t, first, "first", claims)
	identity, err := v.Verify(context.Background(), token)
	if err != nil || identity.Subject != "workload" || identity.ProviderID != "local" || identity.Audience != "jolt" {
		t.Fatalf("identity=%+v err=%v", identity, err)
	}
	for _, tc := range []struct {
		name   string
		claims jwt.Claims
		key    *rsa.PrivateKey
	}{
		{"issuer", jwt.Claims{Issuer: "other", Subject: "workload", Audience: jwt.Audience{"jolt"}, Expiry: claims.Expiry}, first},
		{"subject", jwt.Claims{Issuer: "issuer", Audience: jwt.Audience{"jolt"}, Expiry: claims.Expiry}, first},
		{"audience", jwt.Claims{Issuer: "issuer", Subject: "workload", Audience: jwt.Audience{"other"}, Expiry: claims.Expiry}, first},
		{"missing expiry", jwt.Claims{Issuer: "issuer", Subject: "workload", Audience: jwt.Audience{"jolt"}}, first},
		{"expired exactly now", jwt.Claims{Issuer: "issuer", Subject: "workload", Audience: jwt.Audience{"jolt"}, Expiry: jwt.NewNumericDate(now)}, first},
		{"not yet valid", jwt.Claims{Issuer: "issuer", Subject: "workload", Audience: jwt.Audience{"jolt"}, Expiry: claims.Expiry, NotBefore: jwt.NewNumericDate(now.Add(time.Minute))}, first},
		{"invalid signature", claims, other},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := v.Verify(context.Background(), sign(t, tc.key, "first", tc.claims)); err == nil {
				t.Fatal("invalid token accepted")
			}
		})
	}
	mu.Lock()
	current = secondJWKS
	mu.Unlock()
	rotated := sign(t, second, "second", claims)
	if _, err := v.Verify(context.Background(), rotated); err == nil {
		t.Fatal("unknown key bypassed refresh rate limit")
	}
	mu.Lock()
	calls := fetches
	mu.Unlock()
	if calls != 1 {
		t.Fatalf("unknown key caused excessive refresh: %d", calls)
	}
	now = now.Add(11 * time.Second)
	if _, err := v.Verify(context.Background(), rotated); err != nil {
		t.Fatalf("rotated key rejected: %v", err)
	}
	mu.Lock()
	calls = fetches
	mu.Unlock()
	if calls != 2 {
		t.Fatalf("expected refresh after rotation, got %d", calls)
	}
	reusedJWKS := jwks(t, "second", first)
	mu.Lock()
	current = reusedJWKS
	mu.Unlock()
	now = now.Add(11 * time.Second)
	reusedID := sign(t, first, "second", claims)
	if _, err := v.Verify(context.Background(), reusedID); err != nil {
		t.Fatalf("key material changed under the same kid: %v", err)
	}
	if _, err := v.Verify(context.Background(), rotated); err == nil {
		t.Fatal("retired key accepted after refresh")
	}
	mu.Lock()
	status = http.StatusServiceUnavailable
	mu.Unlock()
	now = now.Add(6 * time.Minute)
	if _, err := v.Verify(context.Background(), reusedID); err == nil {
		t.Fatal("expired cache was used after refresh failure")
	}
}

func TestSVIDValidationUsesTrustDomainBundleAndStrictExpiry(t *testing.T) {
	key, other := signingKey(t), signingKey(t)
	bundle := jwks(t, "key", key)
	v, err := NewSVIDValidator("spiffe", "example.org", "jolt", bundle)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	valid := jwt.Claims{Subject: "spiffe://example.org/workload", Audience: jwt.Audience{"jolt"}, Expiry: jwt.NewNumericDate(now.Add(time.Hour))}
	identity, err := v.Verify(sign(t, key, "key", valid))
	if err != nil || identity.Subject != valid.Subject || identity.ProviderID != "spiffe" {
		t.Fatalf("identity=%+v err=%v", identity, err)
	}
	for _, tc := range []struct {
		name   string
		claims jwt.Claims
		key    *rsa.PrivateKey
		id     string
	}{
		{"wrong domain", jwt.Claims{Subject: "spiffe://other.org/workload", Audience: valid.Audience, Expiry: valid.Expiry}, key, "key"},
		{"invalid id", jwt.Claims{Subject: "not-spiffe", Audience: valid.Audience, Expiry: valid.Expiry}, key, "key"},
		{"wrong audience", jwt.Claims{Subject: valid.Subject, Audience: jwt.Audience{"other"}, Expiry: valid.Expiry}, key, "key"},
		{"missing expiry", jwt.Claims{Subject: valid.Subject, Audience: valid.Audience}, key, "key"},
		{"expired within library leeway", jwt.Claims{Subject: valid.Subject, Audience: valid.Audience, Expiry: jwt.NewNumericDate(now.Add(-10 * time.Second))}, key, "key"},
		{"wrong key", valid, other, "key"},
		{"wrong kid", valid, key, "other"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := v.Verify(sign(t, tc.key, tc.id, tc.claims)); err == nil {
				t.Fatal("invalid SVID accepted")
			}
		})
	}
}

func TestSVIDBundleRequiresAUsableAuthority(t *testing.T) {
	edPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rsaKey := signingKey(t)
	ed := jose.JSONWebKey{Key: edPublic, KeyID: "ed", Use: "sig", Algorithm: "EdDSA"}
	badEC := jose.JSONWebKey{Key: &ecKey.PublicKey, KeyID: "ec", Use: "sig", Algorithm: "ES384"}
	rsaAuthority := jose.JSONWebKey{Key: &rsaKey.PublicKey, KeyID: "rsa", Use: "sig", Algorithm: "RS256"}
	bundle := func(keys ...jose.JSONWebKey) []byte {
		t.Helper()
		encoded, err := json.Marshal(jose.JSONWebKeySet{Keys: keys})
		if err != nil {
			t.Fatal(err)
		}
		return encoded
	}
	for _, keys := range [][]jose.JSONWebKey{{ed}, {badEC}} {
		if _, err := NewSVIDValidator("provider", "example.org", "jolt", bundle(keys...)); err == nil {
			t.Fatal("bundle without a usable SVID authority accepted")
		}
	}
	v, err := NewSVIDValidator("provider", "example.org", "jolt", bundle(ed, badEC, rsaAuthority))
	if err != nil || len(v.keys) != 1 {
		t.Fatalf("mixed bundle: validator=%+v error=%v", v, err)
	}
	claims := jwt.Claims{Subject: "spiffe://example.org/workload", Audience: jwt.Audience{"jolt"}, Expiry: jwt.NewNumericDate(time.Now().Add(time.Minute))}
	if _, err := v.Verify(sign(t, rsaKey, "rsa", claims)); err != nil {
		t.Fatalf("usable authority rejected: %v", err)
	}
}

func TestUntrustedJWKSAndCompactTokenAreBounded(t *testing.T) {
	key := signingKey(t)
	set := jwks(t, "key", key)
	var decoded jose.JSONWebKeySet
	if err := json.Unmarshal(set, &decoded); err != nil {
		t.Fatal(err)
	}
	duplicate, _ := json.Marshal(jose.JSONWebKeySet{Keys: append(decoded.Keys, decoded.Keys...)})
	private, _ := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: key, KeyID: "key"}}})
	for _, data := range [][]byte{[]byte(`{"keys":[],"keys":[]}`), duplicate, private, []byte(`{"keys":[]}`)} {
		if _, err := parseKeys(data); err == nil {
			t.Fatal("invalid key set accepted")
		}
	}
	for _, raw := range []string{"", strings.Repeat("x", maxTokenBytes+1), "abc.def.ghi", "e30.e30.", "e30.e30.eA=="} {
		if validateCompactToken(raw) == nil {
			t.Fatalf("invalid token accepted: %q", raw[:min(len(raw), 20)])
		}
	}
	// Duplicate claims are forbidden even if a trusted key signed the token.
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","kid":"key"}`))
	body := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"a","sub":"b"}`))
	digest := sha256.Sum256([]byte(header + "." + body))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	if err := validateCompactToken(fmt.Sprintf("%s.%s.%s", header, body, base64.RawURLEncoding.EncodeToString(signature))); err == nil {
		t.Fatal("duplicate claims accepted")
	}
}

func TestJWKSRefreshIsBoundedAndSharedByConcurrentVerifications(t *testing.T) {
	key := signingKey(t)
	data := jwks(t, "key", key)
	var mu sync.Mutex
	requests := 0
	issuer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		requests++
		mu.Unlock()
		_, _ = w.Write(data)
	}))
	defer issuer.Close()
	v, err := NewJWTValidator(JWTConfig{ProviderID: "local", Issuer: "issuer", Audience: "jolt", JWKSURL: issuer.URL, Algorithms: []string{"RS256"}})
	if err != nil {
		t.Fatal(err)
	}
	claims := jwt.Claims{Issuer: "issuer", Subject: "workload", Audience: jwt.Audience{"jolt"}, Expiry: jwt.NewNumericDate(time.Now().Add(time.Hour))}
	token := sign(t, key, "key", claims)
	var wg sync.WaitGroup
	errs := make(chan error, 20)
	for range 20 {
		wg.Add(1)
		go func() { defer wg.Done(); _, err := v.Verify(context.Background(), token); errs <- err }()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent validation: %v", err)
		}
	}
	mu.Lock()
	total := requests
	mu.Unlock()
	if total != 1 {
		t.Fatalf("expected one JWKS request, got %d", total)
	}

	oversized := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("x", maxJWKSBytes+1)))
	}))
	defer oversized.Close()
	large, err := NewJWTValidator(JWTConfig{ProviderID: "local", Issuer: "issuer", Audience: "jolt", JWKSURL: oversized.URL, Algorithms: []string{"RS256"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := large.Verify(context.Background(), token); err == nil {
		t.Fatal("oversized JWKS accepted")
	}

	slow := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer slow.Close()
	timed, err := NewJWTValidator(JWTConfig{ProviderID: "local", Issuer: "issuer", Audience: "jolt", JWKSURL: slow.URL, Algorithms: []string{"RS256"}})
	if err != nil {
		t.Fatal(err)
	}
	timed.client.Timeout = 50 * time.Millisecond
	start := time.Now()
	if _, err := timed.Verify(context.Background(), token); err == nil || time.Since(start) > time.Second {
		t.Fatalf("JWKS timeout not enforced: %v", err)
	}
}

func TestRejectsUnsafeProviderSettings(t *testing.T) {
	base := JWTConfig{ProviderID: "provider", Issuer: "issuer", Audience: "jolt", JWKSURL: "https://example.test/keys", Algorithms: []string{"RS256"}}
	for _, mutate := range []func(*JWTConfig){
		func(c *JWTConfig) { c.Algorithms = []string{"HS256"} },
		func(c *JWTConfig) { c.Algorithms = []string{"none"} },
		func(c *JWTConfig) { c.Algorithms = []string{"RS256", "RS256"} },
		func(c *JWTConfig) { c.JWKSURL = "http://example.test/keys" },
		func(c *JWTConfig) { c.JWKSURL = "https://user:secret@example.test/keys" },
		func(c *JWTConfig) { c.Audience = "" },
	} {
		config := base
		mutate(&config)
		if _, err := NewJWTValidator(config); err == nil {
			t.Fatalf("unsafe settings accepted: %+v", config)
		}
	}
}
