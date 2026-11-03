package workload

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4/jwt"
)

func TestProviderFileDispatchesVerifiedJWTAndSVID(t *testing.T) {
	key := signingKey(t)
	bundle := jwks(t, "key", key)
	issuer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(bundle) }))
	defer issuer.Close()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "bundle.json"), bundle, 0600); err != nil {
		t.Fatal(err)
	}
	definitions := providerDocument{Version: 1, Providers: []providerDefinition{
		{ID: "oidc", Type: "jwt", Issuer: "issuer", Audience: "app", JWKSURL: issuer.URL, Algorithms: []string{"RS256"}},
		{ID: "spire", Type: "jwt_svid", TrustDomain: "example.org", Audience: "spire-audience", BundleFile: "bundle.json"},
	}}
	data, err := json.Marshal(definitions)
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "providers.json")
	if err := os.WriteFile(file, data, 0600); err != nil {
		t.Fatal(err)
	}
	providers, err := LoadProviders(file)
	if err != nil {
		t.Fatal(err)
	}
	expires := jwt.NewNumericDate(time.Now().Add(time.Hour))
	jwtToken := sign(t, key, "key", jwt.Claims{Issuer: "issuer", Subject: "account", Audience: jwt.Audience{"app"}, Expiry: expires})
	jwtIdentity, err := providers.Verify(context.Background(), jwtToken)
	if err != nil || jwtIdentity.ProviderID != "oidc" || jwtIdentity.Subject != "account" || jwtIdentity.Issuer != "issuer" {
		t.Fatalf("JWT identity=%+v err=%v", jwtIdentity, err)
	}
	svidToken := sign(t, key, "key", jwt.Claims{Subject: "spiffe://example.org/service", Audience: jwt.Audience{"spire-audience"}, Expiry: expires})
	svidIdentity, err := providers.Verify(context.Background(), svidToken)
	if err != nil || svidIdentity.ProviderID != "spire" || svidIdentity.Subject != "spiffe://example.org/service" || svidIdentity.Issuer != "" {
		t.Fatalf("SVID identity=%+v err=%v", svidIdentity, err)
	}
	ambiguous := sign(t, key, "key", jwt.Claims{Issuer: "issuer", Subject: "spiffe://example.org/service", Audience: jwt.Audience{"app", "spire-audience"}, Expiry: expires})
	if _, err := providers.Verify(context.Background(), ambiguous); err == nil {
		t.Fatal("ambiguous provider selection accepted")
	}
	unmapped := sign(t, key, "key", jwt.Claims{Issuer: "other", Subject: "account", Audience: jwt.Audience{"app"}, Expiry: expires})
	if _, err := providers.Verify(context.Background(), unmapped); err == nil {
		t.Fatal("unknown issuer accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := providers.Verify(ctx, jwtToken); err == nil {
		t.Fatal("canceled verification accepted")
	}
}

func TestProviderFileRejectsAmbiguousOrInvalidConfiguration(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "providers.json")
	valid := providerDefinition{ID: "one", Type: "jwt", Issuer: "issuer", Audience: "jolt", JWKSURL: "https://issuer.example/keys", Algorithms: []string{"RS256"}}
	second := valid
	second.ID = "two"
	for _, tc := range []struct {
		name string
		data []byte
	}{
		{"duplicate route", mustJSON(t, providerDocument{Version: 1, Providers: []providerDefinition{valid, second}})},
		{"duplicate id", mustJSON(t, providerDocument{Version: 1, Providers: []providerDefinition{valid, valid}})},
		{"unknown field", []byte(`{"version":1,"providers":[{"id":"x","type":"jwt","issuer":"i","audience":"a","jwks_url":"https://example.org","algorithms":["RS256"],"unexpected":true}]}`)},
		{"duplicate field", []byte(`{"version":1,"version":1,"providers":[]}`)},
		{"wrong version", mustJSON(t, providerDocument{Version: 2, Providers: []providerDefinition{valid}})},
		{"missing bundle", mustJSON(t, providerDocument{Version: 1, Providers: []providerDefinition{{ID: "s", Type: "jwt_svid", TrustDomain: "example.org", Audience: "jolt", BundleFile: "missing"}}})},
		{"oversized", []byte(strings.Repeat(" ", maxProviderFileBytes+1))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.WriteFile(file, tc.data, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadProviders(file); err == nil {
				t.Fatal("invalid provider file accepted")
			}
		})
	}
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
