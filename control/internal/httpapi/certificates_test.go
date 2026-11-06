package httpapi

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jfxdev/jolt/control/internal/config"
	"github.com/jfxdev/jolt/control/internal/pki"
	"github.com/jfxdev/jolt/control/internal/signedauth"
	"github.com/jfxdev/jolt/control/internal/store"
)

// managedAuthority builds an authority over its own database, so a test can
// hand it to a Control Tower the way main does.
func managedAuthority(t *testing.T) *pki.Manager {
	t.Helper()
	storage, err := store.Open(filepath.Join(t.TempDir(), "pki.db"), make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = storage.Close() })
	authority, err := pki.NewManager(storage, pki.Options{Key: make([]byte, 32), Names: []string{"control.lan"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := authority.Ensure(context.Background()); err != nil {
		t.Fatal(err)
	}
	return authority
}

func managedHarness(t *testing.T) (*typedHarness, *pki.Manager) {
	t.Helper()
	authority := managedAuthority(t)
	h := newTypedHarness(t, false, func(*http.Request) (int, http.Header, string) { return 404, nil, "{}" }, func(cfg *config.Config) {
		cfg.TLSMode, cfg.Authority, cfg.SigningSource = config.TLSManaged, authority, authority
		cfg.AuthorizationSigningKeyID, cfg.AuthorizationSigningKey = "", nil
	})
	return h, authority
}

var certificatePaths = []string{
	"/api/v1/control-tower/crypto/ca",
	"/api/v1/control-tower/crypto/trust-bundle",
	"/api/v1/control-tower/crypto/authorization-keys",
}

func TestAnAdminSeesTheInventoryWithoutAnySecret(t *testing.T) {
	h, authority := managedHarness(t)
	w := h.do("admin", http.MethodGet, certificatePaths[0], nil)
	if w.Code != http.StatusOK {
		t.Fatalf("inventory: %d %s", w.Code, w.Body)
	}
	var inventory struct {
		Mode          string     `json:"mode"`
		Fingerprint   string     `json:"root_fingerprint"`
		Display       string     `json:"root_fingerprint_display"`
		BundleVersion int64      `json:"bundle_version"`
		Items         []pki.Item `json:"items"`
	}
	decodeBody(t, w, &inventory)
	if inventory.Mode != "managed" || inventory.Fingerprint != authority.RootFingerprint() || inventory.BundleVersion != 1 || !strings.Contains(inventory.Display, ":") {
		t.Fatalf("inventory: %+v", inventory)
	}
	kinds := map[string]bool{}
	for _, item := range inventory.Items {
		kinds[item.Kind] = true
	}
	for _, kind := range []string{"root", "intermediate", "https", "signing_key"} {
		if !kinds[kind] {
			t.Errorf("missing %s: %+v", kind, inventory.Items)
		}
	}
	_, signing := authority.Current()
	for _, path := range certificatePaths {
		body := h.do("admin", http.MethodGet, path, nil).Body.String()
		if strings.Contains(body, "PRIVATE") || strings.Contains(body, string(signing.Seed())) {
			t.Errorf("%s leaks a private key", path)
		}
	}
}

func TestTheTrustBundleAndTheNodeYAMLAgreeWithTheAuthority(t *testing.T) {
	h, authority := managedHarness(t)
	var bundle pki.Bundle
	decodeBody(t, h.do("admin", http.MethodGet, certificatePaths[1], nil), &bundle)
	if err := pki.VerifyBundle(bundle, nil, authority.RootFingerprint(), time.Now()); err != nil {
		t.Fatalf("the served bundle does not verify: %v", err)
	}
	var keys struct {
		SigningKeyID string `json:"signing_key_id"`
		Keys         []struct {
			ID  string `json:"id"`
			Key string `json:"key"`
		} `json:"keys"`
		NodeYAML string `json:"node_yaml"`
	}
	decodeBody(t, h.do("admin", http.MethodGet, certificatePaths[2], nil), &keys)
	current, _ := authority.Current()
	if keys.SigningKeyID != current || len(keys.Keys) != len(bundle.SigningKeys) || len(keys.Keys) == 0 {
		t.Fatalf("keys: %+v", keys)
	}
	if !strings.HasPrefix(keys.NodeYAML, "authorization_public_keys:\n") {
		t.Fatalf("yaml: %q", keys.NodeYAML)
	}
	for _, key := range keys.Keys {
		if !strings.Contains(keys.NodeYAML, "  - id: "+key.ID+"\n    key: \""+key.Key+"\"\n") {
			t.Errorf("yaml lacks %s:\n%s", key.ID, keys.NodeYAML)
		}
	}
}

func TestOnlyAnAdministratorReadsTheAuthority(t *testing.T) {
	h, _ := managedHarness(t)
	for _, path := range certificatePaths {
		if w := h.do("operator", http.MethodGet, path, nil); w.Code != http.StatusForbidden {
			t.Errorf("operator %s: %d", path, w.Code)
		}
		w := httptest.NewRecorder()
		h.handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		if w.Code != http.StatusUnauthorized {
			t.Errorf("anonymous %s: %d", path, w.Code)
		}
		for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
			if w := h.do("admin", method, path, nil); w.Code < 400 {
				t.Errorf("%s %s changed something: %d", method, path, w.Code)
			}
		}
	}
}

func TestWithoutManagedTLSTheRoutesSayTheyAreOff(t *testing.T) {
	h := newTypedHarness(t, false, func(*http.Request) (int, http.Header, string) { return 404, nil, "{}" })
	for _, path := range certificatePaths {
		w := h.do("admin", http.MethodGet, path, nil)
		if w.Code != http.StatusNotFound || !strings.Contains(w.Body.String(), "managed_tls_disabled") {
			t.Errorf("%s: %d %s", path, w.Code, w.Body)
		}
	}
	var about struct {
		Features struct {
			ManagedTLS bool `json:"managed_tls"`
		} `json:"features"`
	}
	decodeBody(t, h.do("admin", http.MethodGet, "/api/v1/control-tower/about", nil), &about)
	if about.Features.ManagedTLS {
		t.Fatal("managed TLS reported on a manual Control Tower")
	}
	managed, _ := managedHarness(t)
	decodeBody(t, managed.do("admin", http.MethodGet, "/api/v1/control-tower/about", nil), &about)
	if !about.Features.ManagedTLS {
		t.Fatal("managed TLS not reported")
	}
}

func TestCertificateMetricsReportOnlyWhatIsInUse(t *testing.T) {
	authority := managedAuthority(t)
	storage, err := store.Open(filepath.Join(t.TempDir(), "control.db"), make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = storage.Close() })
	cfg := config.Config{EncryptionKey: make([]byte, 32), StaticDir: t.TempDir(), Authority: authority, SigningSource: authority, MetricsToken: "0123456789abcdef-token"}
	server, handler := newServerHandler(cfg, storage, slog.New(slog.NewTextHandler(io.Discard, nil)), &http.Client{})
	now := time.Now()
	server.refreshCertificateMetrics(now)
	request := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	request.Header.Set("Authorization", "Bearer "+cfg.MetricsToken)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, request)
	body := w.Body.String()
	for _, kind := range certificateKinds {
		if !strings.Contains(body, `jolt_certificate_expiry_seconds{kind="`+kind+`"}`) {
			t.Errorf("no series for %s:\n%s", kind, body)
		}
	}
	if !strings.Contains(body, "jolt_trust_bundle_version 1") {
		t.Errorf("no bundle version:\n%s", body)
	}
	// The root outlives the intermediate, which outlives the HTTPS leaf.
	var root, issuer, leaf float64
	for _, line := range strings.Split(body, "\n") {
		for kind, target := range map[string]*float64{"root": &root, "intermediate": &issuer, "https": &leaf} {
			if strings.HasPrefix(line, `jolt_certificate_expiry_seconds{kind="`+kind+`"} `) {
				_ = json.Unmarshal([]byte(strings.Fields(line)[1]), target)
			}
		}
	}
	if !(root > issuer && issuer > leaf && leaf > 80*24*3600 && leaf < 91*24*3600) {
		t.Errorf("remaining lifetimes root=%v intermediate=%v leaf=%v", root, issuer, leaf)
	}
}

type testClock struct{ now time.Time }

func (c *testClock) Now() time.Time { return c.now }

// TestASignedReadKeepsVerifyingAcrossARotationUsingOnlyWhatTheBundleCarried
// plays a node: it knows only the bundle chain it was sent, and every read the
// Control Tower signs, before and after the rotation, must verify with it.
func TestASignedReadKeepsVerifyingAcrossARotationUsingOnlyWhatTheBundleCarried(t *testing.T) {
	clock := &testClock{now: time.Now().UTC()}
	storage, err := store.Open(filepath.Join(t.TempDir(), "pki.db"), make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = storage.Close() })
	authority, err := pki.NewManager(storage, pki.Options{Key: make([]byte, 32), Now: clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	if err := authority.Ensure(context.Background()); err != nil {
		t.Fatal(err)
	}
	nodeBundle := authority.Bundle()
	var verified []string
	h := newTypedHarness(t, true, func(r *http.Request) (int, http.Header, string) {
		header := make(http.Header)
		header.Set("Content-Type", "application/json")
		if r.URL.Path == "/api/v1/node" {
			return 200, header, `{"node_id":"n1","capabilities":["signed_local_read_v1","signed_local_tree_read_v1"]}`
		}
		// Tokens are stamped with the real time; which keys the node trusts is
		// decided by the bundle at the simulated time.
		claims, _, err := signedauth.VerifyLocalRead(r.Header.Get(signedAuthorizationHeader), nodeBundle.PublicKeys(clock.now), "n1", signedReadOperation(strings.TrimPrefix(r.URL.Path, "/api/v1/"), r.Method), "m", ".", time.Now())
		if err != nil {
			t.Errorf("the node cannot verify what the Control Tower signed: %v", err)
			return 500, header, `{}`
		}
		verified = append(verified, claims.KeyID)
		header.Set("X-Jolt-Access-Applied", "v1")
		return 200, header, `{"items":[]}`
	}, func(cfg *config.Config) {
		cfg.Authority, cfg.SigningSource = authority, authority
		cfg.AuthorizationSigningKeyID, cfg.AuthorizationSigningKey = "", nil
	})
	read := func() {
		t.Helper()
		if w := h.do("admin", http.MethodGet, "/api/v1/nodes/n1/mounts/m/files", nil); w.Code != http.StatusOK {
			t.Fatalf("read: %d %s", w.Code, w.Body)
		}
	}
	step := func(d time.Duration) {
		clock.now = clock.now.Add(d)
		if err := authority.Ensure(context.Background()); err != nil {
			t.Fatal(err)
		}
		// The node adopts each bundle the way it must: only if it chains to the one it has.
		if next := authority.Bundle(); next.Version != nodeBundle.Version {
			if err := pki.VerifyBundle(next, &nodeBundle, "", clock.now); err != nil {
				t.Fatalf("node refuses bundle %d: %v", next.Version, err)
			}
			nodeBundle = next
		}
	}
	read()
	step(61 * 24 * time.Hour) // the successor is published
	read()
	step(7 * 24 * time.Hour) // and starts to sign
	read()
	step(7 * 24 * time.Hour) // the first key leaves
	read()
	if len(verified) != 4 || verified[0] == verified[2] || verified[2] != verified[3] || verified[0] != verified[1] {
		t.Fatalf("keys used across the rotation: %v", verified)
	}
}

func TestTheExpiryGaugeFollowsTheKeyInUseNotTheOneBeingRetired(t *testing.T) {
	clock := &testClock{now: time.Now().UTC()}
	storage, err := store.Open(filepath.Join(t.TempDir(), "pki.db"), make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = storage.Close() })
	authority, err := pki.NewManager(storage, pki.Options{Key: make([]byte, 32), Now: clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	for _, step := range []time.Duration{0, 61 * 24 * time.Hour, 7 * 24 * time.Hour} {
		clock.now = clock.now.Add(step)
		if err := authority.Ensure(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	// Day 68: the first key is retired and ends in 22 days; the one in use has 82.
	cfg := config.Config{EncryptionKey: make([]byte, 32), StaticDir: t.TempDir(), Authority: authority, SigningSource: authority, MetricsToken: "0123456789abcdef-token"}
	server, handler := newServerHandler(cfg, storage, slog.New(slog.NewTextHandler(io.Discard, nil)), &http.Client{})
	server.refreshCertificateMetrics(clock.now)
	request := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	request.Header.Set("Authorization", "Bearer "+cfg.MetricsToken)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, request)
	var remaining float64
	for _, line := range strings.Split(w.Body.String(), "\n") {
		if strings.HasPrefix(line, `jolt_certificate_expiry_seconds{kind="signing_key"} `) {
			_ = json.Unmarshal([]byte(strings.Fields(line)[1]), &remaining)
		}
	}
	if days := remaining / 86400; days < 80 || days > 83 {
		t.Fatalf("the gauge shows %.1f days; the key in use has about 82", days)
	}
}
