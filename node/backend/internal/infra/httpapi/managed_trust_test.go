package httpapi

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jfxdev/jolt/backend/internal/entities"
	"github.com/jfxdev/jolt/backend/internal/infra/config"
	db "github.com/jfxdev/jolt/backend/internal/infra/state"
	"github.com/jfxdev/jolt/backend/internal/services/filesystem"
	"github.com/jfxdev/jolt/backend/internal/services/grants"
	"github.com/jfxdev/jolt/backend/internal/services/jobs"
	"github.com/jfxdev/jolt/backend/internal/services/pairing"
	"github.com/jfxdev/jolt/backend/internal/trust"
	"github.com/jfxdev/jolt/backend/internal/trust/trusttest"
)

const hash64 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

type managedNode struct {
	handler http.Handler
	trust   *trust.Manager
	ca      *trusttest.CA
	store   *db.Store
}

func newManagedNode(t *testing.T, enroll bool) *managedNode {
	t.Helper()
	return newManagedNodeIn(t, enroll, config.TLSManaged)
}

func newManagedNodeIn(t *testing.T, enroll bool, mode string) *managedNode {
	t.Helper()
	store, err := db.Open(filepath.Join(t.TempDir(), "state"), make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	ca := trusttest.New(t)
	manager, err := trust.Load(context.Background(), store, nil, func() time.Time { return trusttest.Epoch })
	if err != nil {
		t.Fatal(err)
	}
	if enroll {
		chain, der := ca.APIPair(t, "node.lan")
		if err := manager.Enroll(context.Background(), ca.Pin(), ca.Bundle(t, 1, "k1", nil, "k1"), chain, der, hash64); err != nil {
			t.Fatal(err)
		}
	}
	files := filesystem.New(store)
	identity := entities.Identity{NodeID: "n1"}
	cfg := config.Config{ControlTowerToken: "secret", NodeName: "test", APIAddress: ":0", MTLSAddress: ":0", TLSMode: mode}
	handler := New(cfg, identity, files, jobs.New(store, files), pairing.New(store, identity), grants.New(store, files),
		slog.New(slog.NewTextHandler(io.Discard, nil)), manager, store)
	return &managedNode{handler: handler, trust: manager, ca: ca, store: store}
}

func (n *managedNode) call(method, path string, body []byte, token string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, path, bytes.NewReader(body))
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	response := httptest.NewRecorder()
	n.handler.ServeHTTP(response, request)
	return response
}

func TestAnUnenrolledNodeHasNoManagedRoutesAndNoCapability(t *testing.T) {
	n := newManagedNode(t, false)
	for _, route := range [][2]string{{"GET", "/api/v1/crypto/trust-bundle"}, {"PUT", "/api/v1/crypto/trust-bundle"}, {"POST", "/api/v1/crypto/api-cert/csr"}, {"PUT", "/api/v1/crypto/api-cert"}} {
		if w := n.call(route[0], route[1], []byte("{}"), "secret"); w.Code != http.StatusNotFound && w.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s %s: %d %s", route[0], route[1], w.Code, w.Body)
		}
	}
	if w := n.call("GET", "/api/v1/node", nil, "secret"); strings.Contains(w.Body.String(), "managed_tls_v1") {
		t.Fatal("an unenrolled node advertises managed TLS")
	}
}

func TestAnEnrolledNodeAdvertisesManagedTLSAndNeedsTheToken(t *testing.T) {
	n := newManagedNode(t, true)
	if w := n.call("GET", "/api/v1/node", nil, "secret"); !strings.Contains(w.Body.String(), `"managed_tls_v1"`) || !strings.Contains(w.Body.String(), `"signed_local_read_v1"`) {
		t.Fatalf("capabilities: %s", w.Body)
	}
	for _, route := range [][2]string{{"GET", "/api/v1/crypto/trust-bundle"}, {"PUT", "/api/v1/crypto/trust-bundle"}, {"POST", "/api/v1/crypto/api-cert/csr"}, {"PUT", "/api/v1/crypto/api-cert"}} {
		if w := n.call(route[0], route[1], []byte("{}"), ""); w.Code != http.StatusUnauthorized {
			t.Errorf("%s %s without a token: %d", route[0], route[1], w.Code)
		}
		if w := n.call(route[0], route[1], []byte("{}"), "wrong"); w.Code != http.StatusUnauthorized {
			t.Errorf("%s %s with a wrong token: %d", route[0], route[1], w.Code)
		}
	}
}

func TestTheControlTowerCanReadWhatTheNodeHolds(t *testing.T) {
	n := newManagedNode(t, true)
	w := n.call("GET", "/api/v1/crypto/trust-bundle", nil, "secret")
	var status struct {
		Version     int64 `json:"bundle_version"`
		Certificate struct {
			NotAfter string `json:"not_after"`
			Serial   string `json:"serial"`
		} `json:"api_certificate"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &status) != nil || status.Version != 1 || status.Certificate.Serial == "" || status.Certificate.NotAfter == "" {
		t.Fatalf("status: %d %s", w.Code, w.Body)
	}
}

func TestANewerBundleIsAdoptedAndAnythingElseIsRefusedWithoutChange(t *testing.T) {
	n := newManagedNode(t, true)
	good, _ := n.ca.Bundle(t, 2, "k1", nil, "k1", "k2").Marshal()
	if w := n.call("PUT", "/api/v1/crypto/trust-bundle", good, "secret"); w.Code != 200 || n.trust.BundleVersion() != 2 {
		t.Fatalf("adopt: %d %s", w.Code, w.Body)
	}
	if n.trust.AuthorizationKeys()["k2"] == nil {
		t.Fatal("the new key is not trusted")
	}
	older, _ := n.ca.Bundle(t, 1, "k1", nil, "k1").Marshal()
	foreign, _ := trusttest.New(t).Bundle(t, 9, "k1", nil, "k1").Marshal()
	selfSigned, _ := n.ca.Bundle(t, 3, "k9", nil, "k1", "k9").Marshal()
	for name, body := range map[string][]byte{"older": older, "foreign authority": foreign, "signed by the key it adds": selfSigned} {
		if w := n.call("PUT", "/api/v1/crypto/trust-bundle", body, "secret"); w.Code != http.StatusUnprocessableEntity || !strings.Contains(w.Body.String(), "trust_bundle_refused") {
			t.Errorf("%s: %d %s", name, w.Code, w.Body)
		}
	}
	if n.trust.BundleVersion() != 2 {
		t.Fatal("a refused bundle changed the one in use")
	}
	for name, body := range map[string][]byte{"not json": []byte("nope"), "unknown field": []byte(`{"version":3,"surprise":1}`), "oversized": bytes.Repeat([]byte("a"), 300<<10)} {
		if w := n.call("PUT", "/api/v1/crypto/trust-bundle", body, "secret"); w.Code < 400 || w.Code >= 500 {
			t.Errorf("%s: %d", name, w.Code)
		}
	}
}

func TestRenewingTheAPICertificateOverHTTP(t *testing.T) {
	n := newManagedNode(t, true)
	body, _ := json.Marshal(map[string][]string{"names": {"node.lan", "10.0.0.4"}})
	w := n.call("POST", "/api/v1/crypto/api-cert/csr", body, "secret")
	var out struct {
		CSR string `json:"csr_pem"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &out) != nil {
		t.Fatalf("csr: %d %s", w.Code, w.Body)
	}
	block, _ := pem.Decode([]byte(out.CSR))
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil || csr.CheckSignature() != nil || csr.Subject.CommonName != "n1" {
		t.Fatalf("csr content: %v", err)
	}
	issued := n.ca.Leaf(t, csr.PublicKey, "n1", x509.ExtKeyUsageServerAuth, trusttest.Epoch.Add(90*24*time.Hour), "node.lan", "10.0.0.4")
	install, _ := json.Marshal(map[string]string{"certificate_pem": trusttest.PEM(issued, n.ca.Issuer)})
	if w := n.call("PUT", "/api/v1/crypto/api-cert", install, "secret"); w.Code != 200 {
		t.Fatalf("install: %d %s", w.Code, w.Body)
	}
	if _, serial := n.trust.CertificateEnd(); serial != issued.SerialNumber.Text(16) {
		t.Fatal("the renewed certificate is not in service")
	}
	// Nothing is pending any more.
	if w := n.call("PUT", "/api/v1/crypto/api-cert", install, "secret"); w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("second install: %d", w.Code)
	}
}

func TestCertificateNamesAreValidatedBeforeAnythingIsSigned(t *testing.T) {
	n := newManagedNode(t, true)
	tooMany := make([]string, 17)
	for i := range tooMany {
		tooMany[i] = "host.lan"
	}
	for name, names := range map[string][]string{
		"none": {}, "space": {"bad name"}, "slash": {"a/b"}, "url": {"https://x"}, "leading dash": {"-x.lan"}, "too many": tooMany, "empty": {""}, "long": {strings.Repeat("a", 300)},
	} {
		body, _ := json.Marshal(map[string][]string{"names": names})
		if w := n.call("POST", "/api/v1/crypto/api-cert/csr", body, "secret"); w.Code != http.StatusBadRequest {
			t.Errorf("%s: %d %s", name, w.Code, w.Body)
		}
	}
	for _, names := range [][]string{{"node.lan"}, {"10.0.0.1"}, {"::1"}, {"a.b-c.example"}} {
		body, _ := json.Marshal(map[string][]string{"names": names})
		if w := n.call("POST", "/api/v1/crypto/api-cert/csr", body, "secret"); w.Code != 200 {
			t.Errorf("%v: %d %s", names, w.Code, w.Body)
		}
	}
}

func TestAKeyFromTheBundleVerifiesASignedReadWithoutAnyYAMLKey(t *testing.T) {
	n := newManagedNode(t, true)
	keys := n.trust.AuthorizationKeys()
	if len(keys) != 1 || !keys["k1"].Equal(n.ca.SigningKey("k1").Public().(ed25519.PublicKey)) {
		t.Fatalf("keys: %v", keys)
	}
}

// asControlTower makes the request look as if it arrived on a connection whose
// client certificate the TLS layer verified for the given leaf.
func (n *managedNode) asControlTower(method, path string, leaf *x509.Certificate) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, path, nil)
	if leaf != nil {
		request.TLS = &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{leaf, n.ca.Issuer, n.ca.Root}}}
	}
	response := httptest.NewRecorder()
	n.handler.ServeHTTP(response, request)
	return response
}

func (n *managedNode) controlTowerLeaf(t *testing.T, name string, usage x509.ExtKeyUsage) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return n.ca.Leaf(t, &key.PublicKey, name, usage, trusttest.Epoch.Add(90*24*time.Hour))
}

func TestManagedOnlyAuthenticatesTheControlTowerByCertificateAndRefusesTheToken(t *testing.T) {
	n := newManagedNodeIn(t, true, config.TLSManagedOnly)
	leaf := n.controlTowerLeaf(t, trust.ControlTowerName, x509.ExtKeyUsageClientAuth)
	if w := n.asControlTower("GET", "/api/v1/node", leaf); w.Code != http.StatusOK {
		t.Fatalf("the certificate was refused: %d %s", w.Code, w.Body)
	}
	if w := n.asControlTower("GET", "/api/v1/crypto/trust-bundle", leaf); !strings.Contains(w.Body.String(), `"auth_mode":"certificate"`) {
		t.Fatalf("the node does not say it authenticates by certificate: %s", w.Body)
	}
	if w := newManagedNode(t, true).call("GET", "/api/v1/crypto/trust-bundle", nil, "secret"); !strings.Contains(w.Body.String(), `"auth_mode":"token"`) {
		t.Fatalf("a managed node does not say it authenticates by token: %s", w.Body)
	}
	// The token the node holds opens nothing, over a connection with no certificate or with one.
	if w := n.call("GET", "/api/v1/node", nil, "secret"); w.Code != http.StatusUnauthorized {
		t.Fatalf("the shared token was accepted: %d %s", w.Code, w.Body)
	}
	withToken := httptest.NewRequest("GET", "/api/v1/node", nil)
	withToken.Header.Set("Authorization", "Bearer secret")
	withToken.TLS = &tls.ConnectionState{}
	rec := httptest.NewRecorder()
	n.handler.ServeHTTP(rec, withToken)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("the token over TLS without a certificate: %d", rec.Code)
	}
	// A certificate with another name, or meant for a server, is nobody.
	for name, other := range map[string]*x509.Certificate{
		"another name": n.controlTowerLeaf(t, "Someone Else", x509.ExtKeyUsageClientAuth),
		"server usage": n.controlTowerLeaf(t, trust.ControlTowerName, x509.ExtKeyUsageServerAuth),
	} {
		if w := n.asControlTower("GET", "/api/v1/node", other); w.Code != http.StatusUnauthorized {
			t.Errorf("%s: %d", name, w.Code)
		}
	}
}

func TestManagedOnlyStopsAtOnceForACertificateTheBundleRevokes(t *testing.T) {
	n := newManagedNodeIn(t, true, config.TLSManagedOnly)
	leaf := n.controlTowerLeaf(t, trust.ControlTowerName, x509.ExtKeyUsageClientAuth)
	if w := n.asControlTower("GET", "/api/v1/node", leaf); w.Code != http.StatusOK {
		t.Fatalf("before: %d", w.Code)
	}
	revoked, _ := n.ca.Bundle(t, 2, "k1", []string{leaf.SerialNumber.Text(16)}, "k1").Marshal()
	if w := n.asControlTower("PUT", "/api/v1/crypto/trust-bundle", leaf); w.Code != http.StatusBadRequest {
		t.Fatalf("a push with no body should be refused for its content, not its caller: %d", w.Code)
	}
	request := httptest.NewRequest("PUT", "/api/v1/crypto/trust-bundle", bytes.NewReader(revoked))
	request.TLS = &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{leaf, n.ca.Issuer, n.ca.Root}}}
	rec := httptest.NewRecorder()
	n.handler.ServeHTTP(rec, request)
	if rec.Code != http.StatusOK {
		t.Fatalf("the push of the revocation: %d %s", rec.Code, rec.Body)
	}
	if w := n.asControlTower("GET", "/api/v1/node", leaf); w.Code != http.StatusUnauthorized {
		t.Fatalf("a revoked certificate still authenticates: %d", w.Code)
	}
}

func TestManagedOnlyHasNoOperationalTokenToRotateButManagedStillDoes(t *testing.T) {
	only := newManagedNodeIn(t, true, config.TLSManagedOnly)
	leaf := only.controlTowerLeaf(t, trust.ControlTowerName, x509.ExtKeyUsageClientAuth)
	for _, route := range []string{"/api/v1/crypto/operational-token/prepare", "/api/v1/crypto/operational-token/commit"} {
		if w := only.asControlTower("POST", route, leaf); w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "operational_token_disabled") {
			t.Errorf("%s: %d %s", route, w.Code, w.Body)
		}
	}
	plain := newManagedNode(t, true)
	if w := plain.call("POST", "/api/v1/crypto/operational-token/prepare", []byte(`{"new_token":"short"}`), "secret"); w.Code != http.StatusBadRequest {
		t.Fatalf("managed mode lost its token rotation: %d %s", w.Code, w.Body)
	}
}

func TestManagedOnlyDoesNotChangeANodeThatWasNeverEnrolled(t *testing.T) {
	n := newManagedNodeIn(t, false, config.TLSManagedOnly)
	if w := n.call("GET", "/api/v1/node", nil, "secret"); w.Code != http.StatusOK {
		t.Fatalf("an unenrolled node stopped taking its token: %d", w.Code)
	}
}
