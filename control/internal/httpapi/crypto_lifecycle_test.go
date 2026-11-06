package httpapi

import (
	"context"
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
	"github.com/jfxdev/jolt/control/internal/security"
	"github.com/jfxdev/jolt/control/internal/store"
)

const cryptoBase = "/api/v1/control-tower/crypto/"

func serialOf(authority *pki.Manager, kind, state string) string {
	for _, item := range authority.Inventory() {
		if item.Kind == kind && (state == "" || item.State == state) {
			return item.Serial
		}
	}
	return ""
}

// managedRecord gives the harness an enrolled node the way enrollment would.
func managedRecord(t *testing.T, h *enrollHarness, id, serial string, bundle int64) {
	t.Helper()
	sealed, _ := security.Encrypt(make([]byte, 32), "token")
	now := time.Now().UTC()
	if err := h.storage.SaveNode(context.Background(), store.Node{ID: id, Name: id + "-name", Endpoint: "https://" + id + ".lan:8080", TokenEncrypted: sealed, State: "online", CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := h.storage.SaveManagedNode(context.Background(), store.ManagedNode{NodeID: id, EnrolledAt: now, BundleVersion: bundle, CertSerial: serial, CertNotBefore: now, CertNotAfter: now.Add(80 * 24 * time.Hour)}); err != nil {
		t.Fatal(err)
	}
}

func TestOnlyAnAdministratorRevokesRotatesOrPromotes(t *testing.T) {
	h := newEnrollHarness(t)
	routes := []struct{ method, path string }{
		{"GET", cryptoBase + "revocations"},
		{"POST", cryptoBase + "revocations"},
		{"POST", cryptoBase + "ca/intermediate/rotate"},
		{"POST", cryptoBase + "ca/root/rotate"},
		{"POST", cryptoBase + "ca/root/promote"},
	}
	version := h.authority.Bundle().Version
	for _, route := range routes {
		if w := h.do("operator", route.method, route.path, map[string]any{"serial": "ab"}); w.Code != http.StatusForbidden {
			t.Errorf("operator %s %s: %d", route.method, route.path, w.Code)
		}
		w := httptest.NewRecorder()
		h.handler.ServeHTTP(w, httptest.NewRequest(route.method, route.path, strings.NewReader(`{}`)))
		if w.Code != http.StatusUnauthorized {
			t.Errorf("anonymous %s %s: %d", route.method, route.path, w.Code)
		}
	}
	if h.authority.Bundle().Version != version {
		t.Fatal("a refused request changed the bundle")
	}
}

func TestRevokingANodeByNameOrByTheSerialOfAnythingIssued(t *testing.T) {
	h := newEnrollHarness(t)
	managedRecord(t, h, "n1", "beef01", 1)
	before := h.authority.Bundle().Version
	// Unknown serials fill nothing.
	if w := h.do("admin", "POST", cryptoBase+"revocations", map[string]any{"serial": "deadbeef"}); w.Code != http.StatusNotFound || !strings.Contains(w.Body.String(), "unknown_certificate") {
		t.Fatalf("unknown: %d %s", w.Code, w.Body)
	}
	for name, body := range map[string]map[string]any{
		"both":    {"serial": "beef01", "node_id": "n1"},
		"neither": {},
		"long":    {"serial": "beef01", "reason": strings.Repeat("x", 201)},
	} {
		if w := h.do("admin", "POST", cryptoBase+"revocations", body); w.Code != http.StatusBadRequest {
			t.Errorf("%s: %d %s", name, w.Code, w.Body)
		}
	}
	if w := h.do("admin", "POST", cryptoBase+"revocations", map[string]any{"node_id": "ghost"}); w.Code != http.StatusNotFound {
		t.Errorf("a node nobody enrolled: %d", w.Code)
	}
	if h.authority.Bundle().Version != before {
		t.Fatal("a refusal changed the bundle")
	}
	w := h.do("admin", "POST", cryptoBase+"revocations", map[string]any{"node_id": "n1", "reason": "disk stolen"})
	if w.Code != http.StatusOK || !h.authority.Bundle().Revoked("beef01") || h.authority.Bundle().Version != before+1 {
		t.Fatalf("revoke by node: %d %s", w.Code, w.Body)
	}
	// By serial of something the Control Tower itself uses.
	https := serialOf(h.authority, "https", "")
	if w := h.do("admin", "POST", cryptoBase+"revocations", map[string]any{"serial": strings.ToUpper(https)}); w.Code != http.StatusOK || !h.authority.Bundle().Revoked(https) {
		t.Fatalf("revoke by serial: %d %s", w.Code, w.Body)
	}
	var list struct {
		Items []pki.Revocation `json:"items"`
	}
	decodeBody(t, h.do("admin", "GET", cryptoBase+"revocations", nil), &list)
	if len(list.Items) != 2 {
		t.Fatalf("list: %+v", list.Items)
	}
	found := false
	for _, item := range list.Items {
		found = found || (item.Serial == "beef01" && item.Reason == "disk stolen" && item.Subject == "node n1")
	}
	if !found {
		t.Fatalf("the node's revocation is not described: %+v", list.Items)
	}
}

func TestARootAndTheIntermediateInUseAreNotRevokedByHand(t *testing.T) {
	h := newEnrollHarness(t)
	if w := h.do("admin", "POST", cryptoBase+"revocations", map[string]any{"serial": serialOf(h.authority, "root", "")}); w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "root_not_revocable") {
		t.Errorf("root: %d %s", w.Code, w.Body)
	}
	if w := h.do("admin", "POST", cryptoBase+"revocations", map[string]any{"serial": serialOf(h.authority, "intermediate", "active")}); w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "use_rotation") {
		t.Errorf("intermediate: %d %s", w.Code, w.Body)
	}
}

func TestRotatingTheIntermediateOverHTTP(t *testing.T) {
	h := newEnrollHarness(t)
	if w := h.do("admin", "POST", cryptoBase+"ca/intermediate/rotate", map[string]any{}); w.Code != http.StatusOK {
		t.Fatalf("planned: %d %s", w.Code, w.Body)
	}
	if _, issuers, _ := h.authority.Bundle().Certificates(); len(issuers) != 2 {
		t.Fatalf("planned rotation: %d intermediates", len(issuers))
	}
	if w := h.do("admin", "POST", cryptoBase+"ca/intermediate/rotate", map[string]any{}); w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "intermediate_limit") {
		t.Fatalf("third: %d %s", w.Code, w.Body)
	}
	if w := h.do("admin", "POST", cryptoBase+"ca/intermediate/rotate", map[string]any{"revoke_previous": true, "reason": "leaked"}); w.Code != http.StatusOK {
		t.Fatalf("revoking: %d %s", w.Code, w.Body)
	}
	bundle := h.authority.Bundle()
	if _, issuers, _ := bundle.Certificates(); len(issuers) != 1 || len(bundle.RevokedSerials) != 2 {
		t.Fatalf("after revoking: %d intermediates, %d revoked", len(issuers), len(bundle.RevokedSerials))
	}
}

// withoutRootKey is the database as it is after the root key was exported.
type withoutRootKey struct{ *store.Store }

func (w withoutRootKey) ListPKIObjects(ctx context.Context) ([]store.PKIObject, error) {
	objects, err := w.Store.ListPKIObjects(ctx)
	for i := range objects {
		if objects[i].Kind == store.PKIRoot {
			objects[i].Secret = ""
		}
	}
	return objects, err
}

func TestAnIntermediateRotationWithoutTheRootKeyExplainsHowToBringItBack(t *testing.T) {
	pkiStore, err := store.Open(filepath.Join(t.TempDir(), "pki.db"), make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pkiStore.Close() })
	full, err := pki.NewManager(pkiStore, pki.Options{Key: make([]byte, 32)})
	if err != nil {
		t.Fatal(err)
	}
	if err := full.Ensure(context.Background()); err != nil {
		t.Fatal(err)
	}
	exported, err := pki.NewManager(withoutRootKey{pkiStore}, pki.Options{Key: make([]byte, 32)})
	if err != nil {
		t.Fatal(err)
	}
	if err := exported.Ensure(context.Background()); err != nil {
		t.Fatal(err)
	}
	h := newEnrollHarness(t, func(cfg *config.Config) { cfg.Authority, cfg.SigningSource = exported, exported })
	w := h.do("admin", "POST", cryptoBase+"ca/intermediate/rotate", map[string]any{})
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "root_unavailable") || !strings.Contains(w.Body.String(), "ca import-root") {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if w := h.do("admin", "POST", cryptoBase+"ca/root/rotate", nil); w.Code != http.StatusAccepted {
		t.Fatalf("a new root needs no old key, but got %d %s", w.Code, w.Body)
	}
}

func TestAPromotionWaitsForEveryNodeToHoldTheBundleWithTheNewRoot(t *testing.T) {
	h := newEnrollHarness(t)
	if w := h.do("admin", "POST", cryptoBase+"ca/root/promote", map[string]any{}); w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "no_rotation_prepared") {
		t.Fatalf("promote with nothing prepared: %d %s", w.Code, w.Body)
	}
	if w := h.do("admin", "POST", cryptoBase+"ca/root/rotate", nil); w.Code != http.StatusAccepted {
		t.Fatalf("begin: %d %s", w.Code, w.Body)
	}
	if w := h.do("admin", "POST", cryptoBase+"ca/root/rotate", nil); w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "rotation_busy") {
		t.Fatalf("begin twice: %d %s", w.Code, w.Body)
	}
	current := h.authority.Bundle().Version
	managedRecord(t, h, "slow", "aa01", current-1)
	managedRecord(t, h, "ready", "aa02", current)
	w := h.do("admin", "POST", cryptoBase+"ca/root/promote", map[string]any{})
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "nodes_behind") || !strings.Contains(w.Body.String(), "slow") || strings.Contains(w.Body.String(), "ready") {
		t.Fatalf("promote with a node behind: %d %s", w.Code, w.Body)
	}
	if h.authority.Rotation().Phase != "prepared" {
		t.Fatal("a refused promotion moved the rotation")
	}
	if w := h.do("admin", "POST", cryptoBase+"ca/root/promote", map[string]any{"force": true}); w.Code != http.StatusOK || h.authority.Rotation().Phase != "promoted" {
		t.Fatalf("forced promote: %d %s", w.Code, w.Body)
	}
}

func TestTheInventoryShowsTheRotationAndEveryEnrolledNode(t *testing.T) {
	h := newEnrollHarness(t)
	managedRecord(t, h, "n1", "aa01", 1)
	_ = h.authority.BeginRootRotation(context.Background())
	var inventory struct {
		Rotation pki.Rotation  `json:"rotation"`
		Next     string        `json:"next_root_fingerprint_display"`
		Nodes    []nodeCertRow `json:"nodes"`
	}
	decodeBody(t, h.do("admin", "GET", cryptoBase+"ca", nil), &inventory)
	if inventory.Rotation.Phase != "prepared" || !strings.Contains(inventory.Next, ":") {
		t.Fatalf("rotation: %+v %q", inventory.Rotation, inventory.Next)
	}
	if len(inventory.Nodes) != 1 || inventory.Nodes[0].Name != "n1-name" || inventory.Nodes[0].BundleBehind != h.authority.Bundle().Version-1 || inventory.Nodes[0].CertSerial != "aa01" {
		t.Fatalf("nodes: %+v", inventory.Nodes)
	}
}

func TestTheMetricSaysWhenTheRootKeyLeftTheDatabase(t *testing.T) {
	pkiStore, err := store.Open(filepath.Join(t.TempDir(), "pki.db"), make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pkiStore.Close() })
	full, _ := pki.NewManager(pkiStore, pki.Options{Key: make([]byte, 32)})
	if err := full.Ensure(context.Background()); err != nil {
		t.Fatal(err)
	}
	exported, _ := pki.NewManager(withoutRootKey{pkiStore}, pki.Options{Key: make([]byte, 32)})
	if err := exported.Ensure(context.Background()); err != nil {
		t.Fatal(err)
	}
	storage, err := store.Open(filepath.Join(t.TempDir(), "control.db"), make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = storage.Close() })
	cfg := config.Config{EncryptionKey: make([]byte, 32), StaticDir: t.TempDir(), Authority: exported, SigningSource: exported, MetricsToken: "0123456789abcdef-token"}
	server, handler := newServerHandler(cfg, storage, slog.New(slog.NewTextHandler(io.Discard, nil)), &http.Client{})
	server.refreshCertificateMetrics(time.Now())
	request := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	request.Header.Set("Authorization", "Bearer "+cfg.MetricsToken)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, request)
	if !strings.Contains(w.Body.String(), "jolt_root_key_in_database 0") {
		t.Fatalf("metrics:\n%s", w.Body)
	}
}

// Open connections to nodes are judged again whenever the bundle changes what
// the Control Tower trusts, which is what makes a revocation take effect now.
func TestWhatChangesTheBundleMakesTheControlTowerJudgeItsOpenConnectionsAgain(t *testing.T) {
	h := newEnrollHarness(t)
	managedRecord(t, h, "n1", "beef01", 1)
	rechecks := 0
	h.server.recheckNodes = func() { rechecks++ }
	step := func(name string, call func()) {
		before := rechecks
		call()
		if rechecks != before+1 {
			t.Errorf("%s: %d rechecks", name, rechecks-before)
		}
	}
	step("a revocation", func() {
		if w := h.do("admin", "POST", cryptoBase+"revocations", map[string]any{"node_id": "n1"}); w.Code != http.StatusOK {
			t.Fatalf("%d %s", w.Code, w.Body)
		}
	})
	step("an intermediate rotation", func() {
		if w := h.do("admin", "POST", cryptoBase+"ca/intermediate/rotate", map[string]any{"revoke_previous": true}); w.Code != http.StatusOK {
			t.Fatalf("%d %s", w.Code, w.Body)
		}
	})
	// A request that is refused changes nothing, so it judges nothing again.
	before := rechecks
	h.do("admin", "POST", cryptoBase+"revocations", map[string]any{"serial": "deadbeef"})
	if rechecks != before {
		t.Error("a refused revocation rechecked the connections")
	}
}

func TestANodeWhoseCertificateWasRevokedDoesNotHoldARootRotationBack(t *testing.T) {
	h := newEnrollHarness(t)
	current := h.authority.Bundle().Version
	managedRecord(t, h, "gone", "aa01", current-5)
	if w := h.do("admin", "POST", cryptoBase+"revocations", map[string]any{"node_id": "gone"}); w.Code != http.StatusOK {
		t.Fatalf("revoke: %d %s", w.Code, w.Body)
	}
	if w := h.do("admin", "POST", cryptoBase+"ca/root/rotate", nil); w.Code != http.StatusAccepted {
		t.Fatalf("begin: %d %s", w.Code, w.Body)
	}
	if w := h.do("admin", "POST", cryptoBase+"ca/root/promote", map[string]any{}); w.Code != http.StatusOK {
		t.Fatalf("a revoked node blocked the promotion: %d %s", w.Code, w.Body)
	}
}
