package httpapi

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jfxdev/jolt/control/internal/config"
	"github.com/jfxdev/jolt/control/internal/metrics"
	"github.com/jfxdev/jolt/control/internal/pki"
	"github.com/jfxdev/jolt/control/internal/security"
	"github.com/jfxdev/jolt/control/internal/store"
)

// fakeNode plays a managed node's trust API with the same rules the real one
// applies: it adopts a bundle only if pki.VerifyBundle accepts it, and installs
// a certificate only if it is for the key it prepared.
type fakeNode struct {
	mu            sync.Mutex
	id            string
	bundle        *pki.Bundle
	serial        string
	notAfter      time.Time
	pendingKey    *ecdsa.PrivateKey
	calls         []string
	down          bool
	refuseBundle  string
	installedKeys []*ecdsa.PublicKey
	now           func() time.Time
}

func (n *fakeNode) handle(r *http.Request) (*http.Response, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.calls = append(n.calls, r.Method+" "+r.URL.Path)
	reply := func(status int, body any) (*http.Response, error) {
		encoded, _ := json.Marshal(body)
		return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(bytes.NewReader(encoded))}, nil
	}
	if n.down {
		return nil, errors.New("connection refused")
	}
	switch r.Method + " " + r.URL.Path {
	case "GET /api/v1/crypto/trust-bundle":
		version := int64(0)
		if n.bundle != nil {
			version = n.bundle.Version
		}
		return reply(200, map[string]any{"bundle_version": version, "api_certificate": map[string]any{"not_after": n.notAfter, "serial": n.serial}})
	case "PUT /api/v1/crypto/trust-bundle":
		data, _ := io.ReadAll(r.Body)
		candidate, err := pki.ParseBundle(data)
		if err != nil {
			return reply(400, map[string]any{"error": map[string]any{"code": "invalid_trust_bundle", "message": err.Error()}})
		}
		if n.refuseBundle != "" {
			return reply(422, map[string]any{"error": map[string]any{"code": "trust_bundle_refused", "message": n.refuseBundle}})
		}
		if err := pki.VerifyBundle(candidate, n.bundle, "", n.now()); err != nil {
			return reply(422, map[string]any{"error": map[string]any{"code": "trust_bundle_refused", "message": err.Error()}})
		}
		n.bundle = &candidate
		return reply(200, map[string]any{})
	case "POST /api/v1/crypto/api-cert/csr":
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		n.pendingKey = key
		request, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: n.id}}, key)
		return reply(200, map[string]string{"csr_pem": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: request}))})
	case "PUT /api/v1/crypto/api-cert":
		var body struct {
			Certificate string `json:"certificate_pem"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		block, _ := pem.Decode([]byte(body.Certificate))
		leaf, err := x509.ParseCertificate(block.Bytes)
		if err != nil || n.pendingKey == nil || !leaf.PublicKey.(*ecdsa.PublicKey).Equal(&n.pendingKey.PublicKey) {
			return reply(422, map[string]any{"error": map[string]any{"code": "certificate_refused", "message": "not for the pending key"}})
		}
		n.installedKeys = append(n.installedKeys, leaf.PublicKey.(*ecdsa.PublicKey))
		n.serial, n.notAfter, n.pendingKey = leaf.SerialNumber.Text(16), leaf.NotAfter, nil
		return reply(200, map[string]any{})
	}
	return reply(404, map[string]any{})
}

func (n *fakeNode) count(call string) int {
	n.mu.Lock()
	defer n.mu.Unlock()
	total := 0
	for _, c := range n.calls {
		if c == call {
			total++
		}
	}
	return total
}

type syncHarness struct {
	clock     *testClock
	server    *Server
	storage   *store.Store
	authority *pki.Manager
	nodes     map[string]*fakeNode
	registry  *metrics.Registry
}

func newSyncHarness(t *testing.T, ids ...string) *syncHarness {
	t.Helper()
	clock := &testClock{now: time.Now().UTC()}
	pkiStore, err := store.Open(filepath.Join(t.TempDir(), "pki.db"), make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pkiStore.Close() })
	authority, err := pki.NewManager(pkiStore, pki.Options{Key: make([]byte, 32), Now: clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	if err := authority.Ensure(context.Background()); err != nil {
		t.Fatal(err)
	}
	storage, err := store.Open(filepath.Join(t.TempDir(), "control.db"), make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = storage.Close() })
	h := &syncHarness{clock: clock, storage: storage, authority: authority, nodes: map[string]*fakeNode{}}
	sealed, _ := security.Encrypt(make([]byte, 32), "token")
	now := time.Now().UTC()
	for _, id := range ids {
		h.nodes[id] = &fakeNode{id: id, now: clock.Now}
		if err := storage.SaveNode(context.Background(), store.Node{ID: id, Name: id, Endpoint: "https://" + id + ".lan:8080", TokenEncrypted: sealed, State: "online", CreatedAt: now, UpdatedAt: now}); err != nil {
			t.Fatal(err)
		}
	}
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		node := h.nodes[strings.TrimSuffix(r.URL.Hostname(), ".lan")]
		if node == nil {
			return nil, errors.New("no such node")
		}
		return node.handle(r)
	})}
	cfg := config.Config{EncryptionKey: make([]byte, 32), StaticDir: t.TempDir(), Authority: authority, SigningSource: authority}
	h.server, _ = newServerHandler(cfg, storage, slog.New(slog.NewTextHandler(io.Discard, nil)), client)
	h.registry = h.server.registry
	return h
}

// advance lets the authority's clock run and brings it up to date, which
// publishes a newer bundle once the signing key has a successor to announce.
func (h *syncHarness) advance(t *testing.T, d time.Duration) {
	t.Helper()
	h.clock.now = h.clock.now.Add(d)
	if err := h.authority.Ensure(context.Background()); err != nil {
		t.Fatal(err)
	}
}

// enrolled puts a node in the state enrollment would leave it in: it holds
// bundle version `have` and a certificate with the given dates.
func (h *syncHarness) enrolled(t *testing.T, id string, have *pki.Bundle, notBefore, notAfter time.Time) {
	t.Helper()
	node := h.nodes[id]
	node.bundle, node.serial, node.notAfter = have, "aa", notAfter
	if err := h.storage.SaveManagedNode(context.Background(), store.ManagedNode{NodeID: id, EnrolledAt: notBefore, BundleVersion: versionOf(have), CertSerial: "aa", CertNotBefore: notBefore, CertNotAfter: notAfter}); err != nil {
		t.Fatal(err)
	}
}

func versionOf(b *pki.Bundle) int64 {
	if b == nil {
		return 0
	}
	return b.Version
}

func (h *syncHarness) record(t *testing.T, id string) store.ManagedNode {
	t.Helper()
	all, _ := h.storage.ListManagedNodes(context.Background())
	for _, m := range all {
		if m.NodeID == id {
			return m
		}
	}
	t.Fatalf("no record for %s", id)
	return store.ManagedNode{}
}

func TestANodeBehindOnTheBundleIsSentTheCurrentOneAndNothingElse(t *testing.T) {
	h := newSyncHarness(t, "n1")
	held := h.authority.Bundle() // what the node got when it enrolled
	h.enrolled(t, "n1", &held, h.clock.now.Add(-time.Hour), h.clock.now.Add(80*24*time.Hour))
	h.server.syncManagedNodes(context.Background(), h.clock.now)
	node := h.nodes["n1"]
	if node.count("PUT /api/v1/crypto/trust-bundle") != 0 {
		t.Fatal("a current node was sent a bundle")
	}
	// The authority publishes a successor key: the node is now behind.
	h.advance(t, 61*24*time.Hour)
	latest := h.authority.Bundle()
	if latest.Version <= held.Version {
		t.Fatalf("the authority did not publish: %d", latest.Version)
	}
	h.enrolled(t, "n1", &held, h.clock.now.Add(-time.Hour), h.clock.now.Add(80*24*time.Hour)) // the record is fresh; the bundle is not
	h.server.syncManagedNodes(context.Background(), h.clock.now)
	if node.bundle == nil || node.bundle.Version != latest.Version {
		t.Fatalf("the node did not receive the bundle: %+v", node.bundle)
	}
	if rec := h.record(t, "n1"); rec.BundleVersion != latest.Version || rec.LastError != "" {
		t.Fatalf("record: %+v", rec)
	}
	if node.count("POST /api/v1/crypto/api-cert/csr") != 0 {
		t.Fatal("a certificate far from its end was renewed")
	}
	before := node.count("PUT /api/v1/crypto/trust-bundle")
	h.server.syncManagedNodes(context.Background(), h.clock.now.Add(time.Minute))
	if node.count("PUT /api/v1/crypto/trust-bundle") != before {
		t.Fatal("the same bundle was sent again")
	}
}

func TestACertificateIsRenewedAtTwoThirdsOfItsLife(t *testing.T) {
	h := newSyncHarness(t, "n1")
	now := time.Now().UTC()
	current := h.authority.Bundle()
	notBefore := now.Add(-61 * 24 * time.Hour) // 90-day life: two thirds is day 60
	h.enrolled(t, "n1", &current, notBefore, notBefore.Add(90*24*time.Hour))
	early := newSyncHarness(t, "n1")
	earlyCurrent := early.authority.Bundle()
	early.enrolled(t, "n1", &earlyCurrent, now.Add(-30*24*time.Hour), now.Add(60*24*time.Hour))
	early.server.syncManagedNodes(context.Background(), now)
	if early.nodes["n1"].count("POST /api/v1/crypto/api-cert/csr") != 0 {
		t.Fatal("renewed at one third of the life")
	}

	h.server.syncManagedNodes(context.Background(), now)
	node := h.nodes["n1"]
	if node.count("POST /api/v1/crypto/api-cert/csr") != 1 || node.count("PUT /api/v1/crypto/api-cert") != 1 || len(node.installedKeys) != 1 {
		t.Fatalf("renewal calls: %v", node.calls)
	}
	record := h.record(t, "n1")
	if record.CertSerial == "aa" || record.CertSerial != node.serial || !record.CertNotAfter.After(now.Add(80*24*time.Hour)) || record.LastError != "" {
		t.Fatalf("record after renewal: %+v", record)
	}
	// The next pass finds a fresh certificate and does nothing.
	h.server.syncManagedNodes(context.Background(), now.Add(time.Minute))
	if node.count("POST /api/v1/crypto/api-cert/csr") != 1 {
		t.Fatal("a fresh certificate was renewed again")
	}
}

func TestAProblemWithOneNodeIsRecordedAndDoesNotStopTheOthers(t *testing.T) {
	h := newSyncHarness(t, "down", "refuses", "fine")
	held := h.authority.Bundle()
	h.advance(t, 61*24*time.Hour)
	now := h.clock.now
	h.enrolled(t, "down", &held, now.Add(-time.Hour), now.Add(80*24*time.Hour))
	h.enrolled(t, "refuses", &held, now.Add(-time.Hour), now.Add(80*24*time.Hour))
	h.enrolled(t, "fine", &held, now.Add(-time.Hour), now.Add(80*24*time.Hour))
	h.nodes["down"].down = true
	h.nodes["refuses"].refuseBundle = "not newer than the one in use"
	h.server.syncManagedNodes(context.Background(), now)
	if h.nodes["fine"].bundle.Version != h.authority.Bundle().Version {
		t.Fatal("a healthy node waited for broken ones")
	}
	down, refuses, fine := h.record(t, "down"), h.record(t, "refuses"), h.record(t, "fine")
	if !strings.Contains(down.LastError, "read the node's trust state") || down.LastErrorAt == nil {
		t.Fatalf("unreachable node: %+v", down)
	}
	if !strings.Contains(refuses.LastError, "send the trust bundle") || !strings.Contains(refuses.LastError, "not newer") || refuses.BundleVersion != held.Version {
		t.Fatalf("refusing node: %+v", refuses)
	}
	if fine.LastError != "" || fine.BundleVersion != h.authority.Bundle().Version {
		t.Fatalf("healthy node: %+v", fine)
	}
	// When the node comes back, the error clears.
	h.nodes["down"].down = false
	h.server.syncManagedNodes(context.Background(), now.Add(time.Minute))
	if again := h.record(t, "down"); again.LastError != "" || again.LastErrorAt != nil || h.nodes["down"].bundle.Version != h.authority.Bundle().Version {
		t.Fatalf("recovered node: %+v", again)
	}
}

func TestANodeThatWasNeverEnrolledIsLeftAlone(t *testing.T) {
	h := newSyncHarness(t, "manual")
	h.server.syncManagedNodes(context.Background(), time.Now().UTC())
	if len(h.nodes["manual"].calls) != 0 {
		t.Fatalf("a hand-configured node was contacted: %v", h.nodes["manual"].calls)
	}
}

func TestTheNodesOwnCertificateIsBelievedWhenTheRecordIsStale(t *testing.T) {
	h := newSyncHarness(t, "n1")
	now := time.Now().UTC()
	current := h.authority.Bundle()
	h.enrolled(t, "n1", &current, now.Add(-100*24*time.Hour), now.Add(-10*24*time.Hour)) // the record thinks it ended
	// The node actually installed a newer one just before a crash.
	h.nodes["n1"].serial, h.nodes["n1"].notAfter = "bb", now.Add(85*24*time.Hour)
	h.server.syncManagedNodes(context.Background(), now)
	if h.nodes["n1"].count("POST /api/v1/crypto/api-cert/csr") != 0 {
		t.Fatal("a certificate the node already renewed was renewed again")
	}
	if record := h.record(t, "n1"); record.CertSerial != "bb" || !record.CertNotAfter.After(now.Add(80*24*time.Hour)) {
		t.Fatalf("record: %+v", record)
	}
}

func TestExpiredEnrollmentsAreSweptByThePass(t *testing.T) {
	h := newSyncHarness(t)
	now := time.Now().UTC()
	token := store.JoinToken{ID: "t", SecretHash: "h", NodeName: "alpha", Approval: "manual", CreatedBy: "admin", CreatedAt: now, ExpiresAt: now.Add(time.Hour)}
	if err := h.storage.CreateJoinToken(context.Background(), token); err != nil {
		t.Fatal(err)
	}
	if _, err := h.storage.StartEnrollment(context.Background(), "h", store.Enrollment{ID: "e", State: store.EnrollmentPending, NodeName: "alpha", CSRPEM: "csr", OperationalEncrypted: "sealed", CreatedAt: now, ExpiresAt: now.Add(store.EnrollmentLifetime)}, now); err != nil {
		t.Fatal(err)
	}
	h.server.syncManagedNodes(context.Background(), now.Add(store.EnrollmentLifetime+time.Second))
	got, _ := h.storage.GetEnrollment(context.Background(), "e", now.Add(time.Hour))
	if got.State != store.EnrollmentExpired || got.CSRPEM != "" || got.OperationalEncrypted != "" {
		t.Fatalf("the sweep did not clear what the request held: %+v", got)
	}
}

func TestTheSyncReportsHowFarNodesAreBehind(t *testing.T) {
	h := newSyncHarness(t, "a", "b")
	now := time.Now().UTC()
	current := h.authority.Bundle()
	h.enrolled(t, "a", &current, now.Add(-time.Hour), now.Add(10*24*time.Hour))
	h.enrolled(t, "b", &current, now.Add(-time.Hour), now.Add(80*24*time.Hour))
	h.nodes["a"].down, h.nodes["b"].down = true, true
	h.server.syncManagedNodes(context.Background(), now)
	var out bytes.Buffer
	_ = h.registry.Write(&out)
	text := out.String()
	for _, want := range []string{"jolt_managed_nodes 2", "jolt_managed_node_bundle_lag 0", "jolt_managed_node_certificate_expiry_seconds "} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q in\n%s", want, text)
		}
	}
	// The soonest certificate is the one with 10 days, in seconds.
	if !strings.Contains(text, "jolt_managed_node_certificate_expiry_seconds 8") || strings.Contains(text, "jolt_managed_node_certificate_expiry_seconds 6") {
		t.Errorf("expiry gauge does not follow the soonest node:\n%s", text)
	}
}
