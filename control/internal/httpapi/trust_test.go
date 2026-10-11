package httpapi

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jfxdev/jolt/control/internal/rbac"
	"github.com/jfxdev/jolt/control/internal/security"
	"github.com/jfxdev/jolt/control/internal/store"
)

// trustFixture wires two fake nodes whose peer listings the test controls, so
// the asymmetric states that used to be invisible can be asserted directly.
type trustFixture struct {
	handler http.Handler
	storage *store.Store
	session string
	calls   map[string]*atomic.Int32
}

func (f *trustFixture) count(key string) int32 {
	if counter, ok := f.calls[key]; ok {
		return counter.Load()
	}
	return 0
}

type nodeResponses struct {
	issuerPeers          string
	targetPeers          string
	inviteStatus         string
	requestStatus        string
	issuerGrants         string
	acceptStatus         int
	revokeIssuerOK       bool
	revokeTargetOK       bool
	reflectRevocations   bool
	targetPeersStatus    int
	issuerMetadataID     string
	issuerMetadataStatus int
}

func newTrustFixture(t *testing.T, responses nodeResponses) *trustFixture {
	t.Helper()
	if responses.issuerPeers == "" {
		responses.issuerPeers = `{"items":[]}`
	}
	if responses.targetPeers == "" {
		responses.targetPeers = `{"items":[]}`
	}
	if responses.issuerGrants == "" {
		responses.issuerGrants = `{"items":[]}`
	}
	if responses.acceptStatus == 0 {
		responses.acceptStatus = http.StatusOK
	}
	if responses.issuerMetadataID == "" {
		responses.issuerMetadataID = "source"
	}
	fixture := &trustFixture{calls: map[string]*atomic.Int32{
		"approve": {}, "accept": {}, "reject": {},
		"revoke-issuer": {}, "revoke-target": {},
	}}
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		header := http.Header{"Content-Type": []string{"application/json"}}
		body, status := `{}`, http.StatusOK
		issuer := request.URL.Host == "source.test"
		switch {
		case request.URL.Path == "/api/v1/node" && issuer:
			body = `{"node_id":"` + responses.issuerMetadataID + `","name":"Source","fingerprint":"SOURCE-FP","identity_epoch":1,"mtls_endpoint":"https://source.test:8443"}`
			if responses.issuerMetadataStatus != 0 {
				status = responses.issuerMetadataStatus
			}
		case request.URL.Path == "/api/v1/node":
			body = `{"node_id":"target","name":"Target","fingerprint":"TARGET-FP","identity_epoch":1,"mtls_endpoint":"https://target.test:8443"}`
		case request.URL.Path == "/api/v1/peers" && request.Method == http.MethodGet && issuer:
			body = responses.issuerPeers
			if responses.reflectRevocations && fixture.count("revoke-issuer") > 0 {
				body = `{"items":[{"node_id":"target","state":"revoked","fingerprint":"TARGET-FP"}]}`
			}
		case request.URL.Path == "/api/v1/peers" && request.Method == http.MethodGet:
			body = responses.targetPeers
			if responses.reflectRevocations && fixture.count("revoke-target") > 0 {
				body = `{"items":[{"node_id":"` + responses.issuerMetadataID + `","state":"revoked","fingerprint":"SOURCE-FP"}]}`
			}
			if responses.targetPeersStatus != 0 {
				status = responses.targetPeersStatus
			}
		case request.URL.Path == "/api/v1/grants" && request.Method == http.MethodGet:
			body = responses.issuerGrants
		case request.URL.Path == "/api/v1/pairing/invites" && request.Method == http.MethodGet:
			body = `{"items":[{"invite_id":"invite-1","status":"` + responses.inviteStatus + `"}]}`
		case request.URL.Path == "/api/v1/pairing/requests" && request.Method == http.MethodGet:
			body = `{"items":[{"request_id":"request-1","status":"` + responses.requestStatus + `"}]}`
		case request.URL.Path == "/api/v1/pairing/invites/invite-1/approve":
			fixture.calls["approve"].Add(1)
		case request.URL.Path == "/api/v1/pairing/requests/request-1/accept":
			fixture.calls["accept"].Add(1)
			status = responses.acceptStatus
			if status != http.StatusOK {
				body = `{"error":{"code":"invalid_request","message":"request is no longer pending"}}`
			}
		case request.URL.Path == "/api/v1/pairing/requests/request-1/reject":
			fixture.calls["reject"].Add(1)
		case request.Method == http.MethodDelete && request.URL.Path == "/api/v1/peers/target":
			fixture.calls["revoke-issuer"].Add(1)
			if !responses.revokeIssuerOK {
				status, body = http.StatusBadGateway, `{"error":{"code":"node_unavailable","message":"node down"}}`
			}
		case request.Method == http.MethodDelete && request.URL.Path == "/api/v1/peers/"+responses.issuerMetadataID:
			fixture.calls["revoke-target"].Add(1)
			if !responses.revokeTargetOK {
				status, body = http.StatusBadGateway, `{"error":{"code":"node_unavailable","message":"node down"}}`
			}
		case request.Method == http.MethodDelete && strings.HasPrefix(request.URL.Path, "/api/v1/pairing/invites/"):
			// invite revocation during rejection
		default:
			t.Errorf("unexpected node call: %s %s%s", request.Method, request.URL.Host, request.URL.Path)
			status = http.StatusNotFound
		}
		return &http.Response{StatusCode: status, Header: header, Body: io.NopCloser(strings.NewReader(body))}, nil
	})}
	handler, storage, session := testUserHandlerWithClient(t, store.User{
		ID: "admin-1", Username: "admin", Role: "admin", Enabled: true,
	}, client)
	fixture.handler, fixture.storage, fixture.session = handler, storage, session
	now := time.Now().UTC()
	encrypted, err := security.Encrypt(make([]byte, 32), "node-token")
	if err != nil {
		t.Fatal(err)
	}
	for _, node := range []store.Node{
		{ID: "source", Name: "Source", Endpoint: "http://source.test", TokenEncrypted: encrypted, State: "online", CreatedAt: now, UpdatedAt: now},
		{ID: "target", Name: "Target", Endpoint: "http://target.test", TokenEncrypted: encrypted, State: "online", CreatedAt: now, UpdatedAt: now},
	} {
		if err := storage.SaveNode(context.Background(), node); err != nil {
			t.Fatal(err)
		}
	}
	return fixture
}

func (f *trustFixture) saveConnection(t *testing.T, status string) store.Connection {
	t.Helper()
	now := time.Now().UTC()
	token, err := security.Encrypt(make([]byte, 32), "invite-token")
	if err != nil {
		t.Fatal(err)
	}
	connection := store.Connection{
		RequestID: "request-1", InviteID: "invite-1", IssuerNodeID: "source", TargetNodeID: "target",
		InviteTokenEncrypted: token, IssuerFingerprint: "SOURCE-FP", Status: status,
		ExpiresAt: now.Add(time.Hour), CreatedAt: now, UpdatedAt: now,
	}
	if err := f.storage.SaveConnection(context.Background(), connection); err != nil {
		t.Fatal(err)
	}
	return connection
}

func (f *trustFixture) do(method, path string, body []byte) *httptest.ResponseRecorder {
	response := httptest.NewRecorder()
	f.handler.ServeHTTP(response, authenticatedRequest(method, path, f.session, body))
	return response
}

func TestReconcileConnectionCompletesOnlyTheMissingSide(t *testing.T) {
	fixture := newTrustFixture(t, nodeResponses{
		issuerPeers:   `{"items":[{"node_id":"target","state":"trusted","fingerprint":"TARGET-FP"}]}`,
		targetPeers:   `{"items":[]}`,
		inviteStatus:  "consumed",
		requestStatus: "pending_review",
	})
	fixture.saveConnection(t, "partially_connected")

	response := fixture.do(http.MethodPost, "/api/v1/control-tower/connections/request-1/reconcile", []byte(`{}`))
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if fixture.count("approve") != 0 {
		t.Errorf("issuer approve replayed %d times; the invite was already consumed", fixture.count("approve"))
	}
	if fixture.count("accept") != 1 {
		t.Errorf("target accept calls = %d, want 1", fixture.count("accept"))
	}
	connection, err := fixture.storage.GetConnection(context.Background(), "request-1")
	if err != nil || connection.Status != "connected" {
		t.Fatalf("connection=%+v err=%v", connection, err)
	}
}

func TestReconcileConnectionIsIdempotentWhenBothSidesTrust(t *testing.T) {
	fixture := newTrustFixture(t, nodeResponses{
		issuerPeers:   `{"items":[{"node_id":"target","state":"online","fingerprint":"TARGET-FP"}]}`,
		targetPeers:   `{"items":[{"node_id":"source","state":"online","fingerprint":"SOURCE-FP"}]}`,
		inviteStatus:  "consumed",
		requestStatus: "accepted",
	})
	fixture.saveConnection(t, "connected")

	response := fixture.do(http.MethodPost, "/api/v1/control-tower/connections/request-1/reconcile", []byte(`{}`))
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if fixture.count("approve") != 0 || fixture.count("accept") != 0 {
		t.Errorf("approve=%d accept=%d; an already connected pair must not be touched",
			fixture.count("approve"), fixture.count("accept"))
	}
}

// A one-sided revoke consumes the invite and resolves the request, so the
// handshake cannot be replayed. Reconciliation has to say so instead of
// failing opaquely.
func TestReconcileConnectionRequiresNewInviteWhenRequestIsResolved(t *testing.T) {
	fixture := newTrustFixture(t, nodeResponses{
		issuerPeers:   `{"items":[{"node_id":"target","state":"offline","fingerprint":"TARGET-FP"}]}`,
		targetPeers:   `{"items":[{"node_id":"source","state":"revoked","fingerprint":"SOURCE-FP"}]}`,
		inviteStatus:  "consumed",
		requestStatus: "accepted",
	})
	fixture.saveConnection(t, "connected")

	response := fixture.do(http.MethodPost, "/api/v1/control-tower/connections/request-1/reconcile", []byte(`{}`))
	if response.Code != http.StatusConflict {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var payload struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatal(err)
	}
	if payload.Error.Code != "reconcile_requires_new_invite" {
		t.Fatalf("error code = %q", payload.Error.Code)
	}
	connection, err := fixture.storage.GetConnection(context.Background(), "request-1")
	if err != nil || connection.Status != "partially_connected" {
		t.Fatalf("connection=%+v err=%v", connection, err)
	}
}

func TestRejectPartiallyConnectedRevokesIssuerTrust(t *testing.T) {
	fixture := newTrustFixture(t, nodeResponses{
		issuerPeers:    `{"items":[{"node_id":"target","state":"trusted","fingerprint":"TARGET-FP"}]}`,
		inviteStatus:   "consumed",
		requestStatus:  "pending_review",
		revokeIssuerOK: true,
	})
	fixture.saveConnection(t, "partially_connected")

	response := fixture.do(http.MethodPost, "/api/v1/control-tower/connections/request-1/reject", nil)
	if response.Code != http.StatusNoContent {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if fixture.count("revoke-issuer") != 1 {
		t.Errorf("issuer peer revocations = %d, want 1; rejection must not leave the issuer trusting the target",
			fixture.count("revoke-issuer"))
	}
	connection, err := fixture.storage.GetConnection(context.Background(), "request-1")
	if err != nil || connection.Status != "rejected" {
		t.Fatalf("connection=%+v err=%v", connection, err)
	}
}

func TestRejectConnectedConnectionIsRefused(t *testing.T) {
	fixture := newTrustFixture(t, nodeResponses{inviteStatus: "consumed", requestStatus: "accepted"})
	fixture.saveConnection(t, "connected")

	response := fixture.do(http.MethodPost, "/api/v1/control-tower/connections/request-1/reject", nil)
	if response.Code != http.StatusConflict {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if fixture.count("reject") != 0 {
		t.Error("a connected pair must not have its target-side request rejected")
	}
}

func TestRevokeConnectionRemovesTrustOnBothNodes(t *testing.T) {
	for _, issuerID := range []string{"source", "source-current"} {
		t.Run(issuerID, func(t *testing.T) {
			fixture := newTrustFixture(t, nodeResponses{
				issuerPeers:  `{"items":[{"node_id":"target","state":"online","fingerprint":"TARGET-FP"}]}`,
				targetPeers:  `{"items":[{"node_id":"` + issuerID + `","state":"online","fingerprint":"SOURCE-FP"}]}`,
				inviteStatus: "consumed", requestStatus: "accepted",
				revokeIssuerOK: true, revokeTargetOK: true,
				reflectRevocations: true,
				issuerMetadataID:   issuerID,
			})
			fixture.saveConnection(t, "connected")
			for _, nodeID := range []string{"source", "target"} {
				view := fixture.do(http.MethodGet, "/api/v1/control-tower/nodes/"+nodeID+"/trust", nil)
				var payload trustView
				if err := json.Unmarshal(view.Body.Bytes(), &payload); err != nil || view.Code != http.StatusOK || len(payload.Peers) != 1 {
					t.Fatalf("before revoke: node=%s status=%d body=%s err=%v", nodeID, view.Code, view.Body.String(), err)
				}
				if payload.Peers[0].TrustStatus != trustConnected {
					t.Fatalf("current IDs must resolve reciprocal trust: %+v", payload.Peers[0])
				}
				counterpartID := "source"
				if nodeID == "source" {
					counterpartID = "target"
				}
				if payload.Peers[0].RegisteredNodeID != counterpartID {
					t.Fatalf("registered node ID must remain usable for navigation: %+v", payload.Peers[0])
				}
			}

			response := fixture.do(http.MethodPost, "/api/v1/control-tower/connections/request-1/revoke", []byte(`{}`))
			if response.Code != http.StatusOK {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
			if fixture.count("revoke-issuer") != 1 || fixture.count("revoke-target") != 1 {
				t.Errorf("issuer=%d target=%d, want 1 each",
					fixture.count("revoke-issuer"), fixture.count("revoke-target"))
			}
			connection, err := fixture.storage.GetConnection(context.Background(), "request-1")
			if err != nil || connection.Status != "revoked" {
				t.Fatalf("connection=%+v err=%v", connection, err)
			}
			for _, nodeID := range []string{"source", "target"} {
				view := fixture.do(http.MethodGet, "/api/v1/control-tower/nodes/"+nodeID+"/trust", nil)
				var payload trustView
				if err := json.Unmarshal(view.Body.Bytes(), &payload); err != nil || view.Code != http.StatusOK || len(payload.Peers) != 0 {
					t.Fatalf("after revoke: node=%s status=%d body=%s err=%v", nodeID, view.Code, view.Body.String(), err)
				}
				if len(payload.Connections) != 1 || payload.Connections[0].Status != "revoked" {
					t.Fatalf("revocation history must remain available: %+v", payload.Connections)
				}
			}
		})
	}
}

func TestRevokeConnectionRequiresCurrentNodeIdentities(t *testing.T) {
	fixture := newTrustFixture(t, nodeResponses{
		issuerMetadataStatus: http.StatusServiceUnavailable,
		revokeIssuerOK:       true, revokeTargetOK: true,
	})
	fixture.saveConnection(t, "connected")
	response := fixture.do(http.MethodPost, "/api/v1/control-tower/connections/request-1/revoke", []byte(`{}`))
	if response.Code != http.StatusBadGateway {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if fixture.count("revoke-issuer") != 0 || fixture.count("revoke-target") != 0 {
		t.Fatal("revocation must not use stale IDs when identity lookup fails")
	}
	connection, err := fixture.storage.GetConnection(context.Background(), "request-1")
	if err != nil || connection.Status != "connected" {
		t.Fatalf("connection=%+v err=%v", connection, err)
	}
}

func TestNodeTrustOmitsOnlyCompletedRevocations(t *testing.T) {
	for _, test := range []struct {
		name                string
		remoteState         string
		remoteStatus        int
		localIdentityStatus int
		unregistered        bool
		wantPeers           int
	}{
		{name: "revoked on both nodes", remoteState: "revoked"},
		{name: "revoked locally and missing remotely"},
		{name: "other node still trusts us", remoteState: "online", wantPeers: 1},
		{name: "other node offline but still trusts us", remoteState: "offline", wantPeers: 1},
		{name: "other node has an identity mismatch", remoteState: "identity_changed", wantPeers: 1},
		{name: "other node unavailable", remoteStatus: http.StatusServiceUnavailable, wantPeers: 1},
		{name: "other node unregistered", unregistered: true, wantPeers: 1},
		{name: "local identity unavailable", localIdentityStatus: http.StatusServiceUnavailable, wantPeers: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			remotePeers := `{"items":[]}`
			if test.remoteState != "" {
				remotePeers = `{"items":[{"node_id":"source","state":"` + test.remoteState + `"}]}`
			}
			fixture := newTrustFixture(t, nodeResponses{
				issuerPeers: `{"items":[{"node_id":"target","state":"revoked"}]}`,
				targetPeers: remotePeers, targetPeersStatus: test.remoteStatus,
				issuerGrants:         `{"items":[{"grant_id":"grant-1","peer_node_id":"target","enabled":false}]}`,
				issuerMetadataStatus: test.localIdentityStatus,
			})
			if test.unregistered {
				if err := fixture.storage.DeleteNode(context.Background(), "target"); err != nil {
					t.Fatal(err)
				}
			}
			response := fixture.do(http.MethodGet, "/api/v1/control-tower/nodes/source/trust", nil)
			var view trustView
			if err := json.Unmarshal(response.Body.Bytes(), &view); err != nil || response.Code != http.StatusOK {
				t.Fatalf("status=%d body=%s err=%v", response.Code, response.Body.String(), err)
			}
			if view.Peers == nil || len(view.Peers) != test.wantPeers {
				t.Fatalf("peers=%+v, want %d", view.Peers, test.wantPeers)
			}
		})
	}
}

// The half-done revoke is the bug this endpoint replaces, so it must surface as
// a failure naming both sides rather than a success.
func TestRevokeConnectionReportsAHalfDoneRevoke(t *testing.T) {
	fixture := newTrustFixture(t, nodeResponses{
		inviteStatus: "consumed", requestStatus: "accepted",
		revokeIssuerOK: true, revokeTargetOK: false,
	})
	fixture.saveConnection(t, "connected")

	response := fixture.do(http.MethodPost, "/api/v1/control-tower/connections/request-1/revoke", []byte(`{}`))
	if response.Code != http.StatusConflict {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var payload struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
		Sides []sideResult `json:"sides"`
	}
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatal(err)
	}
	if payload.Error.Code != "revoke_incomplete" || len(payload.Sides) != 2 {
		t.Fatalf("payload=%+v", payload)
	}
	connection, err := fixture.storage.GetConnection(context.Background(), "request-1")
	if err != nil || connection.Status != "connected" {
		t.Fatalf("connection=%+v err=%v; a failed revoke must not claim success", connection, err)
	}
}

// This is the live incident: the issuer reports the peer as merely offline
// while the target has revoked it. The trust view has to name that.
func TestNodeTrustReportsPeerRevokedOnTheOtherSide(t *testing.T) {
	fixture := newTrustFixture(t, nodeResponses{
		issuerPeers:   `{"items":[{"node_id":"target","state":"offline","fingerprint":"TARGET-FP","consecutive_failures":2354}]}`,
		targetPeers:   `{"items":[{"node_id":"source","state":"revoked","fingerprint":"SOURCE-FP"}]}`,
		issuerGrants:  `{"items":[{"grant_id":"grant-1","peer_node_id":"target","mount_id":"media","path":"movies","direction":"receive","enabled":true}]}`,
		inviteStatus:  "consumed",
		requestStatus: "accepted",
	})
	fixture.saveConnection(t, "connected")

	response := fixture.do(http.MethodGet, "/api/v1/control-tower/nodes/source/trust", nil)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var view trustView
	if err := json.NewDecoder(response.Body).Decode(&view); err != nil {
		t.Fatal(err)
	}
	if len(view.Peers) != 1 {
		t.Fatalf("peers=%+v", view.Peers)
	}
	peer := view.Peers[0]
	if peer.TrustStatus != trustRevokedByPeer {
		t.Errorf("trust_status = %q, want %q", peer.TrustStatus, trustRevokedByPeer)
	}
	if peer.Reciprocal {
		t.Error("a peer that revoked us is not reciprocal")
	}
	if peer.RemoteState != "revoked" {
		t.Errorf("remote_state = %q", peer.RemoteState)
	}
	if len(peer.Grants) != 1 || peer.Grants[0].ID != "grant-1" {
		t.Errorf("grants = %+v; the trust view must expose the grants that are still enabled", peer.Grants)
	}
	if len(view.Connections) != 1 {
		t.Errorf("connections = %+v", view.Connections)
	}
}

func TestNodeTrustReportsAHealthyPairAsConnected(t *testing.T) {
	fixture := newTrustFixture(t, nodeResponses{
		issuerPeers:   `{"items":[{"node_id":"target","state":"online","fingerprint":"TARGET-FP"}]}`,
		targetPeers:   `{"items":[{"node_id":"source","state":"online","fingerprint":"SOURCE-FP"}]}`,
		inviteStatus:  "consumed",
		requestStatus: "accepted",
	})

	response := fixture.do(http.MethodGet, "/api/v1/control-tower/nodes/source/trust", nil)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var view trustView
	if err := json.NewDecoder(response.Body).Decode(&view); err != nil {
		t.Fatal(err)
	}
	if len(view.Peers) != 1 || view.Peers[0].TrustStatus != trustConnected || !view.Peers[0].Reciprocal {
		t.Fatalf("peers=%+v", view.Peers)
	}
	if view.Peers[0].AsymmetryReason != "" {
		t.Errorf("asymmetry_reason = %q, want empty", view.Peers[0].AsymmetryReason)
	}
}

func TestListConnectionsExposesPartiallyConnected(t *testing.T) {
	fixture := newTrustFixture(t, nodeResponses{inviteStatus: "consumed", requestStatus: "pending_review"})
	fixture.saveConnection(t, "partially_connected")

	response := fixture.do(http.MethodGet, "/api/v1/control-tower/connections", nil)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var payload struct {
		Items []store.Connection `json:"items"`
	}
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.Items) != 1 || payload.Items[0].Status != "partially_connected" {
		t.Fatalf("items=%+v", payload.Items)
	}
	if strings.Contains(response.Body.String(), "invite_token") {
		t.Error("the encrypted invite secret must never be serialized")
	}
}

// Composing the trust view server-side must not hand an operator material it
// could not fetch directly: grants and pairing rows keep their own capability.
func TestNodeTrustOmitsGrantsAndPairingWithoutCapability(t *testing.T) {
	fixture := newTrustFixture(t, nodeResponses{
		issuerPeers:   `{"items":[{"node_id":"target","state":"online","fingerprint":"TARGET-FP"}]}`,
		targetPeers:   `{"items":[{"node_id":"source","state":"online","fingerprint":"SOURCE-FP"}]}`,
		issuerGrants:  `{"items":[{"grant_id":"grant-1","peer_node_id":"target","mount_id":"media","path":"movies","direction":"receive","enabled":true}]}`,
		inviteStatus:  "pending",
		requestStatus: "pending_review",
	})
	ctx := context.Background()
	now := time.Now().UTC()
	operator := store.User{
		ID: "operator-1", Username: "operator", Role: "operator", Enabled: true,
		PasswordHash: "unused-hash", CreatedAt: now, UpdatedAt: now,
	}
	if err := fixture.storage.CreateUser(ctx, operator); err != nil {
		t.Fatal(err)
	}
	policy := store.Policy{
		ID: "policy-peers", Name: "peers-list", CreatedAt: now, UpdatedAt: now,
		Rules: []rbac.Rule{
			{Path: "nodes/source", Capabilities: []string{"list"}},
			{Path: "nodes/source/peers", Capabilities: []string{"list"}},
		},
	}
	if err := fixture.storage.CreatePolicy(ctx, policy); err != nil {
		t.Fatal(err)
	}
	if err := fixture.storage.SetSubjectPolicies(ctx, "user", operator.ID, []string{policy.ID}); err != nil {
		t.Fatal(err)
	}
	session := "operator-session"
	if err := fixture.storage.CreateSession(ctx, security.Digest(session),
		operator.ID, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}

	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, authenticatedRequest(
		http.MethodGet, "/api/v1/control-tower/nodes/source/trust", session, nil))
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var view trustView
	if err := json.NewDecoder(response.Body).Decode(&view); err != nil {
		t.Fatal(err)
	}
	if view.CanListGrants || view.CanReadPairing {
		t.Fatalf("capability flags = grants:%t pairing:%t, want both false",
			view.CanListGrants, view.CanReadPairing)
	}
	if len(view.Peers) != 1 {
		t.Fatalf("peers=%+v", view.Peers)
	}
	if len(view.Peers[0].Grants) != 0 {
		t.Errorf("grants leaked without list capability: %+v", view.Peers[0].Grants)
	}
	if len(view.Invites) != 0 || len(view.Requests) != 0 {
		t.Errorf("pairing material leaked without sudo: invites=%+v requests=%+v",
			view.Invites, view.Requests)
	}
}

// The target's request is already resolved, so there is nothing to reject
// there — and that must not block removing the issuer's orphaned trust, which
// is the whole point of rejecting a partially_connected request.
func TestRejectPartiallyConnectedWithResolvedTargetStillRevokesIssuer(t *testing.T) {
	fixture := newTrustFixture(t, nodeResponses{
		issuerPeers:    `{"items":[{"node_id":"target","state":"trusted","fingerprint":"TARGET-FP"}]}`,
		inviteStatus:   "consumed",
		requestStatus:  "rejected",
		revokeIssuerOK: true,
	})
	fixture.saveConnection(t, "partially_connected")

	response := fixture.do(http.MethodPost, "/api/v1/control-tower/connections/request-1/reject", nil)
	if response.Code != http.StatusNoContent {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if fixture.count("reject") != 0 {
		t.Error("a resolved request must not be rejected again on the target")
	}
	if fixture.count("revoke-issuer") != 1 {
		t.Errorf("issuer peer revocations = %d, want 1", fixture.count("revoke-issuer"))
	}
	connection, err := fixture.storage.GetConnection(context.Background(), "request-1")
	if err != nil || connection.Status != "rejected" {
		t.Fatalf("connection=%+v err=%v", connection, err)
	}
}
