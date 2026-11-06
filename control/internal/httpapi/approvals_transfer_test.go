package httpapi

import (
	"context"
	"crypto/ed25519"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jfxdev/jolt/control/internal/config"
	"github.com/jfxdev/jolt/control/internal/rbac"
	"github.com/jfxdev/jolt/control/internal/security"
	"github.com/jfxdev/jolt/control/internal/store"
)

// transferApprovalHarness is the transfer fake with an operator whose delete
// and update on the source need a person's approval, and an administrator.
func transferApprovalHarness(t *testing.T, fake *transferFake, marked ...string) (http.Handler, *store.Store, map[string]string) {
	t.Helper()
	ctx, now := context.Background(), time.Now().UTC()
	storage, err := store.Open(filepath.Join(t.TempDir(), "control.db"), make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = storage.Close() })
	sessions := map[string]string{"admin": "admin-session", "operator": "operator-session"}
	for id, role := range map[string]string{"admin": "admin", "operator": "operator"} {
		if err := storage.CreateUser(ctx, store.User{ID: id, Username: id, PasswordHash: "unused", Role: role, Enabled: true, CreatedAt: now, UpdatedAt: now}); err != nil {
			t.Fatal(err)
		}
		if err := storage.CreateSession(ctx, security.Digest(sessions[id]), id, now.Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	encrypted, _ := security.Encrypt(make([]byte, 32), "node-token")
	for _, node := range []store.Node{
		{ID: "source", Name: "Source", Endpoint: "http://source.test", TokenEncrypted: encrypted, State: "online", CreatedAt: now, UpdatedAt: now},
		{ID: "destination", Name: "Destination", Endpoint: "http://destination.test", TokenEncrypted: encrypted, State: "online", CreatedAt: now, UpdatedAt: now},
	} {
		if err := storage.SaveNode(ctx, node); err != nil {
			t.Fatal(err)
		}
	}
	if len(marked) == 0 {
		marked = []string{"delete", "update"}
	}
	policy := store.Policy{ID: "operator-transfers", Name: "operator-transfers", CreatedAt: now, UpdatedAt: now, Rules: []rbac.Rule{
		{Path: "nodes/source/files/mounts/source-media/**", Capabilities: []string{"read", "list", "delete", "update"}, NeedsApproval: marked},
		{Path: "nodes/destination/files/mounts/incoming/**", Capabilities: []string{"create", "list"}},
		{Path: "nodes/destination/transfers", Capabilities: []string{"create", "execute"}},
	}}
	if err := storage.CreatePolicy(ctx, policy); err != nil {
		t.Fatal(err)
	}
	if err := storage.SetSubjectPolicies(ctx, "user", "operator", []string{policy.ID}); err != nil {
		t.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	fake.keys = map[string]ed25519.PublicKey{"key": key.Public().(ed25519.PublicKey)}
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		status, header, body := fake.handle(t, r)
		return &http.Response{StatusCode: status, Header: header, Body: io.NopCloser(strings.NewReader(body))}, nil
	})}
	handler := newHandler(config.Config{EncryptionKey: make([]byte, 32), StaticDir: t.TempDir(), SignedLocalJobs: true, Approvals: true,
		AuthorizationSigningKeyID: "key", AuthorizationSigningKey: key}, storage, slog.New(slog.NewTextHandler(io.Discard, nil)), client)
	return handler, storage, sessions
}

func TestAMoveBetweenNodesThatNeedsApprovalIsPreviewedAndCreatedAgainByTheApprover(t *testing.T) {
	fake := &transferFake{sourceIdentity: "source", destinationCaps: transferCaps, moving: true}
	handler, storage, sessions := transferApprovalHarness(t, fake)
	call := func(user, method, path, body, key string) *httptest.ResponseRecorder {
		r := authenticatedRequest(method, path, sessions[user], []byte(body))
		if key != "" {
			r.Header.Set("Idempotency-Key", key)
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	transfers := "/api/v1/nodes/destination/transfers"
	// The preview is allowed: it changes nothing, and it shows the numbers.
	if w := call("operator", http.MethodPost, transfers+"/plan", movePayload, ""); w.Code != http.StatusOK {
		t.Fatalf("preview: %d %s", w.Code, w.Body)
	}
	created := call("operator", http.MethodPost, transfers, confirmedMovePayload, "k1")
	if created.Code != http.StatusAccepted || !strings.Contains(created.Body.String(), "pending_approval") || !strings.Contains(created.Body.String(), `"files":2`) {
		t.Fatalf("create: %d %s", created.Code, created.Body)
	}
	if len(fake.createBodies) != 0 {
		t.Fatalf("a move that needs approval reached the node: %+v", fake.createBodies)
	}
	if strings.Contains(created.Body.String(), "one-use") {
		t.Fatalf("the requester's confirmation leaked: %s", created.Body)
	}
	pendings, err := storage.ListPendingOperations(context.Background(), store.PendingState, "", "", 10, time.Now())
	if err != nil || len(pendings) != 1 || pendings[0].Kind != store.PendingKindTransfer || strings.Contains(string(pendings[0].Body), "move_plan") {
		t.Fatalf("pending %+v %v", pendings, err)
	}
	id := pendings[0].ID
	approve := call("admin", http.MethodPost, decide+id+"/approve", ``, "")
	if approve.Code != http.StatusOK || !strings.Contains(approve.Body.String(), `"state":"executed"`) {
		t.Fatalf("approve: %d %s", approve.Code, approve.Body)
	}
	if len(fake.createBodies) != 1 {
		t.Fatalf("creations: %d", len(fake.createBodies))
	}
	body := fake.createBodies[0]
	if body["operation"] != "move" || body["plan_id"] != "plan_1" || body["plan_token"] != "one-use" {
		t.Fatalf("the approver did not confirm their own preview: %+v", body)
	}
	if len(fake.previewBodies) != 3 {
		t.Fatalf("previews: requester's, the kept one's and the approver's expected, got %d", len(fake.previewBodies))
	}
	if fake.previewBodies[len(fake.previewBodies)-1]["subject_type"] != "user" {
		t.Fatalf("approver preview: %+v", fake.previewBodies[len(fake.previewBodies)-1])
	}
	jobID := signedTransferJobID("user", "admin", "approval-"+id, "destination")
	if link, err := storage.GetJobAuthorizationLink(context.Background(), "destination", jobID); err != nil || link.ActorID != "admin" {
		t.Fatalf("the job is not the approver's, or its key is not stable: %+v %v", link, err)
	}
	// Approving again does not create a second job.
	if repeat := call("admin", http.MethodPost, decide+id+"/approve", ``, ""); !strings.Contains(repeat.Body.String(), `"replayed":true`) || len(fake.createBodies) != 1 {
		t.Fatalf("repeat: %d %s creations %d", repeat.Code, repeat.Body, len(fake.createBodies))
	}
}

func TestACopyBetweenNodesNeedsApprovalOnlyWhenItMayOverwrite(t *testing.T) {
	fake := &transferFake{sourceIdentity: "source", destinationCaps: transferCaps}
	handler, _, sessions := transferApprovalHarness(t, fake)
	post := func(payload, key string) *httptest.ResponseRecorder {
		r := authenticatedRequest(http.MethodPost, "/api/v1/nodes/destination/transfers", sessions["operator"], []byte(payload))
		r.Header.Set("Idempotency-Key", key)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	// A plain copy never touches the source and creates nothing at the destination
	// the policy marked: the operator has only create there.
	if w := post(transferPayload, "plain-copy"); w.Code != http.StatusAccepted || strings.Contains(w.Body.String(), "pending_approval") {
		t.Fatalf("plain copy: %d %s", w.Code, w.Body)
	}
	if len(fake.createBodies) != 1 {
		t.Fatalf("the plain copy did not reach the node: %d", len(fake.createBodies))
	}
}

func TestATransferApprovalFailsWhenWhatWouldMoveHasChanged(t *testing.T) {
	fake := &transferFake{sourceIdentity: "source", destinationCaps: transferCaps, moving: true}
	handler, storage, sessions := transferApprovalHarness(t, fake)
	// The requester was shown 5 files; the preview now finds 2.
	body := `{"operation":"move","source":{"node_id":"source","mount_id":"source-media","paths":["exports/one.txt","exports/folder"]},"destination":{"mount_id":"incoming","path":"imports/archive"},"conflict_policy":"fail"}`
	op, _, err := storage.CreatePendingOperation(context.Background(), store.PendingOperation{
		Kind: store.PendingKindTransfer, RequesterType: "user", RequesterID: "operator", Method: http.MethodPost, NodeID: "destination", Resource: "transfers",
		Body: []byte(body), Summary: []byte(`{"operation":"move","files":5,"bytes":12}`),
		Requirements: []store.PendingRequirement{
			{Path: "nodes/source/files/mounts/source-media/exports/one.txt", Capability: "delete"},
			{Path: "nodes/source/files/mounts/source-media/exports/one.txt", Capability: "update"},
			{Path: "nodes/source/files/mounts/source-media/exports/folder", Capability: "delete"},
			{Path: "nodes/source/files/mounts/source-media/exports/folder", Capability: "update"},
		},
	}, 5, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	r := authenticatedRequest(http.MethodPost, decide+op.ID+"/approve", sessions["admin"], nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if !strings.Contains(w.Body.String(), "tree_changed") || len(fake.createBodies) != 0 {
		t.Fatalf("approve: %d %s creations %d", w.Code, w.Body, len(fake.createBodies))
	}
}
