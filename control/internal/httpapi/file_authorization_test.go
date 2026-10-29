package httpapi

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jfxdev/jolt/control/internal/rbac"
	"github.com/jfxdev/jolt/control/internal/security"
	"github.com/jfxdev/jolt/control/internal/store"
)

// Regressions for the release audit: denied trees must never reach the node.
func TestRecursiveMutationsRespectDescendantDenies(t *testing.T) {
	for _, actor := range []string{"operator", "service_account"} {
		t.Run(actor, func(t *testing.T) {
			h := newShareHarness(t, []rbac.Rule{
				{Path: "nodes/nod_a/files/mounts/media/**", Capabilities: []string{"read", "list", "create", "update", "delete"}},
				{Path: "nodes/nod_a/files/mounts/media/docs/private/**", Capabilities: []string{"deny"}},
				{Path: "nodes/nod_a/jobs/**", Capabilities: []string{"create"}},
			})
			if actor == "service_account" {
				useServiceAccount(t, h)
			}
			base := "/api/v1/nodes/nod_a/mounts/media/files"
			for _, tc := range []struct {
				name, method, target string
				body                 any
				want                 int
			}{
				{"direct denied read", "GET", base + "/content?path=docs/private/secret.txt", nil, 403},
				{"recursive archive protected", "GET", base + "/archive?path=docs", nil, 403},
				{"recursive disk usage protected", "GET", base + "/disk-usage?path=docs", nil, 403},
				{"recursive copy is denied", "POST", base + "/copy", map[string]any{"source_path": "docs", "destination_path": "copy"}, 403},
				{"recursive move is denied", "POST", base + "/move", map[string]any{"source_path": "docs", "destination_path": "moved"}, 403},
				{"recursive delete is denied", "DELETE", base + "?path=docs&recursive=true", nil, 403},
			} {
				t.Run(tc.name, func(t *testing.T) {
					before := len(h.calls)
					got := h.do(t, tc.method, tc.target, tc.body)
					if len(h.calls) != before {
						t.Fatal("denied request reached node")
					}
					if got.Code != tc.want {
						t.Fatalf("want status %d, got %d", tc.want, got.Code)
					}
				})
			}
		})
	}

}

func TestLogicalTransferChecksExactPathsAndSupportsSubpathOnlyPolicies(t *testing.T) {
	plans := 0
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		body := `{}`
		switch r.URL.Path {
		case "/api/v1/node":
			id := "destination"
			if r.URL.Host == "source.test" {
				id = "source"
			}
			body = `{"node_id":"` + id + `","fingerprint":"FP"}`
		case "/api/v1/grants":
			if r.URL.Host == "source.test" {
				body = `{"items":[{"grant_id":"source-grant","peer_node_id":"destination","mount_id":"media","path":".","direction":"send","enabled":true,"permissions":{"read":true}}]}`
			} else {
				body = `{"items":[{"grant_id":"destination-grant","peer_node_id":"source","mount_id":"incoming","path":".","direction":"receive","enabled":true,"permissions":{"write":true},"conflict_policies":["fail"]}]}`
			}
		case "/api/v1/transfers/pull/batch/plan":
			plans++
			body = `{"files_total":1,"bytes_total":10}`
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
	})}
	actor := store.User{ID: "op", Username: "op", Role: "operator", Enabled: true}
	handler, storage, session := testUserHandlerWithClient(t, actor, client)
	now := time.Now().UTC()
	encrypted, err := security.Encrypt(make([]byte, 32), "node-token")
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"source", "destination"} {
		if err := storage.SaveNode(context.Background(), store.Node{ID: id, Name: id, Endpoint: "http://" + id + ".test", TokenEncrypted: encrypted, State: "online", CreatedAt: now, UpdatedAt: now}); err != nil {
			t.Fatal(err)
		}
	}
	if err := storage.CreatePolicy(context.Background(), store.Policy{ID: "pol", Name: "pol", CreatedAt: now, UpdatedAt: now, Rules: []rbac.Rule{
		{Path: "nodes/source/files/mounts/media/**", Capabilities: []string{"read"}},
		{Path: "nodes/source/files/mounts/media/private/**", Capabilities: []string{"deny"}},
		{Path: "nodes/destination/files/mounts/incoming/**", Capabilities: []string{"create"}},
		{Path: "nodes/destination/transfers", Capabilities: []string{"create"}},
	}}); err != nil {
		t.Fatal(err)
	}
	if err := storage.SetSubjectPolicies(context.Background(), "user", actor.ID, []string{"pol"}); err != nil {
		t.Fatal(err)
	}
	payload := []byte(`{"operation":"copy","source":{"node_id":"source","mount_id":"media","paths":["private/secret.txt"]},"destination":{"mount_id":"incoming","path":"archive"},"conflict_policy":"fail"}`)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, authenticatedRequest("POST", "/api/v1/nodes/destination/transfers/plan", session, payload))
	t.Logf("denied exact file transfer plan status=%d nodePlanCalls=%d body=%s", w.Code, plans, w.Body.String())
	if w.Code != 403 || plans != 0 {
		t.Fatalf("denied transfer unexpectedly reached the node")
	}
	policy := store.Policy{ID: "pol", Name: "pol", UpdatedAt: now, Rules: []rbac.Rule{
		{Path: "nodes/source/files/mounts/media/public/**", Capabilities: []string{"read"}},
		{Path: "nodes/destination/files/mounts/incoming/public/**", Capabilities: []string{"create"}},
		{Path: "nodes/destination/transfers", Capabilities: []string{"create"}},
	}}
	if err := storage.UpdatePolicy(context.Background(), policy); err != nil {
		t.Fatal(err)
	}
	payload = []byte(`{"operation":"copy","source":{"node_id":"source","mount_id":"media","paths":["public/file.txt"]},"destination":{"mount_id":"incoming","path":"public"},"conflict_policy":"fail"}`)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, authenticatedRequest("POST", "/api/v1/nodes/destination/transfers/plan", session, payload))
	if w.Code != 200 || plans != 1 {
		t.Fatalf("subpath-only policy refused: status=%d plans=%d body=%s", w.Code, plans, w.Body.String())
	}
	policy.Rules = append(policy.Rules, rbac.Rule{Path: "nodes/destination/files/mounts/incoming/public/private/**", Capabilities: []string{"deny"}})
	if err := storage.UpdatePolicy(context.Background(), policy); err != nil {
		t.Fatal(err)
	}
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, authenticatedRequest("POST", "/api/v1/nodes/destination/transfers/plan", session, payload))
	if w.Code != 403 || plans != 1 {
		t.Fatalf("destination deny ignored: status=%d plans=%d body=%s", w.Code, plans, w.Body.String())
	}
}

func TestRenameConflictRequiresTheDestinationParentScope(t *testing.T) {
	requirements := nodeAuthorizationRequirements("node", "mounts/media/files/copy", http.MethodPost,
		fileTargets{Source: "source.txt", Destination: "public/exact.txt", ConflictPolicy: "rename"})
	for _, requirement := range requirements {
		if requirement.Capability == "create" && strings.Contains(requirement.Path, "/files/mounts/") {
			if requirement.Path != "nodes/node/files/mounts/media/public" {
				t.Fatalf("rename scope=%s", requirement.Path)
			}
			return
		}
	}
	t.Fatal("no destination authorization")
}

func useServiceAccount(t *testing.T, h *shareHarness) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC()
	if err := h.storage.CreateServiceAccount(ctx, store.ServiceAccount{ID: "svc", Name: "svc", Enabled: true, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := h.storage.CreateServiceAccountToken(ctx, store.ServiceAccountToken{ID: "sat", ServiceAccountID: "svc", Name: "test", TokenHash: security.Digest("synthetic-service-token"), CreatedAt: now}, false); err != nil {
		t.Fatal(err)
	}
	if err := h.storage.CreateAccessGroup(ctx, store.AccessGroup{ID: "group", Name: "group", Enabled: true, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := h.storage.SetAccessGroupNodes(ctx, "group", []string{"nod_a"}); err != nil {
		t.Fatal(err)
	}
	if err := h.storage.SetServiceAccountGroups(ctx, "svc", []string{"group"}); err != nil {
		t.Fatal(err)
	}
	if err := h.storage.SetSubjectPolicies(ctx, "service_account", "svc", []string{"pol_share"}); err != nil {
		t.Fatal(err)
	}
	original := h.handler
	h.handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Header.Set("Authorization", "Bearer synthetic-service-token")
		original.ServeHTTP(w, r)
	})
}
