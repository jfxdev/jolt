package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jfxdev/jolt/control/internal/rbac"
)

// A node that predates a feature must be told to upgrade, not trusted to cope:
// every route that rests on a capability refuses, and nothing that changes
// anything reaches the node.
func TestRoutesThatRestOnACapabilityRefuseOldNodes(t *testing.T) {
	t.Run("folder plans", func(t *testing.T) {
		h := newPlanApprovalHarness(t)
		h.capabilities = `[]`
		h.setPolicyFor(t, "plain", plainFolderRules(), "operator")
		w := h.do("operator", http.MethodPost, planURL, map[string]any{"operation": "delete", "source_path": "tree"})
		if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "node_upgrade_required") {
			t.Fatalf("plan: %d %s", w.Code, w.Body)
		}
		w = h.doWith("operator", http.MethodPost, planURL+"/plan1/confirm", map[string]any{"token": "t"}, map[string]string{"Idempotency-Key": "k1"})
		if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "node_upgrade_required") {
			t.Fatalf("confirm: %d %s", w.Code, w.Body)
		}
		for _, call := range h.seen() {
			if call.method != "GET" {
				t.Fatalf("an old node was asked to change something: %+v", h.seen())
			}
		}
	})
	t.Run("folder approvals", func(t *testing.T) {
		h := newPlanApprovalHarness(t)
		w := h.do("operator", http.MethodPost, planURL, map[string]any{"operation": "delete", "source_path": "tree"})
		var notice struct {
			ID string `json:"pending_operation_id"`
		}
		decodeBody(t, w, &notice)
		h.capabilities = `[]`
		approve := h.do("admin", http.MethodPost, decide+notice.ID+"/approve", nil)
		if !strings.Contains(approve.Body.String(), "node_upgrade_required") || h.count("POST", "/accept") != 0 {
			t.Fatalf("approve on an old node: %d %s", approve.Code, approve.Body)
		}
	})
	t.Run("transfers between nodes", func(t *testing.T) {
		fake := &transferFake{sourceIdentity: "source", destinationCaps: `[]`}
		handler, _, sessions := transferApprovalHarness(t, fake)
		for _, path := range []string{"/api/v1/nodes/destination/transfers/plan", "/api/v1/nodes/destination/transfers"} {
			request := authenticatedRequest(http.MethodPost, path, sessions["admin"], []byte(transferPayload))
			request.Header.Set("Idempotency-Key", "old-node")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), "node_upgrade_required") {
				t.Fatalf("%s: %d %s", path, response.Code, response.Body)
			}
		}
		if len(fake.createBodies) != 0 {
			t.Fatalf("a transfer was created on an old node: %+v", fake.createBodies)
		}
	})
}

func plainFolderRules() []rbac.Rule {
	return []rbac.Rule{
		{Path: approvalMount + "/**", Capabilities: []string{"read", "list", "delete"}},
		{Path: "nodes/n1/jobs", Capabilities: []string{"create", "list", "execute"}},
	}
}
