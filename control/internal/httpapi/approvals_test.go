package httpapi

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jfxdev/jolt/control/internal/config"
	"github.com/jfxdev/jolt/control/internal/rbac"
	"github.com/jfxdev/jolt/control/internal/security"
	"github.com/jfxdev/jolt/control/internal/store"
)

const approvalMount = "nodes/n1/files/mounts/m"

type approvalNodeCall struct {
	method, path, query, body, idempotency string
}

type approvalHarness struct {
	*typedHarness
	mutex sync.Mutex
	calls []approvalNodeCall
}

func (h *approvalHarness) nodeCalls() []approvalNodeCall {
	h.mutex.Lock()
	defer h.mutex.Unlock()
	return append([]approvalNodeCall(nil), h.calls...)
}

// newApprovalHarness starts a Control Tower with approvals on (or off) and a
// node that records what reaches it. operator may delete only with approval.
func newApprovalHarness(t *testing.T, approvals bool, options ...func(*config.Config)) *approvalHarness {
	t.Helper()
	h := &approvalHarness{}
	h.typedHarness = newTypedHarness(t, false, func(r *http.Request) (int, http.Header, string) {
		header := make(http.Header)
		header.Set("Content-Type", "application/json")
		if r.URL.Path == "/api/v1/node" {
			return 200, header, `{"node_id":"n1","capabilities":[]}`
		}
		body, _ := io.ReadAll(r.Body)
		h.mutex.Lock()
		h.calls = append(h.calls, approvalNodeCall{method: r.Method, path: r.URL.Path, query: r.URL.Query().Get("path"), body: string(body), idempotency: r.Header.Get("Idempotency-Key")})
		h.mutex.Unlock()
		return 200, header, `{"done":true}`
	}, append([]func(*config.Config){func(cfg *config.Config) {
		cfg.Approvals, cfg.SignedLocalReads, cfg.SignedUploads, cfg.SignedLocalJobs = approvals, false, false, false
	}}, options...)...)
	h.setPolicy(t, "operator-policy", []rbac.Rule{
		{Path: approvalMount + "/**", Capabilities: []string{"read", "list", "delete", "update", "create"}, NeedsApproval: []string{"delete", "update"}},
		{Path: "nodes/n1/jobs", Capabilities: []string{"create", "list"}},
	}, "operator")
	return h
}

func (h *approvalHarness) setPolicy(t *testing.T, id string, rules []rbac.Rule, subject string) {
	t.Helper()
	now := time.Now().UTC()
	if err := h.storage.CreatePolicy(context.Background(), store.Policy{ID: id, Name: id, CreatedAt: now, UpdatedAt: now, Rules: rules}); err != nil {
		t.Fatal(err)
	}
	if err := h.storage.SetSubjectPolicies(context.Background(), "user", subject, []string{id}); err != nil {
		t.Fatal(err)
	}
}

func (h *approvalHarness) addUser(t *testing.T, id string) {
	t.Helper()
	now := time.Now().UTC()
	if err := h.storage.CreateUser(context.Background(), store.User{ID: id, Username: id, PasswordHash: "unused", Role: "operator", Enabled: true, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	h.sessions[id] = id + "-session"
	if err := h.storage.CreateSession(context.Background(), security.Digest(h.sessions[id]), id, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
}

func decodeBody(t *testing.T, w *httptest.ResponseRecorder, into any) {
	t.Helper()
	if err := json.Unmarshal(w.Body.Bytes(), into); err != nil {
		t.Fatalf("%v: %s", err, w.Body)
	}
}

func (h *approvalHarness) request(t *testing.T, user, method, path string, body any) (pendingID string) {
	t.Helper()
	w := h.do(user, method, path, body)
	if w.Code != http.StatusAccepted {
		t.Fatalf("%s %s: %d %s", method, path, w.Code, w.Body)
	}
	var out struct {
		ID    string `json:"pending_operation_id"`
		State string `json:"state"`
	}
	decodeBody(t, w, &out)
	if !strings.HasPrefix(out.ID, "pop_") || out.State != "pending_approval" || w.Header().Get("Location") != "/api/v1/control-tower/pending-operations/"+out.ID {
		t.Fatalf("response %+v location=%q", out, w.Header().Get("Location"))
	}
	return out.ID
}

const decide = "/api/v1/control-tower/pending-operations/"

func TestApprovedDeleteRunsOnceAsTheApprover(t *testing.T) {
	h := newApprovalHarness(t, true)
	id := h.request(t, "operator", http.MethodDelete, "/api/v1/nodes/n1/mounts/m/files?path=docs/a.txt", nil)
	if len(h.nodeCalls()) != 0 {
		t.Fatalf("the request reached the node before approval: %+v", h.nodeCalls())
	}
	// The same request again does not queue a second approval.
	if again := h.request(t, "operator", http.MethodDelete, "/api/v1/nodes/n1/mounts/m/files?path=docs/a.txt", nil); again != id {
		t.Fatalf("duplicate queued as %s", again)
	}
	// The requester cannot decide, and an unrelated operator cannot even look.
	if w := h.do("operator", http.MethodPost, decide+id+"/approve", nil); w.Code != http.StatusForbidden {
		t.Fatalf("requester approval: %d %s", w.Code, w.Body)
	}
	h.addUser(t, "bystander")
	if w := h.do("bystander", http.MethodGet, decide+id, nil); w.Code != http.StatusForbidden {
		t.Fatalf("bystander read: %d", w.Code)
	}
	if w := h.do("operator", http.MethodGet, decide+id, nil); w.Code != http.StatusOK {
		t.Fatalf("requester read: %d", w.Code)
	}
	w := h.do("admin", http.MethodPost, decide+id+"/approve", nil)
	var out struct {
		Operation struct {
			State       string `json:"state"`
			DecidedByID string `json:"decided_by_id"`
		} `json:"pending_operation"`
		Result   struct{ Status int } `json:"result"`
		Replayed bool                 `json:"replayed"`
	}
	decodeBody(t, w, &out)
	if w.Code != http.StatusOK || out.Operation.State != "executed" || out.Operation.DecidedByID != "admin" || out.Result.Status != 200 || out.Replayed {
		t.Fatalf("approve: %d %s", w.Code, w.Body)
	}
	calls := h.nodeCalls()
	if len(calls) != 1 || calls[0].method != http.MethodDelete || calls[0].query != "docs/a.txt" {
		t.Fatalf("node calls %+v", calls)
	}
	// Approving again answers with the stored result and does not run it again.
	w = h.do("admin", http.MethodPost, decide+id+"/approve", nil)
	decodeBody(t, w, &out)
	if w.Code != http.StatusOK || !out.Replayed || len(h.nodeCalls()) != 1 {
		t.Fatalf("repeat: %d %s calls=%d", w.Code, w.Body, len(h.nodeCalls()))
	}
}

func TestEveryCapabilityNotMarkedStillRunsDirectly(t *testing.T) {
	h := newApprovalHarness(t, true)
	if w := h.do("operator", http.MethodGet, "/api/v1/nodes/n1/mounts/m/files?path=docs", nil); w.Code != http.StatusOK {
		t.Fatalf("an unmarked read was held for approval: %d %s", w.Code, w.Body)
	}
	if len(h.nodeCalls()) != 1 {
		t.Fatalf("calls %+v", h.nodeCalls())
	}
}

func TestMoveIsKeptWithItsBodyAndReplayedWithAStableKey(t *testing.T) {
	h := newApprovalHarness(t, true)
	body := map[string]any{"source_path": "docs/a.txt", "destination_path": "docs/b.txt"}
	id := h.request(t, "operator", http.MethodPost, "/api/v1/nodes/n1/mounts/m/files/move", body)
	if w := h.do("admin", http.MethodPost, decide+id+"/approve", nil); w.Code != http.StatusOK {
		t.Fatalf("approve: %d %s", w.Code, w.Body)
	}
	calls := h.nodeCalls()
	if len(calls) != 1 || calls[0].method != http.MethodPost || !strings.HasSuffix(calls[0].path, "/files/move") || calls[0].idempotency != "approval-"+id {
		t.Fatalf("calls %+v", calls)
	}
	var sent map[string]any
	if err := json.Unmarshal([]byte(calls[0].body), &sent); err != nil || sent["source_path"] != "docs/a.txt" || sent["destination_path"] != "docs/b.txt" {
		t.Fatalf("body %q %v", calls[0].body, err)
	}
}

func TestRejectedRequestNeverRuns(t *testing.T) {
	h := newApprovalHarness(t, true)
	id := h.request(t, "operator", http.MethodDelete, "/api/v1/nodes/n1/mounts/m/files?path=docs/a.txt", nil)
	if w := h.do("operator", http.MethodPost, decide+id+"/reject", nil); w.Code != http.StatusForbidden {
		t.Fatalf("requester reject: %d", w.Code)
	}
	if w := h.do("admin", http.MethodPost, decide+id+"/reject", map[string]any{"note": "not this one"}); w.Code != http.StatusOK {
		t.Fatalf("reject: %d %s", w.Code, w.Body)
	}
	if w := h.do("admin", http.MethodPost, decide+id+"/approve", nil); w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "pending_operation_rejected") {
		t.Fatalf("approving a rejected request: %d %s", w.Code, w.Body)
	}
	if w := h.do("admin", http.MethodPost, decide+id+"/reject", nil); w.Code != http.StatusConflict {
		t.Fatalf("rejecting twice: %d", w.Code)
	}
	if w := h.do("admin", http.MethodPost, decide+id+"/reject", map[string]any{"note": strings.Repeat("x", 300)}); w.Code != http.StatusBadRequest {
		t.Fatalf("long note: %d", w.Code)
	}
	if len(h.nodeCalls()) != 0 {
		t.Fatalf("a rejected request reached the node: %+v", h.nodeCalls())
	}
}

func TestExpiredRequestCannotBeApproved(t *testing.T) {
	h := newApprovalHarness(t, true)
	op, _, err := h.storage.CreatePendingOperation(context.Background(), store.PendingOperation{
		RequesterType: "user", RequesterID: "operator", Method: http.MethodDelete, NodeID: "n1", Resource: "mounts/m/files", RawQuery: "path=docs/a.txt",
		Requirements: []store.PendingRequirement{{Path: approvalMount + "/docs/a.txt", Capability: "delete"}},
	}, 5, time.Now().Add(-store.PendingLifetime-time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if w := h.do("admin", http.MethodPost, decide+op.ID+"/approve", nil); w.Code != http.StatusGone {
		t.Fatalf("approve: %d %s", w.Code, w.Body)
	}
	if len(h.nodeCalls()) != 0 {
		t.Fatal("an expired request ran")
	}
}

func TestSelfApprovalNeedsAnExplicitAcknowledgement(t *testing.T) {
	h := newApprovalHarness(t, true)
	h.addUser(t, "boss")
	h.setPolicy(t, "boss-policy", []rbac.Rule{
		{Path: approvalMount + "/**", Capabilities: []string{"read", "list", "delete"}, NeedsApproval: []string{"delete"}},
		{Path: "nodes/n1/jobs", Capabilities: []string{"create"}},
		{Path: approvalsResource, Capabilities: []string{"sudo", "list"}},
	}, "boss")
	id := h.request(t, "boss", http.MethodDelete, "/api/v1/nodes/n1/mounts/m/files?path=docs/mine.txt", nil)
	if w := h.do("boss", http.MethodPost, decide+id+"/approve", nil); w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "self_approval_requires_acknowledgement") {
		t.Fatalf("without acknowledgement: %d %s", w.Code, w.Body)
	}
	if len(h.nodeCalls()) != 0 {
		t.Fatal("ran without the acknowledgement")
	}
	if w := h.do("boss", http.MethodPost, decide+id+"/approve", map[string]any{"acknowledge_self_approval": true}); w.Code != http.StatusOK {
		t.Fatalf("with acknowledgement: %d %s", w.Code, w.Body)
	}
	if len(h.nodeCalls()) != 1 {
		t.Fatalf("calls %+v", h.nodeCalls())
	}
}

func TestApproverNeedsTheOperationPermissionToo(t *testing.T) {
	h := newApprovalHarness(t, true)
	h.addUser(t, "clerk")
	// May decide requests but may not delete anything in the mount.
	h.setPolicy(t, "clerk-policy", []rbac.Rule{{Path: approvalsResource, Capabilities: []string{"sudo", "list"}}}, "clerk")
	id := h.request(t, "operator", http.MethodDelete, "/api/v1/nodes/n1/mounts/m/files?path=docs/a.txt", nil)
	w := h.do("clerk", http.MethodPost, decide+id+"/approve", nil)
	var out struct {
		Operation struct{ State string } `json:"pending_operation"`
		Result    struct{ Status int }   `json:"result"`
	}
	decodeBody(t, w, &out)
	if out.Operation.State != "failed" || out.Result.Status != http.StatusForbidden || len(h.nodeCalls()) != 0 {
		t.Fatalf("an approver without delete ran it: %d %s calls=%+v", w.Code, w.Body, h.nodeCalls())
	}
}

func TestApprovalIsRefusedWhenTheRequesterLostAccess(t *testing.T) {
	h := newApprovalHarness(t, true)
	id := h.request(t, "operator", http.MethodDelete, "/api/v1/nodes/n1/mounts/m/files?path=docs/a.txt", nil)
	if err := h.storage.SetSubjectPolicies(context.Background(), "user", "operator", nil); err != nil {
		t.Fatal(err)
	}
	if w := h.do("admin", http.MethodPost, decide+id+"/approve", nil); w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "requester_not_allowed") {
		t.Fatalf("approve: %d %s", w.Code, w.Body)
	}
	if len(h.nodeCalls()) != 0 {
		t.Fatal("a request ran for someone who lost access")
	}
	op, err := h.storage.GetPendingOperation(context.Background(), id, time.Now())
	if err != nil || op.State != store.PendingRejected {
		t.Fatalf("state %+v %v", op, err)
	}
}

func TestMarkedCapabilitiesAreRefusedWhereARequestCannotBeKept(t *testing.T) {
	h := newApprovalHarness(t, true)
	// An overwriting upload needs update, which is marked, and uploads cannot be
	// stored for approval: it must be refused, not granted.
	w := h.do("operator", http.MethodPut, "/api/v1/nodes/n1/mounts/m/files/content?path=docs/a.txt&overwrite=true", nil)
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "approval_unsupported") {
		t.Fatalf("upload: %d %s", w.Code, w.Body)
	}
	// A listing in the policy path family without any support is also unaffected.
	if len(h.nodeCalls()) != 0 {
		t.Fatalf("calls %+v", h.nodeCalls())
	}
}

func TestMarkedCapabilitiesStayRefusedWhenApprovalsAreOff(t *testing.T) {
	h := newApprovalHarness(t, false)
	for _, test := range []struct{ method, path string }{
		{http.MethodDelete, "/api/v1/nodes/n1/mounts/m/files?path=docs/a.txt"},
		{http.MethodPost, "/api/v1/nodes/n1/mounts/m/files/move"},
	} {
		var body any
		if test.method == http.MethodPost {
			body = map[string]any{"source_path": "a", "destination_path": "b"}
		}
		if w := h.do("operator", test.method, test.path, body); w.Code != http.StatusForbidden {
			t.Fatalf("%s: %d %s", test.path, w.Code, w.Body)
		}
	}
	if len(h.nodeCalls()) != 0 {
		t.Fatalf("calls %+v", h.nodeCalls())
	}
	// The unmarked capabilities of the same rule keep working.
	if w := h.do("operator", http.MethodGet, "/api/v1/nodes/n1/mounts/m/files?path=docs", nil); w.Code != http.StatusOK {
		t.Fatalf("read: %d", w.Code)
	}
	for _, path := range []string{strings.TrimSuffix(decide, "/"), decide + "pop_x", decide + "pop_x/approve", decide + "pop_x/reject"} {
		method := http.MethodPost
		if !strings.Contains(path, "/approve") && !strings.Contains(path, "/reject") {
			method = http.MethodGet
		}
		if w := h.do("admin", method, path, nil); w.Code != http.StatusNotFound || !strings.Contains(w.Body.String(), "approvals_disabled") {
			t.Fatalf("%s %s: %d %s", method, path, w.Code, w.Body)
		}
	}
}

func TestApprovalMarksNeedTheFeatureAndAValidRule(t *testing.T) {
	rule := func(extra map[string]any) []map[string]any {
		r := map[string]any{"path": approvalMount + "/**", "capabilities": []string{"read", "delete"}, "needs_approval": []string{"delete"}}
		for key, value := range extra {
			r[key] = value
		}
		return []map[string]any{r}
	}
	for name, test := range map[string]struct {
		rules           []map[string]any
		wantOff, wantOn int
	}{
		"delete marked":                    {rule(nil), 400, 201},
		"not granted by the rule":          {rule(map[string]any{"capabilities": []string{"read"}}), 400, 400},
		"on a denial":                      {rule(map[string]any{"capabilities": []string{"deny"}}), 400, 400},
		"a capability that is not allowed": {rule(map[string]any{"needs_approval": []string{"read"}, "capabilities": []string{"read"}}), 400, 400},
		"repeated":                         {rule(map[string]any{"needs_approval": []string{"delete", "delete"}}), 400, 400},
		"no marks":                         {rule(map[string]any{"needs_approval": []string{}}), 201, 201},
	} {
		for _, approvals := range []bool{false, true} {
			h := newApprovalHarness(t, approvals)
			w := h.do("admin", http.MethodPost, "/api/v1/control-tower/policies", map[string]any{"name": "policy-x", "description": "", "rules": test.rules})
			want := test.wantOff
			if approvals {
				want = test.wantOn
			}
			if w.Code != want {
				t.Fatalf("%s approvals=%v: %d want %d: %s", name, approvals, w.Code, want, w.Body)
			}
		}
	}
	// A policy that carries marks cannot be edited while the feature is off: the
	// editor would drop them.
	h := newApprovalHarness(t, false)
	if w := h.do("admin", http.MethodPatch, "/api/v1/control-tower/policies/operator-policy", map[string]any{"name": "operator-policy", "description": "", "rules": []map[string]any{{"path": "nodes/n1", "capabilities": []string{"read"}}}}); w.Code != http.StatusConflict {
		t.Fatalf("editing marked policy with approvals off: %d %s", w.Code, w.Body)
	}
}

func TestPendingListIsForApproversAndRequesters(t *testing.T) {
	h := newApprovalHarness(t, true)
	h.request(t, "operator", http.MethodDelete, "/api/v1/nodes/n1/mounts/m/files?path=docs/a.txt", nil)
	var list struct {
		Items []struct {
			ID            string `json:"pending_operation_id"`
			State         string `json:"state"`
			RequesterName string `json:"requester_name"`
		} `json:"items"`
	}
	w := h.do("admin", http.MethodGet, "/api/v1/control-tower/pending-operations?state=pending", nil)
	decodeBody(t, w, &list)
	if w.Code != http.StatusOK || len(list.Items) != 1 || list.Items[0].RequesterName != "operator" {
		t.Fatalf("approver list: %d %s", w.Code, w.Body)
	}
	if strings.Contains(w.Body.String(), "docs/a.txt") == false {
		t.Fatalf("the approver cannot see what is being asked: %s", w.Body)
	}
	if w := h.do("operator", http.MethodGet, "/api/v1/control-tower/pending-operations", nil); w.Code != http.StatusForbidden {
		t.Fatalf("requester full list: %d", w.Code)
	}
	list.Items = nil
	w = h.do("operator", http.MethodGet, "/api/v1/control-tower/pending-operations?mine=true", nil)
	decodeBody(t, w, &list)
	if w.Code != http.StatusOK || len(list.Items) != 1 {
		t.Fatalf("own list: %d %s", w.Code, w.Body)
	}
	h.addUser(t, "bystander")
	list.Items = nil
	w = h.do("bystander", http.MethodGet, "/api/v1/control-tower/pending-operations?mine=true", nil)
	decodeBody(t, w, &list)
	if w.Code != http.StatusOK || len(list.Items) != 0 {
		t.Fatalf("someone else's requests leaked: %d %s", w.Code, w.Body)
	}
}

func TestOnlyTheWebhookSummaryLeavesTheServer(t *testing.T) {
	var mutex sync.Mutex
	var received []string
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mutex.Lock()
		received = append(received, string(body))
		mutex.Unlock()
	}))
	defer hook.Close()
	h := newApprovalHarness(t, true, func(cfg *config.Config) { cfg.ApprovalWebhookURL = hook.URL })
	h.request(t, "operator", http.MethodDelete, "/api/v1/nodes/n1/mounts/m/files?path=docs/secret-name.txt", nil)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		mutex.Lock()
		count := len(received)
		mutex.Unlock()
		if count > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	mutex.Lock()
	defer mutex.Unlock()
	if len(received) != 1 {
		t.Fatalf("webhook calls: %d", len(received))
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(received[0]), &payload); err != nil || payload["event"] != "pending_operation" || payload["operation"] != "delete" || payload["mount_id"] != "m" {
		t.Fatalf("payload %s %v", received[0], err)
	}
	if strings.Contains(received[0], "secret-name") || strings.Contains(received[0], "docs/") {
		t.Fatalf("a path leaked in the notification: %s", received[0])
	}
}

func TestAnAgentCannotAskForApproval(t *testing.T) {
	server := &Server{config: config.Config{Approvals: true}}
	plain := httptest.NewRequest(http.MethodDelete, "/", nil)
	if _, collector := server.withApprovalCollector(plain, "mounts/m/files"); collector == nil {
		t.Fatal("an ordinary request cannot be kept for approval")
	}
	agent := plain.WithContext(context.WithValue(plain.Context(), agentKey, agentContext{}))
	if _, collector := server.withApprovalCollector(agent, "mounts/m/files"); collector != nil {
		t.Fatal("an agent request could be kept for approval")
	}
	if _, collector := server.withApprovalCollector(plain, "mounts/m/files/content"); collector != nil {
		t.Fatal("a route that cannot be replayed was armed for approval")
	}
}

func TestAReplayCannotReachBeyondWhatWasApproved(t *testing.T) {
	h := newApprovalHarness(t, true)
	h.addUser(t, "clerk")
	// The clerk's own delete is marked too, so only the grant of the approved
	// request lets the replay through the gate.
	h.setPolicy(t, "clerk-policy", []rbac.Rule{
		{Path: approvalMount + "/**", Capabilities: []string{"read", "delete"}, NeedsApproval: []string{"delete"}},
		{Path: approvalsResource, Capabilities: []string{"sudo", "list"}},
	}, "clerk")
	// The approved requirements name one file; the stored request names another.
	op, _, err := h.storage.CreatePendingOperation(context.Background(), store.PendingOperation{
		RequesterType: "user", RequesterID: "operator", Method: http.MethodDelete, NodeID: "n1", Resource: "mounts/m/files", RawQuery: "path=docs/other.txt",
		Requirements: []store.PendingRequirement{{Path: approvalMount + "/docs/a.txt", Capability: "delete"}},
	}, 5, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	w := h.do("clerk", http.MethodPost, decide+op.ID+"/approve", nil)
	var out struct {
		Operation struct{ State string } `json:"pending_operation"`
		Result    struct{ Status int }   `json:"result"`
	}
	decodeBody(t, w, &out)
	if out.Operation.State != "failed" || out.Result.Status != http.StatusForbidden || len(h.nodeCalls()) != 0 {
		t.Fatalf("a replay went past its approval: %d %s calls=%+v", w.Code, w.Body, h.nodeCalls())
	}
	open, err := h.storage.ListPendingOperations(context.Background(), store.PendingState, "user", "clerk", 10, time.Now())
	if err != nil || len(open) != 0 {
		t.Fatalf("the replay queued another approval: %+v %v", open, err)
	}
}

func TestEffectiveAccessShowsAGrantThatWaitsForApproval(t *testing.T) {
	for _, approvals := range []bool{true, false} {
		h := newApprovalHarness(t, approvals)
		out, code := askEffective(t, h.typedHarness, "admin", "user", "operator", map[string]string{"path": approvalMount + "/docs/a.txt", "entry_type": "file"})
		if code != http.StatusOK {
			t.Fatalf("code %d", code)
		}
		deleted, read := out.Results[0].Capabilities["delete"], out.Results[0].Capabilities["read"]
		wantOutcome := map[bool]string{true: "approval", false: "denied"}[approvals]
		if deleted.Outcome != wantOutcome || deleted.Allowed || read.Outcome != "allowed" || !read.Allowed {
			t.Fatalf("approvals=%v: delete=%+v read=%+v", approvals, deleted, read)
		}
	}
}
