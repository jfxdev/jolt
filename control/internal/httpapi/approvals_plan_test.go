package httpapi

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/jfxdev/jolt/control/internal/config"
	"github.com/jfxdev/jolt/control/internal/rbac"
)

type planNodeCall struct {
	method, path, subject, idempotency string
}

type planApprovalHarness struct {
	*typedHarness
	mutex sync.Mutex
	calls []planNodeCall
	// files, directories and bytes are what the node counts when asked to plan.
	files, directories, bytes int64
	plans                     int
	// capabilities is what the node reports; empty means a node that predates them.
	capabilities string
}

const planNodeCapabilities = `["destructive_plans_v1","signed_local_copy_execution_v1","signed_job_authorization_registration_v1","signed_job_authorization_status_v1","signed_job_options_binding_v1"]`

func (h *planApprovalHarness) seen() []planNodeCall {
	h.mutex.Lock()
	defer h.mutex.Unlock()
	return append([]planNodeCall(nil), h.calls...)
}

func (h *planApprovalHarness) count(method, suffix string) int {
	total := 0
	for _, call := range h.seen() {
		if call.method == method && strings.HasSuffix(call.path, suffix) {
			total++
		}
	}
	return total
}

func newPlanApprovalHarness(t *testing.T) *planApprovalHarness {
	t.Helper()
	h := &planApprovalHarness{files: 2, directories: 3, bytes: 2048, capabilities: planNodeCapabilities}
	h.typedHarness = newTypedHarness(t, false, func(r *http.Request) (int, http.Header, string) {
		header := make(http.Header)
		header.Set("Content-Type", "application/json")
		var body []byte
		if r.Body != nil {
			body, _ = io.ReadAll(r.Body)
		}
		var payload struct {
			Subject string `json:"subject_id"`
		}
		_ = json.Unmarshal(body, &payload)
		if r.URL.Path != "/api/v1/node" {
			h.mutex.Lock()
			h.calls = append(h.calls, planNodeCall{r.Method, r.URL.Path, payload.Subject, r.Header.Get("Idempotency-Key")})
			h.mutex.Unlock()
		}
		switch {
		case r.URL.Path == "/api/v1/node":
			return 200, header, `{"node_id":"n1","capabilities":` + h.capabilities + `}`
		case r.URL.Path == "/api/v1/mounts/m/files/destructive-plans":
			h.mutex.Lock()
			h.plans++
			id := h.plans
			h.mutex.Unlock()
			return 201, header, fmt.Sprintf(`{"plan_id":"plan%d","token":"token-%d","operation":"delete","mount_id":"m","source_path":"tree","files":%d,"directories":%d,"bytes":%d}`, id, id, h.files, h.directories, h.bytes)
		case strings.HasSuffix(r.URL.Path, "/accept"):
			return 202, header, `{"job_id":"job1","type":"delete","state":"waiting_validation","mount_id":"m","source_path":"tree","recursive":true,"max_attempts":1}`
		case r.URL.Path == "/api/v1/jobs/job1":
			return 200, header, `{"job_id":"job1","type":"delete","state":"waiting_validation","mount_id":"m","source_path":"tree","recursive":true,"max_attempts":1}`
		case r.URL.Path == "/api/v1/jobs/job1/authorization" && r.Method == http.MethodGet:
			header.Set("X-Jolt-Job-Authorization-Status", "v1")
			return 200, header, `{"revision":0,"expires_at":null,"envelope_digest":"","execution_enabled":false}`
		case r.URL.Path == "/api/v1/jobs/job1/cancel":
			return 200, header, `{"job_id":"job1","state":"canceled"}`
		}
		return 500, header, `{"error":{"code":"unavailable","message":"x"}}`
	}, func(cfg *config.Config) { cfg.Approvals = true })
	h.setPolicyFor(t, "operator-policy", []rbac.Rule{
		{Path: approvalMount + "/**", Capabilities: []string{"read", "list", "delete"}, NeedsApproval: []string{"delete"}},
		{Path: "nodes/n1/jobs", Capabilities: []string{"create", "list", "execute"}},
	}, "operator")
	return h
}

func (h *planApprovalHarness) setPolicyFor(t *testing.T, id string, rules []rbac.Rule, subject string) {
	t.Helper()
	(&approvalHarness{typedHarness: h.typedHarness}).setPolicy(t, id, rules, subject)
}

const planURL = "/api/v1/nodes/n1/mounts/m/files/destructive-plans"

func TestAFolderDeleteThatNeedsApprovalIsPlannedForTheApproverNotTheRequester(t *testing.T) {
	h := newPlanApprovalHarness(t)
	w := h.do("operator", http.MethodPost, planURL, map[string]any{"operation": "delete", "source_path": "tree"})
	var notice struct {
		ID          string `json:"pending_operation_id"`
		State       string `json:"state"`
		Token       string `json:"token"`
		PlanID      string `json:"plan_id"`
		Files       int64  `json:"files"`
		Directories int64  `json:"directories"`
		Bytes       int64  `json:"bytes"`
	}
	decodeBody(t, w, &notice)
	if w.Code != http.StatusAccepted || notice.State != "pending_approval" || notice.Files != 2 || notice.Directories != 3 || notice.Bytes != 2048 {
		t.Fatalf("request: %d %s", w.Code, w.Body)
	}
	if notice.Token != "" || notice.PlanID != "" || strings.Contains(w.Body.String(), "token-1") {
		t.Fatalf("the requester was handed a way to confirm: %s", w.Body)
	}
	if h.count("POST", "/accept") != 0 {
		t.Fatal("something was confirmed before the approval")
	}
	// Asking again for the same folder does not queue another approval.
	again := h.do("operator", http.MethodPost, planURL, map[string]any{"operation": "delete", "source_path": "tree"})
	var second struct {
		ID string `json:"pending_operation_id"`
	}
	decodeBody(t, again, &second)
	if second.ID != notice.ID {
		t.Fatalf("duplicate queued: %s vs %s", second.ID, notice.ID)
	}
	approve := h.do("admin", http.MethodPost, decide+notice.ID+"/approve", nil)
	var out struct {
		Operation struct{ State string } `json:"pending_operation"`
		Result    struct{ Status int }   `json:"result"`
	}
	decodeBody(t, approve, &out)
	if approve.Code != http.StatusOK || out.Operation.State != "executed" || out.Result.Status != http.StatusAccepted {
		t.Fatalf("approve: %d %s", approve.Code, approve.Body)
	}
	// The approver planned and confirmed it as themselves, with a key that
	// cannot start a second job.
	var accept planNodeCall
	for _, call := range h.seen() {
		if strings.HasSuffix(call.path, "/accept") {
			accept = call
		}
	}
	if accept.subject != "admin" || accept.idempotency != "approval-"+notice.ID {
		t.Fatalf("accept: %+v", accept)
	}
	approvals := 0
	for _, call := range h.seen() {
		if call.method == "POST" && call.path == "/api/v1/mounts/m/files/destructive-plans" && call.subject == "admin" {
			approvals++
		}
	}
	if approvals != 1 {
		t.Fatalf("the approver planned %d times: %+v", approvals, h.seen())
	}
	link, err := h.storage.GetJobAuthorizationLink(t.Context(), "n1", "job1")
	if err != nil || link.ActorID != "admin" {
		t.Fatalf("the job is not the approver's: %+v %v", link, err)
	}
	// Repeating the approval does not plan or confirm again.
	before := len(h.seen())
	repeat := h.do("admin", http.MethodPost, decide+notice.ID+"/approve", nil)
	if repeat.Code != http.StatusOK || !strings.Contains(repeat.Body.String(), `"replayed":true`) || len(h.seen()) != before {
		t.Fatalf("repeat: %d %s calls %d→%d", repeat.Code, repeat.Body, before, len(h.seen()))
	}
}

func TestAnApprovedFolderIsNotDeletedIfTheTreeChangedMeanwhile(t *testing.T) {
	h := newPlanApprovalHarness(t)
	w := h.do("operator", http.MethodPost, planURL, map[string]any{"operation": "delete", "source_path": "tree"})
	var notice struct {
		ID string `json:"pending_operation_id"`
	}
	decodeBody(t, w, &notice)
	h.files = 40 // someone added files after the requester's plan
	approve := h.do("admin", http.MethodPost, decide+notice.ID+"/approve", nil)
	var out struct {
		Operation struct{ State string } `json:"pending_operation"`
		Result    struct{ Status int }   `json:"result"`
	}
	decodeBody(t, approve, &out)
	if out.Operation.State != "failed" || out.Result.Status != http.StatusConflict || !strings.Contains(approve.Body.String(), "tree_changed") {
		t.Fatalf("approve: %d %s", approve.Code, approve.Body)
	}
	if !strings.Contains(approve.Body.String(), "era 2 arquivos") || h.count("POST", "/accept") != 0 {
		t.Fatalf("a changed tree was confirmed or not explained: %s", approve.Body)
	}
}

func TestAStalePlanCannotBeConfirmedAroundTheApproval(t *testing.T) {
	h := newPlanApprovalHarness(t)
	// A plan made before the rule asked for approval: the token is spent, the
	// job is canceled, and nothing runs.
	w := h.doWith("operator", http.MethodPost, "/api/v1/nodes/n1/mounts/m/files/destructive-plans/plan9/confirm", map[string]any{"token": "old-token"}, map[string]string{"Idempotency-Key": "confirm-1"})
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "approval_required") {
		t.Fatalf("confirm: %d %s", w.Code, w.Body)
	}
	if h.count("POST", "/cancel") != 1 {
		t.Fatalf("the job was left waiting: %+v", h.seen())
	}
	if _, err := h.storage.GetJobAuthorizationLink(t.Context(), "n1", "job1"); err == nil {
		t.Fatal("a job that needs approval was bound to a lease")
	}
}

func TestAMoveOfAFolderAsksForApprovalOnItsSourceAndDestination(t *testing.T) {
	h := newPlanApprovalHarness(t)
	h.setPolicyFor(t, "operator-move", []rbac.Rule{
		{Path: approvalMount + "/**", Capabilities: []string{"read", "list", "create", "update"}, NeedsApproval: []string{"update"}},
		{Path: "nodes/n1/jobs", Capabilities: []string{"create", "list", "execute"}},
	}, "operator")
	w := h.do("operator", http.MethodPost, planURL, map[string]any{"operation": "move", "source_path": "tree", "destination_path": "elsewhere/tree"})
	if w.Code != http.StatusAccepted || !strings.Contains(w.Body.String(), "pending_approval") {
		t.Fatalf("move request: %d %s", w.Code, w.Body)
	}
	if h.count("POST", "/accept") != 0 {
		t.Fatal("a move was confirmed before approval")
	}
}

func TestAFolderDeleteWithoutAnyMarkIsPlannedAsBefore(t *testing.T) {
	h := newPlanApprovalHarness(t)
	h.setPolicyFor(t, "plain", []rbac.Rule{
		{Path: approvalMount + "/**", Capabilities: []string{"read", "list", "delete"}},
		{Path: "nodes/n1/jobs", Capabilities: []string{"create", "list", "execute"}},
	}, "operator")
	w := h.do("operator", http.MethodPost, planURL, map[string]any{"operation": "delete", "source_path": "tree"})
	if w.Code != http.StatusCreated || !strings.Contains(w.Body.String(), "token-1") {
		t.Fatalf("plain plan: %d %s", w.Code, w.Body)
	}
}
