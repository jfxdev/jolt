package httpapi

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jfxdev/jolt/control/internal/config"
	"github.com/jfxdev/jolt/control/internal/filetypes"
	"github.com/jfxdev/jolt/control/internal/rbac"
	"github.com/jfxdev/jolt/control/internal/store"
)

type trashHarness struct {
	*typedHarness
	mutex sync.Mutex
	calls []string
	items map[string]map[string]any
	// mountOf lets a test make the node answer for another mount.
	capabilities string
}

func (h *trashHarness) record() []string {
	h.mutex.Lock()
	defer h.mutex.Unlock()
	return append([]string(nil), h.calls...)
}

func trashItem(id, path string) map[string]any {
	return map[string]any{"trash_id": id, "mount_id": "m", "path": path, "type": "file", "state": "stored",
		"deleted_at": "2026-11-06T12:00:00Z", "expires_at": "2026-12-06T12:00:00Z"}
}

func newTrashHarness(t *testing.T, rules []rbac.Rule, options ...func(*config.Config)) *trashHarness {
	t.Helper()
	h := &trashHarness{capabilities: `["trash_v1"]`, items: map[string]map[string]any{
		"tr_1_open":   trashItem("tr_1_open", "docs/report.txt"),
		"tr_2_secret": trashItem("tr_2_secret", "secret/plan.txt"),
		"tr_3_key":    trashItem("tr_3_key", "docs/key.pem"),
	}}
	h.typedHarness = newTypedHarness(t, false, func(r *http.Request) (int, http.Header, string) {
		header := make(http.Header)
		header.Set("Content-Type", "application/json")
		if r.URL.Path == "/api/v1/node" {
			return 200, header, `{"node_id":"n1","capabilities":` + h.capabilities + `}`
		}
		h.mutex.Lock()
		h.calls = append(h.calls, r.Method+" "+r.URL.Path)
		h.mutex.Unlock()
		path := strings.TrimPrefix(r.URL.Path, "/api/v1/mounts/m/trash")
		if path == "" {
			var list []map[string]any
			for _, item := range h.items {
				list = append(list, item)
			}
			body, _ := json.Marshal(map[string]any{"items": list})
			return 200, header, string(body)
		}
		id := strings.Trim(strings.TrimSuffix(path, "/restore"), "/")
		item, ok := h.items[id]
		if !ok {
			return 404, header, `{"error":{"code":"trash_not_found"}}`
		}
		body, _ := json.Marshal(item)
		return 200, header, string(body)
	}, append([]func(*config.Config){func(cfg *config.Config) {
		cfg.SignedLocalReads, cfg.SignedUploads, cfg.SignedLocalJobs = false, false, false
	}}, options...)...)
	now := time.Now().UTC()
	if err := h.storage.CreatePolicy(context.Background(), store.Policy{ID: "p", Name: "p", CreatedAt: now, UpdatedAt: now, Rules: rules}); err != nil {
		t.Fatal(err)
	}
	if err := h.storage.SetSubjectPolicies(context.Background(), "user", "operator", []string{"p"}); err != nil {
		t.Fatal(err)
	}
	return h
}

const trashURL = "/api/v1/nodes/n1/mounts/m/trash"

func docsRules(capabilities ...string) []rbac.Rule {
	return []rbac.Rule{{Path: approvalMount + "/docs/**", Capabilities: capabilities}}
}

func TestTrashListShowsOnlyWhatTheCallerCouldRead(t *testing.T) {
	h := newTrashHarness(t, docsRules("read", "list"))
	var list struct {
		Items []struct {
			ID string `json:"trash_id"`
		} `json:"items"`
	}
	w := h.do("operator", http.MethodGet, trashURL, nil)
	decodeBody(t, w, &list)
	ids := map[string]bool{}
	for _, item := range list.Items {
		ids[item.ID] = true
	}
	if w.Code != http.StatusOK || !ids["tr_1_open"] || !ids["tr_3_key"] || ids["tr_2_secret"] || len(ids) != 2 {
		t.Fatalf("list: %d %s", w.Code, w.Body)
	}
	if strings.Contains(w.Body.String(), "secret/plan.txt") {
		t.Fatalf("a name the caller cannot read leaked: %s", w.Body)
	}
	// An administrator sees everything.
	w = h.do("admin", http.MethodGet, trashURL, nil)
	decodeBody(t, w, &list)
	if len(list.Items) != 3 {
		t.Fatalf("admin list: %s", w.Body)
	}
}

func TestTrashEntryReadsAnswerAsNotFoundWhenTheCallerCannotSeeThem(t *testing.T) {
	h := newTrashHarness(t, docsRules("read", "list"))
	if w := h.do("operator", http.MethodGet, trashURL+"/tr_1_open", nil); w.Code != http.StatusOK {
		t.Fatalf("visible entry: %d %s", w.Code, w.Body)
	}
	hidden := h.do("operator", http.MethodGet, trashURL+"/tr_2_secret", nil)
	missing := h.do("operator", http.MethodGet, trashURL+"/tr_9_nothing", nil)
	if hidden.Code != http.StatusNotFound || missing.Code != http.StatusNotFound {
		t.Fatalf("hidden %d, missing %d", hidden.Code, missing.Code)
	}
	var a, b struct {
		Error struct{ Code string } `json:"error"`
	}
	decodeBody(t, hidden, &a)
	decodeBody(t, missing, &b)
	if a.Error.Code != b.Error.Code {
		t.Fatalf("an entry that exists answers differently from one that does not: %s vs %s", a.Error.Code, b.Error.Code)
	}
}

func TestRestoreNeedsCreateAndPurgeNeedsDeleteOnTheOriginalPath(t *testing.T) {
	h := newTrashHarness(t, docsRules("read", "list"))
	if w := h.do("operator", http.MethodPost, trashURL+"/tr_1_open/restore", nil); w.Code != http.StatusForbidden {
		t.Fatalf("restore without create: %d %s", w.Code, w.Body)
	}
	if w := h.do("operator", http.MethodDelete, trashURL+"/tr_1_open", nil); w.Code != http.StatusForbidden {
		t.Fatalf("purge without delete: %d %s", w.Code, w.Body)
	}
	for _, call := range h.record() {
		if strings.HasPrefix(call, "POST") || strings.HasPrefix(call, "DELETE") {
			t.Fatalf("a refused change reached the node: %v", h.record())
		}
	}
	h = newTrashHarness(t, docsRules("read", "list", "create", "delete"))
	if w := h.do("operator", http.MethodPost, trashURL+"/tr_1_open/restore", nil); w.Code != http.StatusOK {
		t.Fatalf("restore: %d %s", w.Code, w.Body)
	}
	if w := h.do("operator", http.MethodDelete, trashURL+"/tr_1_open", nil); w.Code != http.StatusOK {
		t.Fatalf("purge: %d %s", w.Code, w.Body)
	}
	// The entry under secret/ is outside every rule: neither is allowed.
	if w := h.do("operator", http.MethodPost, trashURL+"/tr_2_secret/restore", nil); w.Code != http.StatusNotFound && w.Code != http.StatusForbidden {
		t.Fatalf("restore outside the rules: %d", w.Code)
	}
	calls := strings.Join(h.record(), "\n")
	if !strings.Contains(calls, "POST /api/v1/mounts/m/trash/tr_1_open/restore") || !strings.Contains(calls, "DELETE /api/v1/mounts/m/trash/tr_1_open") || strings.Contains(calls, "tr_2_secret/restore") && strings.Contains(calls, "POST /api/v1/mounts/m/trash/tr_2_secret") {
		t.Fatalf("calls:\n%s", calls)
	}
}

func TestTrashRoutesFailClosedOnOldNodesAndOddRequests(t *testing.T) {
	h := newTrashHarness(t, docsRules("read", "list", "create", "delete"))
	h.capabilities = `[]`
	if w := h.do("operator", http.MethodGet, trashURL, nil); w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "node_upgrade_required") {
		t.Fatalf("old node: %d %s", w.Code, w.Body)
	}
	h.capabilities = `["trash_v1"]`
	for _, test := range []struct{ method, path string }{
		{http.MethodPut, trashURL}, {http.MethodPost, trashURL}, {http.MethodPatch, trashURL + "/tr_1_open"},
		{http.MethodGet, trashURL + "/tr_1_open/restore"}, {http.MethodPost, trashURL + "/tr_1_open/other"},
	} {
		if w := h.do("operator", test.method, test.path, nil); w.Code != http.StatusNotFound {
			t.Fatalf("%s %s: %d", test.method, test.path, w.Code)
		}
	}
	if w := h.do("operator", http.MethodGet, trashURL+"/..%2F..%2Fetc", nil); w.Code == http.StatusOK {
		t.Fatalf("an id with separators was accepted: %d", w.Code)
	}
	// A node that answers with an entry of another mount, or one not stored, is not believed.
	h.items["tr_1_open"]["mount_id"] = "other"
	if w := h.do("operator", http.MethodDelete, trashURL+"/tr_1_open", nil); w.Code != http.StatusBadGateway {
		t.Fatalf("foreign mount entry: %d %s", w.Code, w.Body)
	}
	h.items["tr_1_open"]["mount_id"] = "m"
	h.items["tr_1_open"]["state"] = "purging"
	if w := h.do("operator", http.MethodDelete, trashURL+"/tr_1_open", nil); w.Code != http.StatusBadGateway {
		t.Fatalf("entry in another state: %d", w.Code)
	}
	for _, call := range h.record() {
		if strings.HasPrefix(call, "DELETE") {
			t.Fatalf("a purge reached the node: %v", h.record())
		}
	}
}

func TestTrashFollowsTypedRulesOfThePathTheEntryHad(t *testing.T) {
	rules := []rbac.Rule{
		{Path: approvalMount + "/docs/**", Capabilities: []string{"read", "list", "create", "delete"}},
		{Path: approvalMount + "/docs/**", Capabilities: []string{"deny", "read"}, FileTypes: &filetypes.Selector{Extensions: []string{"pem"}}},
	}
	h := newTrashHarness(t, rules, func(cfg *config.Config) {
		cfg.TypedPolicies, cfg.SignedLocalReads, cfg.SignedUploads, cfg.SignedLocalJobs = true, true, true, true
	})
	var list struct {
		Items []struct {
			ID string `json:"trash_id"`
		} `json:"items"`
	}
	w := h.do("operator", http.MethodGet, trashURL, nil)
	decodeBody(t, w, &list)
	for _, item := range list.Items {
		if item.ID == "tr_3_key" {
			t.Fatalf("a key the caller cannot read is listed: %s", w.Body)
		}
	}
	if len(list.Items) != 1 || list.Items[0].ID != "tr_1_open" {
		t.Fatalf("list %s", w.Body)
	}
	if w := h.do("operator", http.MethodGet, trashURL+"/tr_3_key", nil); w.Code != http.StatusNotFound {
		t.Fatalf("hidden key entry: %d", w.Code)
	}
}

func TestCallerWithNoReadRuleSeesAnEmptyTrashNotAnError(t *testing.T) {
	var list struct {
		Items []json.RawMessage `json:"items"`
	}
	h := newTrashHarness(t, docsRules("list"))
	w := h.do("operator", http.MethodGet, trashURL, nil)
	decodeBody(t, w, &list)
	if w.Code != http.StatusOK || len(list.Items) != 0 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
}

func TestAnAgentNeverReachesTheTrash(t *testing.T) {
	var calls atomic.Int32
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(`{"node_id":"n1","capabilities":["trash_v1"],"items":[]}`))}, nil
	})}
	f := setupAgent(t, store.DefaultAgentLimits(), client)
	// The agent may read the mount, so a listing of what was deleted there
	// would pass the ordinary read check: the route refuses it by itself.
	for _, path := range []string{"/api/v1/nodes/n1/mounts/m/trash", "/api/v1/nodes/n1/mounts/m/trash/tr_1_a"} {
		response := httptest.NewRecorder()
		f.handler.ServeHTTP(response, f.request("GET", path))
		if response.Code != http.StatusForbidden || !strings.Contains(response.Body.String(), "trash_not_for_agents") {
			t.Fatalf("%s: %d %s", path, response.Code, response.Body)
		}
	}
	if calls.Load() != 0 {
		t.Fatalf("the node was asked on behalf of an agent: %d", calls.Load())
	}
}
