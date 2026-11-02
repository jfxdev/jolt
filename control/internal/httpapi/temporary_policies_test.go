package httpapi

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jfxdev/jolt/control/internal/store"
)

func TestTemporaryAgentAssignmentKeepsReadOnlyCeiling(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{}`))}, nil
	})}
	f := setupAgent(t, store.DefaultAgentLimits(), client)
	base := "/api/v1/control-tower/service-accounts/" + f.accountID + "/policies/temporary"
	request := func(method, path, body string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		f.handler.ServeHTTP(w, authenticatedRequest(method, path, f.adminSession, []byte(body)))
		return w
	}
	if w := request("POST", base, `{"policy_id":"wide"}`); w.Code != http.StatusCreated || !strings.Contains(w.Body.String(), "expires_at") {
		t.Fatalf("grant: %d %s", w.Code, w.Body.String())
	}
	if w := request("GET", base, ""); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"policy_id":"wide"`) {
		t.Fatalf("list: %d %s", w.Code, w.Body.String())
	}
	if w := request("POST", base, `{"policy_id":"wide","duration_seconds":3601}`); w.Code != http.StatusBadRequest {
		t.Fatalf("excessive duration: %d %s", w.Code, w.Body.String())
	}
	response := httptest.NewRecorder()
	f.handler.ServeHTTP(response, f.request("DELETE", "/api/v1/nodes/n1/mounts/m/files?path=test"))
	if response.Code != http.StatusForbidden || !strings.Contains(response.Body.String(), "agent_read_only") {
		t.Fatalf("temporary policy exceeded agent ceiling: %d %s", response.Code, response.Body.String())
	}
	if w := request("DELETE", base+"/wide", ""); w.Code != http.StatusNoContent {
		t.Fatalf("revoke: %d %s", w.Code, w.Body.String())
	}
	events, _, err := f.storage.ListAuditEvents(context.Background(), store.AuditQuery{Limit: 100})
	found := false
	for _, event := range events {
		if event.Action == "grant_temporary_policy" && event.Detail["expires_at"] != nil {
			found = true
		}
	}
	if err != nil || !found {
		t.Fatalf("missing grant audit: %+v %v", events, err)
	}
}
