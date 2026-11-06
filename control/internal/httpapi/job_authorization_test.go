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

func TestJobActionsRevalidateCurrentFilePermissions(t *testing.T) {
	job := `{"job_id":"job-1","type":"copy_local","mount_id":"media","source_path":"source","destination_path":"destination/file","conflict_policy":"ask"}`
	mutations := 0
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		body := job
		if r.Method == http.MethodPost {
			mutations++
			body = `{}`
		}
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
	})}
	actor := store.User{ID: "actor", Username: "actor", Role: "operator", Enabled: true}
	handler, storage, session := testUserHandlerWithClient(t, actor, client)
	now := time.Now().UTC()
	token, err := security.Encrypt(make([]byte, 32), "node-token")
	if err != nil {
		t.Fatal(err)
	}
	if err := storage.SaveNode(context.Background(), store.Node{ID: "node", Name: "node", Endpoint: "http://node.test", TokenEncrypted: token, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	rules := []rbac.Rule{
		{Path: "nodes/node/jobs/**", Capabilities: []string{"execute", "update"}},
		{Path: "nodes/node/files/mounts/media/source/**", Capabilities: []string{"read"}},
		{Path: "nodes/node/files/mounts/media/destination/**", Capabilities: []string{"create", "update"}},
	}
	policy := store.Policy{ID: "policy", Name: "policy", Rules: rules, CreatedAt: now, UpdatedAt: now}
	if err := storage.CreatePolicy(context.Background(), policy); err != nil {
		t.Fatal(err)
	}
	if err := storage.SetSubjectPolicies(context.Background(), "user", actor.ID, []string{policy.ID}); err != nil {
		t.Fatal(err)
	}
	request := func(route string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, authenticatedRequest(http.MethodPost, "/api/v1/nodes/node/jobs/job-1/"+route, session, []byte(`{"action":"overwrite"}`)))
		return w
	}
	for _, route := range []string{"retry", "resume", "items/0/override"} {
		if w := request(route); w.Code != http.StatusOK {
			t.Fatalf("allowed %s: %d %s", route, w.Code, w.Body.String())
		}
	}
	// A job initially configured with fail can acquire persistent overwrite or
	// rename item actions through an override, including apply-to-following.
	// A later retry must not rely solely on its original conflict policy.
	job = `{"job_id":"job-1","type":"copy_local","mount_id":"media","source_path":"source","destination_path":"destination/file","conflict_policy":"fail"}`
	policy.Rules[2].Capabilities = []string{"create"}
	if err := storage.UpdatePolicy(context.Background(), policy); err != nil {
		t.Fatal(err)
	}
	before := mutations
	for _, route := range []string{"retry", "resume", "items/0/override"} {
		if w := request(route); w.Code != http.StatusForbidden {
			t.Fatalf("missing update for %s: %d %s", route, w.Code, w.Body.String())
		}
	}
	if mutations != before {
		t.Fatal("job action without update reached node")
	}
	policy.Rules[2].Capabilities = []string{"create", "update"}
	policy.Rules[2].Path = "nodes/node/files/mounts/media/destination/file"
	if err := storage.UpdatePolicy(context.Background(), policy); err != nil {
		t.Fatal(err)
	}
	if w := request("items/0/override"); w.Code != http.StatusForbidden {
		t.Fatalf("missing rename parent authorization: %d %s", w.Code, w.Body.String())
	}
	policy.Rules[2].Path = "nodes/node/files/mounts/media/destination/**"
	if err := storage.UpdatePolicy(context.Background(), policy); err != nil {
		t.Fatal(err)
	}
	if w := request("resume"); w.Code != http.StatusOK {
		t.Fatalf("parent authorization rejected: %d %s", w.Code, w.Body.String())
	}
	policy.Rules = append(policy.Rules, rbac.Rule{Path: "nodes/node/files/mounts/media/source/private/**", Capabilities: []string{"deny"}})
	if err := storage.UpdatePolicy(context.Background(), policy); err != nil {
		t.Fatal(err)
	}
	before = mutations
	for _, route := range []string{"retry", "resume", "items/0/override"} {
		if w := request(route); w.Code != http.StatusForbidden {
			t.Fatalf("denied %s: %d %s", route, w.Code, w.Body.String())
		}
	}
	if mutations != before {
		t.Fatal("denied job action reached node")
	}
	job = `{"job_id":"job-1","type":"copy_local","mount_id":"media","source_path":"unpermitted/jobs","destination_path":"destination/file","conflict_policy":"ask"}`
	if w := request("resume"); w.Code != http.StatusForbidden {
		t.Fatalf("a source directory named jobs bypassed authorization: %d %s", w.Code, w.Body.String())
	}
	job = `{"job_id":"job-1","type":"transfer_pull","mount_id":"media"}`
	if w := request("resume"); w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "job_authorization_upgrade_required") {
		t.Fatalf("remote job must fail closed: %d %s", w.Code, w.Body.String())
	}
}
