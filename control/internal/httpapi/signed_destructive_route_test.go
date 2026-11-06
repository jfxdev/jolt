package httpapi

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jfxdev/jolt/control/internal/config"
	"github.com/jfxdev/jolt/control/internal/security"
	"github.com/jfxdev/jolt/control/internal/store"
)

func destructiveRouteHarness(t *testing.T, nodeHandler func(*http.Request) (int, string)) (http.Handler, string, *[]string) {
	t.Helper()
	return destructiveRouteHarnessConfigured(t, true, nodeHandler)
}

func destructiveRouteHarnessWithFlag(t *testing.T, enabled bool) (http.Handler, string, *[]string) {
	t.Helper()
	return destructiveRouteHarnessConfigured(t, enabled, func(*http.Request) (int, string) { return http.StatusOK, `{}` })
}

func destructiveRouteHarnessConfigured(t *testing.T, enabled bool, nodeHandler func(*http.Request) (int, string)) (http.Handler, string, *[]string) {
	t.Helper()
	ctx, now := context.Background(), time.Now().UTC()
	storage, err := store.Open(filepath.Join(t.TempDir(), "control.db"), make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = storage.Close() })
	if err := storage.CreateUser(ctx, store.User{ID: "admin", Username: "admin", PasswordHash: "unused", Role: "admin", Enabled: true, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	session := "route-test-session"
	if err := storage.CreateSession(ctx, security.Digest(session), "admin", now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	encrypted, err := security.Encrypt(make([]byte, 32), "node-token")
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"n1", "n2"} {
		if err := storage.SaveNode(ctx, store.Node{ID: id, Name: "node " + id, Endpoint: "http://" + id + ".invalid", TokenEncrypted: encrypted, State: "online", CreatedAt: now, UpdatedAt: now}); err != nil {
			t.Fatal(err)
		}
	}
	var calls []string
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls = append(calls, r.Method+" "+r.URL.Path)
		status, body := nodeHandler(r)
		return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
	})}
	// No signing key: a job could never be bound to an authorization.
	handler := newHandler(config.Config{EncryptionKey: make([]byte, 32), StaticDir: t.TempDir(), SignedLocalJobs: enabled}, storage, slog.New(slog.NewTextHandler(io.Discard, nil)), client)
	return handler, session, &calls
}

func TestConfirmingAPlanCancelsTheJobWhenItCannotBeAuthorized(t *testing.T) {
	handler, session, calls := destructiveRouteHarness(t, func(r *http.Request) (int, string) {
		switch r.URL.Path {
		case "/api/v1/node":
			return http.StatusOK, `{"node_id":"n1","capabilities":["destructive_plans_v1","signed_local_copy_execution_v1","signed_job_authorization_registration_v1","signed_job_options_binding_v1"]}`
		case "/api/v1/mounts/files/files/destructive-plans/plan1/accept":
			return http.StatusAccepted, `{"job_id":"job1","type":"delete","state":"waiting_validation","mount_id":"files","source_path":"tree","recursive":true,"max_attempts":1}`
		case "/api/v1/jobs/job1/cancel":
			return http.StatusOK, `{"job_id":"job1","state":"canceled"}`
		}
		return http.StatusNotFound, `{"error":{"code":"not_found","message":"not found"}}`
	})
	r := authenticatedRequest(http.MethodPost, "/api/v1/nodes/n1/mounts/files/files/destructive-plans/plan1/confirm", session, []byte(`{"token":"secret-token"}`))
	r.Header.Set("Idempotency-Key", "confirm-1")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "permission_denied") {
		t.Fatalf("confirm: %d %s", w.Code, w.Body)
	}
	canceled := false
	for _, call := range *calls {
		canceled = canceled || call == "POST /api/v1/jobs/job1/cancel"
	}
	if !canceled {
		t.Fatalf("the unauthorized job was left waiting: %v", *calls)
	}
	if strings.Contains(w.Body.String(), "secret-token") {
		t.Fatal("the confirmation token was echoed")
	}
}

func TestDestructiveRoutesRefuseBadRequestsBeforeTouchingTheNode(t *testing.T) {
	handler, session, calls := destructiveRouteHarness(t, func(r *http.Request) (int, string) {
		return http.StatusNotFound, `{"error":{"code":"not_found","message":"not found"}}`
	})
	post := func(path string, body string, headers map[string]string) *httptest.ResponseRecorder {
		r := authenticatedRequest(http.MethodPost, path, session, []byte(body))
		for name, value := range headers {
			r.Header.Set(name, value)
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	plans := "/api/v1/nodes/n1/mounts/files/files/destructive-plans"
	for name, test := range map[string]struct {
		path, body string
		headers    map[string]string
	}{
		"unknown operation":  {plans, `{"operation":"copy","source_path":"tree"}`, nil},
		"unknown field":      {plans, `{"operation":"delete","source_path":"tree","x":1}`, nil},
		"path outside":       {plans, `{"operation":"delete","source_path":"../x"}`, nil},
		"no idempotency key": {plans + "/p/confirm", `{"token":"t"}`, nil},
		"no token":           {plans + "/p/confirm", `{}`, map[string]string{"Idempotency-Key": "k"}},
		"invalid key":        {plans + "/p/confirm", `{"token":"t"}`, map[string]string{"Idempotency-Key": "bad key!"}},
		"unknown node":       {"/api/v1/nodes/other/mounts/files/files/destructive-plans", `{"operation":"delete","source_path":"tree"}`, nil},
	} {
		if w := post(test.path, test.body, test.headers); w.Code < 400 || w.Code >= 500 {
			t.Fatalf("%s: %d %s", name, w.Code, w.Body)
		}
	}
	if len(*calls) != 0 {
		t.Fatalf("the node was contacted for a rejected request: %v", *calls)
	}
}

// The node accepts the subject of a destructive plan from whoever holds its
// operational token, so the pass-through proxy must never reach those routes.
func TestPassThroughProxyNeverReachesDestructivePlans(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		handler, session, calls := destructiveRouteHarness(t, func(r *http.Request) (int, string) {
			return http.StatusOK, `{}`
		})
		if !enabled {
			// A handler without the dedicated routes.
			handler, session, calls = destructiveRouteHarnessWithFlag(t, false)
		}
		for _, path := range []string{
			"/api/v1/nodes/n1/mounts/files/files/destructive-plans/plan1/accept",
			"/api/v1/nodes/n1/mounts/files/files/destructive-plans/plan1",
			"/api/v1/nodes/n1/mounts/files/files/destructive-plans/extra/accept",
		} {
			for _, method := range []string{http.MethodPost, http.MethodGet, http.MethodDelete, http.MethodPut} {
				r := authenticatedRequest(method, path, session, []byte(`{"subject_type":"user","subject_id":"admin","token":"x"}`))
				w := httptest.NewRecorder()
				handler.ServeHTTP(w, r)
				if w.Code != http.StatusNotFound && w.Code != http.StatusMethodNotAllowed {
					t.Fatalf("enabled=%v %s %s: %d %s", enabled, method, path, w.Code, w.Body)
				}
			}
		}
		if len(*calls) != 0 {
			t.Fatalf("enabled=%v the node was reached through the proxy: %v", enabled, *calls)
		}
	}
}
