package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/jfxdev/jolt/control/internal/config"
	"github.com/jfxdev/jolt/control/internal/rbac"
	"github.com/jfxdev/jolt/control/internal/security"
	"github.com/jfxdev/jolt/control/internal/store"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestTokenRotationReconcilesLostCommitAndRejectsConcurrentRequest(t *testing.T) {
	var mu sync.Mutex
	active := "old"
	prepared := ""
	lost := false
	entered := make(chan struct{})
	release := make(chan struct{})
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		mu.Lock()
		defer mu.Unlock()
		status := 200
		if strings.HasSuffix(r.URL.Path, "/prepare") {
			mu.Unlock()
			close(entered)
			<-release
			mu.Lock()
			var payload struct {
				NewToken string `json:"new_token"`
			}
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Error(err)
			}
			prepared = payload.NewToken
		} else {
			token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			if token != prepared && token != active {
				status = 401
			} else {
				active = token
				if !lost {
					lost = true
					return nil, errors.New("lost commit response")
				}
			}
		}
		return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{}`))}, nil
	})}
	h, storage, session := testUserHandlerWithClient(t, store.User{ID: "admin", Username: "admin", Role: "admin", Enabled: true}, client)
	encrypted, _ := security.Encrypt(make([]byte, 32), "old")
	now := time.Now().UTC()
	if err := storage.SaveNode(context.Background(), store.Node{ID: "node", Name: "Node", Endpoint: "http://node.test", TokenEncrypted: encrypted, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	call := func(handler http.Handler) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, authenticatedRequest("POST", "/api/v1/control-tower/nodes/node/rotate-token", session, []byte(`{}`)))
		return w
	}
	first := make(chan *httptest.ResponseRecorder, 1)
	go func() { first <- call(h) }()
	<-entered
	if w := call(h); w.Code != 409 {
		t.Fatalf("concurrent rotation: %d %s", w.Code, w.Body)
	}
	close(release)
	if w := <-first; w.Code != 502 {
		t.Fatalf("lost response: %d %s", w.Code, w.Body)
	}
	// New handler has no in-memory coordination state, just the persisted intent.
	restarted := newHandler(config.Config{EncryptionKey: make([]byte, 32), StaticDir: t.TempDir()}, storage, slog.New(slog.NewTextHandler(io.Discard, nil)), client)
	if w := call(restarted); w.Code != 200 {
		t.Fatalf("reconcile: %d %s", w.Code, w.Body)
	}
	node, err := storage.GetNode(context.Background(), "node")
	if err != nil {
		t.Fatal(err)
	}
	token, err := security.Decrypt(make([]byte, 32), node.TokenEncrypted)
	if err != nil || token != active || token != prepared {
		t.Fatal("control and node diverged")
	}
}

func TestProxyForwardsEventCursorAndSummaryUsesListPermission(t *testing.T) {
	cursor := ""
	calls := 0
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		cursor = r.Header.Get("Last-Event-ID")
		headers := make(http.Header)
		body := `{"counts":{"running":3},"observed_at":"2026-10-24T12:00:00Z"}`
		if strings.HasSuffix(r.URL.Path, "/events") {
			headers.Set("Content-Type", "text/event-stream")
			body = "id: 43\nevent: job\ndata: {}\n\n"
		}
		return &http.Response{StatusCode: 200, Header: headers, Body: io.NopCloser(strings.NewReader(body))}, nil
	})}
	h, storage, session := testUserHandlerWithClient(t, store.User{ID: "operator", Username: "operator", Role: "operator", Enabled: true}, client)
	now := time.Now().UTC()
	encrypted, _ := security.Encrypt(make([]byte, 32), "node-token")
	if err := storage.SaveNode(context.Background(), store.Node{ID: "node", Name: "Node", Endpoint: "http://node.test", TokenEncrypted: encrypted, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	request := func(path string) *httptest.ResponseRecorder {
		r := authenticatedRequest("GET", path, session, nil)
		r.Header.Set("Last-Event-ID", "42")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	if w := request("/api/v1/nodes/node/jobs/summary"); w.Code != 403 || calls != 0 {
		t.Fatalf("summary leaked: %d calls=%d", w.Code, calls)
	}
	if err := storage.CreatePolicy(context.Background(), store.Policy{ID: "jobs", Name: "jobs", CreatedAt: now, UpdatedAt: now, Rules: []rbac.Rule{{Path: "nodes/node/jobs", Capabilities: []string{"list"}}}}); err != nil {
		t.Fatal(err)
	}
	if err := storage.SetSubjectPolicies(context.Background(), "user", "operator", []string{"jobs"}); err != nil {
		t.Fatal(err)
	}
	if w := request("/api/v1/nodes/node/jobs/summary"); w.Code != 200 {
		t.Fatalf("summary: %d %s", w.Code, w.Body)
	}
	if w := request("/api/v1/nodes/node/jobs/events"); w.Code != 200 || cursor != "42" {
		t.Fatalf("cursor=%q status=%d", cursor, w.Code)
	}
}

func TestUploadVerificationUsesSessionDestination(t *testing.T) {
	h, _, session, _ := uploadProxyFixture(t, "operator")
	for _, id := range []string{"upl_public", "upl_private"} {
		r := authenticatedRequest("GET", "/api/v1/nodes/node/mounts/media/files/uploads/"+id+"/verification?path=public", session, nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		want := 200
		if id == "upl_private" {
			want = 403
		}
		if w.Code != want {
			t.Fatalf("id=%s status=%d body=%s", id, w.Code, w.Body)
		}
	}
}
