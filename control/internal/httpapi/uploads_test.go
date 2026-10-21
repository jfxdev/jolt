package httpapi

import (
	"context"
	"encoding/json"
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

func uploadProxyFixture(t *testing.T, role string) (http.Handler, *store.Store, string, *int) {
	t.Helper()
	mutations := 0
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		body := `{"upload_id":"upl_public","mount_id":"media","destination_path":"public/file.txt","offset":4}`
		if strings.Contains(r.URL.Path, "upl_private") {
			body = `{"upload_id":"upl_private","mount_id":"media","destination_path":"private/secret.txt"}`
		}
		if strings.HasSuffix(r.URL.Path, "/uploads") {
			body = `{"sessions":[` + body + `,{"upload_id":"upl_private","mount_id":"media","destination_path":"private/secret.txt"}]}`
		}
		if r.Method == http.MethodPatch {
			bytes, err := io.ReadAll(r.Body)
			if err != nil || string(bytes) != "data" || r.Header.Get("Content-Range") != "bytes 0-3/4" {
				t.Errorf("chunk=%q range=%q err=%v", bytes, r.Header.Get("Content-Range"), err)
			}
		}
		if r.Method != http.MethodGet {
			mutations++
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
	})}
	actor := store.User{ID: "operator", Username: "operator", Role: role, Enabled: true}
	handler, storage, session := testUserHandlerWithClient(t, actor, client)
	now := time.Now().UTC()
	encrypted, err := security.Encrypt(make([]byte, 32), "node-token")
	if err != nil {
		t.Fatal(err)
	}
	if err := storage.SaveNode(context.Background(), store.Node{ID: "node", Name: "Node", Endpoint: "http://node.test", TokenEncrypted: encrypted, State: "online", CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := storage.CreatePolicy(context.Background(), store.Policy{ID: "uploads", Name: "uploads", CreatedAt: now, UpdatedAt: now, Rules: []rbac.Rule{
		{Path: "nodes/node/files/mounts/media/public/**", Capabilities: []string{"create"}},
		{Path: "nodes/node/jobs", Capabilities: []string{"create"}},
	}}); err != nil {
		t.Fatal(err)
	}
	if err := storage.SetSubjectPolicies(context.Background(), "user", actor.ID, []string{"uploads"}); err != nil {
		t.Fatal(err)
	}
	return handler, storage, session, &mutations
}

func TestUploadProxySupportsChunksForAdminAndSubpathOperator(t *testing.T) {
	for _, role := range []string{"admin", "operator"} {
		t.Run(role, func(t *testing.T) {
			h, _, session, calls := uploadProxyFixture(t, role)
			r := authenticatedRequest(http.MethodPatch, "/api/v1/nodes/node/mounts/media/files/uploads/upl_public", session, []byte("data"))
			r.Header.Set("Content-Range", "bytes 0-3/4")
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != 200 || *calls != 1 {
				t.Fatalf("status=%d calls=%d body=%s", w.Code, *calls, w.Body.String())
			}
		})
	}
}

func TestUploadSessionAuthorizesPersistedPathAndRechecksRevocation(t *testing.T) {
	h, storage, session, calls := uploadProxyFixture(t, "operator")
	base := "/api/v1/nodes/node/mounts/media/files/uploads/"
	for _, method := range []string{http.MethodGet, http.MethodPatch, http.MethodPost, http.MethodDelete} {
		p := base + "upl_private"
		if method == http.MethodPost {
			p += "/complete"
		}
		p += "?path=public/file.txt"
		body := []byte(nil)
		if method == http.MethodPost {
			body = []byte(`{}`)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, authenticatedRequest(method, p, session, body))
		if w.Code != 403 {
			t.Fatalf("method=%s status=%d body=%s", method, w.Code, w.Body.String())
		}
	}
	if *calls != 0 {
		t.Fatal("denied mutation reached node")
	}
	if err := storage.SetSubjectPolicies(context.Background(), "user", "operator", nil); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, authenticatedRequest(http.MethodPatch, base+"upl_public", session, []byte("data")))
	if w.Code != 403 || *calls != 0 {
		t.Fatalf("revoked session status=%d calls=%d", w.Code, *calls)
	}
}

func TestUploadSessionListingDoesNotLeakOtherSubpaths(t *testing.T) {
	h, _, session, _ := uploadProxyFixture(t, "operator")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, authenticatedRequest(http.MethodGet, "/api/v1/nodes/node/mounts/media/files/uploads", session, nil))
	var response struct {
		Sessions []uploadSessionView `json:"sessions"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil || w.Code != 200 || len(response.Sessions) != 1 || response.Sessions[0].ID != "upl_public" {
		t.Fatalf("status=%d body=%s error=%v", w.Code, w.Body.String(), err)
	}
}
