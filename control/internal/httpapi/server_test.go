package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jfxdev/jolt/control/internal/config"
	"github.com/jfxdev/jolt/control/internal/rbac"
	"github.com/jfxdev/jolt/control/internal/security"
	"github.com/jfxdev/jolt/control/internal/store"
)

func testUserHandler(t *testing.T, actor store.User) (http.Handler, *store.Store, string) {
	return testUserHandlerWithClient(t, actor, nil)
}

func testUserHandlerWithClient(t *testing.T, actor store.User, client *http.Client) (http.Handler, *store.Store, string) {
	t.Helper()
	storage, err := store.Open(filepath.Join(t.TempDir(), "control.db"), make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = storage.Close() })
	now := time.Now().UTC()
	if actor.CreatedAt.IsZero() {
		actor.CreatedAt, actor.UpdatedAt = now, now
	}
	if actor.PasswordHash == "" {
		actor.PasswordHash = "unused-hash"
	}
	if err := storage.CreateUser(context.Background(), actor); err != nil {
		t.Fatal(err)
	}
	token := "test-browser-session"
	if err := storage.CreateSession(context.Background(), security.Digest(token), actor.ID, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	handler := newHandler(config.Config{EncryptionKey: make([]byte, 32), StaticDir: t.TempDir()},
		storage, slog.New(slog.NewTextHandler(io.Discard, nil)), client)
	return handler, storage, token
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func TestProxyStreamsInlineMediaWithRange(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Path != "/api/v1/mounts/media/files/content" ||
			request.URL.Query().Get("path") != "clip.mp4" ||
			request.URL.Query().Get("disposition") != "inline" {
			t.Errorf("unexpected node request: %s", request.URL)
		}
		if request.Header.Get("Range") != "bytes=100-199" || request.Header.Get("If-Range") != `"etag-1"` {
			t.Errorf("range headers = %q, %q", request.Header.Get("Range"), request.Header.Get("If-Range"))
		}
		header := make(http.Header)
		header.Set("Content-Type", "video/mp4")
		header.Set("Content-Disposition", `attachment; filename="clip.mp4"`)
		header.Set("Accept-Ranges", "bytes")
		header.Set("Content-Range", "bytes 100-199/1000")
		return &http.Response{
			StatusCode: http.StatusPartialContent,
			Header:     header,
			Body:       io.NopCloser(strings.NewReader("media-bytes")),
		}, nil
	})}
	handler, storage, session := testUserHandlerWithClient(t, store.User{
		ID: "admin-1", Username: "admin", Role: "admin", Enabled: true,
	}, client)
	encrypted, err := security.Encrypt(make([]byte, 32), "node-token")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err := storage.SaveNode(context.Background(), store.Node{
		ID: "node-1", Name: "Node", Endpoint: "http://node.test", TokenEncrypted: encrypted,
		State: "online", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	request := authenticatedRequest(http.MethodGet,
		"/api/v1/nodes/node-1/mounts/media/files/content?path=clip.mp4&disposition=inline", session, nil)
	request.Header.Set("Range", "bytes=100-199")
	request.Header.Set("If-Range", `"etag-1"`)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusPartialContent || response.Body.String() != "media-bytes" {
		t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
	}
	if got := response.Header().Get("Content-Disposition"); got != "inline" {
		t.Errorf("content disposition = %q", got)
	}
	if got := response.Header().Get("Content-Range"); got != "bytes 100-199/1000" {
		t.Errorf("content range = %q", got)
	}
}

func authenticatedRequest(method, path, token string, body []byte) *http.Request {
	request := httptest.NewRequest(method, path, bytes.NewReader(body))
	request.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
	if len(body) > 0 {
		request.Header.Set("Content-Type", "application/json")
	}
	return request
}

func TestAdminUserLifecycleAPI(t *testing.T) {
	handler, storage, token := testUserHandler(t, store.User{
		ID: "admin-1", Username: "admin", Role: "admin", Enabled: true,
	})
	create := httptest.NewRecorder()
	handler.ServeHTTP(create, authenticatedRequest(http.MethodPost, "/api/v1/control-tower/users", token,
		[]byte(`{"username":"operator.one","password":"a-secure-password","role":"operator","enabled":true}`)))
	if create.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", create.Code, create.Body.String())
	}
	users, err := storage.ListUsers(context.Background())
	if err != nil || len(users) != 2 {
		t.Fatalf("users=%+v err=%v", users, err)
	}
	var operator store.User
	for _, user := range users {
		if user.Username == "operator.one" {
			operator = user
		}
	}
	if operator.ID == "" || operator.PasswordHash == "" {
		t.Fatalf("operator not persisted correctly: %+v", operator)
	}
	update := httptest.NewRecorder()
	handler.ServeHTTP(update, authenticatedRequest(http.MethodPatch,
		"/api/v1/control-tower/users/"+operator.ID, token, []byte(`{"enabled":false}`)))
	if update.Code != http.StatusOK {
		t.Fatalf("update status=%d body=%s", update.Code, update.Body.String())
	}
	updated, err := storage.GetUser(context.Background(), operator.ID)
	if err != nil || updated.Enabled {
		t.Fatalf("updated=%+v err=%v", updated, err)
	}
	remove := httptest.NewRecorder()
	handler.ServeHTTP(remove, authenticatedRequest(http.MethodDelete,
		"/api/v1/control-tower/users/"+operator.ID, token, nil))
	if remove.Code != http.StatusNoContent {
		t.Fatalf("delete status=%d body=%s", remove.Code, remove.Body.String())
	}
}

func TestOperatorCannotManageUsers(t *testing.T) {
	handler, _, token := testUserHandler(t, store.User{
		ID: "operator-1", Username: "operator", Role: "operator", Enabled: true,
	})
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, authenticatedRequest(http.MethodGet, "/api/v1/control-tower/users", token, nil))
	if response.Code != http.StatusForbidden {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestControlTowerListsSearchOnServer(t *testing.T) {
	handler, storage, token := testUserHandler(t, store.User{
		ID: "admin-1", Username: "admin", Role: "admin", Enabled: true,
	})
	ctx := context.Background()
	now := time.Now().UTC()
	for _, user := range []store.User{
		{ID: "search-user", Username: "find-user", PasswordHash: "unused-hash", Role: "operator", Enabled: true, CreatedAt: now, UpdatedAt: now},
		{ID: "other-user", Username: "other-user", PasswordHash: "unused-hash", Role: "operator", Enabled: true, CreatedAt: now, UpdatedAt: now},
	} {
		if err := storage.CreateUser(ctx, user); err != nil {
			t.Fatal(err)
		}
	}
	for _, account := range []store.ServiceAccount{
		{ID: "search-key", Name: "find-key", Description: "key to find", Enabled: true, CreatedAt: now, UpdatedAt: now},
		{ID: "other-key", Name: "other-key", Enabled: true, CreatedAt: now, UpdatedAt: now},
	} {
		if err := storage.CreateServiceAccount(ctx, account); err != nil {
			t.Fatal(err)
		}
	}
	for _, group := range []store.AccessGroup{
		{ID: "search-group", Name: "find-group", Description: "group to find", Enabled: true, CreatedAt: now, UpdatedAt: now},
		{ID: "other-group", Name: "other-group", Enabled: true, CreatedAt: now, UpdatedAt: now},
	} {
		if err := storage.CreateAccessGroup(ctx, group); err != nil {
			t.Fatal(err)
		}
	}
	for _, policy := range []store.Policy{
		{ID: "search-policy", Name: "find-policy", Description: "policy to find", CreatedAt: now, UpdatedAt: now},
		{ID: "other-policy", Name: "other-policy", CreatedAt: now, UpdatedAt: now},
	} {
		if err := storage.CreatePolicy(ctx, policy); err != nil {
			t.Fatal(err)
		}
	}
	for _, role := range []store.Role{
		{ID: "search-role", Name: "find-role", Description: "role to find", CreatedAt: now, UpdatedAt: now},
		{ID: "other-role", Name: "other-role", CreatedAt: now, UpdatedAt: now},
	} {
		if err := storage.CreateRole(ctx, role); err != nil {
			t.Fatal(err)
		}
	}

	for _, test := range []struct {
		name string
		path string
		want string
	}{
		{name: "users", path: "/api/v1/control-tower/users?q=find-user", want: `"username":"find-user"`},
		{name: "api keys", path: "/api/v1/control-tower/service-accounts?q=key%20to%20find", want: `"name":"find-key"`},
		{name: "groups", path: "/api/v1/control-tower/access-groups?q=find-group", want: `"name":"find-group"`},
		{name: "policies", path: "/api/v1/control-tower/policies?q=find-policy", want: `"name":"find-policy"`},
		{name: "roles", path: "/api/v1/control-tower/roles?q=find-role", want: `"name":"find-role"`},
	} {
		t.Run(test.name, func(t *testing.T) {
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, authenticatedRequest(http.MethodGet, test.path, token, nil))
			if response.Code != http.StatusOK {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
			var payload struct {
				Items []json.RawMessage `json:"items"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
				t.Fatal(err)
			}
			if len(payload.Items) != 1 || !strings.Contains(string(payload.Items[0]), test.want) {
				t.Fatalf("unexpected search result: %s", response.Body.String())
			}
		})
	}

	wildcard := httptest.NewRecorder()
	handler.ServeHTTP(wildcard, authenticatedRequest(http.MethodGet,
		"/api/v1/control-tower/users?q=%25", token, nil))
	var wildcardPayload struct {
		Items []json.RawMessage `json:"items"`
	}
	if err := json.Unmarshal(wildcard.Body.Bytes(), &wildcardPayload); err != nil {
		t.Fatal(err)
	}
	if wildcard.Code != http.StatusOK || len(wildcardPayload.Items) != 0 {
		t.Fatalf("wildcard search body=%s", wildcard.Body.String())
	}
}

func TestAuditAPIExposesAppliedPolicyContextAndValidatesFilters(t *testing.T) {
	handler, storage, token := testUserHandler(t, store.User{
		ID: "admin-1", Username: "admin", Role: "admin", Enabled: true,
	})
	storage.AuditDecision(context.Background(), "operator-1", "user", "authorize",
		"nodes/node-a/jobs", "denied", "cor-audit",
		[]string{"policy-jobs", "policy-deny"}, "nodes/node-a/jobs", "execute")

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, authenticatedRequest(http.MethodGet,
		"/api/v1/control-tower/audit?result=denied&correlation_id=cor-audit&limit=25", token, nil))
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var payload struct {
		Events  []store.AuditEvent `json:"events"`
		HasMore bool               `json:"has_more"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.Events) != 1 || payload.Events[0].Capability != "execute" ||
		len(payload.Events[0].PolicyIDs) != 2 {
		t.Fatalf("unexpected audit response: %+v", payload)
	}

	invalid := httptest.NewRecorder()
	handler.ServeHTTP(invalid, authenticatedRequest(http.MethodGet,
		"/api/v1/control-tower/audit?limit=0", token, nil))
	if invalid.Code != http.StatusBadRequest {
		t.Fatalf("invalid limit status=%d body=%s", invalid.Code, invalid.Body.String())
	}
}

func TestOperatorCannotListAuditEvents(t *testing.T) {
	handler, _, token := testUserHandler(t, store.User{
		ID: "operator-1", Username: "operator", Role: "operator", Enabled: true,
	})
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, authenticatedRequest(http.MethodGet,
		"/api/v1/control-tower/audit", token, nil))
	if response.Code != http.StatusForbidden {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestServiceAccountCredentialLifecycleAndFailClosedAuthorization(t *testing.T) {
	handler, storage, adminToken := testUserHandler(t, store.User{
		ID: "admin-1", Username: "admin", Role: "admin", Enabled: true,
	})
	now := time.Now().UTC()
	if err := storage.CreateAccessGroup(context.Background(), store.AccessGroup{ID: "group-backup", Name: "group-backup", Enabled: true, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	create := httptest.NewRecorder()
	handler.ServeHTTP(create, authenticatedRequest(http.MethodPost,
		"/api/v1/control-tower/service-accounts", adminToken,
		[]byte(`{"name":"backup-agent","description":"Nightly backup","token_name":"initial","group_ids":["group-backup"]}`)))
	if create.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", create.Code, create.Body.String())
	}
	var created struct {
		ServiceAccount store.ServiceAccount `json:"service_account"`
		Credential     struct {
			ID    string `json:"token_id"`
			Token string `json:"token"`
		} `json:"credential"`
	}
	if err := json.Unmarshal(create.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if created.ServiceAccount.ID == "" || created.Credential.ID == "" ||
		!strings.HasPrefix(created.Credential.Token, "jolt_svc_") {
		t.Fatalf("unexpected response: %+v", created)
	}
	listTokens := httptest.NewRecorder()
	handler.ServeHTTP(listTokens, authenticatedRequest(http.MethodGet,
		"/api/v1/control-tower/service-accounts/"+created.ServiceAccount.ID+"/tokens",
		adminToken, nil))
	if listTokens.Code != http.StatusOK || strings.Contains(listTokens.Body.String(), created.Credential.Token) ||
		strings.Contains(listTokens.Body.String(), "token_hash") {
		t.Fatalf("token metadata leaked credential: status=%d body=%s", listTokens.Code, listTokens.Body.String())
	}

	meRequest := httptest.NewRequest(http.MethodGet, "/api/v1/control-tower/auth/me", nil)
	meRequest.Header.Set("Authorization", "Bearer "+created.Credential.Token)
	me := httptest.NewRecorder()
	handler.ServeHTTP(me, meRequest)
	if me.Code != http.StatusOK || !strings.Contains(me.Body.String(), `"actor_type":"service_account"`) {
		t.Fatalf("me status=%d body=%s", me.Code, me.Body.String())
	}

	nodesRequest := httptest.NewRequest(http.MethodGet, "/api/v1/control-tower/nodes", nil)
	nodesRequest.Header.Set("Authorization", "Bearer "+created.Credential.Token)
	nodes := httptest.NewRecorder()
	handler.ServeHTTP(nodes, nodesRequest)
	if nodes.Code != http.StatusOK || !strings.Contains(nodes.Body.String(), `"items":[]`) {
		t.Fatalf("nodes status=%d body=%s", nodes.Code, nodes.Body.String())
	}

	revoke := httptest.NewRecorder()
	handler.ServeHTTP(revoke, authenticatedRequest(http.MethodDelete,
		"/api/v1/control-tower/service-accounts/"+created.ServiceAccount.ID+"/tokens/"+created.Credential.ID,
		adminToken, nil))
	if revoke.Code != http.StatusNoContent {
		t.Fatalf("revoke status=%d body=%s", revoke.Code, revoke.Body.String())
	}
	rejectedRequest := httptest.NewRequest(http.MethodGet, "/api/v1/control-tower/auth/me", nil)
	rejectedRequest.Header.Set("Authorization", "Bearer "+created.Credential.Token)
	rejected := httptest.NewRecorder()
	handler.ServeHTTP(rejected, rejectedRequest)
	if rejected.Code != http.StatusUnauthorized {
		t.Fatalf("revoked token status=%d body=%s", rejected.Code, rejected.Body.String())
	}
}

func TestServiceAccountMultipleGroupsLifecycleAndActiveGroupRequirement(t *testing.T) {
	handler, storage, adminToken := testUserHandler(t, store.User{
		ID: "admin-1", Username: "admin", Role: "admin", Enabled: true,
	})
	ctx := context.Background()
	now := time.Now().UTC()
	for _, group := range []store.AccessGroup{
		{ID: "group-one", Name: "group-one", Enabled: true, CreatedAt: now, UpdatedAt: now},
		{ID: "group-two", Name: "group-two", Enabled: true, CreatedAt: now, UpdatedAt: now},
		{ID: "group-disabled", Name: "group-disabled", Enabled: false, CreatedAt: now, UpdatedAt: now},
	} {
		if err := storage.CreateAccessGroup(ctx, group); err != nil {
			t.Fatal(err)
		}
	}

	missingGroups := httptest.NewRecorder()
	handler.ServeHTTP(missingGroups, authenticatedRequest(http.MethodPost,
		"/api/v1/control-tower/service-accounts", adminToken,
		[]byte(`{"name":"missing-groups","token_name":"initial"}`)))
	if missingGroups.Code != http.StatusBadRequest || !strings.Contains(missingGroups.Body.String(), `"invalid_access_groups"`) {
		t.Fatalf("missing groups status=%d body=%s", missingGroups.Code, missingGroups.Body.String())
	}

	create := httptest.NewRecorder()
	handler.ServeHTTP(create, authenticatedRequest(http.MethodPost,
		"/api/v1/control-tower/service-accounts", adminToken,
		[]byte(`{"name":"multi-group-key","token_name":"initial","group_ids":["group-one","group-two"]}`)))
	if create.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", create.Code, create.Body.String())
	}
	var created struct {
		ServiceAccount store.ServiceAccount `json:"service_account"`
		Credential     struct {
			Token string `json:"token"`
		} `json:"credential"`
	}
	if err := json.Unmarshal(create.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}

	list := httptest.NewRecorder()
	handler.ServeHTTP(list, authenticatedRequest(http.MethodGet,
		"/api/v1/control-tower/service-accounts/"+created.ServiceAccount.ID+"/groups", adminToken, nil))
	if list.Code != http.StatusOK || !strings.Contains(list.Body.String(), `"group_ids":["group-one","group-two"]`) {
		t.Fatalf("group list status=%d body=%s", list.Code, list.Body.String())
	}

	inactive := httptest.NewRecorder()
	handler.ServeHTTP(inactive, authenticatedRequest(http.MethodPut,
		"/api/v1/control-tower/service-accounts/"+created.ServiceAccount.ID+"/groups", adminToken,
		[]byte(`{"ids":["group-disabled"]}`)))
	if inactive.Code != http.StatusBadRequest {
		t.Fatalf("inactive status=%d body=%s", inactive.Code, inactive.Body.String())
	}
	empty := httptest.NewRecorder()
	handler.ServeHTTP(empty, authenticatedRequest(http.MethodPut,
		"/api/v1/control-tower/service-accounts/"+created.ServiceAccount.ID+"/groups", adminToken,
		[]byte(`{"ids":[]}`)))
	if empty.Code != http.StatusBadRequest {
		t.Fatalf("empty status=%d body=%s", empty.Code, empty.Body.String())
	}

	replace := httptest.NewRecorder()
	handler.ServeHTTP(replace, authenticatedRequest(http.MethodPut,
		"/api/v1/control-tower/service-accounts/"+created.ServiceAccount.ID+"/groups", adminToken,
		[]byte(`{"ids":["group-two"]}`)))
	if replace.Code != http.StatusOK || !strings.Contains(replace.Body.String(), `"group_ids":["group-two"]`) {
		t.Fatalf("replace status=%d body=%s", replace.Code, replace.Body.String())
	}

	authorized := httptest.NewRequest(http.MethodGet, "/api/v1/control-tower/auth/me", nil)
	authorized.Header.Set("Authorization", "Bearer "+created.Credential.Token)
	authorizedResponse := httptest.NewRecorder()
	handler.ServeHTTP(authorizedResponse, authorized)
	if authorizedResponse.Code != http.StatusOK {
		t.Fatalf("active group auth status=%d body=%s", authorizedResponse.Code, authorizedResponse.Body.String())
	}
	groupTwo, err := storage.GetAccessGroup(ctx, "group-two")
	if err != nil {
		t.Fatal(err)
	}
	groupTwo.Enabled = false
	groupTwo.UpdatedAt = now.Add(time.Second)
	if err := storage.UpdateAccessGroup(ctx, groupTwo); err != nil {
		t.Fatal(err)
	}
	blocked := httptest.NewRequest(http.MethodGet, "/api/v1/control-tower/auth/me", nil)
	blocked.Header.Set("Authorization", "Bearer "+created.Credential.Token)
	blockedResponse := httptest.NewRecorder()
	handler.ServeHTTP(blockedResponse, blocked)
	if blockedResponse.Code != http.StatusUnauthorized || !strings.Contains(blockedResponse.Body.String(), `"api_key_without_active_group"`) {
		t.Fatalf("inactive-only auth status=%d body=%s", blockedResponse.Code, blockedResponse.Body.String())
	}
}

func TestOperatorCannotManageServiceAccounts(t *testing.T) {
	handler, _, token := testUserHandler(t, store.User{
		ID: "operator-1", Username: "operator", Role: "operator", Enabled: true,
	})
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, authenticatedRequest(http.MethodGet,
		"/api/v1/control-tower/service-accounts", token, nil))
	if response.Code != http.StatusForbidden {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestAdminRotatesNodeOperationalTokenWithoutExposingIt(t *testing.T) {
	const oldToken = "old-node-token"
	var calls atomic.Int32
	var preparedToken string
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		call := calls.Add(1)
		if call == 1 {
			if r.Header.Get("Authorization") != "Bearer "+oldToken {
				t.Errorf("prepare authorization=%q", r.Header.Get("Authorization"))
			}
			var payload struct {
				NewToken string `json:"new_token"`
			}
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Error(err)
			}
			preparedToken = payload.NewToken
			if len(preparedToken) < 32 {
				t.Errorf("prepared token is too short")
			}
		} else if call == 2 && r.Header.Get("Authorization") != "Bearer "+preparedToken {
			t.Errorf("commit authorization=%q", r.Header.Get("Authorization"))
		}
		return &http.Response{
			StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{}`)),
		}, nil
	})}
	handler, storage, session := testUserHandlerWithClient(t, store.User{
		ID: "admin-1", Username: "admin", Role: "admin", Enabled: true,
	}, client)
	encrypted, err := security.Encrypt(make([]byte, 32), oldToken)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err := storage.SaveNode(context.Background(), store.Node{
		ID: "node-1", Name: "Node", Endpoint: "http://node.test", TokenEncrypted: encrypted,
		State: "online", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, authenticatedRequest(http.MethodPost,
		"/api/v1/control-tower/nodes/node-1/rotate-token", session, []byte(`{}`)))
	if response.Code != http.StatusOK || calls.Load() != 2 ||
		strings.Contains(response.Body.String(), preparedToken) {
		t.Fatalf("status=%d calls=%d body=%s", response.Code, calls.Load(), response.Body.String())
	}
	node, err := storage.GetNode(context.Background(), "node-1")
	if err != nil {
		t.Fatal(err)
	}
	persisted, err := security.Decrypt(make([]byte, 32), node.TokenEncrypted)
	if err != nil || persisted != preparedToken || persisted == oldToken {
		t.Fatalf("persisted token mismatch err=%v", err)
	}
}

func TestIdentityRotationDistributesSignedHandoverToRegisteredPeer(t *testing.T) {
	var applied atomic.Int32
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		body := `{}`
		switch {
		case r.URL.Host == "source.test" && r.Method == http.MethodPost &&
			r.URL.Path == "/api/v1/crypto/identity/rotate":
			body = `{"next_active":{"node_id":"source","fingerprint":"NEW","identity_epoch":2},` +
				`"handover":{"node_id":"source","previous_epoch":1,"next_epoch":2,` +
				`"previous_fingerprint":"OLD","next_fingerprint":"NEW"}}`
		case r.URL.Host == "source.test" && r.Method == http.MethodGet &&
			r.URL.Path == "/api/v1/peers":
			body = `{"items":[{"node_id":"target","fingerprint":"TARGET","identity_epoch":1,"state":"trusted"}]}`
		case r.URL.Host == "target.test" && r.Method == http.MethodGet &&
			r.URL.Path == "/api/v1/peers":
			body = `{"items":[{"node_id":"source","fingerprint":"OLD","identity_epoch":1,"state":"trusted"}]}`
		case r.URL.Host == "target.test" && r.Method == http.MethodPatch &&
			r.URL.Path == "/api/v1/peers/source/identity/handover":
			var handover identityHandover
			if err := json.NewDecoder(r.Body).Decode(&handover); err != nil {
				t.Error(err)
			}
			if handover.NodeID != "source" || handover.PreviousEpoch != 1 || handover.NextEpoch != 2 {
				t.Errorf("unexpected handover: %+v", handover)
			}
			applied.Add(1)
			body = `{"node_id":"source","fingerprint":"NEW","identity_epoch":2,"state":"unknown"}`
		default:
			t.Errorf("unexpected node call: %s %s", r.Method, r.URL)
		}
		return &http.Response{
			StatusCode: http.StatusOK, Header: make(http.Header),
			Body: io.NopCloser(strings.NewReader(body)),
		}, nil
	})}
	handler, storage, session := testUserHandlerWithClient(t, store.User{
		ID: "admin-1", Username: "admin", Role: "admin", Enabled: true,
	}, client)
	encrypted, err := security.Encrypt(make([]byte, 32), "node-token")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	for _, node := range []store.Node{
		{ID: "source", Name: "Source", Endpoint: "http://source.test", TokenEncrypted: encrypted,
			State: "online", CreatedAt: now, UpdatedAt: now},
		{ID: "target", Name: "Target", Endpoint: "http://target.test", TokenEncrypted: encrypted,
			State: "online", CreatedAt: now, UpdatedAt: now},
	} {
		if err := storage.SaveNode(context.Background(), node); err != nil {
			t.Fatal(err)
		}
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, authenticatedRequest(http.MethodPost,
		"/api/v1/control-tower/nodes/source/rotate-identity", session,
		[]byte(`{"confirmed_fingerprint":"OLD"}`)))
	if response.Code != http.StatusOK || applied.Load() != 1 ||
		!strings.Contains(response.Body.String(), `"acknowledged_peer_node_ids":["target"]`) ||
		!strings.Contains(response.Body.String(), `"pending_peer_node_ids":[]`) {
		t.Fatalf("status=%d applied=%d body=%s", response.Code, applied.Load(), response.Body.String())
	}
}

func TestMTLSRotationDistributionAcknowledgesRegisteredPeer(t *testing.T) {
	var accepted, recorded atomic.Int32
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		body := `{}`
		switch {
		case r.URL.Host == "source.test" && r.Method == http.MethodGet &&
			r.URL.Path == "/api/v1/crypto/mtls/rollout":
			body = `{"node_id":"source","certificate":{"serial":"abc","certificate_sha256":"SHA",` +
				`"identity_fingerprint":"SOURCE","state":"next"},"certificate_pem":"PUBLIC"}`
		case r.URL.Host == "source.test" && r.Method == http.MethodGet &&
			r.URL.Path == "/api/v1/peers":
			body = `{"items":[{"node_id":"target","fingerprint":"TARGET","identity_epoch":1,"state":"online"}]}`
		case r.URL.Host == "target.test" && r.Method == http.MethodPatch &&
			r.URL.Path == "/api/v1/peers/source/mtls/rollout":
			var envelope mtlsRolloutEnvelope
			if err := json.NewDecoder(r.Body).Decode(&envelope); err != nil {
				t.Error(err)
			}
			if envelope.NodeID != "source" || envelope.Certificate.Serial != "abc" {
				t.Errorf("unexpected rollout: %+v", envelope)
			}
			accepted.Add(1)
			body = `{"node_id":"source","serial":"abc"}`
		case r.URL.Host == "source.test" && r.Method == http.MethodPost &&
			r.URL.Path == "/api/v1/crypto/mtls/rollout/deliveries":
			var delivery struct {
				Serial     string `json:"serial"`
				PeerNodeID string `json:"peer_node_id"`
			}
			if err := json.NewDecoder(r.Body).Decode(&delivery); err != nil {
				t.Error(err)
			}
			if delivery.Serial != "abc" || delivery.PeerNodeID != "target" {
				t.Errorf("unexpected delivery: %+v", delivery)
			}
			recorded.Add(1)
		default:
			t.Errorf("unexpected node call: %s %s", r.Method, r.URL)
		}
		return &http.Response{
			StatusCode: http.StatusOK, Header: make(http.Header),
			Body: io.NopCloser(strings.NewReader(body)),
		}, nil
	})}
	handler, storage, session := testUserHandlerWithClient(t, store.User{
		ID: "admin-1", Username: "admin", Role: "admin", Enabled: true,
	}, client)
	encrypted, err := security.Encrypt(make([]byte, 32), "node-token")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	for _, node := range []store.Node{
		{ID: "source", Name: "Source", Endpoint: "http://source.test", TokenEncrypted: encrypted,
			State: "online", CreatedAt: now, UpdatedAt: now},
		{ID: "target", Name: "Target", Endpoint: "http://target.test", TokenEncrypted: encrypted,
			State: "online", CreatedAt: now, UpdatedAt: now},
	} {
		if err := storage.SaveNode(context.Background(), node); err != nil {
			t.Fatal(err)
		}
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, authenticatedRequest(http.MethodPost,
		"/api/v1/control-tower/nodes/source/distribute-mtls-rotation", session, []byte(`{}`)))
	if response.Code != http.StatusOK || accepted.Load() != 1 || recorded.Load() != 1 ||
		!strings.Contains(response.Body.String(), `"acknowledged_peer_node_ids":["target"]`) ||
		!strings.Contains(response.Body.String(), `"pending_peer_node_ids":[]`) {
		t.Fatalf("status=%d accepted=%d recorded=%d body=%s",
			response.Code, accepted.Load(), recorded.Load(), response.Body.String())
	}
}

func TestRBACDeniesBeforeNodeCallAndSeparatesFilesFromTransfers(t *testing.T) {
	var nodeCalls atomic.Int32
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		nodeCalls.Add(1)
		if r.Header.Get("Authorization") != "Bearer node-token" {
			t.Errorf("node authorization = %q", r.Header.Get("Authorization"))
			return &http.Response{
				StatusCode: http.StatusUnauthorized, Header: make(http.Header),
				Body: io.NopCloser(strings.NewReader(`{"error":"unauthorized"}`)),
			}, nil
		}
		body := `{"items":[]}`
		if r.URL.Path == "/api/v1/node" {
			body = `{"node_id":"node-1","name":"Node","fingerprint":"AA","mtls_endpoint":"https://node.test:8443"}`
		}
		header := make(http.Header)
		header.Set("Content-Type", "application/json")
		return &http.Response{
			StatusCode: http.StatusOK, Header: header, Body: io.NopCloser(strings.NewReader(body)),
		}, nil
	})}

	handler, storage, _ := testUserHandlerWithClient(t, store.User{
		ID: "admin-1", Username: "admin", Role: "admin", Enabled: true,
	}, client)
	ctx := context.Background()
	now := time.Now().UTC()
	encrypted, err := security.Encrypt(make([]byte, 32), "node-token")
	if err != nil {
		t.Fatal(err)
	}
	if err := storage.SaveNode(ctx, store.Node{
		ID: "node-1", Name: "Node", Endpoint: "http://node.test", TokenEncrypted: encrypted,
		State: "online", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	account := store.ServiceAccount{
		ID: "svc-reader", Name: "reader-agent", Enabled: true, CreatedAt: now, UpdatedAt: now,
	}
	if err := storage.CreateServiceAccount(ctx, account); err != nil {
		t.Fatal(err)
	}
	const serviceToken = "jolt_svc_reader"
	if err := storage.CreateServiceAccountToken(ctx, store.ServiceAccountToken{
		ID: "sat-reader", ServiceAccountID: account.ID, Name: "test",
		TokenHash: security.Digest(serviceToken), CreatedAt: now,
	}, false); err != nil {
		t.Fatal(err)
	}
	allow := store.Policy{
		ID: "policy-files", Name: "media-read", CreatedAt: now, UpdatedAt: now,
		Rules: []rbac.Rule{
			{Path: "nodes/node-1", Capabilities: []string{"list"}},
			{Path: "nodes/node-1/files/mounts/media", Capabilities: []string{"read", "list"}},
		},
	}
	if err := storage.CreatePolicy(ctx, allow); err != nil {
		t.Fatal(err)
	}
	if err := storage.SetSubjectPolicies(ctx, "service_account", account.ID, []string{allow.ID}); err != nil {
		t.Fatal(err)
	}
	group := store.AccessGroup{ID: "group-reader", Name: "group-reader", Enabled: true, CreatedAt: now, UpdatedAt: now}
	if err := storage.CreateAccessGroup(ctx, group); err != nil {
		t.Fatal(err)
	}
	if err := storage.SetAccessGroupNodes(ctx, group.ID, []string{"node-1"}); err != nil {
		t.Fatal(err)
	}
	if err := storage.SetServiceAccountGroups(ctx, account.ID, []string{group.ID}); err != nil {
		t.Fatal(err)
	}
	serviceRequest := func(method, path string) *http.Request {
		request := httptest.NewRequest(method, path, nil)
		request.Header.Set("Authorization", "Bearer "+serviceToken)
		return request
	}
	permissionRequest := httptest.NewRequest(http.MethodPost, "/api/v1/control-tower/auth/permissions",
		strings.NewReader(`{"paths":["nodes/node-1/files/mounts/media","nodes/node-1/transfers"]}`))
	permissionRequest.Header.Set("Authorization", "Bearer "+serviceToken)
	permissions := httptest.NewRecorder()
	handler.ServeHTTP(permissions, permissionRequest)
	if permissions.Code != http.StatusOK ||
		!strings.Contains(permissions.Body.String(), `"nodes/node-1/files/mounts/media":["read","list"]`) ||
		!strings.Contains(permissions.Body.String(), `"nodes/node-1/transfers":[]`) {
		t.Fatalf("permissions status=%d body=%s", permissions.Code, permissions.Body.String())
	}
	read := httptest.NewRecorder()
	handler.ServeHTTP(read, serviceRequest(http.MethodGet,
		"/api/v1/nodes/node-1/mounts/media/files/content?path=movie.mkv"))
	if read.Code != http.StatusOK || nodeCalls.Load() != 1 {
		t.Fatalf("read status=%d calls=%d body=%s", read.Code, nodeCalls.Load(), read.Body.String())
	}
	upload := httptest.NewRecorder()
	handler.ServeHTTP(upload, serviceRequest(http.MethodPut,
		"/api/v1/nodes/node-1/mounts/media/files/content?path=new.mkv"))
	if upload.Code != http.StatusForbidden || nodeCalls.Load() != 1 {
		t.Fatalf("upload status=%d calls=%d body=%s", upload.Code, nodeCalls.Load(), upload.Body.String())
	}
	transfer := httptest.NewRecorder()
	transferRequest := httptest.NewRequest(http.MethodPost, "/api/v1/nodes/node-1/transfers/pull",
		strings.NewReader(`{"peer_node_id":"node-2"}`))
	transferRequest.Header.Set("Authorization", "Bearer "+serviceToken)
	handler.ServeHTTP(transfer, transferRequest)
	if transfer.Code != http.StatusForbidden || nodeCalls.Load() != 1 {
		t.Fatalf("transfer status=%d calls=%d body=%s", transfer.Code, nodeCalls.Load(), transfer.Body.String())
	}

	deny := store.Policy{
		ID: "policy-deny", Name: "deny-media", CreatedAt: now, UpdatedAt: now,
		Rules: []rbac.Rule{{Path: "nodes/node-1/files/mounts/media", Capabilities: []string{"deny"}}},
	}
	if err := storage.CreatePolicy(ctx, deny); err != nil {
		t.Fatal(err)
	}
	if err := storage.SetSubjectPolicies(ctx, "service_account", account.ID, []string{allow.ID, deny.ID}); err != nil {
		t.Fatal(err)
	}
	deniedRead := httptest.NewRecorder()
	handler.ServeHTTP(deniedRead, serviceRequest(http.MethodGet,
		"/api/v1/nodes/node-1/mounts/media/files/content?path=movie.mkv"))
	if deniedRead.Code != http.StatusForbidden || nodeCalls.Load() != 1 {
		t.Fatalf("denied read status=%d calls=%d body=%s", deniedRead.Code, nodeCalls.Load(), deniedRead.Body.String())
	}
}

func TestAPIKeyGroupRestrictsNodeFileAccess(t *testing.T) {
	var calls atomic.Int32
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		calls.Add(1)
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(`{"items":[]}`))}, nil
	})}
	handler, storage, _ := testUserHandlerWithClient(t, store.User{ID: "admin-1", Username: "admin", Role: "admin", Enabled: true}, client)
	ctx := context.Background()
	now := time.Now().UTC()
	encrypted, err := security.Encrypt(make([]byte, 32), "node-token")
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"node-a", "node-b"} {
		if err := storage.SaveNode(ctx, store.Node{ID: id, Name: id, Endpoint: "http://" + id + ".test", TokenEncrypted: encrypted, State: "online", CreatedAt: now, UpdatedAt: now}); err != nil {
			t.Fatal(err)
		}
	}
	policy := store.Policy{ID: "files-read", Name: "files-read", CreatedAt: now, UpdatedAt: now,
		Rules: []rbac.Rule{{Path: "nodes/node-a/files/mounts/media", Capabilities: []string{"list"}}}}
	if err := storage.CreatePolicy(ctx, policy); err != nil {
		t.Fatal(err)
	}
	group := store.AccessGroup{ID: "group-files", Name: "group-files", Enabled: true, CreatedAt: now, UpdatedAt: now}
	if err := storage.CreateAccessGroup(ctx, group); err != nil {
		t.Fatal(err)
	}
	if err := storage.SetAccessGroupNodes(ctx, group.ID, []string{"node-a"}); err != nil {
		t.Fatal(err)
	}
	if err := storage.SetAccessGroupPolicies(ctx, group.ID, []string{policy.ID}); err != nil {
		t.Fatal(err)
	}
	account := store.ServiceAccount{ID: "svc-files", Name: "svc-files", Enabled: true, CreatedAt: now, UpdatedAt: now}
	if err := storage.CreateServiceAccount(ctx, account); err != nil {
		t.Fatal(err)
	}
	if err := storage.SetServiceAccountGroups(ctx, account.ID, []string{group.ID}); err != nil {
		t.Fatal(err)
	}
	secondPolicy := store.Policy{ID: "files-read-b", Name: "files-read-b", CreatedAt: now, UpdatedAt: now,
		Rules: []rbac.Rule{{Path: "nodes/node-b/files/mounts/media", Capabilities: []string{"list"}}}}
	if err := storage.CreatePolicy(ctx, secondPolicy); err != nil {
		t.Fatal(err)
	}
	secondGroup := store.AccessGroup{ID: "group-files-b", Name: "group-files-b", Enabled: true, CreatedAt: now, UpdatedAt: now}
	if err := storage.CreateAccessGroup(ctx, secondGroup); err != nil {
		t.Fatal(err)
	}
	if err := storage.SetAccessGroupNodes(ctx, secondGroup.ID, []string{"node-b"}); err != nil {
		t.Fatal(err)
	}
	if err := storage.SetAccessGroupPolicies(ctx, secondGroup.ID, []string{secondPolicy.ID}); err != nil {
		t.Fatal(err)
	}
	if err := storage.SetServiceAccountGroups(ctx, account.ID, []string{group.ID, secondGroup.ID}); err != nil {
		t.Fatal(err)
	}
	if err := storage.CreateServiceAccountToken(ctx, store.ServiceAccountToken{ID: "key-files", ServiceAccountID: account.ID, Name: "key", TokenHash: security.Digest("jolt_svc_test"), CreatedAt: now}, false); err != nil {
		t.Fatal(err)
	}

	allowed := httptest.NewRequest(http.MethodGet, "/api/v1/nodes/node-a/mounts/media/files", nil)
	allowed.Header.Set("Authorization", "Bearer jolt_svc_test")
	allowedResponse := httptest.NewRecorder()
	handler.ServeHTTP(allowedResponse, allowed)
	if allowedResponse.Code != http.StatusOK || calls.Load() != 1 {
		t.Fatalf("allowed status=%d calls=%d body=%s", allowedResponse.Code, calls.Load(), allowedResponse.Body.String())
	}
	secondAllowed := httptest.NewRequest(http.MethodGet, "/api/v1/nodes/node-b/mounts/media/files", nil)
	secondAllowed.Header.Set("Authorization", "Bearer jolt_svc_test")
	secondAllowedResponse := httptest.NewRecorder()
	handler.ServeHTTP(secondAllowedResponse, secondAllowed)
	if secondAllowedResponse.Code != http.StatusOK || calls.Load() != 2 {
		t.Fatalf("second group status=%d calls=%d body=%s", secondAllowedResponse.Code, calls.Load(), secondAllowedResponse.Body.String())
	}
	denied := httptest.NewRequest(http.MethodGet, "/api/v1/nodes/node-c/mounts/media/files", nil)
	denied.Header.Set("Authorization", "Bearer jolt_svc_test")
	deniedResponse := httptest.NewRecorder()
	handler.ServeHTTP(deniedResponse, denied)
	if deniedResponse.Code != http.StatusForbidden || calls.Load() != 2 {
		t.Fatalf("denied status=%d calls=%d body=%s", deniedResponse.Code, calls.Load(), deniedResponse.Body.String())
	}
}

func TestAccessGroupCRUDAPI(t *testing.T) {
	handler, storage, session := testUserHandler(t, store.User{ID: "admin-1", Username: "admin", Role: "admin", Enabled: true})
	ctx := context.Background()
	now := time.Now().UTC()
	if err := storage.SaveNode(ctx, store.Node{ID: "node-1", Name: "Node", Endpoint: "http://node.test", TokenEncrypted: "encrypted", State: "online", CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	policy := store.Policy{ID: "policy-1", Name: "policy-1", CreatedAt: now, UpdatedAt: now, Rules: []rbac.Rule{{Path: "nodes/node-1/files/mounts/media", Capabilities: []string{"read"}}}}
	if err := storage.CreatePolicy(ctx, policy); err != nil {
		t.Fatal(err)
	}
	create := httptest.NewRecorder()
	handler.ServeHTTP(create, authenticatedRequest(http.MethodPost, "/api/v1/control-tower/access-groups", session, []byte(`{"name":"media-automation","description":"Media API","enabled":true}`)))
	if create.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", create.Code, create.Body.String())
	}
	var group store.AccessGroup
	if err := json.Unmarshal(create.Body.Bytes(), &group); err != nil {
		t.Fatal(err)
	}
	for _, assignment := range []struct{ path, body string }{
		{"/nodes", `{"ids":["node-1"]}`},
		{"/policies", `{"ids":["policy-1"]}`},
	} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, authenticatedRequest(http.MethodPut, "/api/v1/control-tower/access-groups/"+group.ID+assignment.path, session, []byte(assignment.body)))
		if response.Code != http.StatusOK {
			t.Fatalf("assignment %s status=%d body=%s", assignment.path, response.Code, response.Body.String())
		}
	}
	update := httptest.NewRecorder()
	handler.ServeHTTP(update, authenticatedRequest(http.MethodPatch, "/api/v1/control-tower/access-groups/"+group.ID, session, []byte(`{"description":""}`)))
	if update.Code != http.StatusOK || !strings.Contains(update.Body.String(), `"description":""`) {
		t.Fatalf("update status=%d body=%s", update.Code, update.Body.String())
	}
	list := httptest.NewRecorder()
	handler.ServeHTTP(list, authenticatedRequest(http.MethodGet, "/api/v1/control-tower/access-groups", session, nil))
	if list.Code != http.StatusOK || !strings.Contains(list.Body.String(), `"node_ids":["node-1"]`) || !strings.Contains(list.Body.String(), `"policy_ids":["policy-1"]`) {
		t.Fatalf("list status=%d body=%s", list.Code, list.Body.String())
	}
	remove := httptest.NewRecorder()
	handler.ServeHTTP(remove, authenticatedRequest(http.MethodDelete, "/api/v1/control-tower/access-groups/"+group.ID, session, nil))
	if remove.Code != http.StatusNoContent {
		t.Fatalf("delete status=%d body=%s", remove.Code, remove.Body.String())
	}
}

func TestRemoteTransferAuthorizationResolvesExactGrantMounts(t *testing.T) {
	var grantCalls atomic.Int32
	var transferCalls atomic.Int32
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		header := make(http.Header)
		header.Set("Content-Type", "application/json")
		body := `{"job_id":"job-1"}`
		if r.URL.Path == "/api/v1/grants" {
			grantCalls.Add(1)
			if r.URL.Host == "source.test" {
				body = `{"items":[{"grant_id":"source-grant","peer_node_id":"destination","mount_id":"source-media","direction":"send","enabled":true,"permissions":{"read":true}}]}`
			} else {
				body = `{"items":[{"grant_id":"destination-grant","peer_node_id":"source","mount_id":"incoming","direction":"receive","enabled":true,"permissions":{"write":true}}]}`
			}
		} else if r.URL.Path == "/api/v1/transfers/pull" {
			transferCalls.Add(1)
		}
		return &http.Response{
			StatusCode: http.StatusOK, Header: header, Body: io.NopCloser(strings.NewReader(body)),
		}, nil
	})}
	handler, storage, _ := testUserHandlerWithClient(t, store.User{
		ID: "admin-1", Username: "admin", Role: "admin", Enabled: true,
	}, client)
	ctx := context.Background()
	now := time.Now().UTC()
	encrypted, err := security.Encrypt(make([]byte, 32), "node-token")
	if err != nil {
		t.Fatal(err)
	}
	for _, node := range []store.Node{
		{ID: "source", Name: "Source", Endpoint: "http://source.test", TokenEncrypted: encrypted, State: "online", CreatedAt: now, UpdatedAt: now},
		{ID: "destination", Name: "Destination", Endpoint: "http://destination.test", TokenEncrypted: encrypted, State: "online", CreatedAt: now, UpdatedAt: now},
	} {
		if err := storage.SaveNode(ctx, node); err != nil {
			t.Fatal(err)
		}
	}
	account := store.ServiceAccount{
		ID: "svc-transfer", Name: "transfer-agent", Enabled: true, CreatedAt: now, UpdatedAt: now,
	}
	if err := storage.CreateServiceAccount(ctx, account); err != nil {
		t.Fatal(err)
	}
	const serviceToken = "jolt_svc_transfer"
	if err := storage.CreateServiceAccountToken(ctx, store.ServiceAccountToken{
		ID: "sat-transfer", ServiceAccountID: account.ID, Name: "test",
		TokenHash: security.Digest(serviceToken), CreatedAt: now,
	}, false); err != nil {
		t.Fatal(err)
	}
	policy := store.Policy{
		ID: "policy-transfer", Name: "exact-transfer", CreatedAt: now, UpdatedAt: now,
		Rules: []rbac.Rule{
			{Path: "nodes/destination/transfers", Capabilities: []string{"execute"}},
			{Path: "nodes/source/files/mounts/source-media", Capabilities: []string{"read"}},
			{Path: "nodes/destination/files/mounts/incoming", Capabilities: []string{"create"}},
		},
	}
	if err := storage.CreatePolicy(ctx, policy); err != nil {
		t.Fatal(err)
	}
	if err := storage.SetSubjectPolicies(ctx, "service_account", account.ID, []string{policy.ID}); err != nil {
		t.Fatal(err)
	}
	group := store.AccessGroup{ID: "group-transfer", Name: "group-transfer", Enabled: true, CreatedAt: now, UpdatedAt: now}
	if err := storage.CreateAccessGroup(ctx, group); err != nil {
		t.Fatal(err)
	}
	if err := storage.SetAccessGroupNodes(ctx, group.ID, []string{"source", "destination"}); err != nil {
		t.Fatal(err)
	}
	if err := storage.SetServiceAccountGroups(ctx, account.ID, []string{group.ID}); err != nil {
		t.Fatal(err)
	}

	request := func() *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/api/v1/nodes/destination/transfers/pull",
			strings.NewReader(`{"peer_node_id":"source","source_grant_id":"source-grant","destination_grant_id":"destination-grant"}`))
		r.Header.Set("Authorization", "Bearer "+serviceToken)
		return r
	}
	allowed := httptest.NewRecorder()
	handler.ServeHTTP(allowed, request())
	if allowed.Code != http.StatusOK || grantCalls.Load() != 2 || transferCalls.Load() != 1 {
		t.Fatalf("allowed status=%d grants=%d transfers=%d body=%s",
			allowed.Code, grantCalls.Load(), transferCalls.Load(), allowed.Body.String())
	}

	policy.Rules[2].Path = "nodes/destination/files/mounts/other"
	policy.UpdatedAt = now.Add(time.Second)
	if err := storage.UpdatePolicy(ctx, policy); err != nil {
		t.Fatal(err)
	}
	denied := httptest.NewRecorder()
	handler.ServeHTTP(denied, request())
	if denied.Code != http.StatusForbidden || grantCalls.Load() != 4 || transferCalls.Load() != 1 {
		t.Fatalf("denied status=%d grants=%d transfers=%d body=%s",
			denied.Code, grantCalls.Load(), transferCalls.Load(), denied.Body.String())
	}
}

func TestLogicalTransfersResolveGrantsWithoutLeakingThemAndForwardIdempotency(t *testing.T) {
	for _, test := range []struct {
		name                 string
		currentIDs           bool
		missingSource        bool
		missingDestination   bool
		wrongDestinationPeer bool
	}{
		{name: "registered IDs match"},
		{name: "current peer IDs differ from registered IDs", currentIDs: true},
		{name: "source grant disabled", currentIDs: true, missingSource: true},
		{name: "destination grant missing", currentIDs: true, missingDestination: true},
		{name: "both authorizations missing", currentIDs: true, missingSource: true, missingDestination: true},
		{name: "destination grant for another peer", currentIDs: true, wrongDestinationPeer: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			sourcePeerID, destinationPeerID := "source", "destination"
			if test.currentIDs {
				sourcePeerID, destinationPeerID = "source-current", "destination-current"
			}
			var planCalls, createCalls atomic.Int32
			var receivedCreate map[string]any
			client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
				header := make(http.Header)
				header.Set("Content-Type", "application/json")
				body, status := `{}`, http.StatusOK
				switch request.URL.Path {
				case "/api/v1/node":
					peerID := destinationPeerID
					if request.URL.Host == "source.test" {
						peerID = sourcePeerID
					}
					body = `{"node_id":"` + peerID + `","fingerprint":"FP"}`
				case "/api/v1/grants":
					if request.URL.Host == "source.test" {
						body = `{"items":[{"grant_id":"source-grant","peer_node_id":"` + destinationPeerID + `","mount_id":"source-media","path":"exports","direction":"send","enabled":` + fmt.Sprint(!test.missingSource) + `,"permissions":{"read":true,"delete":true}}]}`
					} else {
						grantPeerID := sourcePeerID
						if test.wrongDestinationPeer {
							grantPeerID = "other-peer"
						}
						body = `{"items":[{"grant_id":"destination-grant","peer_node_id":"` + grantPeerID + `","mount_id":"incoming","path":"imports","direction":"receive","enabled":true,"permissions":{"write":true},"conflict_policies":["fail","rename"]}]}`
						if test.missingDestination {
							body = `{"items":[]}`
						}
					}
				case "/api/v1/mounts":
					body = `{"items":[{"mount_id":"incoming","name":"Incoming","enabled":true,"state":"available","writable":true}]}`
				case "/api/v1/transfers/pull/batch/plan":
					planCalls.Add(1)
					body = `{"files_total":2,"bytes_total":12,"copy_count":2,"skip_count":0,"rename_count":0,"conflict_count":0}`
				case "/api/v1/transfers/pull/batch":
					createCalls.Add(1)
					if request.Header.Get("Idempotency-Key") != "logical-key" || request.Header.Get("X-Jolt-Idempotency-Hash") == "" {
						t.Errorf("idempotency headers = %q %q", request.Header.Get("Idempotency-Key"), request.Header.Get("X-Jolt-Idempotency-Hash"))
					}
					if err := json.NewDecoder(request.Body).Decode(&receivedCreate); err != nil {
						t.Error(err)
					}
					body, status = `{"job_id":"batch-job"}`, http.StatusCreated
				}
				return &http.Response{StatusCode: status, Header: header, Body: io.NopCloser(strings.NewReader(body))}, nil
			})}
			handler, storage, session := testUserHandlerWithClient(t, store.User{
				ID: "admin-1", Username: "admin", Role: "admin", Enabled: true,
			}, client)
			now := time.Now().UTC()
			encrypted, err := security.Encrypt(make([]byte, 32), "node-token")
			if err != nil {
				t.Fatal(err)
			}
			for _, node := range []store.Node{
				{ID: "source", Name: "Source", Endpoint: "http://source.test", TokenEncrypted: encrypted, State: "online", CreatedAt: now, UpdatedAt: now},
				{ID: "destination", Name: "Destination", Endpoint: "http://destination.test", TokenEncrypted: encrypted, State: "online", CreatedAt: now, UpdatedAt: now},
			} {
				if err := storage.SaveNode(context.Background(), node); err != nil {
					t.Fatal(err)
				}
			}
			targets := httptest.NewRecorder()
			handler.ServeHTTP(targets, authenticatedRequest(http.MethodPost, "/api/v1/nodes/source/transfers/targets", session,
				[]byte(`{"operation":"move","source":{"mount_id":"source-media","paths":["exports/one.txt","exports/folder"]}}`)))
			payload := []byte(`{"operation":"move","source":{"node_id":"source","mount_id":"source-media","paths":["exports/one.txt","exports/folder"]},"destination":{"mount_id":"incoming","path":"imports/archive"},"conflict_policy":"fail"}`)
			if test.missingSource || test.missingDestination || test.wrongDestinationPeer {
				var response struct {
					Targets []transferTargetNode    `json:"targets"`
					Blocked []blockedTransferTarget `json:"blocked_targets"`
				}
				if err := json.Unmarshal(targets.Body.Bytes(), &response); err != nil || targets.Code != http.StatusOK || len(response.Targets) != 0 || len(response.Blocked) != 1 {
					t.Fatalf("targets status=%d body=%s err=%v", targets.Code, targets.Body.String(), err)
				}
				reasons := response.Blocked[0].Reasons
				if response.Blocked[0].NodeID != "destination" ||
					containsString(reasons, "source_grant_missing") != test.missingSource ||
					containsString(reasons, "destination_grant_missing") != (test.missingDestination || test.wrongDestinationPeer) ||
					strings.Contains(targets.Body.String(), "grant_id") {
					t.Fatalf("unexpected authorization diagnostics: %s", targets.Body.String())
				}
				plan := httptest.NewRecorder()
				handler.ServeHTTP(plan, authenticatedRequest(http.MethodPost, "/api/v1/nodes/destination/transfers/plan", session, payload))
				createRequest := authenticatedRequest(http.MethodPost, "/api/v1/nodes/destination/transfers", session, payload)
				createRequest.Header.Set("Idempotency-Key", "logical-key")
				create := httptest.NewRecorder()
				handler.ServeHTTP(create, createRequest)
				if plan.Code != http.StatusUnprocessableEntity || create.Code != http.StatusUnprocessableEntity || planCalls.Load() != 0 || createCalls.Load() != 0 {
					t.Fatalf("incompatible grants must block plan/create: plan=%d create=%d calls=%d/%d", plan.Code, create.Code, planCalls.Load(), createCalls.Load())
				}
				return
			}
			if targets.Code != http.StatusOK || strings.Contains(targets.Body.String(), "grant_id") ||
				!strings.Contains(targets.Body.String(), `"root_path":"imports"`) || !strings.Contains(targets.Body.String(), `"max_source_paths":1000`) {
				t.Fatalf("targets status=%d body=%s", targets.Code, targets.Body.String())
			}
			plan := httptest.NewRecorder()
			handler.ServeHTTP(plan, authenticatedRequest(http.MethodPost, "/api/v1/nodes/destination/transfers/plan", session, payload))
			if plan.Code != http.StatusOK || planCalls.Load() != 1 || !strings.Contains(plan.Body.String(), `"files_total":2`) {
				t.Fatalf("plan status=%d calls=%d body=%s", plan.Code, planCalls.Load(), plan.Body.String())
			}
			createRequest := authenticatedRequest(http.MethodPost, "/api/v1/nodes/destination/transfers", session, payload)
			createRequest.Header.Set("Idempotency-Key", "logical-key")
			create := httptest.NewRecorder()
			handler.ServeHTTP(create, createRequest)
			if create.Code != http.StatusAccepted || createCalls.Load() != 1 ||
				create.Header().Get("Location") != "/api/v1/nodes/destination/jobs/batch-job" {
				t.Fatalf("create status=%d calls=%d location=%q body=%s", create.Code, createCalls.Load(), create.Header().Get("Location"), create.Body.String())
			}
			if receivedCreate["source_grant_id"] != "source-grant" || receivedCreate["destination_grant_id"] != "destination-grant" ||
				receivedCreate["destination_path"] != "archive" || receivedCreate["operation"] != "move" || receivedCreate["peer_node_id"] != sourcePeerID {
				t.Fatalf("unexpected resolved node payload: %+v", receivedCreate)
			}
			paths, _ := receivedCreate["source_paths"].([]any)
			if len(paths) != 2 || paths[0] != "folder" || paths[1] != "one.txt" {
				t.Fatalf("unexpected translated paths: %+v", paths)
			}
		})
	}
}

func TestLogicalTransferSelectionLimitIsStructured(t *testing.T) {
	handler, _, session := testUserHandler(t, store.User{ID: "admin-1", Username: "admin", Role: "admin", Enabled: true})
	paths := make([]string, 1001)
	for index := range paths {
		paths[index] = fmt.Sprintf("file-%d", index)
	}
	body, err := json.Marshal(map[string]any{
		"operation": "copy", "source": map[string]any{"node_id": "source", "mount_id": "mount", "paths": paths},
		"destination": map[string]any{"mount_id": "mount", "path": "target"},
	})
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, authenticatedRequest(http.MethodPost, "/api/v1/nodes/destination/transfers/plan", session, body))
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), `"selection_limit_exceeded"`) {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestPeerRevocationRequiresDeleteCapability(t *testing.T) {
	requirements := nodeAuthorizationRequirements("node-1", "peers/peer-2", http.MethodDelete, fileTargets{})
	if len(requirements) != 1 || requirements[0].Path != "nodes/node-1/peers" ||
		requirements[0].Capability != "delete" {
		t.Fatalf("requirements=%+v", requirements)
	}
	update := nodeAuthorizationRequirements("node-1", "peers/peer-2", http.MethodPatch, fileTargets{})
	if len(update) != 1 || update[0].Path != "nodes/node-1/peers" || update[0].Capability != "update" {
		t.Fatalf("update requirements=%+v", update)
	}
	identity := nodeAuthorizationRequirements("node-1", "crypto/identity/rotate", http.MethodPost, fileTargets{})
	if len(identity) != 1 || identity[0].Path != "nodes/node-1/keys/identity" ||
		identity[0].Capability != "sudo" {
		t.Fatalf("identity requirements=%+v", identity)
	}
}

func TestAdminPolicyAPIAndAssignment(t *testing.T) {
	handler, storage, token := testUserHandler(t, store.User{
		ID: "admin-1", Username: "admin", Role: "admin", Enabled: true,
	})
	now := time.Now().UTC()
	account := store.ServiceAccount{
		ID: "svc-1", Name: "automation", Enabled: true, CreatedAt: now, UpdatedAt: now,
	}
	if err := storage.CreateServiceAccount(context.Background(), account); err != nil {
		t.Fatal(err)
	}
	create := httptest.NewRecorder()
	handler.ServeHTTP(create, authenticatedRequest(http.MethodPost, "/api/v1/control-tower/policies", token,
		[]byte(`{"name":"media-read","description":"Read media","rules":[{"path":"nodes/*/files/mounts/media","capabilities":["read","list"]}]}`)))
	if create.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", create.Code, create.Body.String())
	}
	var policy store.Policy
	if err := json.Unmarshal(create.Body.Bytes(), &policy); err != nil {
		t.Fatal(err)
	}
	assign := httptest.NewRecorder()
	handler.ServeHTTP(assign, authenticatedRequest(http.MethodPut,
		"/api/v1/control-tower/service-accounts/"+account.ID+"/policies", token,
		[]byte(`{"policy_ids":["`+policy.ID+`"]}`)))
	if assign.Code != http.StatusOK {
		t.Fatalf("assign status=%d body=%s", assign.Code, assign.Body.String())
	}
	ids, err := storage.SubjectPolicyIDs(context.Background(), "service_account", account.ID)
	if err != nil || len(ids) != 1 || ids[0] != policy.ID {
		t.Fatalf("ids=%v err=%v", ids, err)
	}
}

func TestAdminRoleAPIAndUserAssignment(t *testing.T) {
	handler, storage, token := testUserHandler(t, store.User{
		ID: "admin-1", Username: "admin", Role: "admin", Enabled: true,
	})
	ctx := context.Background()
	now := time.Now().UTC()
	policy := store.Policy{
		ID: "policy-media", Name: "media-read", CreatedAt: now, UpdatedAt: now,
		Rules: []rbac.Rule{{Path: "nodes/node-1/files/mounts/media", Capabilities: []string{"read"}}},
	}
	if err := storage.CreatePolicy(ctx, policy); err != nil {
		t.Fatal(err)
	}
	user := store.User{
		ID: "operator-1", Username: "operator.one", PasswordHash: "hash",
		Role: "operator", Enabled: true, CreatedAt: now, UpdatedAt: now,
	}
	if err := storage.CreateUser(ctx, user); err != nil {
		t.Fatal(err)
	}

	create := httptest.NewRecorder()
	handler.ServeHTTP(create, authenticatedRequest(http.MethodPost, "/api/v1/control-tower/roles", token,
		[]byte(`{"name":"media-readers","description":"Leitores de mídia","policy_ids":["`+policy.ID+`"]}`)))
	if create.Code != http.StatusCreated {
		t.Fatalf("create role status=%d body=%s", create.Code, create.Body.String())
	}
	var role store.Role
	if err := json.Unmarshal(create.Body.Bytes(), &role); err != nil {
		t.Fatal(err)
	}
	if role.ID == "" || len(role.PolicyIDs) != 1 || role.PolicyIDs[0] != policy.ID {
		t.Fatalf("unexpected role: %+v", role)
	}
	list := httptest.NewRecorder()
	handler.ServeHTTP(list, authenticatedRequest(http.MethodGet, "/api/v1/control-tower/roles", token, nil))
	if list.Code != http.StatusOK || !strings.Contains(list.Body.String(), `"name":"media-readers"`) {
		t.Fatalf("list roles status=%d body=%s", list.Code, list.Body.String())
	}

	assign := httptest.NewRecorder()
	handler.ServeHTTP(assign, authenticatedRequest(http.MethodPut,
		"/api/v1/control-tower/users/"+user.ID+"/roles", token,
		[]byte(`{"role_ids":["`+role.ID+`"]}`)))
	if assign.Code != http.StatusOK {
		t.Fatalf("assign role status=%d body=%s", assign.Code, assign.Body.String())
	}
	inherited, err := storage.RBACPoliciesForSubject(ctx, "user", user.ID)
	if err != nil || len(inherited) != 1 || inherited[0].ID != policy.ID {
		t.Fatalf("inherited policies=%+v err=%v", inherited, err)
	}

	remove := httptest.NewRecorder()
	handler.ServeHTTP(remove, authenticatedRequest(http.MethodDelete,
		"/api/v1/control-tower/roles/"+role.ID, token, nil))
	if remove.Code != http.StatusNoContent {
		t.Fatalf("delete role status=%d body=%s", remove.Code, remove.Body.String())
	}
	roleIDs, err := storage.UserRoleIDs(ctx, user.ID)
	if err != nil || len(roleIDs) != 0 {
		t.Fatalf("role assignment survived deletion: ids=%v err=%v", roleIDs, err)
	}
}

func TestLoginLocksOutAfterRepeatedFailuresAndClearsOnSuccess(t *testing.T) {
	hash, err := security.HashPassword("correct-horse-battery-staple")
	if err != nil {
		t.Fatal(err)
	}
	handler, _, _ := testUserHandler(t, store.User{
		ID: "admin-1", Username: "admin", Role: "admin", Enabled: true, PasswordHash: hash,
	})
	attempt := func(password string) *httptest.ResponseRecorder {
		body, _ := json.Marshal(map[string]string{"username": "admin", "password": password})
		request := httptest.NewRequest(http.MethodPost, "/api/v1/control-tower/auth/login", bytes.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response
	}

	for i := 0; i < 4; i++ {
		if response := attempt("wrong-password"); response.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d status=%d body=%s", i, response.Code, response.Body.String())
		}
	}

	success := attempt("correct-horse-battery-staple")
	if success.Code != http.StatusOK {
		t.Fatalf("authenticated attempt before lockout status=%d body=%s", success.Code, success.Body.String())
	}

	for i := 0; i < 4; i++ {
		if response := attempt("wrong-password"); response.Code != http.StatusUnauthorized {
			t.Fatalf("post-success attempt %d status=%d body=%s", i, response.Code, response.Body.String())
		}
	}
	locked := attempt("wrong-password")
	if locked.Code != http.StatusUnauthorized {
		t.Fatalf("5th failure status=%d body=%s", locked.Code, locked.Body.String())
	}
	blocked := attempt("correct-horse-battery-staple")
	if blocked.Code != http.StatusTooManyRequests {
		t.Fatalf("locked-out attempt with correct password status=%d body=%s", blocked.Code, blocked.Body.String())
	}
	if blocked.Header().Get("Retry-After") == "" {
		t.Fatal("expected Retry-After header on lockout response")
	}
}

func TestBrowserConnectionRequestAutoApprovesWhenActorCanAdministerTarget(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	expiresAt := now.Add(time.Hour).Format(time.RFC3339Nano)
	var inviteApproved, requestAccepted atomic.Bool
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		header := http.Header{"Content-Type": []string{"application/json"}}
		body, status := `{}`, http.StatusOK
		switch {
		case request.Method == http.MethodGet && request.URL.Path == "/api/v1/node" && request.URL.Host == "source.test":
			body = `{"node_id":"source","name":"Source","fingerprint":"SOURCE-FP","identity_epoch":1,"mtls_endpoint":"https://source.test:8443"}`
		case request.Method == http.MethodGet && request.URL.Path == "/api/v1/node" && request.URL.Host == "target.test":
			body = `{"node_id":"target","name":"Target","fingerprint":"TARGET-FP","identity_epoch":1,"mtls_endpoint":"https://target.test:8443"}`
		case request.Method == http.MethodPost && request.URL.Path == "/api/v1/pairing/invites" && request.URL.Host == "source.test":
			status = http.StatusCreated
			body = `{"invite":{"invite_id":"invite-1","transfer_mode":"dual_channel","issuer_role":"sender_receiver","invitee_role":"sender_receiver","expires_at":"` + expiresAt + `"},"invite_token":"invite-token"}`
		case request.Method == http.MethodPost && request.URL.Path == "/api/v1/pairing/requests" && request.URL.Host == "target.test":
			status = http.StatusCreated
			body = `{"request_id":"request-1","expires_at":"` + expiresAt + `","status":"pending_review"}`
		case request.Method == http.MethodGet && request.URL.Path == "/api/v1/peers":
			// establishConnection probes both sides before acting so it can be
			// re-run; neither node trusts the other yet.
			body = `{"items":[]}`
		case request.Method == http.MethodGet && request.URL.Path == "/api/v1/pairing/invites" && request.URL.Host == "source.test":
			body = `{"items":[{"invite_id":"invite-1","status":"pending"}]}`
		case request.Method == http.MethodGet && request.URL.Path == "/api/v1/pairing/requests" && request.URL.Host == "target.test":
			body = `{"items":[{"request_id":"request-1","status":"pending_review"}]}`
		case request.Method == http.MethodPost && request.URL.Path == "/api/v1/pairing/invites/invite-1/approve" && request.URL.Host == "source.test":
			inviteApproved.Store(true)
		case request.Method == http.MethodPost && request.URL.Path == "/api/v1/pairing/requests/request-1/accept" && request.URL.Host == "target.test":
			var payload struct {
				ConfirmedFingerprint string `json:"confirmed_fingerprint"`
			}
			if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
				t.Errorf("decode acceptance payload: %v", err)
			}
			if payload.ConfirmedFingerprint != "SOURCE-FP" {
				t.Errorf("confirmed fingerprint = %q", payload.ConfirmedFingerprint)
			}
			requestAccepted.Store(true)
		default:
			t.Errorf("unexpected node call: %s %s%s", request.Method, request.URL.Host, request.URL.Path)
			status = http.StatusNotFound
		}
		return &http.Response{StatusCode: status, Header: header, Body: io.NopCloser(strings.NewReader(body))}, nil
	})}
	handler, storage, session := testUserHandlerWithClient(t, store.User{
		ID: "admin-1", Username: "admin", Role: "admin", Enabled: true,
	}, client)
	encrypted, err := security.Encrypt(make([]byte, 32), "node-token")
	if err != nil {
		t.Fatal(err)
	}
	for _, node := range []store.Node{
		{ID: "source", Name: "Source", Endpoint: "http://source.test", TokenEncrypted: encrypted, State: "online", CreatedAt: now, UpdatedAt: now},
		{ID: "target", Name: "Target", Endpoint: "http://target.test", TokenEncrypted: encrypted, State: "online", CreatedAt: now, UpdatedAt: now},
	} {
		if err := storage.SaveNode(ctx, node); err != nil {
			t.Fatal(err)
		}
	}

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, authenticatedRequest(http.MethodPost, "/api/v1/control-tower/connections", session,
		[]byte(`{"issuer_node_id":"source","target_node_id":"target","transfer_mode":"dual_channel","issuer_role":"sender_receiver","invitee_role":"sender_receiver","expiry_minutes":20}`)))
	if response.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var result struct {
		Status       string `json:"status"`
		AutoApproved bool   `json:"auto_approved"`
	}
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	if !result.AutoApproved || result.Status != "connected" || !inviteApproved.Load() || !requestAccepted.Load() {
		t.Fatalf("result=%+v inviteApproved=%t requestAccepted=%t", result, inviteApproved.Load(), requestAccepted.Load())
	}
	connection, err := storage.GetConnection(ctx, "request-1")
	if err != nil || connection.Status != "connected" {
		t.Fatalf("connection=%+v err=%v", connection, err)
	}
}

func TestBrowserConnectionRequestStaysPendingWithoutTargetAdminAccess(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	expiresAt := now.Add(time.Hour).Format(time.RFC3339Nano)
	var targetMetadataCalled atomic.Bool
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		header := http.Header{"Content-Type": []string{"application/json"}}
		body, status := `{}`, http.StatusOK
		switch {
		case request.Method == http.MethodGet && request.URL.Path == "/api/v1/node" && request.URL.Host == "source.test":
			body = `{"node_id":"source","name":"Source","fingerprint":"SOURCE-FP","identity_epoch":1,"mtls_endpoint":"https://source.test:8443"}`
		case request.URL.Host == "target.test" && request.URL.Path == "/api/v1/node":
			targetMetadataCalled.Store(true)
			status = http.StatusInternalServerError
		case request.Method == http.MethodPost && request.URL.Path == "/api/v1/pairing/invites" && request.URL.Host == "source.test":
			status = http.StatusCreated
			body = `{"invite":{"invite_id":"invite-1","transfer_mode":"dual_channel","issuer_role":"sender_receiver","invitee_role":"sender_receiver","expires_at":"` + expiresAt + `"},"invite_token":"invite-token"}`
		case request.Method == http.MethodPost && request.URL.Path == "/api/v1/pairing/requests" && request.URL.Host == "target.test":
			status = http.StatusCreated
			body = `{"request_id":"request-1","expires_at":"` + expiresAt + `","status":"pending_review"}`
		default:
			t.Errorf("unexpected node call: %s %s%s", request.Method, request.URL.Host, request.URL.Path)
			status = http.StatusNotFound
		}
		return &http.Response{StatusCode: status, Header: header, Body: io.NopCloser(strings.NewReader(body))}, nil
	})}
	handler, storage, session := testUserHandlerWithClient(t, store.User{
		ID: "operator-1", Username: "operator", Role: "operator", Enabled: true,
	}, client)
	encrypted, err := security.Encrypt(make([]byte, 32), "node-token")
	if err != nil {
		t.Fatal(err)
	}
	for _, node := range []store.Node{
		{ID: "source", Name: "Source", Endpoint: "http://source.test", TokenEncrypted: encrypted, State: "online", CreatedAt: now, UpdatedAt: now},
		{ID: "target", Name: "Target", Endpoint: "http://target.test", TokenEncrypted: encrypted, State: "online", CreatedAt: now, UpdatedAt: now},
	} {
		if err := storage.SaveNode(ctx, node); err != nil {
			t.Fatal(err)
		}
	}
	policy := store.Policy{ID: "connections-sudo", Name: "connections-sudo", CreatedAt: now, UpdatedAt: now,
		Rules: []rbac.Rule{{Path: "control-tower/connections", Capabilities: []string{"sudo"}}}}
	if err := storage.CreatePolicy(ctx, policy); err != nil {
		t.Fatal(err)
	}
	if err := storage.SetSubjectPolicies(ctx, "user", "operator-1", []string{policy.ID}); err != nil {
		t.Fatal(err)
	}

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, authenticatedRequest(http.MethodPost, "/api/v1/control-tower/connections", session,
		[]byte(`{"issuer_node_id":"source","target_node_id":"target","transfer_mode":"dual_channel","issuer_role":"sender_receiver","invitee_role":"sender_receiver","expiry_minutes":20}`)))
	if response.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var result struct {
		Status       string `json:"status"`
		AutoApproved bool   `json:"auto_approved"`
	}
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	if result.AutoApproved || result.Status != "pending_review" || targetMetadataCalled.Load() {
		t.Fatalf("result=%+v targetMetadataCalled=%t", result, targetMetadataCalled.Load())
	}
	connection, err := storage.GetConnection(ctx, "request-1")
	if err != nil || connection.Status != "pending_review" {
		t.Fatalf("connection=%+v err=%v", connection, err)
	}
}

func TestFileScopeRejectsTraversalAndNormalizes(t *testing.T) {
	base := "nodes/node-a/files/mounts/media"
	cases := map[string]string{
		"":                       base,
		".":                      base,
		"/":                      base,
		"photos":                 base + "/photos",
		"/photos/2024/":          base + "/photos/2024",
		"photos//2024":           base + "/photos/2024",
		"./photos":               base + "/photos",
		"Fotos de Família/a.jpg": base + "/Fotos de Família/a.jpg",
		"..":                     "",
		"photos/../../etc":       "",
		"photos/..":              "",
	}
	for relative, expected := range cases {
		if got := fileScope(base, relative); got != expected {
			t.Fatalf("fileScope(%q) = %q, want %q", relative, got, expected)
		}
	}
}

func TestMountFileRequirementsAreSubpathScoped(t *testing.T) {
	requirements := nodeAuthorizationRequirements("node-1", "mounts/m1/files", http.MethodGet,
		fileTargets{Paths: []string{"photos/2024"}})
	if len(requirements) != 1 ||
		requirements[0].Path != "nodes/node-1/files/mounts/m1/photos/2024" ||
		requirements[0].Capability != "list" {
		t.Fatalf("unexpected listing requirements: %+v", requirements)
	}

	// Copy authorizes reading the source subtree and writing the destination
	// subtree separately.
	copyRequirements := nodeAuthorizationRequirements("node-1", "mounts/m1/files/copy", http.MethodPost,
		fileTargets{Source: "photos/a.jpg", Destination: "backup/a.jpg"})
	expected := map[string]string{
		"nodes/node-1/files/mounts/m1/photos/a.jpg": "read",
		"nodes/node-1/files/mounts/m1/backup/a.jpg": "create",
		"nodes/node-1/jobs":                         "create",
	}
	if len(copyRequirements) != len(expected) {
		t.Fatalf("unexpected copy requirements: %+v", copyRequirements)
	}
	for _, requirement := range copyRequirements {
		if expected[requirement.Path] != requirement.Capability {
			t.Fatalf("unexpected copy requirement %+v", requirement)
		}
	}

	// A traversing path must deny rather than widen to the whole mount.
	if got := nodeAuthorizationRequirements("node-1", "mounts/m1/files", http.MethodDelete,
		fileTargets{Paths: []string{"../../etc"}}); got != nil {
		t.Fatalf("traversal produced requirements: %+v", got)
	}

	// With no path at all the mount itself remains the scope.
	mountWide := nodeAuthorizationRequirements("node-1", "mounts/m1/files", http.MethodGet, fileTargets{})
	if len(mountWide) != 1 || mountWide[0].Path != "nodes/node-1/files/mounts/m1" {
		t.Fatalf("unexpected mount-wide requirements: %+v", mountWide)
	}
}
