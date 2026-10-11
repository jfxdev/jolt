package httpapi

import (
	"bytes"
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

// shareHarness builds a Control Tower with one node registered and a policy
// granting the actor the capabilities named for the given paths.
type shareHarness struct {
	handler http.Handler
	storage *store.Store
	session string
	nodeID  string
	calls   []*http.Request
}

func newShareHarness(t *testing.T, rules []rbac.Rule) *shareHarness {
	t.Helper()
	harness := &shareHarness{nodeID: "nod_a"}
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		harness.calls = append(harness.calls, request)
		header := make(http.Header)
		header.Set("Content-Type", "application/octet-stream")
		header.Set("Content-Disposition", `attachment; filename="a.txt"`)
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     header,
			Body:       io.NopCloser(strings.NewReader("file-bytes")),
		}, nil
	})}
	actor := store.User{ID: "usr_owner", Username: "owner", Role: "operator", Enabled: true}
	handler, storage, session := testUserHandlerWithClient(t, actor, client)
	harness.handler, harness.storage, harness.session = handler, storage, session

	now := time.Now().UTC()
	encryptedToken, err := security.Encrypt(make([]byte, 32), "node-token")
	if err != nil {
		t.Fatal(err)
	}
	if err := storage.SaveNode(context.Background(), store.Node{
		ID: harness.nodeID, Name: "nas", Endpoint: "http://node.test",
		TokenEncrypted: encryptedToken, State: "online", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if len(rules) > 0 {
		if err := storage.CreatePolicy(context.Background(), store.Policy{
			ID: "pol_share", Name: "share", Rules: rules, CreatedAt: now, UpdatedAt: now,
		}); err != nil {
			t.Fatal(err)
		}
		if err := storage.SetSubjectPolicies(context.Background(), "user", actor.ID,
			[]string{"pol_share"}); err != nil {
			t.Fatal(err)
		}
	}
	return harness
}

func (h *shareHarness) do(t *testing.T, method, target string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		reader = bytes.NewReader(encoded)
	}
	request := httptest.NewRequest(method, target, reader)
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	request.AddCookie(&http.Cookie{Name: sessionCookie, Value: h.session})
	recorder := httptest.NewRecorder()
	h.handler.ServeHTTP(recorder, request)
	return recorder
}

// public issues a request with no session, as an anonymous visitor would.
func (h *shareHarness) public(t *testing.T, method, target string, body any,
	cookies ...*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		reader = bytes.NewReader(encoded)
	}
	request := httptest.NewRequest(method, target, reader)
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}
	recorder := httptest.NewRecorder()
	h.handler.ServeHTTP(recorder, request)
	return recorder
}

func fullAccessRules() []rbac.Rule {
	return []rbac.Rule{
		{Path: "control-tower/shares", Capabilities: []string{"create", "list", "delete"}},
		{Path: "nodes/nod_a/files/mounts/media/**", Capabilities: []string{"read", "list"}},
	}
}

func createShareFor(t *testing.T, harness *shareHarness, body map[string]any) (store.Share, string) {
	t.Helper()
	recorder := harness.do(t, http.MethodPost, "/api/v1/control-tower/shares", body)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("create share: %d %s", recorder.Code, recorder.Body.String())
	}
	var response struct {
		Share store.Share `json:"share"`
		Token string      `json:"token"`
		URL   string      `json:"url"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Token == "" {
		t.Fatal("create share returned no token")
	}
	return response.Share, response.Token
}

func TestCreateShareRequiresReadOnTheExactSubpath(t *testing.T) {
	// The actor may read only one subtree, so sharing a sibling must fail.
	harness := newShareHarness(t, []rbac.Rule{
		{Path: "control-tower/shares", Capabilities: []string{"create", "list", "delete"}},
		{Path: "nodes/nod_a/files/mounts/media/publico/**", Capabilities: []string{"read", "list"}},
	})
	allowed := harness.do(t, http.MethodPost, "/api/v1/control-tower/shares", map[string]any{
		"node_id": "nod_a", "mount_id": "media", "path": "publico/a.txt", "kind": "file",
	})
	if allowed.Code != http.StatusCreated {
		t.Fatalf("sharing a readable path failed: %d %s", allowed.Code, allowed.Body.String())
	}
	denied := harness.do(t, http.MethodPost, "/api/v1/control-tower/shares", map[string]any{
		"node_id": "nod_a", "mount_id": "media", "path": "privado/b.txt", "kind": "file",
	})
	if denied.Code != http.StatusForbidden {
		t.Fatalf("sharing an unreadable path returned %d %s", denied.Code, denied.Body.String())
	}
}

func TestCreateShareRejectsTraversalAndBadInput(t *testing.T) {
	harness := newShareHarness(t, fullAccessRules())
	cases := []map[string]any{
		{"node_id": "nod_a", "mount_id": "media", "path": "../etc/passwd", "kind": "file"},
		{"node_id": "nod_a", "mount_id": "media", "path": "a.txt", "kind": "upload"},
		{"node_id": "nod_a", "mount_id": "media", "path": "a.txt", "kind": "file", "max_downloads": -1},
		{"node_id": "nod_a", "mount_id": "media", "path": "a.txt", "kind": "file", "password": "short"},
		{"node_id": "", "mount_id": "media", "path": "a.txt", "kind": "file"},
		{"node_id": "nod_a", "mount_id": "media", "path": "a.txt", "kind": "file",
			"expires_in_seconds": 400 * 24 * 3600},
	}
	for _, body := range cases {
		recorder := harness.do(t, http.MethodPost, "/api/v1/control-tower/shares", body)
		if recorder.Code < 400 {
			t.Fatalf("invalid share %v was accepted: %d", body, recorder.Code)
		}
	}
}

func TestShareTokenIsReturnedOnceAndStoredHashed(t *testing.T) {
	harness := newShareHarness(t, fullAccessRules())
	share, token := createShareFor(t, harness, map[string]any{
		"node_id": "nod_a", "mount_id": "media", "path": "a.txt", "kind": "file",
	})
	stored, err := harness.storage.GetShare(context.Background(), share.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.TokenHash != security.Digest(token) {
		t.Fatal("share token is not stored as a digest")
	}
	if strings.Contains(stored.TokenHash, token) {
		t.Fatal("share token leaked into storage")
	}
	// Listing must never expose the digest or the token.
	listing := harness.do(t, http.MethodGet, "/api/v1/control-tower/shares", nil)
	if strings.Contains(listing.Body.String(), token) ||
		strings.Contains(listing.Body.String(), stored.TokenHash) {
		t.Fatal("share listing leaked the token")
	}
}

func TestPublicShareServesContentWithoutASession(t *testing.T) {
	harness := newShareHarness(t, fullAccessRules())
	_, token := createShareFor(t, harness, map[string]any{
		"node_id": "nod_a", "mount_id": "media", "path": "docs/a.txt", "kind": "file",
	})
	recorder := harness.public(t, http.MethodGet, "/api/v1/public/shares/"+token+"/content", nil)
	if recorder.Code != http.StatusOK {
		t.Fatalf("public download returned %d %s", recorder.Code, recorder.Body.String())
	}
	if recorder.Body.String() != "file-bytes" {
		t.Fatalf("unexpected body %q", recorder.Body.String())
	}
	// The node call must target exactly the shared path with the node's token.
	last := harness.calls[len(harness.calls)-1]
	if last.URL.Query().Get("path") != "docs/a.txt" {
		t.Fatalf("node path = %q", last.URL.Query().Get("path"))
	}
	if last.Header.Get("Authorization") != "Bearer node-token" {
		t.Fatal("the node token was not used for the share")
	}
	// A public response must not be cached by a shared proxy.
	if !strings.Contains(recorder.Header().Get("Cache-Control"), "no-store") {
		t.Fatalf("Cache-Control = %q", recorder.Header().Get("Cache-Control"))
	}
}

func TestPublicShareRejectsUnknownAndRevokedTokensIdentically(t *testing.T) {
	harness := newShareHarness(t, fullAccessRules())
	share, token := createShareFor(t, harness, map[string]any{
		"node_id": "nod_a", "mount_id": "media", "path": "a.txt", "kind": "file",
	})
	unknown := harness.public(t, http.MethodGet, "/api/v1/public/shares/does-not-exist", nil)
	if unknown.Code != http.StatusNotFound {
		t.Fatalf("unknown token returned %d", unknown.Code)
	}
	if err := harness.storage.RevokeShare(context.Background(), share.ID, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	revoked := harness.public(t, http.MethodGet, "/api/v1/public/shares/"+token, nil)
	if revoked.Code != http.StatusGone {
		t.Fatalf("revoked token returned %d", revoked.Code)
	}
	content := harness.public(t, http.MethodGet, "/api/v1/public/shares/"+token+"/content", nil)
	if content.Code != http.StatusGone {
		t.Fatalf("revoked share still served content: %d", content.Code)
	}
}

func TestPublicShareEnforcesExpiry(t *testing.T) {
	harness := newShareHarness(t, fullAccessRules())
	_, token := createShareFor(t, harness, map[string]any{
		"node_id": "nod_a", "mount_id": "media", "path": "a.txt", "kind": "file",
		"expires_in_seconds": 1,
	})
	if recorder := harness.public(t, http.MethodGet,
		"/api/v1/public/shares/"+token+"/content", nil); recorder.Code != http.StatusOK {
		t.Fatalf("fresh share returned %d", recorder.Code)
	}
	// Move the stored expiry into the past rather than sleeping.
	share, err := harness.storage.ShareByTokenHash(context.Background(), security.Digest(token))
	if err != nil {
		t.Fatal(err)
	}
	past := time.Now().UTC().Add(-time.Minute)
	share.ExpiresAt = &past
	if err := harness.storage.DeleteShare(context.Background(), share.ID); err != nil {
		t.Fatal(err)
	}
	if err := harness.storage.CreateShare(context.Background(), share); err != nil {
		t.Fatal(err)
	}
	if recorder := harness.public(t, http.MethodGet,
		"/api/v1/public/shares/"+token+"/content", nil); recorder.Code != http.StatusGone {
		t.Fatalf("expired share returned %d", recorder.Code)
	}
}

func TestPublicShareEnforcesDownloadBudget(t *testing.T) {
	harness := newShareHarness(t, fullAccessRules())
	_, token := createShareFor(t, harness, map[string]any{
		"node_id": "nod_a", "mount_id": "media", "path": "a.txt", "kind": "file",
		"max_downloads": 2,
	})
	for attempt := 1; attempt <= 2; attempt++ {
		if recorder := harness.public(t, http.MethodGet,
			"/api/v1/public/shares/"+token+"/content", nil); recorder.Code != http.StatusOK {
			t.Fatalf("download %d returned %d", attempt, recorder.Code)
		}
	}
	if recorder := harness.public(t, http.MethodGet,
		"/api/v1/public/shares/"+token+"/content", nil); recorder.Code != http.StatusGone {
		t.Fatalf("download past the budget returned %d", recorder.Code)
	}
}

func TestRangeRequestDoesNotConsumeTheDownloadBudget(t *testing.T) {
	harness := newShareHarness(t, fullAccessRules())
	_, token := createShareFor(t, harness, map[string]any{
		"node_id": "nod_a", "mount_id": "media", "path": "big.bin", "kind": "file",
		"max_downloads": 1,
	})
	// A resumed download sends several ranged requests for one logical
	// download, so they must not each spend the budget.
	for attempt := 0; attempt < 3; attempt++ {
		request := httptest.NewRequest(http.MethodGet,
			"/api/v1/public/shares/"+token+"/content", nil)
		request.Header.Set("Range", "bytes=0-9")
		recorder := httptest.NewRecorder()
		harness.handler.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusOK {
			t.Fatalf("ranged request %d returned %d", attempt, recorder.Code)
		}
	}
	share, err := harness.storage.ShareByTokenHash(context.Background(), security.Digest(token))
	if err != nil {
		t.Fatal(err)
	}
	if share.DownloadCount != 0 {
		t.Fatalf("ranged requests consumed %d downloads", share.DownloadCount)
	}
}

func TestPasswordProtectedShareRequiresUnlock(t *testing.T) {
	harness := newShareHarness(t, fullAccessRules())
	share, token := createShareFor(t, harness, map[string]any{
		"node_id": "nod_a", "mount_id": "media", "path": "a.txt", "kind": "file",
		"password": "correct horse battery",
	})
	locked := harness.public(t, http.MethodGet, "/api/v1/public/shares/"+token+"/content", nil)
	if locked.Code != http.StatusUnauthorized {
		t.Fatalf("locked share served content: %d", locked.Code)
	}
	wrong := harness.public(t, http.MethodPost, "/api/v1/public/shares/"+token+"/unlock",
		map[string]any{"password": "wrong"})
	if wrong.Code != http.StatusUnauthorized {
		t.Fatalf("wrong password returned %d", wrong.Code)
	}
	unlock := harness.public(t, http.MethodPost, "/api/v1/public/shares/"+token+"/unlock",
		map[string]any{"password": "correct horse battery"})
	if unlock.Code != http.StatusOK {
		t.Fatalf("unlock returned %d %s", unlock.Code, unlock.Body.String())
	}
	var ticket *http.Cookie
	for _, cookie := range unlock.Result().Cookies() {
		if cookie.Name == shareCookiePrefix+share.ID {
			ticket = cookie
		}
	}
	if ticket == nil {
		t.Fatal("unlock set no ticket cookie")
	}
	if !ticket.HttpOnly {
		t.Fatal("the unlock ticket is readable by scripts")
	}
	unlocked := harness.public(t, http.MethodGet,
		"/api/v1/public/shares/"+token+"/content", nil, ticket)
	if unlocked.Code != http.StatusOK {
		t.Fatalf("unlocked share returned %d %s", unlocked.Code, unlocked.Body.String())
	}
	// A ticket minted for one share must not open another.
	_, otherToken := createShareFor(t, harness, map[string]any{
		"node_id": "nod_a", "mount_id": "media", "path": "b.txt", "kind": "file",
		"password": "correct horse battery",
	})
	crossed := harness.public(t, http.MethodGet,
		"/api/v1/public/shares/"+otherToken+"/content", nil, ticket)
	if crossed.Code != http.StatusUnauthorized {
		t.Fatalf("an unlock ticket crossed shares: %d", crossed.Code)
	}
}

func TestForgedUnlockTicketIsRejected(t *testing.T) {
	harness := newShareHarness(t, fullAccessRules())
	share, token := createShareFor(t, harness, map[string]any{
		"node_id": "nod_a", "mount_id": "media", "path": "a.txt", "kind": "file",
		"password": "correct horse battery",
	})
	future := time.Now().UTC().Add(time.Hour).Unix()
	forged := []string{
		"", "nonsense",
		// A valid-looking expiry with a bad signature must not pass.
		strings.Join([]string{"9999999999", strings.Repeat("0", 64)}, "."),
		strings.Join([]string{"not-a-number", strings.Repeat("0", 64)}, "."),
	}
	for _, value := range forged {
		recorder := harness.public(t, http.MethodGet, "/api/v1/public/shares/"+token+"/content", nil,
			&http.Cookie{Name: shareCookiePrefix + share.ID, Value: value})
		if recorder.Code != http.StatusUnauthorized {
			t.Fatalf("forged ticket %q returned %d", value, recorder.Code)
		}
	}
	_ = future
}

func TestDirectoryShareConfinesSubpaths(t *testing.T) {
	harness := newShareHarness(t, fullAccessRules())
	_, token := createShareFor(t, harness, map[string]any{
		"node_id": "nod_a", "mount_id": "media", "path": "publico", "kind": "directory",
	})
	// A subpath inside the share resolves under the share root.
	ok := harness.public(t, http.MethodGet,
		"/api/v1/public/shares/"+token+"/list?path=fotos", nil)
	if ok.Code != http.StatusOK {
		t.Fatalf("listing a subpath returned %d %s", ok.Code, ok.Body.String())
	}
	last := harness.calls[len(harness.calls)-1]
	if last.URL.Query().Get("path") != "publico/fotos" {
		t.Fatalf("subpath resolved to %q", last.URL.Query().Get("path"))
	}
	// Traversal out of the shared subtree must be refused.
	for _, escape := range []string{"..", "../privado", "fotos/../../privado"} {
		recorder := harness.public(t, http.MethodGet,
			"/api/v1/public/shares/"+token+"/list?path="+escape, nil)
		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("escape %q returned %d", escape, recorder.Code)
		}
	}
}

func TestFileShareRejectsASubpath(t *testing.T) {
	harness := newShareHarness(t, fullAccessRules())
	_, token := createShareFor(t, harness, map[string]any{
		"node_id": "nod_a", "mount_id": "media", "path": "docs/a.txt", "kind": "file",
	})
	recorder := harness.public(t, http.MethodGet,
		"/api/v1/public/shares/"+token+"/content?path=other.txt", nil)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("a file share accepted a subpath: %d", recorder.Code)
	}
	listing := harness.public(t, http.MethodGet, "/api/v1/public/shares/"+token+"/list", nil)
	if listing.Code != http.StatusBadRequest {
		t.Fatalf("a file share accepted a listing: %d", listing.Code)
	}
}

func TestShareDiesWithTheCreatorsAccess(t *testing.T) {
	harness := newShareHarness(t, fullAccessRules())
	_, token := createShareFor(t, harness, map[string]any{
		"node_id": "nod_a", "mount_id": "media", "path": "a.txt", "kind": "file",
	})
	if recorder := harness.public(t, http.MethodGet,
		"/api/v1/public/shares/"+token+"/content", nil); recorder.Code != http.StatusOK {
		t.Fatalf("share did not serve while authorized: %d", recorder.Code)
	}
	// Revoking the creator's policies must stop their links from serving.
	if err := harness.storage.SetSubjectPolicies(context.Background(), "user", "usr_owner",
		[]string{}); err != nil {
		t.Fatal(err)
	}
	if recorder := harness.public(t, http.MethodGet,
		"/api/v1/public/shares/"+token+"/content", nil); recorder.Code != http.StatusGone {
		t.Fatalf("share outlived the creator's access: %d", recorder.Code)
	}
}

func TestShareDiesWithADisabledCreator(t *testing.T) {
	harness := newShareHarness(t, fullAccessRules())
	_, token := createShareFor(t, harness, map[string]any{
		"node_id": "nod_a", "mount_id": "media", "path": "a.txt", "kind": "file",
	})
	owner, err := harness.storage.GetUser(context.Background(), "usr_owner")
	if err != nil {
		t.Fatal(err)
	}
	owner.Enabled = false
	if err := harness.storage.UpdateUser(context.Background(), owner, ""); err != nil {
		t.Skipf("cannot disable the user in this store revision: %v", err)
	}
	if recorder := harness.public(t, http.MethodGet,
		"/api/v1/public/shares/"+token+"/content", nil); recorder.Code != http.StatusGone {
		t.Fatalf("share outlived a disabled creator: %d", recorder.Code)
	}
}

func TestPublicShareSurfaceIsReadOnly(t *testing.T) {
	harness := newShareHarness(t, fullAccessRules())
	_, token := createShareFor(t, harness, map[string]any{
		"node_id": "nod_a", "mount_id": "media", "path": "publico", "kind": "directory",
	})
	// No public route accepts a write, under any method.
	for _, method := range []string{http.MethodPut, http.MethodDelete, http.MethodPatch} {
		for _, path := range []string{"/content", "/list", "/archive", ""} {
			recorder := harness.public(t, method, "/api/v1/public/shares/"+token+path, nil)
			if recorder.Code < 400 {
				t.Fatalf("%s %s was accepted: %d", method, path, recorder.Code)
			}
		}
	}
}

func TestArchiveShareHonoursTheAllowArchiveFlag(t *testing.T) {
	harness := newShareHarness(t, fullAccessRules())
	disabled := false
	_, token := createShareFor(t, harness, map[string]any{
		"node_id": "nod_a", "mount_id": "media", "path": "publico", "kind": "directory",
		"allow_archive": &disabled,
	})
	if recorder := harness.public(t, http.MethodGet,
		"/api/v1/public/shares/"+token+"/archive", nil); recorder.Code != http.StatusForbidden {
		t.Fatalf("archive was served despite being disabled: %d", recorder.Code)
	}
	_, allowedToken := createShareFor(t, harness, map[string]any{
		"node_id": "nod_a", "mount_id": "media", "path": "outro", "kind": "directory",
	})
	if recorder := harness.public(t, http.MethodGet,
		"/api/v1/public/shares/"+allowedToken+"/archive", nil); recorder.Code != http.StatusOK {
		t.Fatalf("archive was refused despite being enabled: %d", recorder.Code)
	}
}

func TestShareMetadataDoesNotLeakThePath(t *testing.T) {
	harness := newShareHarness(t, fullAccessRules())
	_, token := createShareFor(t, harness, map[string]any{
		"node_id": "nod_a", "mount_id": "media", "path": "privado/contabilidade/2024",
		"kind": "directory", "password": "correct horse battery",
	})
	recorder := harness.public(t, http.MethodGet, "/api/v1/public/shares/"+token, nil)
	if recorder.Code != http.StatusOK {
		t.Fatalf("metadata returned %d", recorder.Code)
	}
	body := recorder.Body.String()
	// A locked link must not reveal where it points, nor which node holds it.
	for _, secret := range []string{"privado/contabilidade", "nod_a", "media"} {
		if strings.Contains(body, secret) {
			t.Fatalf("metadata leaked %q: %s", secret, body)
		}
	}
	if !strings.Contains(body, `"name":"2024"`) {
		t.Fatalf("metadata omitted the display name: %s", body)
	}
}

func TestOnlyOwnerOrAdminCanRevokeAShare(t *testing.T) {
	harness := newShareHarness(t, fullAccessRules())
	share, _ := createShareFor(t, harness, map[string]any{
		"node_id": "nod_a", "mount_id": "media", "path": "a.txt", "kind": "file",
	})
	// The owner may revoke their own link.
	if recorder := harness.do(t, http.MethodPost,
		"/api/v1/control-tower/shares/"+share.ID+"/revoke", nil); recorder.Code != http.StatusNoContent {
		t.Fatalf("owner could not revoke: %d %s", recorder.Code, recorder.Body.String())
	}
	// Revoking twice is a conflict, not a silent success.
	if recorder := harness.do(t, http.MethodPost,
		"/api/v1/control-tower/shares/"+share.ID+"/revoke", nil); recorder.Code != http.StatusConflict {
		t.Fatalf("second revoke returned %d", recorder.Code)
	}
}

func TestShareOfAnotherOwnerNeedsSudo(t *testing.T) {
	harness := newShareHarness(t, fullAccessRules())
	now := time.Now().UTC()
	// A link created by somebody else cannot be removed without sudo.
	foreign := store.Share{
		ID: "shr_foreign", TokenHash: security.Digest("foreign-token"), NodeID: "nod_a",
		MountID: "media", Path: "a.txt", Kind: "file", CreatedBy: "usr_other", CreatedAt: now,
	}
	if err := harness.storage.CreateShare(context.Background(), foreign); err != nil {
		t.Fatal(err)
	}
	recorder := harness.do(t, http.MethodDelete, "/api/v1/control-tower/shares/"+foreign.ID, nil)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("removing another owner's link returned %d %s", recorder.Code, recorder.Body.String())
	}
}

func TestListSharesShowsOnlyOwnLinksWithoutSudo(t *testing.T) {
	harness := newShareHarness(t, fullAccessRules())
	createShareFor(t, harness, map[string]any{
		"node_id": "nod_a", "mount_id": "media", "path": "mine.txt", "kind": "file",
	})
	now := time.Now().UTC()
	if err := harness.storage.CreateShare(context.Background(), store.Share{
		ID: "shr_other", TokenHash: security.Digest("other"), NodeID: "nod_a", MountID: "media",
		Path: "theirs.txt", Kind: "file", Name: "theirs.txt", CreatedBy: "usr_other", CreatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	recorder := harness.do(t, http.MethodGet, "/api/v1/control-tower/shares", nil)
	if recorder.Code != http.StatusOK {
		t.Fatalf("listing returned %d", recorder.Code)
	}
	body := recorder.Body.String()
	if !strings.Contains(body, "mine.txt") {
		t.Fatalf("listing omitted the caller's own link: %s", body)
	}
	if strings.Contains(body, "theirs.txt") {
		t.Fatalf("listing exposed another owner's link: %s", body)
	}
}

func TestCreateShareNeedsTheSharesCapability(t *testing.T) {
	// Read access to the files is not enough to publish a public link.
	harness := newShareHarness(t, []rbac.Rule{
		{Path: "nodes/nod_a/files/mounts/media/**", Capabilities: []string{"read", "list"}},
	})
	recorder := harness.do(t, http.MethodPost, "/api/v1/control-tower/shares", map[string]any{
		"node_id": "nod_a", "mount_id": "media", "path": "a.txt", "kind": "file",
	})
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("share was created without the capability: %d %s", recorder.Code, recorder.Body.String())
	}
}
