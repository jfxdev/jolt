package httpapi

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jfxdev/jolt/control/internal/config"
	"github.com/jfxdev/jolt/control/internal/filetypes"
	"github.com/jfxdev/jolt/control/internal/rbac"
	"github.com/jfxdev/jolt/control/internal/security"
	"github.com/jfxdev/jolt/control/internal/store"
)

type typedHarness struct {
	handler  http.Handler
	storage  *store.Store
	sessions map[string]string
	calls    []string
}

func newTypedHarness(t *testing.T, typed bool, nodeHandler func(*http.Request) (int, http.Header, string), options ...func(*config.Config)) *typedHarness {
	t.Helper()
	ctx, now := context.Background(), time.Now().UTC()
	storage, err := store.Open(filepath.Join(t.TempDir(), "control.db"), make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = storage.Close() })
	h := &typedHarness{storage: storage, sessions: map[string]string{"admin": "admin-session", "operator": "operator-session"}}
	for _, user := range []store.User{
		{ID: "admin", Username: "admin", PasswordHash: "unused", Role: "admin", Enabled: true, CreatedAt: now, UpdatedAt: now},
		{ID: "operator", Username: "operator", PasswordHash: "unused", Role: "operator", Enabled: true, CreatedAt: now, UpdatedAt: now},
	} {
		if err := storage.CreateUser(ctx, user); err != nil {
			t.Fatal(err)
		}
		if err := storage.CreateSession(ctx, security.Digest(h.sessions[user.ID]), user.ID, now.Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	encrypted, err := security.Encrypt(make([]byte, 32), "node-token")
	if err != nil {
		t.Fatal(err)
	}
	if err := storage.SaveNode(ctx, store.Node{ID: "n1", Name: "node", Endpoint: "http://n1.test", TokenEncrypted: encrypted, State: "online", CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		h.calls = append(h.calls, r.Method+" "+r.URL.Path)
		status, header, body := nodeHandler(r)
		if header == nil {
			header = make(http.Header)
		}
		return &http.Response{StatusCode: status, Header: header, Body: io.NopCloser(strings.NewReader(body))}, nil
	})}
	cfg := config.Config{EncryptionKey: make([]byte, 32), StaticDir: t.TempDir(), TypedPolicies: typed, SignedLocalReads: true, SignedUploads: true, SignedLocalJobs: true,
		AuthorizationSigningKeyID: "key", AuthorizationSigningKey: key}
	for _, option := range options {
		option(&cfg)
	}
	h.handler = newHandler(cfg, storage, slog.New(slog.NewTextHandler(io.Discard, nil)), client)
	return h
}

func (h *typedHarness) do(user, method, path string, body any) *httptest.ResponseRecorder {
	var encoded []byte
	if body != nil {
		encoded, _ = json.Marshal(body)
	}
	w := &deadlineRecorder{httptest.NewRecorder()}
	h.handler.ServeHTTP(w, authenticatedRequest(method, path, h.sessions[user], encoded))
	return w.ResponseRecorder
}

// doWith is do with extra request headers.
func (h *typedHarness) doWith(user, method, path string, body any, headers map[string]string) *httptest.ResponseRecorder {
	var encoded []byte
	if body != nil {
		encoded, _ = json.Marshal(body)
	}
	request := authenticatedRequest(method, path, h.sessions[user], encoded)
	for key, value := range headers {
		request.Header.Set(key, value)
	}
	w := &deadlineRecorder{httptest.NewRecorder()}
	h.handler.ServeHTTP(w, request)
	return w.ResponseRecorder
}

func TestTypedRulesAreAcceptedOnlyWhenTypedPoliciesAreEnabled(t *testing.T) {
	base := "nodes/n1/files/mounts/m"
	typedDeny := map[string]any{"path": base + "/**", "capabilities": []string{"deny", "read"}, "file_types": map[string]any{"extensions": []string{"pem"}}}
	typedAllow := map[string]any{"path": base + "/movies/**", "capabilities": []string{"read", "list"}, "file_types": map[string]any{"classes": []string{"video"}}, "visibility": "visible"}
	plainDeny := map[string]any{"path": base + "/vault/**", "capabilities": []string{"deny"}}
	for name, test := range map[string]struct {
		rules           []map[string]any
		wantOff, wantOn int
	}{
		"typed deny":               {[]map[string]any{typedDeny}, 400, 201},
		"typed allow with visible": {[]map[string]any{typedAllow}, 400, 201},
		"path denial is unchanged": {[]map[string]any{plainDeny}, 201, 201},
		"unknown class":            {[]map[string]any{{"path": base + "/**", "capabilities": []string{"read"}, "file_types": map[string]any{"classes": []string{"nonsense"}}}}, 400, 400},
		"empty selector":           {[]map[string]any{{"path": base + "/**", "capabilities": []string{"read"}, "file_types": map[string]any{}}}, 400, 400},
		"visibility needs types":   {[]map[string]any{{"path": base + "/**", "capabilities": []string{"read"}, "visibility": "visible"}}, 400, 400},
		"bad visibility":           {[]map[string]any{{"path": base + "/**", "capabilities": []string{"read"}, "file_types": map[string]any{"extensions": []string{"x"}}, "visibility": "secret"}}, 400, 400},
		"untyped deny with caps":   {[]map[string]any{{"path": base + "/**", "capabilities": []string{"deny", "read"}}}, 400, 400},
	} {
		for _, typed := range []bool{false, true} {
			h := newTypedHarness(t, typed, func(*http.Request) (int, http.Header, string) { return 200, nil, `{}` })
			w := h.do("admin", http.MethodPost, "/api/v1/control-tower/policies", map[string]any{"name": "policy-x", "description": "", "rules": test.rules})
			want := test.wantOff
			if typed {
				want = test.wantOn
			}
			if w.Code != want {
				t.Fatalf("%s typed=%v: %d want %d: %s", name, typed, w.Code, want, w.Body)
			}
		}
	}
}

func TestTypedRulesDecideReadsOnTheNodeAndEverythingElseHere(t *testing.T) {
	var reads, deletes int
	h := newTypedHarness(t, true, func(r *http.Request) (int, http.Header, string) {
		header := make(http.Header)
		header.Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/api/v1/node":
			return 200, header, `{"node_id":"n1","capabilities":["signed_local_read_v1","signed_local_tree_read_v1"]}`
		case r.Method == http.MethodGet:
			reads++
			if r.Header.Get(signedAuthorizationHeader) == "" {
				t.Error("a read reached the node without a signed context")
			}
			header.Set("X-Jolt-Access-Applied", "v1")
			return 200, header, `{"items":[]}`
		case r.Method == http.MethodDelete:
			deletes++
			return 202, header, `{"job_id":"j"}`
		}
		return 404, header, `{}`
	})
	ctx, now := context.Background(), time.Now().UTC()
	pem := &filetypes.Selector{Extensions: []string{"pem"}}
	base := "nodes/n1/files/mounts/m"
	policy := store.Policy{ID: "typed", Name: "typed", CreatedAt: now, UpdatedAt: now, Rules: []rbac.Rule{
		{Path: base + "/**", Capabilities: []string{"read", "list", "delete"}},
		{Path: base + "/**", Capabilities: []string{"deny", "read", "delete"}, FileTypes: pem},
	}}
	if err := h.storage.CreatePolicy(ctx, policy); err != nil {
		t.Fatal(err)
	}
	if err := h.storage.SetSubjectPolicies(ctx, "user", "operator", []string{policy.ID}); err != nil {
		t.Fatal(err)
	}
	// Reads carry a signed context, so the node judges the entry: a file that
	// the typed rule hides still reaches the node, which answers for it.
	for _, name := range []string{"key.pem", "notes.txt"} {
		if w := h.do("operator", http.MethodGet, "/api/v1/nodes/n1/mounts/m/files/content?path=docs/"+name, nil); w.Code != http.StatusOK {
			t.Fatalf("read %s: %d %s", name, w.Code, w.Body)
		}
	}
	if reads != 2 {
		t.Fatalf("reads reaching the node=%d", reads)
	}
	// A direct delete is not filtered by the node, so the Control Tower must
	// refuse what the typed rule hides and allow the rest.
	if w := h.do("operator", http.MethodDelete, "/api/v1/nodes/n1/mounts/m/files?path=docs/key.pem", nil); w.Code != http.StatusForbidden {
		t.Fatalf("delete of a hidden type: %d %s", w.Code, w.Body)
	}
	if w := h.do("operator", http.MethodDelete, "/api/v1/nodes/n1/mounts/m/files?path=docs/notes.txt", nil); w.Code != http.StatusAccepted {
		t.Fatalf("delete of an allowed type: %d %s", w.Code, w.Body)
	}
	if deletes != 1 {
		t.Fatalf("deletes reaching the node=%d", deletes)
	}
}

func TestTypedPoliciesOffKeepTheConservativeEvaluator(t *testing.T) {
	h := newTypedHarness(t, false, func(r *http.Request) (int, http.Header, string) {
		return 200, nil, `{"node_id":"n1","capabilities":[]}`
	})
	ctx, now := context.Background(), time.Now().UTC()
	base := "nodes/n1/files/mounts/m"
	policy := store.Policy{ID: "typed", Name: "typed", CreatedAt: now, UpdatedAt: now, Rules: []rbac.Rule{
		{Path: base + "/**", Capabilities: []string{"read", "list", "delete"}},
		{Path: base + "/**", Capabilities: []string{"deny", "read"}, FileTypes: &filetypes.Selector{Extensions: []string{"pem"}}},
	}}
	if err := h.storage.CreatePolicy(ctx, policy); err != nil {
		t.Fatal(err)
	}
	if err := h.storage.SetSubjectPolicies(ctx, "user", "operator", []string{policy.ID}); err != nil {
		t.Fatal(err)
	}
	// With the feature off, a typed denial already stored still denies, as before.
	if w := h.do("operator", http.MethodDelete, "/api/v1/nodes/n1/mounts/m/files?path=docs/notes.txt", nil); w.Code != http.StatusForbidden {
		t.Fatalf("a typed denial no longer fails closed when the feature is off: %d %s", w.Code, w.Body)
	}
}
